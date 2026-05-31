package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// labelSource tells the engine where to look up a label value when a log
// line is processed.
type labelSource int

const (
	sourceLog labelSource = iota
	sourceDiscovery
	sourceDerived
)

type resolvedLabel struct {
	name   string
	source labelSource
}

type aggregation struct {
	cfg    AggregationCfg
	labels []resolvedLabel

	counter   *prometheus.CounterVec
	histogram *prometheus.HistogramVec
}

// metricEngine owns all declarative aggregations and the global cardinality
// safety net. Each processed log line walks every aggregation, resolves the
// configured labels, and emits the observation.
type metricEngine struct {
	cfg  *Config
	disc *discoveryEngine

	aggs []*aggregation

	seriesGuard   *globalCardinalityTracker
	seriesDropped prometheus.Counter

	linesOK     prometheus.Counter
	parseErrors prometheus.Counter
	unmapped    prometheus.Counter
	mappedSize  prometheus.Gauge
}

// derivedLabels are computed from log fields (e.g. status_class from status).
var derivedLabels = map[string]bool{
	"status_class": true,
}

// logFieldAliases lets aggregations refer to log fields by either the nginx
// variable name or a short alias.
var logFieldAliases = map[string]string{
	"method":        "request_method",
	"upstream_time": "upstream_response_time",
	"http_protocol": "server_protocol",
	"user_agent":    "http_user_agent",
}

func normalizeLogField(name string) string {
	if alias, ok := logFieldAliases[name]; ok {
		return alias
	}
	return name
}

// knownLogFields lists every field name a user can reference from a log line.
// Used for config validation.
var knownLogFields = map[string]bool{
	"server_name":            true,
	"request_uri":            true,
	"request_method":         true,
	"status":                 true,
	"request_time":           true,
	"upstream_response_time": true,
	"body_bytes_sent":        true,
	"bytes_sent":             true,
	"http_user_agent":        true,
	"ua_class":               true,
	"ssl_protocol":           true,
	"server_protocol":        true,
}

func getLogField(e *logEntry, name string) string {
	switch normalizeLogField(name) {
	case "server_name":
		return e.ServerName
	case "request_uri":
		return e.RequestURI
	case "request_method":
		return e.RequestMethod
	case "status":
		return e.Status
	case "request_time":
		return e.RequestTime
	case "upstream_response_time":
		return e.UpstreamTime
	case "body_bytes_sent":
		return e.BodyBytesSent
	case "bytes_sent":
		return e.BytesSent
	case "http_user_agent":
		return e.UserAgent
	case "ua_class":
		return e.UAClass
	case "ssl_protocol":
		return e.SSLProtocol
	case "server_protocol":
		return e.HTTPProtocol
	}
	return ""
}

func deriveLabel(name string, e *logEntry) string {
	switch name {
	case "status_class":
		return statusClass(e.Status)
	}
	return ""
}

func newMetricEngine(cfg *Config, disc *discoveryEngine) (*metricEngine, error) {
	discLabels := map[string]bool{}
	if disc != nil {
		for _, l := range disc.Labels() {
			discLabels[l] = true
		}
	}

	prefix := cfg.Metrics.Prefix
	if prefix == "" {
		prefix = "nginx_proxy"
	}

	e := &metricEngine{
		cfg:         cfg,
		disc:        disc,
		seriesGuard: newGlobalCardinalityTracker(cfg.Metrics.MaxSeriesTotal),
		seriesDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: prefix + "_exporter_series_dropped_total",
			Help: "Series label combinations dropped because max_series_total was reached.",
		}),
		linesOK: prometheus.NewCounter(prometheus.CounterOpts{
			Name: prefix + "_exporter_lines_processed_total",
			Help: "Total log lines successfully parsed and dispatched.",
		}),
		parseErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: prefix + "_exporter_parse_errors_total",
			Help: "Total log lines that failed to parse.",
		}),
		unmapped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: prefix + "_exporter_unmapped_requests_total",
			Help: "Requests for server_names not matched by discovery.",
		}),
		mappedSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: prefix + "_exporter_discovered_server_names",
			Help: "Number of server_names currently mapped by discovery.",
		}),
	}

	prometheus.MustRegister(
		e.seriesDropped,
		e.linesOK,
		e.parseErrors,
		e.unmapped,
		e.mappedSize,
	)

	for i := range cfg.Metrics.Aggregations {
		ac := cfg.Metrics.Aggregations[i]
		agg, err := buildAggregation(ac, prefix, discLabels)
		if err != nil {
			return nil, fmt.Errorf("aggregation[%s]: %w", ac.Name, err)
		}
		e.aggs = append(e.aggs, agg)
	}

	return e, nil
}

func buildAggregation(ac AggregationCfg, prefix string, discLabels map[string]bool) (*aggregation, error) {
	labels := make([]resolvedLabel, 0, len(ac.Labels))
	for _, raw := range ac.Labels {
		l := raw
		var src labelSource
		switch {
		case derivedLabels[l]:
			src = sourceDerived
		case discLabels[l]:
			src = sourceDiscovery
		case knownLogFields[normalizeLogField(l)]:
			src = sourceLog
		default:
			return nil, fmt.Errorf("label %q not found in discovery groups or known log fields", l)
		}
		labels = append(labels, resolvedLabel{name: l, source: src})
	}

	a := &aggregation{cfg: ac, labels: labels}

	labelNames := make([]string, len(labels))
	for i, rl := range labels {
		labelNames[i] = rl.name
	}

	fullName := prefix + "_" + ac.Name
	help := ac.Help
	if help == "" {
		help = "Aggregation " + ac.Name
	}

	switch ac.Type {
	case "counter":
		a.counter = prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: fullName, Help: help},
			labelNames,
		)
		prometheus.MustRegister(a.counter)
	case "histogram":
		buckets := ac.Buckets
		if len(buckets) == 0 {
			return nil, fmt.Errorf("histogram requires non-empty buckets")
		}
		a.histogram = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: fullName, Help: help, Buckets: buckets},
			labelNames,
		)
		prometheus.MustRegister(a.histogram)
	}

	return a, nil
}

// processLine is the hot path. Resolves labels for every aggregation and
// emits observations, respecting the global series cap.
func (e *metricEngine) processLine(entry *logEntry) {
	var discLabels map[string]string
	var mapped bool
	if e.disc != nil {
		discLabels, mapped = e.disc.Resolve(entry.ServerName)
		if !mapped {
			e.unmapped.Inc()
		}
	}

	for _, agg := range e.aggs {
		values := make([]string, len(agg.labels))
		for i, rl := range agg.labels {
			switch rl.source {
			case sourceDiscovery:
				values[i] = discLabels[rl.name]
			case sourceDerived:
				values[i] = deriveLabel(rl.name, entry)
			default:
				values[i] = getLogField(entry, rl.name)
			}
		}

		key := agg.cfg.Name + "\x1f" + strings.Join(values, "\x1f")
		if _, dropped := e.seriesGuard.admit(key); dropped {
			e.seriesDropped.Inc()
			continue
		}

		switch agg.cfg.Type {
		case "counter":
			agg.counter.WithLabelValues(values...).Inc()
		case "histogram":
			raw := getLogField(entry, agg.cfg.SourceField)
			if raw == "" || raw == "-" {
				continue
			}
			v, err := strconv.ParseFloat(strings.TrimSpace(strings.Split(raw, ",")[len(strings.Split(raw, ","))-1]), 64)
			if err != nil {
				continue
			}
			agg.histogram.WithLabelValues(values...).Observe(v)
		}
	}
}

// reportDiscoverySize keeps the gauge up to date. Call from a ticker.
func (e *metricEngine) reportDiscoverySize() {
	if e.disc == nil {
		return
	}
	e.mappedSize.Set(float64(e.disc.Size()))
}
