package main

import (
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// legacyExporter emits the v1.x metric set under the `nginx_log_` prefix
// (or whatever Config.Metrics.Prefix is) for users that upgraded the
// binary without changing their dashboards.
//
// All path-* metrics are guarded by Metrics.Legacy.TrackPaths, which is
// false by default in v0.9+ — this kills the cardinality explosion that
// hit operators on v0.8. To restore the old behaviour, set
//
//	metrics:
//	  legacy:
//	    track_paths: true
//
// in the config file.
type legacyExporter struct {
	cfg *Config

	requests    *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	upstreamDur *prometheus.HistogramVec
	bodySize    *prometheus.HistogramVec

	pathRequests *prometheus.CounterVec
	pathDuration *prometheus.HistogramVec
	pathTracker  *globalCardinalityTracker
	droppedPaths prometheus.Counter

	uaFamilyReqs *prometheus.CounterVec
	uaTracker    *globalCardinalityTracker
	droppedUA    prometheus.Counter

	statusTotal *prometheus.CounterVec
	sslProto    *prometheus.CounterVec
	httpProto   *prometheus.CounterVec
}

func newLegacyExporter(cfg *Config) *legacyExporter {
	if cfg.Metrics.Legacy.Enabled != nil && !*cfg.Metrics.Legacy.Enabled {
		return nil
	}

	prefix := "nginx_log"
	if cfg.Metrics.Legacy.MetricNamesV1 != nil && !*cfg.Metrics.Legacy.MetricNamesV1 {
		prefix = cfg.Metrics.Prefix
	}

	e := &legacyExporter{cfg: cfg}

	e.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: prefix + "_requests_total",
		Help: "Total requests by server, ua class, status and method.",
	}, []string{"server_name", "ua_class", "status", "method"})

	e.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    prefix + "_request_duration_seconds",
		Help:    "Request duration by server and ua class.",
		Buckets: cfg.Buckets.Duration,
	}, []string{"server_name", "ua_class"})

	e.upstreamDur = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    prefix + "_upstream_duration_seconds",
		Help:    "Upstream response time.",
		Buckets: cfg.Buckets.Duration,
	}, []string{"server_name"})

	e.bodySize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    prefix + "_response_bytes",
		Help:    "Response body size.",
		Buckets: cfg.Buckets.Size,
	}, []string{"server_name"})

	e.statusTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: prefix + "_status_total",
		Help: "Requests by exact status code (global).",
	}, []string{"status"})

	e.sslProto = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: prefix + "_ssl_protocol_total",
		Help: "Requests by TLS version.",
	}, []string{"protocol"})

	e.httpProto = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: prefix + "_http_protocol_total",
		Help: "Requests by HTTP version.",
	}, []string{"protocol"})

	prometheus.MustRegister(
		e.requests, e.duration, e.upstreamDur, e.bodySize,
		e.statusTotal, e.sslProto, e.httpProto,
	)

	if cfg.Metrics.Legacy.TrackPaths != nil && *cfg.Metrics.Legacy.TrackPaths {
		max := 5000
		if cfg.Metrics.Legacy.MaxPathsGlobal != nil {
			max = *cfg.Metrics.Legacy.MaxPathsGlobal
		}
		e.pathTracker = newGlobalCardinalityTracker(max)
		e.pathRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: prefix + "_path_requests_total",
			Help: "Requests by server, normalized path and status class.",
		}, []string{"server_name", "path", "status_class"})
		e.pathDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    prefix + "_path_duration_seconds",
			Help:    "Request duration by server and path.",
			Buckets: cfg.Buckets.Duration,
		}, []string{"server_name", "path"})
		e.droppedPaths = prometheus.NewCounter(prometheus.CounterOpts{
			Name: prefix + "_exporter_dropped_paths_total",
			Help: "Path label values replaced with __other__ due to cardinality cap.",
		})
		prometheus.MustRegister(e.pathRequests, e.pathDuration, e.droppedPaths)
	}

	max := 1000
	if cfg.Metrics.Legacy.MaxUAFamiliesGlobal != nil {
		max = *cfg.Metrics.Legacy.MaxUAFamiliesGlobal
	}
	e.uaTracker = newGlobalCardinalityTracker(max)
	e.uaFamilyReqs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: prefix + "_ua_family_requests_total",
		Help: "Requests by user-agent family and server.",
	}, []string{"server_name", "ua_family", "ua_class"})
	e.droppedUA = prometheus.NewCounter(prometheus.CounterOpts{
		Name: prefix + "_exporter_dropped_ua_total",
		Help: "UA family label values replaced with __other__ due to cardinality cap.",
	})
	prometheus.MustRegister(e.uaFamilyReqs, e.droppedUA)

	return e
}

func (e *legacyExporter) processLine(entry *logEntry) {
	if e == nil {
		return
	}

	sn := entry.ServerName
	st := entry.Status
	if sn == "" || st == "" {
		return
	}

	ua := entry.UAClass
	method := entry.RequestMethod

	e.requests.WithLabelValues(sn, ua, st, method).Inc()

	if rt, err := strconv.ParseFloat(entry.RequestTime, 64); err == nil {
		e.duration.WithLabelValues(sn, ua).Observe(rt)
	}

	if entry.UpstreamTime != "" && entry.UpstreamTime != "-" {
		parts := strings.Split(entry.UpstreamTime, ",")
		if ut, err := strconv.ParseFloat(strings.TrimSpace(parts[len(parts)-1]), 64); err == nil {
			e.upstreamDur.WithLabelValues(sn).Observe(ut)
		}
	}

	bs := entry.BodyBytesSent
	if bs == "" {
		bs = entry.BytesSent
	}
	if bsf, err := strconv.ParseFloat(bs, 64); err == nil {
		e.bodySize.WithLabelValues(sn).Observe(bsf)
	}

	if e.pathRequests != nil {
		rawPath := normalizePath(entry.RequestURI)
		key := sn + "\x1f" + rawPath
		path, dropped := e.pathTracker.admit(key)
		if dropped {
			e.droppedPaths.Inc()
			path = "__other__"
		} else {
			path = rawPath
		}
		sc := statusClass(st)
		e.pathRequests.WithLabelValues(sn, path, sc).Inc()
		if rt, err := strconv.ParseFloat(entry.RequestTime, 64); err == nil {
			e.pathDuration.WithLabelValues(sn, path).Observe(rt)
		}
	}

	rawFamily := extractUAFamily(entry.UserAgent)
	uaKey := sn + "\x1f" + rawFamily
	family, dropped := e.uaTracker.admit(uaKey)
	if dropped {
		e.droppedUA.Inc()
		family = "__other__"
	} else {
		family = rawFamily
	}
	e.uaFamilyReqs.WithLabelValues(sn, family, ua).Inc()

	e.statusTotal.WithLabelValues(st).Inc()
	if entry.SSLProtocol != "" && entry.SSLProtocol != "-" {
		e.sslProto.WithLabelValues(entry.SSLProtocol).Inc()
	}
	if entry.HTTPProtocol != "" {
		e.httpProto.WithLabelValues(entry.HTTPProtocol).Inc()
	}
}
