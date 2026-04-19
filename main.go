package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var version = "dev"

type nginxLogEntry struct {
	Status        string `json:"status"`
	ServerName    string `json:"server_name"`
	UAClass       string `json:"ua_class"`
	RequestMethod string `json:"request_method"`
	RequestTime   string `json:"request_time"`
	BodyBytesSent string `json:"body_bytes_sent"`
	BytesSent     string `json:"bytes_sent"`
	RequestURI    string `json:"request_uri"`
	UserAgent     string `json:"http_user_agent"`
	UpstreamTime  string `json:"upstream_response_time"`
	SSLProtocol   string `json:"ssl_protocol"`
	ServerProto   string `json:"server_protocol"`
}

var (
	reNumeric = regexp.MustCompile(`/\d+(/|$)`)
	reHash    = regexp.MustCompile(`/[a-f0-9]{8,}(/|$)`)
	reQuery   = regexp.MustCompile(`\?.*$`)
)

func normalizePath(uri string) string {
	p := reQuery.ReplaceAllString(uri, "")
	p = reNumeric.ReplaceAllString(p, "/:id/")
	p = reHash.ReplaceAllString(p, "/:hash/")
	p = strings.TrimRight(p, "/")
	if p == "" {
		p = "/"
	}
	return p
}

func statusClass(s string) string {
	if len(s) == 0 {
		return "other"
	}
	switch s[0] {
	case '2':
		return "2xx"
	case '3':
		return "3xx"
	case '4':
		return "4xx"
	case '5':
		return "5xx"
	default:
		return "other"
	}
}

// cardinalityTracker limits unique label values per scope (e.g. per server_name).
// Once the cap is reached, new values are replaced with "__other__".
type cardinalityTracker struct {
	mu   sync.Mutex
	sets map[string]map[string]struct{}
	max  int
}

func newCardinalityTracker(max int) *cardinalityTracker {
	return &cardinalityTracker{
		sets: make(map[string]map[string]struct{}),
		max:  max,
	}
}

func (t *cardinalityTracker) resolve(scope, value string) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.sets[scope]
	if !ok {
		s = make(map[string]struct{})
		t.sets[scope] = s
	}
	if _, exists := s[value]; exists {
		return value
	}
	if len(s) >= t.max {
		return "__other__"
	}
	s[value] = struct{}{}
	return value
}

type exporter struct {
	logFile string
	cfg     *Config

	pathTracker *cardinalityTracker
	uaTracker   *cardinalityTracker

	requests    *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	upstreamDur *prometheus.HistogramVec
	bodySize    *prometheus.HistogramVec

	pathRequests *prometheus.CounterVec
	pathDuration *prometheus.HistogramVec

	uaFamilyReqs *prometheus.CounterVec

	statusTotal  *prometheus.CounterVec
	sslProto     *prometheus.CounterVec
	httpProto    *prometheus.CounterVec

	linesOK prometheus.Counter
	lineErr prometheus.Counter

	droppedPaths prometheus.Counter
	droppedUA    prometheus.Counter
}

func newExporter(cfg *Config) *exporter {
	e := &exporter{
		logFile:     cfg.LogFile,
		cfg:         cfg,
		pathTracker: newCardinalityTracker(cfg.Limits.MaxPaths),
		uaTracker:   newCardinalityTracker(cfg.Limits.MaxUAFamilies),

		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nginx_log_requests_total",
			Help: "Total requests by server, ua class, status and method.",
		}, []string{"server_name", "ua_class", "status", "method"}),

		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "nginx_log_request_duration_seconds",
			Help: "Request duration by server and ua class.", Buckets: cfg.Buckets.Duration,
		}, []string{"server_name", "ua_class"}),

		upstreamDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "nginx_log_upstream_duration_seconds",
			Help: "Upstream response time.", Buckets: cfg.Buckets.Duration,
		}, []string{"server_name"}),

		bodySize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "nginx_log_response_bytes",
			Help: "Response body size.", Buckets: cfg.Buckets.Size,
		}, []string{"server_name"}),

		pathRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nginx_log_path_requests_total",
			Help: "Requests by server, normalized path and status class.",
		}, []string{"server_name", "path", "status_class"}),

		pathDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "nginx_log_path_duration_seconds",
			Help: "Request duration by server and path.", Buckets: cfg.Buckets.Duration,
		}, []string{"server_name", "path"}),

		uaFamilyReqs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nginx_log_ua_family_requests_total",
			Help: "Requests by user-agent family and server.",
		}, []string{"server_name", "ua_family", "ua_class"}),

		statusTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nginx_log_status_total",
			Help: "Requests by exact status code (global).",
		}, []string{"status"}),

		sslProto: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nginx_log_ssl_protocol_total",
			Help: "Requests by TLS version.",
		}, []string{"protocol"}),

		httpProto: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nginx_log_http_protocol_total",
			Help: "Requests by HTTP version.",
		}, []string{"protocol"}),

		linesOK: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "nginx_log_exporter_lines_processed_total",
			Help: "Lines processed.",
		}),
		lineErr: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "nginx_log_exporter_parse_errors_total",
			Help: "Lines failed to parse.",
		}),
		droppedPaths: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "nginx_log_exporter_dropped_paths_total",
			Help: "Path label values replaced with __other__ due to cardinality cap.",
		}),
		droppedUA: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "nginx_log_exporter_dropped_ua_total",
			Help: "UA family label values replaced with __other__ due to cardinality cap.",
		}),
	}

	prometheus.MustRegister(
		e.requests, e.duration, e.upstreamDur, e.bodySize,
		e.pathRequests, e.pathDuration, e.uaFamilyReqs,
		e.statusTotal, e.sslProto, e.httpProto,
		e.linesOK, e.lineErr, e.droppedPaths, e.droppedUA,
	)
	return e
}

func (e *exporter) processLine(line []byte) {
	var entry nginxLogEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		e.lineErr.Inc()
		return
	}

	sn := entry.ServerName
	ua := entry.UAClass
	st := entry.Status
	m := entry.RequestMethod

	if sn == "" || st == "" {
		e.lineErr.Inc()
		return
	}

	e.linesOK.Inc()

	// Per-client
	e.requests.WithLabelValues(sn, ua, st, m).Inc()

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

	// Path-level (cardinality-capped)
	rawPath := normalizePath(entry.RequestURI)
	path := e.pathTracker.resolve(sn, rawPath)
	if path == "__other__" && rawPath != "__other__" {
		e.droppedPaths.Inc()
	}
	sc := statusClass(st)
	e.pathRequests.WithLabelValues(sn, path, sc).Inc()
	if rt, err := strconv.ParseFloat(entry.RequestTime, 64); err == nil {
		e.pathDuration.WithLabelValues(sn, path).Observe(rt)
	}

	// UA family (cardinality-capped)
	rawFamily := extractUAFamily(entry.UserAgent)
	family := e.uaTracker.resolve(sn, rawFamily)
	if family == "__other__" && rawFamily != "__other__" {
		e.droppedUA.Inc()
	}
	e.uaFamilyReqs.WithLabelValues(sn, family, ua).Inc()

	// Global
	e.statusTotal.WithLabelValues(st).Inc()
	if entry.SSLProtocol != "" && entry.SSLProtocol != "-" {
		e.sslProto.WithLabelValues(entry.SSLProtocol).Inc()
	}
	if entry.ServerProto != "" {
		e.httpProto.WithLabelValues(entry.ServerProto).Inc()
	}
}

func (e *exporter) tailFile() {
	for {
		if err := e.followFile(); err != nil {
			log.Printf("tail: %v, retrying in 1s", err)
			time.Sleep(time.Second)
		}
	}
}

func (e *exporter) followFile() error {
	f, err := os.Open(e.logFile)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek: %w", err)
	}

	fi, _ := f.Stat()
	lastSize := fi.Size()
	lastIno := fileIno(fi)
	reader := bufio.NewReaderSize(f, 64*1024)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				return fmt.Errorf("read: %w", err)
			}
			newFi, statErr := os.Stat(e.logFile)
			if statErr != nil {
				return fmt.Errorf("stat: %w", statErr)
			}
			if fileIno(newFi) != lastIno {
				return fmt.Errorf("file rotated")
			}
			if newFi.Size() < lastSize {
				f.Seek(0, io.SeekStart)
				reader.Reset(f)
				lastSize = 0
				continue
			}
			lastSize = newFi.Size()
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if len(line) > 1 {
			e.processLine(line)
		}
	}
}

func main() {
	configFile := flag.String("config", "", "Path to config file (YAML)")
	listenAddr := flag.String("listen-address", "", "Override listen address")
	logFile := flag.String("log-file", "", "Override log file path")
	showVersion := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	var cfg *Config
	if *configFile != "" {
		var err error
		cfg, err = loadConfig(*configFile)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
	} else {
		cfg = defaultConfig()
	}

	// CLI overrides
	if *listenAddr != "" {
		parts := strings.SplitN(*listenAddr, ":", 2)
		cfg.Listen.Address = parts[0]
		if len(parts) > 1 {
			if p, err := strconv.Atoi(parts[1]); err == nil {
				cfg.Listen.Port = p
			}
		}
	}
	if *logFile != "" {
		cfg.LogFile = *logFile
	}

	log.Printf("nginx-proxy-exporter %s", version)
	log.Printf("log file: %s", cfg.LogFile)
	log.Printf("listen: %s", cfg.ListenAddr())
	log.Printf("limits: max_paths=%d max_ua_families=%d per server", cfg.Limits.MaxPaths, cfg.Limits.MaxUAFamilies)

	e := newExporter(cfg)
	go e.tailFile()

	if cfg.SSL.Enabled {
		log.Printf("ssl: checking certs every %s from %v", cfg.SSL.Interval, cfg.SSL.Patterns)
		sc := newSSLChecker(cfg.SSL)
		go sc.run()
	}

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	log.Printf("serving metrics at http://%s/metrics", cfg.ListenAddr())
	if err := http.ListenAndServe(cfg.ListenAddr(), nil); err != nil {
		log.Fatalf("http: %v", err)
	}
}
