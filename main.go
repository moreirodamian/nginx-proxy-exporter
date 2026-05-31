package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var version = "dev"

// dispatcher is the lineProcessor handed to the tailer. It owns the JSON
// parsing and forwards each parsed entry to every enabled sink.
type dispatcher struct {
	cfg    *Config
	legacy *legacyExporter
	engine *metricEngine
}

func (d *dispatcher) processLine(line []byte) {
	entry, err := parseLine(line, d.cfg.LogFields)
	if err != nil {
		if d.engine != nil {
			d.engine.parseErrors.Inc()
		}
		return
	}
	if entry.ServerName == "" || entry.Status == "" {
		if d.engine != nil {
			d.engine.parseErrors.Inc()
		}
		return
	}

	if d.legacy != nil {
		d.legacy.processLine(entry)
	}
	if d.engine != nil {
		d.engine.processLine(entry)
		d.engine.linesOK.Inc()
	}
}

func main() {
	configFile := flag.String("config", "", "Path to config file (YAML)")
	listenAddr := flag.String("listen-address", "", "Override listen address (host:port)")
	logFile := flag.String("log-file", "", "Override log file path")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	cfg := defaultConfig()
	if *configFile != "" {
		var err error
		cfg, err = loadConfig(*configFile)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
	} else {
		applyLegacyDefaults(cfg)
	}

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

	printStartupWarnings(cfg)

	var disc *discoveryEngine
	if cfg.Discovery.Enabled {
		var err error
		disc, err = newDiscoveryEngine(cfg.Discovery)
		if err != nil {
			log.Fatalf("discovery: %v", err)
		}
		interval, err := time.ParseDuration(cfg.Discovery.RefreshInterval)
		if err != nil || interval <= 0 {
			interval = 5 * time.Minute
		}
		if err := disc.InitialScan(); err != nil {
			log.Printf("discovery: initial scan: %v", err)
		}
		log.Printf("discovery: enabled, sites_dir=%s refresh=%s labels=%v mapped=%d",
			cfg.Discovery.SitesDir, interval, disc.Labels(), disc.Size())
		go disc.RunPeriodic(interval)
	}

	legacy := newLegacyExporter(cfg)
	if legacy != nil {
		paths := false
		if cfg.Metrics.Legacy.TrackPaths != nil {
			paths = *cfg.Metrics.Legacy.TrackPaths
		}
		log.Printf("metrics: legacy enabled (track_paths=%v)", paths)
	} else {
		log.Printf("metrics: legacy disabled")
	}

	engine, err := newMetricEngine(cfg, disc)
	if err != nil {
		log.Fatalf("metric engine: %v", err)
	}
	if len(engine.aggs) > 0 {
		log.Printf("metrics: %d declarative aggregations registered (prefix=%s, max_series_total=%d)",
			len(engine.aggs), cfg.Metrics.Prefix, cfg.Metrics.MaxSeriesTotal)
	}

	if disc != nil {
		engine.reportDiscoverySize()
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for range t.C {
				engine.reportDiscoverySize()
			}
		}()
	}

	disp := &dispatcher{cfg: cfg, legacy: legacy, engine: engine}
	go newTailer(cfg.LogFile, disp).run()

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

func printStartupWarnings(cfg *Config) {
	legacyOn := cfg.Metrics.Legacy.Enabled != nil && *cfg.Metrics.Legacy.Enabled
	trackPaths := cfg.Metrics.Legacy.TrackPaths != nil && *cfg.Metrics.Legacy.TrackPaths

	if legacyOn && !trackPaths {
		log.Printf("WARN: legacy path tracking DISABLED by default in v0.9+.")
		log.Printf("WARN: metrics nginx_log_path_requests_total and nginx_log_path_duration_seconds will NOT be exported.")
		log.Printf("WARN: To restore the previous (v0.8) behaviour set 'metrics.legacy.track_paths: true' in your config.")
		log.Printf("WARN: See https://github.com/moreirodamian/nginx-proxy-exporter#cardinality for details.")
	}
	if cfg.Metrics.MaxSeriesTotal <= 0 {
		log.Printf("WARN: metrics.max_series_total is unset — declarative aggregations have no cardinality cap.")
	}
}
