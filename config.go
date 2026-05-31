package main

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen  ListenConfig  `yaml:"listen"`
	LogFile string        `yaml:"log_file"`
	SSL     SSLConfig     `yaml:"ssl"`
	Buckets BucketsConfig `yaml:"buckets"`

	LogFields LogFieldsConfig `yaml:"log_fields"`
	Discovery DiscoveryConfig `yaml:"discovery"`
	Metrics   MetricsConfig   `yaml:"metrics"`

	Limits LegacyLimitsConfig `yaml:"limits"`
}

type ListenConfig struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

type SSLConfig struct {
	Enabled      bool     `yaml:"enabled"`
	CertsPath    string   `yaml:"certs_path"`
	Interval     string   `yaml:"check_interval"`
	Patterns     []string `yaml:"glob_patterns"`
	NginxConfDir string   `yaml:"nginx_conf_dir"`
}

type BucketsConfig struct {
	Duration []float64 `yaml:"duration"`
	Size     []float64 `yaml:"response_size"`
}

type LegacyLimitsConfig struct {
	MaxPaths      *int `yaml:"max_paths"`
	MaxUAFamilies *int `yaml:"max_ua_families"`
}

type LogFieldsConfig struct {
	ServerName           string `yaml:"server_name"`
	RequestURI           string `yaml:"request_uri"`
	RequestMethod        string `yaml:"request_method"`
	Status               string `yaml:"status"`
	RequestTime          string `yaml:"request_time"`
	UpstreamResponseTime string `yaml:"upstream_response_time"`
	BodyBytesSent        string `yaml:"body_bytes_sent"`
	BytesSent            string `yaml:"bytes_sent"`
	UserAgent            string `yaml:"http_user_agent"`
	UAClass              string `yaml:"ua_class"`
	SSLProtocol          string `yaml:"ssl_protocol"`
	HTTPProtocol         string `yaml:"server_protocol"`
}

type DiscoveryConfig struct {
	Enabled           bool                `yaml:"enabled"`
	SitesDir          string              `yaml:"sites_dir"`
	RefreshInterval   string              `yaml:"refresh_interval"`
	PathPattern       string              `yaml:"path_pattern"`
	ServerNamePattern string              `yaml:"server_name_pattern"`
	Unmapped          UnmappedConfig      `yaml:"unmapped"`
	StaticOverrides   []DiscoveryOverride `yaml:"static_overrides"`

	pathRegex       *regexp.Regexp
	serverNameRegex *regexp.Regexp
}

type UnmappedConfig struct {
	Labels map[string]string `yaml:"labels"`
	CapTop int               `yaml:"cap_top"`
}

type DiscoveryOverride struct {
	ServerName string            `yaml:"server_name"`
	Labels     map[string]string `yaml:"labels"`
}

type MetricsConfig struct {
	Prefix         string           `yaml:"prefix"`
	Legacy         LegacyConfig     `yaml:"legacy"`
	Aggregations   []AggregationCfg `yaml:"aggregations"`
	MaxSeriesTotal int              `yaml:"max_series_total"`
}

type LegacyConfig struct {
	Enabled             *bool `yaml:"enabled"`
	MetricNamesV1       *bool `yaml:"metric_names_v1"`
	TrackPaths          *bool `yaml:"track_paths"`
	MaxPathsGlobal      *int  `yaml:"max_paths_global"`
	MaxUAFamiliesGlobal *int  `yaml:"max_ua_families_global"`
}

type AggregationCfg struct {
	Name        string    `yaml:"name"`
	Type        string    `yaml:"type"`
	Labels      []string  `yaml:"labels"`
	SourceField string    `yaml:"source_field"`
	Buckets     []float64 `yaml:"buckets"`
	Help        string    `yaml:"help"`
}

func (c *Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.Listen.Address, c.Listen.Port)
}

func defaultConfig() *Config {
	return &Config{
		Listen: ListenConfig{
			Address: "127.0.0.1",
			Port:    4040,
		},
		LogFile: "/var/log/nginx/access.json.log",
		SSL: SSLConfig{
			Enabled:      false,
			Interval:     "1h",
			NginxConfDir: "/etc/nginx/sites-enabled",
			Patterns: []string{
				"/etc/letsencrypt/live/*/fullchain.pem",
			},
		},
		Buckets: BucketsConfig{
			Duration: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 7.5, 10, 15, 20, 30, 60},
			Size:     []float64{100, 1000, 5000, 10000, 50000, 100000, 500000, 1e6, 5e6},
		},
		LogFields: LogFieldsConfig{
			ServerName:           "server_name",
			RequestURI:           "request_uri",
			RequestMethod:        "request_method",
			Status:               "status",
			RequestTime:          "request_time",
			UpstreamResponseTime: "upstream_response_time",
			BodyBytesSent:        "body_bytes_sent",
			BytesSent:            "bytes_sent",
			UserAgent:            "http_user_agent",
			UAClass:              "ua_class",
			SSLProtocol:          "ssl_protocol",
			HTTPProtocol:         "server_protocol",
		},
		Discovery: DiscoveryConfig{
			Enabled:           false,
			SitesDir:          "/etc/nginx/sites-enabled",
			RefreshInterval:   "5m",
			PathPattern:       `(?P<product>[^/]+)/(?P<tenant>[^/]+?)(?:_proxy)?\.conf$`,
			ServerNamePattern: `\bserver_name\s+([^;]+);`,
			Unmapped: UnmappedConfig{
				Labels: map[string]string{
					"product": "__unmapped__",
					"tenant":  "__unmapped__",
				},
				CapTop: 50,
			},
		},
		Metrics: MetricsConfig{
			Prefix:         "nginx_log",
			MaxSeriesTotal: 50000,
		},
	}
}

func loadConfig(path string) (*Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyLegacyDefaults(cfg)

	if cfg.Discovery.Enabled {
		if err := compileDiscoveryPatterns(&cfg.Discovery); err != nil {
			return nil, fmt.Errorf("discovery: %w", err)
		}
	}

	if err := validateAggregations(cfg); err != nil {
		return nil, fmt.Errorf("aggregations: %w", err)
	}

	return cfg, nil
}

// applyLegacyDefaults wires the v1.x "limits:" top-level block into
// metrics.legacy.* if the user didn't set the new keys, and applies the
// safe new defaults (track_paths=false, legacy.enabled=true) when nothing
// is set.
func applyLegacyDefaults(cfg *Config) {
	l := &cfg.Metrics.Legacy

	if l.Enabled == nil {
		t := true
		l.Enabled = &t
	}
	if l.MetricNamesV1 == nil {
		t := true
		l.MetricNamesV1 = &t
	}
	if l.TrackPaths == nil {
		// New safe default — was true in v0.8.x and earlier. The exporter
		// prints a warning at startup when this stays false.
		f := false
		l.TrackPaths = &f
	}
	if l.MaxPathsGlobal == nil {
		if cfg.Limits.MaxPaths != nil {
			l.MaxPathsGlobal = cfg.Limits.MaxPaths
		} else {
			n := 5000
			l.MaxPathsGlobal = &n
		}
	}
	if l.MaxUAFamiliesGlobal == nil {
		if cfg.Limits.MaxUAFamilies != nil {
			l.MaxUAFamiliesGlobal = cfg.Limits.MaxUAFamilies
		} else {
			n := 1000
			l.MaxUAFamiliesGlobal = &n
		}
	}

	if cfg.Metrics.Prefix == "" {
		cfg.Metrics.Prefix = "nginx_log"
	}
	if cfg.Metrics.MaxSeriesTotal == 0 {
		cfg.Metrics.MaxSeriesTotal = 50000
	}
}

func compileDiscoveryPatterns(d *DiscoveryConfig) error {
	if d.PathPattern == "" {
		return fmt.Errorf("discovery.path_pattern is empty")
	}
	if d.ServerNamePattern == "" {
		return fmt.Errorf("discovery.server_name_pattern is empty")
	}
	re, err := regexp.Compile(d.PathPattern)
	if err != nil {
		return fmt.Errorf("path_pattern: %w", err)
	}
	if len(re.SubexpNames()) <= 1 {
		return fmt.Errorf("path_pattern must contain at least one named group like (?P<product>...)")
	}
	d.pathRegex = re

	snre, err := regexp.Compile(d.ServerNamePattern)
	if err != nil {
		return fmt.Errorf("server_name_pattern: %w", err)
	}
	d.serverNameRegex = snre
	return nil
}

func validateAggregations(cfg *Config) error {
	for i, a := range cfg.Metrics.Aggregations {
		if a.Name == "" {
			return fmt.Errorf("aggregation[%d]: name is required", i)
		}
		switch a.Type {
		case "counter", "histogram":
		default:
			return fmt.Errorf("aggregation[%s]: type must be 'counter' or 'histogram' (got %q)", a.Name, a.Type)
		}
		if a.Type == "histogram" && a.SourceField == "" {
			return fmt.Errorf("aggregation[%s]: source_field is required for histogram", a.Name)
		}
	}
	return nil
}

// DiscoveryLabels returns the named groups declared in path_pattern.
// Order is preserved (regex declaration order).
func (d *DiscoveryConfig) DiscoveryLabels() []string {
	if d.pathRegex == nil {
		return nil
	}
	names := d.pathRegex.SubexpNames()
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}
