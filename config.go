package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen  ListenConfig  `yaml:"listen"`
	LogFile string        `yaml:"log_file"`
	SSL     SSLConfig     `yaml:"ssl"`
	Buckets BucketsConfig `yaml:"buckets"`
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

	return cfg, nil
}
