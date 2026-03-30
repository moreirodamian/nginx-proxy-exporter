package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type sslChecker struct {
	patterns     []string
	nginxConfDir string
	interval     time.Duration

	certExpiry *prometheus.GaugeVec
	certTotal  prometheus.Gauge
	checkErrs  prometheus.Counter
}

func newSSLChecker(cfg SSLConfig) *sslChecker {
	interval, err := time.ParseDuration(cfg.Interval)
	if err != nil {
		interval = time.Hour
	}

	s := &sslChecker{
		patterns:     cfg.Patterns,
		nginxConfDir: cfg.NginxConfDir,
		interval:     interval,

		certExpiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ssl_certificate_expiry_seconds",
			Help: "Seconds until certificate expires.",
		}, []string{"subject", "dns_names", "issuer", "path", "in_use"}),

		certTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ssl_certificates_total",
			Help: "Total number of certificates checked.",
		}),

		checkErrs: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ssl_check_errors_total",
			Help: "Total errors reading or parsing certificates.",
		}),
	}

	prometheus.MustRegister(s.certExpiry, s.certTotal, s.checkErrs)
	return s
}

func (s *sslChecker) run() {
	s.check()
	ticker := time.NewTicker(s.interval)
	for range ticker.C {
		s.check()
	}
}

// nginxCertPaths extracts ssl_certificate paths from nginx configs.
var reCertPath = regexp.MustCompile(`ssl_certificate\s+([^;]+);`)

func (s *sslChecker) loadNginxCertPaths() map[string]bool {
	used := make(map[string]bool)
	if s.nginxConfDir == "" {
		return used
	}

	err := filepath.Walk(s.nginxConfDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".conf") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "ssl_certificate_key") {
				continue
			}
			matches := reCertPath.FindStringSubmatch(line)
			if len(matches) > 1 {
				certPath := strings.TrimSpace(matches[1])
				used[certPath] = true
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("ssl: error walking nginx conf dir %s: %v", s.nginxConfDir, err)
	}

	return used
}

func (s *sslChecker) check() {
	s.certExpiry.Reset()

	nginxCerts := s.loadNginxCertPaths()
	if len(nginxCerts) > 0 {
		log.Printf("ssl: found %d cert paths in nginx configs", len(nginxCerts))
	}

	total := 0
	seen := make(map[string]bool)

	// Check certs from glob patterns
	for _, pattern := range s.patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			s.checkErrs.Inc()
			continue
		}

		for _, path := range matches {
			if seen[path] {
				continue
			}
			seen[path] = true

			cert, err := parseCert(path)
			if err != nil {
				s.checkErrs.Inc()
				continue
			}

			inUse := "false"
			if nginxCerts[path] {
				inUse = "true"
			}

			subject := cert.Subject.CommonName
			issuer := cert.Issuer.CommonName
			dnsNames := joinMax(cert.DNSNames, 5)
			expiry := time.Until(cert.NotAfter).Seconds()

			s.certExpiry.WithLabelValues(subject, dnsNames, issuer, path, inUse).Set(expiry)
			total++
		}
	}

	// Also check certs referenced by nginx that might not match glob patterns
	for certPath := range nginxCerts {
		if seen[certPath] {
			continue
		}
		seen[certPath] = true

		cert, err := parseCert(certPath)
		if err != nil {
			s.checkErrs.Inc()
			continue
		}

		subject := cert.Subject.CommonName
		issuer := cert.Issuer.CommonName
		dnsNames := joinMax(cert.DNSNames, 5)
		expiry := time.Until(cert.NotAfter).Seconds()

		s.certExpiry.WithLabelValues(subject, dnsNames, issuer, certPath, "true").Set(expiry)
		total++
	}

	s.certTotal.Set(float64(total))
	log.Printf("ssl: checked %d certificates (%d in-use by nginx)", total, len(nginxCerts))
}

func parseCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, os.ErrInvalid
	}

	return x509.ParseCertificate(block.Bytes)
}

func joinMax(items []string, max int) string {
	if len(items) > max {
		items = items[:max]
	}
	result := ""
	for i, item := range items {
		if i > 0 {
			result += ", "
		}
		result += item
	}
	return result
}
