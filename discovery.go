package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// discoveryEngine scans an nginx sites directory and builds a map from
// server_name to a set of labels derived from the file path. The mapping
// is refreshed periodically; the entire map is swapped atomically so
// readers never see a partial state.
type discoveryEngine struct {
	cfg DiscoveryConfig

	mu      sync.RWMutex
	domains map[string]map[string]string
	labels  []string

	unmappedTracker *globalCardinalityTracker
	unmappedDefault map[string]string
}

func newDiscoveryEngine(cfg DiscoveryConfig) (*discoveryEngine, error) {
	labels := cfg.DiscoveryLabels()
	if len(labels) == 0 {
		return nil, fmt.Errorf("path_pattern has no named groups")
	}

	// Validate unmapped defaults cover all discovery labels.
	for _, l := range labels {
		if _, ok := cfg.Unmapped.Labels[l]; !ok {
			return nil, fmt.Errorf("unmapped.labels missing value for discovery label %q", l)
		}
	}

	defaults := make(map[string]string, len(labels))
	for k, v := range cfg.Unmapped.Labels {
		defaults[k] = v
	}

	return &discoveryEngine{
		cfg:             cfg,
		domains:         map[string]map[string]string{},
		labels:          labels,
		unmappedTracker: newGlobalCardinalityTracker(cfg.Unmapped.CapTop),
		unmappedDefault: defaults,
	}, nil
}

// Labels returns the discovery label names declared in path_pattern.
func (d *discoveryEngine) Labels() []string { return d.labels }

// Size returns the current number of mapped server_names.
func (d *discoveryEngine) Size() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.domains)
}

// Resolve looks up labels for a server_name. The boolean is true when the
// name was found in the discovered map, false when defaults were returned.
func (d *discoveryEngine) Resolve(serverName string) (map[string]string, bool) {
	d.mu.RLock()
	labels, ok := d.domains[serverName]
	d.mu.RUnlock()
	if ok {
		return labels, true
	}
	d.unmappedTracker.admit(serverName)
	return d.unmappedDefault, false
}

// InitialScan does a synchronous first pass so callers can read Size() right
// after construction. Returns the error from filepath.Walk if any.
func (d *discoveryEngine) InitialScan() error {
	return d.refresh()
}

// RunPeriodic starts the periodic refresh loop. Blocks; call in a goroutine.
// InitialScan should be called before this from the main goroutine.
func (d *discoveryEngine) RunPeriodic(interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if err := d.refresh(); err != nil {
			log.Printf("discovery: refresh: %v", err)
		}
	}
}

// extractServerNames scans the file content line by line, skips commented
// lines, and applies the configured regex against each non-comment line. The
// regex is expected to capture the space-separated list of server names in
// its first submatch group. This handles both block-formatted
// (`server_name foo bar;` on its own line) and inline (`server { server_name
// foo; }`) styles, which is why we don't simply use FindAll on the whole file.
func extractServerNames(data []byte, re interface{ FindSubmatch(b []byte) [][]byte }) []string {
	var out []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		match := re.FindSubmatch(line)
		if len(match) < 2 {
			continue
		}
		for _, sn := range strings.Fields(string(match[1])) {
			out = append(out, strings.TrimSpace(sn))
		}
	}
	return out
}

func (d *discoveryEngine) refresh() error {
	newMap := make(map[string]map[string]string)

	err := filepath.Walk(d.cfg.SitesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".conf") {
			return nil
		}

		match := d.cfg.pathRegex.FindStringSubmatch(path)
		if len(match) == 0 {
			return nil
		}

		labels := make(map[string]string, len(d.labels))
		for i, name := range d.cfg.pathRegex.SubexpNames() {
			if i == 0 || name == "" {
				continue
			}
			labels[name] = match[i]
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		for _, sn := range extractServerNames(data, d.cfg.serverNameRegex) {
			if sn == "" || sn == "_" || sn == "localhost" {
				continue
			}
			newMap[sn] = labels
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Static overrides take precedence over discovered mappings.
	for _, ov := range d.cfg.StaticOverrides {
		if ov.ServerName == "" {
			continue
		}
		labels := make(map[string]string, len(d.labels))
		for _, l := range d.labels {
			if v, ok := ov.Labels[l]; ok {
				labels[l] = v
			} else {
				labels[l] = d.unmappedDefault[l]
			}
		}
		newMap[ov.ServerName] = labels
	}

	d.mu.Lock()
	d.domains = newMap
	d.mu.Unlock()
	return nil
}
