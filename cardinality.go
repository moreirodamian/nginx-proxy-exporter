package main

import "sync"

// cardinalityTracker limits unique label values per scope (e.g. per server_name).
// Once the per-scope cap is reached, new values are replaced with "__other__".
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

// resolve returns value if it's already tracked or there's still room in the
// scope, otherwise "__other__". A second return reports whether the value was
// dropped (caller can increment a counter).
func (t *cardinalityTracker) resolve(scope, value string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.sets[scope]
	if !ok {
		s = make(map[string]struct{})
		t.sets[scope] = s
	}
	if _, exists := s[value]; exists {
		return value, false
	}
	if t.max > 0 && len(s) >= t.max {
		return "__other__", true
	}
	s[value] = struct{}{}
	return value, false
}

// globalCardinalityTracker is a single-set tracker shared across all scopes.
// Used as a safety net to put a hard ceiling on the total number of distinct
// values regardless of how many scopes exist.
type globalCardinalityTracker struct {
	mu     sync.Mutex
	values map[string]struct{}
	max    int
}

func newGlobalCardinalityTracker(max int) *globalCardinalityTracker {
	return &globalCardinalityTracker{
		values: make(map[string]struct{}),
		max:    max,
	}
}

func (t *globalCardinalityTracker) admit(value string) (string, bool) {
	if t.max <= 0 {
		return value, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.values[value]; exists {
		return value, false
	}
	if len(t.values) >= t.max {
		return "__other__", true
	}
	t.values[value] = struct{}{}
	return value, false
}

func (t *globalCardinalityTracker) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.values)
}
