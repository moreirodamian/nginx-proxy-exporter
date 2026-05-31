package main

import (
	"regexp"
	"strings"
)

var (
	reNumeric = regexp.MustCompile(`/\d+(/|$)`)
	reHash    = regexp.MustCompile(`/[a-f0-9]{8,}(/|$)`)
	reQuery   = regexp.MustCompile(`\?.*$`)
)

// normalizePath strips query strings and replaces numeric and hex segments
// with placeholders so URIs like /product/123 and /image/a1b2c3d4 collapse
// into /product/:id and /image/:hash respectively.
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
