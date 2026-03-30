package main

import (
	"regexp"
	"strings"
)

// uaFamilyPatterns maps regex patterns to family names.
// Order matters: first match wins.
var uaFamilyPatterns = []struct {
	re     *regexp.Regexp
	family string
}{
	// AI bots
	{regexp.MustCompile(`(?i)ChatGPT`), "ChatGPT"},
	{regexp.MustCompile(`(?i)GPTBot`), "GPTBot"},
	{regexp.MustCompile(`(?i)ClaudeBot|Claude-Web`), "ClaudeBot"},
	{regexp.MustCompile(`(?i)anthropic`), "Anthropic"},
	{regexp.MustCompile(`(?i)Bytespider`), "Bytespider"},
	{regexp.MustCompile(`(?i)CCBot`), "CCBot"},
	{regexp.MustCompile(`(?i)Google-Extended`), "Google-Extended"},
	{regexp.MustCompile(`(?i)Amazonbot`), "Amazonbot"},
	{regexp.MustCompile(`(?i)PetalBot`), "PetalBot"},
	{regexp.MustCompile(`(?i)meta-externalfetcher`), "Meta-ExternalFetcher"},
	{regexp.MustCompile(`(?i)Meta-ExternalAgent`), "Meta-ExternalAgent"},
	{regexp.MustCompile(`(?i)meta-webindexer`), "Meta-WebIndexer"},
	{regexp.MustCompile(`(?i)facebookexternalhit`), "FacebookExternalHit"},
	{regexp.MustCompile(`(?i)PerplexityBot`), "PerplexityBot"},
	{regexp.MustCompile(`(?i)Diffbot`), "Diffbot"},
	{regexp.MustCompile(`(?i)YouBot`), "YouBot"},
	{regexp.MustCompile(`(?i)AI2Bot`), "AI2Bot"},
	{regexp.MustCompile(`(?i)Cohere-ai`), "Cohere"},
	{regexp.MustCompile(`(?i)Timpibot`), "Timpibot"},

	// Search engines
	{regexp.MustCompile(`(?i)Googlebot`), "Googlebot"},
	{regexp.MustCompile(`(?i)bingbot`), "Bingbot"},
	{regexp.MustCompile(`(?i)YandexBot`), "YandexBot"},
	{regexp.MustCompile(`(?i)DuckDuckBot`), "DuckDuckBot"},
	{regexp.MustCompile(`(?i)Baiduspider`), "Baiduspider"},
	{regexp.MustCompile(`(?i)Applebot`), "Applebot"},

	// SEO
	{regexp.MustCompile(`(?i)SemrushBot`), "SemrushBot"},
	{regexp.MustCompile(`(?i)AhrefsBot`), "AhrefsBot"},
	{regexp.MustCompile(`(?i)MJ12bot`), "MJ12bot"},
	{regexp.MustCompile(`(?i)DotBot`), "DotBot"},

	// Browsers (extract family from UA string)
	{regexp.MustCompile(`(?i)Edg/`), "Edge"},
	{regexp.MustCompile(`(?i)OPR/|Opera`), "Opera"},
	{regexp.MustCompile(`(?i)Chrome/.*Safari/`), "Chrome"},
	{regexp.MustCompile(`(?i)Firefox/`), "Firefox"},
	{regexp.MustCompile(`(?i)Safari/.*Version/`), "Safari"},

	// Mobile apps
	{regexp.MustCompile(`(?i)Instagram`), "Instagram"},
	{regexp.MustCompile(`(?i)FBAN|FBAV`), "Facebook-App"},
	{regexp.MustCompile(`(?i)WhatsApp`), "WhatsApp"},
	{regexp.MustCompile(`(?i)Telegram`), "Telegram"},

	// Generic bot catch-all
	{regexp.MustCompile(`(?i)bot|crawler|spider`), "other-bot"},
}

// extractUAFamily returns a normalized user-agent family name.
func extractUAFamily(ua string) string {
	if ua == "" || ua == "-" {
		return "empty"
	}

	for _, p := range uaFamilyPatterns {
		if p.re.MatchString(ua) {
			return p.family
		}
	}

	// Fallback: extract first product token (e.g. "Mozilla" from "Mozilla/5.0 ...")
	if idx := strings.IndexByte(ua, '/'); idx > 0 && idx < 30 {
		return ua[:idx]
	}

	return "other"
}
