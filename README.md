# nginx-proxy-exporter

A lightweight Prometheus exporter for nginx reverse proxies. Reads JSON access logs and SSL certificates, exposes rich metrics with per-client, per-path, and per-user-agent breakdown.

Built as a single static binary with zero dependencies.

## Features

- **Request metrics** — counters and histograms by `server_name`, `status`, `method`, `ua_class`
- **Path-level metrics** — normalized paths (`/product/123` → `/product/:id`) with latency histograms
- **User-agent classification** — automatic grouping into families: `ChatGPT`, `Googlebot`, `Chrome`, `Instagram`, etc.
- **Bot detection** — classifies traffic as `human`, `ai_bot`, `search_bot`, `seo_bot`, `other_bot` (via nginx `map` + `ua_class` log field)
- **SSL certificate monitoring** — reads certs from disk, reports days until expiry, nginx-aware (only checks certs actually referenced in nginx configs)
- **Log rotation aware** — handles inode changes and file truncation
- **Configurable** — YAML config file with sensible defaults, CLI overrides

## Metrics

### Request Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nginx_log_requests_total` | counter | `server_name`, `ua_class`, `status`, `method` | Total requests |
| `nginx_log_request_duration_seconds` | histogram | `server_name`, `ua_class` | Request duration |
| `nginx_log_upstream_duration_seconds` | histogram | `server_name` | Upstream (backend) response time |
| `nginx_log_response_bytes` | histogram | `server_name` | Response body size |
| `nginx_log_path_requests_total` | counter | `server_name`, `path`, `status_class` | Requests by normalized path |
| `nginx_log_path_duration_seconds` | histogram | `server_name`, `path` | Duration by normalized path |
| `nginx_log_ua_family_requests_total` | counter | `server_name`, `ua_family`, `ua_class` | Requests by UA family |
| `nginx_log_status_total` | counter | `status` | Global status code distribution |
| `nginx_log_ssl_protocol_total` | counter | `protocol` | TLS version distribution |
| `nginx_log_http_protocol_total` | counter | `protocol` | HTTP version distribution |

### SSL Certificate Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ssl_certificate_expiry_seconds` | gauge | `subject`, `dns_names`, `issuer`, `path`, `in_use` | Seconds until certificate expires |
| `ssl_certificates_total` | gauge | — | Total certificates checked |
| `ssl_check_errors_total` | counter | — | Certificate read/parse errors |

### User-Agent Families

The exporter automatically groups user-agent strings into families:

| Category | Families |
|----------|----------|
| **AI Bots** | ChatGPT, GPTBot, ClaudeBot, Bytespider, CCBot, Meta-ExternalAgent, PerplexityBot, Amazonbot, PetalBot, Google-Extended, ... |
| **Search Engines** | Googlebot, Bingbot, YandexBot, DuckDuckBot, Baiduspider, Applebot |
| **SEO Crawlers** | SemrushBot, AhrefsBot, MJ12bot, DotBot |
| **Browsers** | Chrome, Firefox, Safari, Edge, Opera |
| **Apps** | Instagram, Facebook-App, WhatsApp, Telegram |

### Path Normalization

URIs are normalized to reduce cardinality:
- `/product/12345` → `/product/:id`
- `/image/a1b2c3d4e5f6` → `/image/:hash`
- `/search?q=foo&page=2` → `/search`

## Requirements

### Nginx Configuration

The exporter reads JSON-formatted access logs. Add this to your nginx config:

```nginx
# User-agent classification (evaluated once per request, zero overhead)
map $http_user_agent $ua_class {
    default                     "human";
    ~*GPTBot                    "ai_bot";
    ~*ChatGPT                   "ai_bot";
    ~*ClaudeBot                 "ai_bot";
    ~*Bytespider                "ai_bot";
    ~*CCBot                     "ai_bot";
    ~*Meta-ExternalAgent        "ai_bot";
    ~*Googlebot                 "search_bot";
    ~*bingbot                   "search_bot";
    ~*SemrushBot                "seo_bot";
    ~*AhrefsBot                 "seo_bot";
    ~*[bB]ot                    "other_bot";
    ~*[cC]rawler                "other_bot";
    ~*[sS]pider                 "other_bot";
}

# JSON log format with ua_class field
log_format json_analytics escape=json '{'
    '"time_local": "$time_local", '
    '"remote_addr": "$remote_addr", '
    '"request_uri": "$request_uri", '
    '"status": "$status", '
    '"server_name": "$server_name", '
    '"request_time": "$request_time", '
    '"request_method": "$request_method", '
    '"body_bytes_sent": "$body_bytes_sent", '
    '"http_user_agent": "$http_user_agent", '
    '"upstream_response_time": "$upstream_response_time", '
    '"ssl_protocol": "$ssl_protocol", '
    '"server_protocol": "$server_protocol", '
    '"ua_class": "$ua_class" '
'}';

access_log /var/log/nginx/access.json.log json_analytics;
```

## Installation

### Binary

Download from [Releases](https://github.com/moreirodamian/nginx-proxy-exporter/releases):

```bash
curl -L https://github.com/moreirodamian/nginx-proxy-exporter/releases/latest/download/nginx-proxy-exporter_linux_amd64 \
  -o /usr/local/bin/nginx-proxy-exporter
chmod +x /usr/local/bin/nginx-proxy-exporter
```

### Build from source

```bash
go build -ldflags "-s -w" -o nginx-proxy-exporter .
```

## Configuration

Create a config file (see [`config.example.yml`](config.example.yml)):

```yaml
listen:
  address: "127.0.0.1"
  port: 4040

log_file: "/var/log/nginx/access.json.log"

ssl:
  enabled: true
  check_interval: "1h"
  nginx_conf_dir: "/etc/nginx/sites-enabled"
  glob_patterns:
    - "/etc/letsencrypt/live/*/fullchain.pem"

buckets:
  duration: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 7.5, 10, 15, 20, 30, 60]
  response_size: [100, 1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000]
```

### CLI Options

```
Usage:
  -config string     Path to config file (YAML)
  -listen-address    Override listen address (host:port)
  -log-file          Override log file path
  -version           Show version and exit
```

All config values can be overridden via CLI flags. Without a config file, sensible defaults are used.

### SSL Certificate Monitoring

When `ssl.enabled` is `true`, the exporter:

1. Scans `nginx_conf_dir` for `ssl_certificate` directives to find which certs are actually in use
2. Reads certificates from `glob_patterns` (default: Let's Encrypt live directory)
3. Reports expiry as `ssl_certificate_expiry_seconds` with an `in_use` label (`true`/`false`)
4. Re-checks on the configured interval (default: 1 hour)

## Systemd Service

```ini
[Unit]
Description=Nginx Proxy Exporter
After=network.target nginx.service

[Service]
Type=simple
ExecStart=/usr/local/bin/nginx-proxy-exporter -config /etc/nginx-proxy-exporter/config.yml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Example Queries

```promql
# Request rate per client
sum by (server_name) (rate(nginx_log_requests_total[5m]))

# AI bot traffic percentage
sum(rate(nginx_log_requests_total{ua_class="ai_bot"}[5m]))
/ sum(rate(nginx_log_requests_total[5m])) * 100

# P50 latency per client
histogram_quantile(0.50, sum by (server_name, le) (rate(nginx_log_request_duration_seconds_bucket[5m])))

# Slow requests (>5s) percentage per client
(1 - sum by (server_name) (rate(nginx_log_request_duration_seconds_bucket{le="5"}[5m]))
/ sum by (server_name) (rate(nginx_log_request_duration_seconds_count[5m]))) * 100

# Top user-agent families
topk(10, sum by (ua_family) (rate(nginx_log_ua_family_requests_total[5m])))

# SSL certificates expiring within 30 days
ssl_certificate_expiry_seconds{in_use="true"} < 2592000
```

## License

MIT
