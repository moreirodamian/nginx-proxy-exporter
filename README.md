# nginx-proxy-exporter

A lightweight Prometheus exporter for nginx reverse proxies. Reads JSON access logs and SSL certificates, exposes rich metrics with configurable cardinality.

Built as a single static binary with zero external dependencies.

## What you get

- **Per-request metrics** — counters and histograms broken down by `server_name`, `status`, `method`, `ua_class`.
- **Optional filesystem discovery** — derive `product`, `tenant` (or any labels you like) from the path of each `.conf` in `/etc/nginx/sites-enabled` and tag every request automatically. No need to inject variables into nginx configs.
- **Declarative metric model** — define your own counters and histograms in YAML. The exporter validates the labels at startup and refuses configs that would explode cardinality.
- **Cardinality safety net** — a global cap (`max_series_total`) stops new label combinations from being recorded once exceeded, with a counter so you know it happened.
- **User-agent classification** — automatic grouping into families: `ChatGPT`, `Googlebot`, `Chrome`, `Instagram`, etc.
- **SSL certificate monitoring** — reads certs from disk, reports days until expiry, nginx-aware (only checks certs referenced from sites configs).
- **Log rotation aware** — handles inode changes and file truncation.

## Two operating modes

### 1. Legacy mode (default — backwards compatible with v0.8)

If you don't add a `metrics:` block to your config, the exporter behaves like v0.8: same metric names (`nginx_log_requests_total`, `nginx_log_request_duration_seconds`, ...), same SSL monitoring, same UA classification.

> **One important difference from v0.8**: path-level metrics (`nginx_log_path_requests_total`, `nginx_log_path_duration_seconds`) are **disabled by default** because they were the cause of a multi-million-series cardinality blow-up on busy multi-tenant proxies. To restore them, see [Cardinality](#cardinality).

### 2. Declarative mode (recommended for multi-tenant proxies)

Define your own aggregations in YAML. Each aggregation says which labels to use (drawn from the log line or from filesystem discovery) and which buckets for histograms. The exporter builds and registers the metrics at startup.

See [`examples/multi-tenant-discovery.yml`](examples/multi-tenant-discovery.yml) for a full multi-tenant setup.

## Filesystem discovery

By convention, organise your nginx site files so each .conf belongs to a `<product>` and `<tenant>`:

```
/etc/nginx/sites-enabled/
├── shop/
│   ├── tenant-a_proxy.conf
│   └── tenant-b_proxy.conf
├── web/
│   ├── tenant-a_proxy.conf       (same tenant, different product)
│   └── tenant-c_proxy.conf
└── landings/
    └── tenant-d_proxy.conf
```

Each .conf can hold any number of `server { server_name X Y Z; ... }` blocks. The exporter:

1. Walks `sites_dir` and matches each .conf path against `discovery.path_pattern` (a regex with named groups).
2. Extracts the `server_name` directives from inside each .conf.
3. Builds a `server_name → labels` map that's refreshed every `refresh_interval`.

When a log line arrives, the exporter looks up `server_name` in the map and applies the labels (`product`, `tenant`, etc.) to every configured aggregation.

Domains not matched by any .conf fall through to the `unmapped.labels` defaults. They're also tracked through the `_exporter_unmapped_requests_total` counter so you can alert when discovery is incomplete.

The regex groups in `path_pattern` define the available labels. You're not limited to `product`/`tenant` — use whatever fits your environment (see [`examples/custom-discovery.yml`](examples/custom-discovery.yml)).

## Cardinality

The exporter has three layers of protection against runaway cardinality:

1. **Declarative model rejects unsafe labels at config load.** If you try to add `path` as a label to an aggregation, you must opt in explicitly — there's no implicit way to attach an unbounded label.
2. **`max_series_total`** is a global cap on distinct label combinations across all aggregations. Once reached, new combinations are dropped and `_exporter_series_dropped_total` is incremented. Default: `50000`.
3. **Legacy `track_paths`** is off by default. When you enable it, `max_paths_global` caps the distinct `(server_name, path)` pairs globally (not per-server, which is what blew up in v0.8).

### Restoring v0.8 behaviour

```yaml
metrics:
  legacy:
    enabled: true
    track_paths: true          # restore nginx_log_path_*
    max_paths_global: 5000     # global cap (was per-server in v0.8)
    max_ua_families_global: 1000
```

See [`examples/v0.8-compat.yml`](examples/v0.8-compat.yml).

## Configuration reference

The minimal config is just a path to your access log — defaults cover everything else:

```yaml
log_file: "/var/log/nginx/access.json.log"
```

Full schema with comments:

```yaml
listen:
  address: "127.0.0.1"      # default
  port: 4040                # default

log_file: "/var/log/nginx/access.json.log"

# JSON field names in YOUR log_format. Defaults match the nginx_log_format
# documented below. Override these instead of changing nginx.
log_fields:
  server_name: "server_name"
  request_uri: "request_uri"
  request_method: "request_method"
  status: "status"
  request_time: "request_time"
  upstream_response_time: "upstream_response_time"
  body_bytes_sent: "body_bytes_sent"
  bytes_sent: "bytes_sent"
  http_user_agent: "http_user_agent"
  ua_class: "ua_class"
  ssl_protocol: "ssl_protocol"
  server_protocol: "server_protocol"

# Filesystem discovery (optional, off by default).
discovery:
  enabled: false
  sites_dir: "/etc/nginx/sites-enabled"
  refresh_interval: "5m"
  path_pattern: '(?P<product>[^/]+)/(?P<tenant>[^/]+?)(?:_proxy)?\.conf$'
  server_name_pattern: '\bserver_name\s+([^;]+);'
  unmapped:
    labels:
      product: "__unmapped__"
      tenant: "__unmapped__"
    cap_top: 50              # only top-N unmapped server_names tracked
  static_overrides:
    - server_name: "vip.example.com"
      labels: { product: "shop", tenant: "vip" }

metrics:
  prefix: "nginx_log"        # all metrics get this prefix
  max_series_total: 50000    # global cardinality cap

  legacy:
    enabled: true            # emit the v0.8 metric set
    metric_names_v1: true    # use the literal v0.8 names (nginx_log_*)
    track_paths: false       # NEW DEFAULT — see Cardinality
    max_paths_global: 5000
    max_ua_families_global: 1000

  # Declarative aggregations. Each one becomes a Prometheus metric.
  # Labels are drawn from either the log line or discovery (named groups).
  aggregations:
    - name: requests_total
      type: counter
      labels: [product, status_class, method]

    - name: request_duration_seconds
      type: histogram
      labels: [product, status_class]
      source_field: request_time
      buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]

# Histogram buckets used by the legacy metric set.
buckets:
  duration: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120]
  response_size: [100, 1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000]

ssl:
  enabled: true
  check_interval: "1h"
  nginx_conf_dir: "/etc/nginx/sites-enabled"
  glob_patterns:
    - "/etc/letsencrypt/live/*/fullchain.pem"
```

### Available label sources for aggregations

| Source           | Where it comes from                                                |
|------------------|--------------------------------------------------------------------|
| Discovery groups | Named groups from `discovery.path_pattern` (e.g. `product`, `tenant`) |
| Log fields       | Any field in `log_fields` (`status`, `method`, `ua_class`, `ssl_protocol`, `server_protocol`, ...) |
| Derived          | `status_class` (`2xx`/`3xx`/`4xx`/`5xx`/`other`)                   |

The exporter validates every label at startup. Unknown labels cause a fatal error before the process starts serving metrics.

### Built-in exporter health metrics

Always exported, with the configured prefix:

| Metric                                       | Type    | Help                                                                |
|----------------------------------------------|---------|---------------------------------------------------------------------|
| `_exporter_lines_processed_total`            | counter | Log lines successfully parsed and dispatched                         |
| `_exporter_parse_errors_total`               | counter | Log lines that failed to parse                                      |
| `_exporter_series_dropped_total`             | counter | Label combinations dropped because `max_series_total` was reached    |
| `_exporter_unmapped_requests_total`          | counter | Requests for `server_name`s not matched by discovery                 |
| `_exporter_discovered_server_names`          | gauge   | Number of `server_name`s currently mapped                            |

## Nginx configuration

The exporter reads a JSON-formatted access log. Add this to your nginx config:

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

If your log_format uses different field names, set `log_fields:` in the config rather than changing nginx.

## Installation

### Binary

```bash
curl -L https://github.com/moreirodamian/nginx-proxy-exporter/releases/latest/download/nginx-proxy-exporter_linux_amd64 \
  -o /usr/local/bin/nginx-proxy-exporter
chmod +x /usr/local/bin/nginx-proxy-exporter
```

### Build from source

```bash
go build -ldflags "-s -w" -o nginx-proxy-exporter .
```

### Systemd

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

### CLI

```
Usage:
  -config string     Path to config file (YAML)
  -listen-address    Override listen address (host:port)
  -log-file          Override log file path
  -version           Show version and exit
```

## Migration from v0.8

| You had…                                             | Do…                                                                                      |
|------------------------------------------------------|------------------------------------------------------------------------------------------|
| A working v0.8 config and dashboards using `nginx_log_path_*` | Drop in [`examples/v0.8-compat.yml`](examples/v0.8-compat.yml) — identical output but with a global path cap. |
| A working v0.8 config and you don't actually use `nginx_log_path_*` | Do nothing. The same config keeps emitting every other metric; only path tracking goes silent (with a startup warning). |
| Multi-tenant proxy, ready to redesign for low cardinality | Adopt [`examples/multi-tenant-discovery.yml`](examples/multi-tenant-discovery.yml). Migrate dashboards from `server_name` labels to `product`/`tenant`. |

## Example queries

### Declarative mode (with discovery)

```promql
# Request rate per product
sum by (product) (rate(nginx_proxy_requests_total[5m]))

# P95 latency per product
histogram_quantile(0.95,
  sum by (product, le) (rate(nginx_proxy_request_duration_seconds_bucket[5m])))

# Top 10 tenants by 5xx rate
topk(10, sum by (product, tenant) (
  rate(nginx_proxy_tenant_requests_total{status_class="5xx"}[5m])))

# AI bot share of total traffic
sum(rate(nginx_proxy_ua_class_total{ua_class="ai_bot"}[5m]))
/ sum(rate(nginx_proxy_ua_class_total[5m])) * 100

# Did discovery miss anyone?
rate(nginx_proxy_exporter_unmapped_requests_total[5m]) > 0
```

### Legacy mode

```promql
# Request rate per client
sum by (server_name) (rate(nginx_log_requests_total[5m]))

# P50 latency per client
histogram_quantile(0.50,
  sum by (server_name, le) (rate(nginx_log_request_duration_seconds_bucket[5m])))
```

## SSL certificate metrics

| Metric                          | Type  | Labels                                              | Description                          |
|---------------------------------|-------|------------------------------------------------------|--------------------------------------|
| `ssl_certificate_expiry_seconds`| gauge | `subject`, `dns_names`, `issuer`, `path`, `in_use`   | Seconds until certificate expires    |
| `ssl_certificates_total`        | gauge | —                                                    | Total certificates checked           |
| `ssl_check_errors_total`        | counter | —                                                  | Certificate read/parse errors        |

## License

MIT
