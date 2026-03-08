# Enterprise Feature Ideas

Ideas that might be worth pursuing. These tend toward the "enterprisey" end of
the spectrum — governance, observability, operational controls — and are
recorded here so they don't get lost.

None of these are committed work. They're notes on what the architecture could
support if the need arises.

## Telemetry sink

Push request/response statistics to an external metrics collector (OTEL
collector, Prometheus pushgateway, Splunk HEC, or any HTTP endpoint) so that
DuckDB HTTP activity can participate in existing dashboards, alerts, and
capacity planning.

The extension already has:
- Per-host and global counters (requests, bytes, elapsed, errors, 429s, pacing)
- An HTTP client capable of POSTing JSON

So the implementation would use the extension's own HTTP machinery to push its
own statistics — which means telemetry requests must be excluded from the
counters they report, or you get infinite regress.

Configuration would fit naturally into `http_config`:

```sql
SET VARIABLE http_config = http_config_set(
    'default',
    json_object('telemetry_sink', 'http://otel-collector:4318/v1/metrics')
);
```

Push triggers (in order of complexity):
1. Explicit `http_flush_stats(sink_url)` — user controls when
2. On extension unload — automatic, best-effort, no threads
3. Every N requests or T seconds — needs a timer or piggyback mechanism

Start with (1) and (2). If someone wants continuous push, they can call
`http_flush_stats()` on an interval from SQL.

## Bandwidth limiting

The extension controls request *count* but not bytes-on-the-wire. Options:

- **In-extension**: cpr exposes `LimitRate{downrate, uprate}` (maps to
  `CURLOPT_MAX_RECV_SPEED_LARGE`). Per-connection, so aggregate =
  `max_concurrent * per_connection_limit`. Approximate but functional.
- **Proxy-based** (preferred): delegate bandwidth control to a throttling
  proxy (Squid `delay_pools`, Charles Proxy). The extension already supports
  `proxy` in config. This delegates both control and responsibility to IT.
- **OS-level**: macOS `dnctl`/`pfctl`, Linux `tc`. Requires root, system-wide.

The proxy approach is architecturally cleaner: the extension owns request-rate
governance, infrastructure owns bandwidth governance.

## Per-query request ceiling

A `max_requests_per_query` config field that hard-caps the total number of HTTP
requests a single query can make, regardless of rate. Guards against
`FROM range(1000000)` scenarios where rate limiting merely slows the avalanche
rather than stopping it.

## Request audit log

Write a structured log (JSON lines or Parquet) of every HTTP request: URL,
method, status code, elapsed, response size, timestamp. Useful for compliance
and post-incident forensics. The sink could be a local file, an S3 path, or
an HTTP endpoint (same telemetry sink pattern).

## Circuit breaker

If a host returns N consecutive errors (5xx or timeout), stop sending requests
to that host for a cooldown period. Prevents the extension from hammering a
service that's already in trouble. Classic Hystrix/resilience4j pattern.

## Retry with backoff

Configurable retry for transient failures (429, 503, network errors) with
exponential backoff and jitter. The rate limiter already handles 429 feedback
by pushing the TAT forward; explicit retry would complement this for cases
where the request should actually be re-sent.

## Mutual TLS (mTLS)

**Implemented.** The `client_cert` and `client_key` config fields are now
supported. See README for usage.

## Expiring bearer tokens

**Partially implemented.** The `bearer_token_expires_at` config field enables
the extension to check token expiry before each request and fail fast with a
clear error. The hosting application owns the refresh chain. See README for
usage. What remains is extension-level automatic token refresh (below).

Many corporate environments issue short-lived bearer tokens via a token
endpoint that itself requires authentication (often Kerberos/Negotiate).
The pattern is:

1. Authenticate to a token service using Negotiate (SPNEGO)
2. Receive a bearer token with an expiry (e.g. 1 hour)
3. Use that token for subsequent API calls
4. Re-authenticate when the token expires

Today this is handled via the `http_config_set_bearer` helper macro:

```sql
SET VARIABLE http_config = http_config_set_bearer(
    'https://api.corp.com/', 'eyJ...', expires_at := 1741564800
);
```

Or from a Python hosting application:

```python
token, expires_at = get_vendor_token()  # your multi-hop auth chain
con.execute(
    "SET VARIABLE http_config = http_config_set_bearer($1, $2, expires_at := $3)",
    ['https://api.corp.com/', token, expires_at]
)
```

The helpers handle merging safely, but the hosting application still owns the
refresh chain. A better approach would be extension-level token caching:

- A process-global token cache keyed by token endpoint URL
- Each entry stores: token, expiry timestamp, the auth method used to obtain it
- On request, if the cached token is expired (or absent), the extension
  automatically re-authenticates and caches the new token
- Config fields: `token_endpoint`, `token_auth_type` (defaults to "negotiate"),
  `token_expiry_field` (JSON path to extract expiry from the token response)

```sql
SET VARIABLE http_config = http_config_set(
    'https://api.corp.com/',
    json_object('auth_type', 'bearer',
                'token_endpoint', 'https://auth.corp.com/token',
                'token_auth_type', 'negotiate')
);
-- Now requests to api.corp.com automatically obtain and refresh tokens
```

The extension already has the building blocks: Negotiate auth, HTTP client,
per-host config scoping, and process-global caches (rate limiters, sessions).
The token cache would follow the same LRU pool pattern.

Open questions:
- Should the token response format be configurable, or assume a convention
  (e.g. `{"access_token": "...", "expires_in": 3600}`)?
- Should the extension support OAuth2 client_credentials grant as another
  token_auth_type?
- Thread safety: token refresh must be serialized per endpoint (mutex per
  cache entry) to avoid thundering herd on expiry.

## HashiCorp Vault integration

Vault is a common secrets backend in enterprise environments. The extension
could fetch secrets (bearer tokens, API keys, client certificates) from Vault
at request time, rather than requiring them to be set in `http_config`.

Two integration patterns:

**1. Vault as a token/secret source (simpler)**

A config field like `vault_secret_path` that tells the extension to read a
secret from Vault before making the HTTP request. The secret value populates
the bearer token (or other auth fields).

```sql
SET VARIABLE http_config = http_config_set(
    'https://api.corp.com/',
    json_object('auth_type', 'bearer',
                'vault_addr', 'https://vault.corp.com',
                'vault_secret_path', 'secret/data/api-corp-com/token',
                'vault_token_field', 'access_token')
);
```

The extension would `GET` the Vault secret endpoint (using its own HTTP
machinery), extract the token, and cache it with TTL awareness (Vault leases
have TTLs). This is essentially the expiring-bearer-token pattern above, with
Vault as the token endpoint.

**2. Vault as a PKI backend (mTLS certificates)**

Vault's PKI secrets engine can issue short-lived client certificates. The
extension could request a certificate from Vault, write it to a temp file (or
use in-memory SSL context if cpr supports it), and use it for mTLS. This is
more complex but eliminates the need to manage certificate files on disk.

**Authentication to Vault itself** is the bootstrap problem. Options:
- Vault token in config (simple but the token itself needs management)
- Kubernetes auth (if running in k8s — the service account JWT is available)
- LDAP/Kerberos auth (the extension already has Negotiate — could use it to
  authenticate to Vault if Vault is configured with Kerberos auth)

Start with pattern (1) — Vault as a bearer token source. It's the most
immediately useful and builds on the expiring-bearer-token cache. Pattern (2)
is a natural follow-on once (1) works.

## Request tagging / correlation IDs

Inject a configurable header (e.g. `X-Request-ID`, `X-Correlation-ID`) into
every outbound request, with a value that traces back to the DuckDB query.
Helps service owners correlate their logs with the DuckDB workload that
generated the traffic.
