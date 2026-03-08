# duckdb-http-client

A DuckDB extension providing HTTP client functions as composable SQL primitives.
Built on the [DuckDB C Extension API](https://github.com/duckdb/extension-template-c)
for binary compatibility across DuckDB versions.

Inspired by Alex Garcia's excellent [sqlite-http](https://github.com/asg017/sqlite-http)
(`http0`) extension for SQLite, which demonstrated how natural and powerful
HTTP-in-SQL can be when done as explicit table-valued and scalar functions
rather than as a transparent filesystem layer.

## Loading

```sql
LOAD 'path/to/http_client.duckdb_extension';
```

Or, if loading an unsigned extension:

```bash
duckdb -unsigned -cmd "LOAD 'build/release/http_client.duckdb_extension';"
```

## HTTP Functions

### Per-verb scalar functions

Each returns a STRUCT with request and response details. Use a subquery or CTE
to access individual fields via dot notation.

`http_get`, `http_head`, `http_options`, `http_put`, and `http_delete` are
idempotent — DuckDB may safely deduplicate identical calls within a query.
`http_post` and `http_patch` are volatile — every call fires regardless.

```sql
-- Simple GET with struct field access
SELECT r.response_status_code, r.response_body
FROM (SELECT http_get('https://httpbin.org/get') AS r);
```

```sql
-- GET with custom headers
SELECT r.response_body
FROM (SELECT http_get('https://httpbin.org/get',
    headers := MAP {'X-Api-Key': 'secret123'}) AS r);
```

```sql
-- POST with JSON body (volatile — always fires)
SELECT r.response_status_code
FROM (SELECT http_post('https://httpbin.org/post',
    body := '{"name": "duckdb"}',
    content_type := 'application/json') AS r);
```

```sql
-- PUT with explicit content type
SELECT r.response_status_code
FROM (SELECT http_put('https://httpbin.org/put',
    body := '<item><name>test</name></item>',
    content_type := 'application/xml') AS r);
```

```sql
-- Data-driven batch: fetch from a list of URLs
SELECT url, r.response_status_code AS status, round(r.elapsed, 3) AS seconds
FROM (
    SELECT url, http_get(url) AS r
    FROM (VALUES ('https://httpbin.org/get'), ('https://httpbin.org/ip')) AS t(url)
)
ORDER BY url;
```

```sql
-- Batch API calls driven by table data
SELECT e.endpoint_url, r.response_status_code AS status
FROM (
    SELECT e.endpoint_url, http_get(e.endpoint_url) AS r
    FROM endpoints AS e
    LEFT OUTER JOIN health_checks AS h ON h.url = e.endpoint_url
    WHERE h.url IS NULL
);
```

### Generic scalar function: `http_request(method, url, ...)`

For dynamic methods or when the verb isn't known at query-writing time. Always
volatile (every call fires).

```sql
SELECT r.response_status_code
FROM (SELECT http_request('GET', 'https://httpbin.org/get') AS r);
```

### JSON variant: `http_request_json(method, url, ...)`

Returns the same result as `http_request` but serialized as a JSON string via
DuckDB's `to_json()`.

```sql
SELECT http_request_json('GET', 'https://httpbin.org/ip');
```

### STRUCT fields

All scalar functions return a STRUCT with the same fields:

| Field | Type | Description |
|-------|------|-------------|
| `request_url` | VARCHAR | The URL as sent |
| `request_method` | VARCHAR | HTTP method used |
| `request_headers` | MAP(VARCHAR, VARCHAR) | Headers sent |
| `request_body` | VARCHAR | Request body, if any |
| `response_status_code` | INTEGER | HTTP status code (200, 404, etc.) |
| `response_status` | VARCHAR | Status line (e.g. `HTTP/1.1 200 OK`) |
| `response_headers` | MAP(VARCHAR, VARCHAR) | Response headers (keys are lowercase, as normalized by libcurl) |
| `response_body` | VARCHAR | Response body |
| `response_url` | VARCHAR | Final URL after redirects |
| `elapsed` | DOUBLE | Request duration in seconds |
| `redirect_count` | INTEGER | Number of redirects followed |

### Function parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | VARCHAR | (required) | Request URL |
| `headers` | MAP(VARCHAR, VARCHAR) | NULL | Request headers as a MAP literal |
| `body` | VARCHAR | NULL | Request body (POST, PUT, PATCH only) |
| `content_type` | VARCHAR | NULL | Content-Type (defaults to `application/json` if body is set) |

The generic `http_request` also takes `method` (VARCHAR) as the first
parameter.

### Recommended pattern: subquery or CTE

Always assign the scalar function result to an alias in a subquery or CTE,
then access fields from the alias. This ensures the HTTP request fires exactly
once per row, regardless of how many fields you reference.

```sql
-- Good: one request, access multiple fields
WITH api_calls AS (
    SELECT id, http_get('https://api.example.com/item/' || id) AS r
    FROM items
)
SELECT id, r.response_status_code, r.response_body, r.elapsed
FROM api_calls;

-- Bad: fires two requests per row (DuckDB evaluates each expression separately)
SELECT
    http_get(url).response_status_code,
    http_get(url).elapsed
FROM urls;
```

This is consistent with how SQL handles any expensive expression — factor it
into a subquery and reference the result by name.

## Configuration

Configuration is managed via a DuckDB variable (`http_config`) containing a
`MAP(VARCHAR, VARCHAR)`. Keys are URL prefixes (scopes); values are JSON
objects with configuration fields. The longest matching prefix wins, with
`'default'` as the fallback.

```sql
SET VARIABLE http_config = MAP {
    'default': '{"timeout": 30, "rate_limit": "20/s"}',
    'https://api.example.com/': '{"auth_type": "bearer", "bearer_token": "sk-abc123", "rate_limit": "5/s"}',
    'https://internal.corp.com/': '{"auth_type": "negotiate", "verify_ssl": false}'
};
```

### Configuration fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `timeout` | integer | 30 | Request timeout in seconds |
| `rate_limit` | string | `"20/s"` | Rate limit (`"10/s"`, `"100/m"`, `"3600/h"`, `"none"` to disable) |
| `burst` | number | 5.0 | Burst capacity for rate limiter |
| `verify_ssl` | boolean | true | Verify SSL certificates |
| `proxy` | string | | HTTP/HTTPS proxy URL |
| `ca_bundle` | string | | Path to CA certificate bundle |
| `auth_type` | string | | `"negotiate"` or `"bearer"` |
| `bearer_token` | string | | Token for Bearer authentication |
| `max_concurrent` | integer | 10 | Max parallel requests per scalar function chunk |
| `global_rate_limit` | string | | Aggregate rate limit across all hosts (e.g. `"50/s"`) |
| `global_burst` | number | 10.0 | Burst capacity for the global rate limiter |

### How configuration flows

The user-facing functions (`http_get`, `http_post`, etc.) are SQL macros that
read `http_config` from the caller's connection via `getvariable()`, then pass
it to the underlying C functions. This means configuration set via
`SET VARIABLE` is correctly visible during function execution.

### Scope resolution example

```sql
SET VARIABLE http_config = MAP {
    'default':                    '{"timeout": 30}',
    'https://api.example.com/':   '{"bearer_token": "abc", "rate_limit": "5/s"}',
    'https://api.example.com/v2/':'{"bearer_token": "xyz"}'
};

-- Uses default config (timeout=30, no auth)
SELECT r.response_status_code
FROM (SELECT http_get('https://other-site.com/data') AS r);

-- Matches 'https://api.example.com/' scope (bearer_token=abc, rate_limit=5/s)
SELECT r.response_status_code
FROM (SELECT http_get('https://api.example.com/v1/users') AS r);

-- Matches 'https://api.example.com/v2/' scope (bearer_token=xyz)
-- Also inherits timeout=30 from default
SELECT r.response_status_code
FROM (SELECT http_get('https://api.example.com/v2/users') AS r);
```

### Rate limiting

Rate limiting uses the GCRA (Generic Cell Rate Algorithm) and is applied
per-host automatically. The default is 20 requests/second with a burst of 5.
Override per-scope via configuration:

```sql
SET VARIABLE http_config = MAP {
    'default': '{"rate_limit": "20/s"}',
    'https://rate-limited-api.com/': '{"rate_limit": "2/s"}'
};
```

### Parallel execution

The scalar functions execute requests in parallel using
libcurl's multi interface (via cpr's `MultiPerform`). When DuckDB passes a
chunk of rows to the scalar function, the extension fires up to
`max_concurrent` requests simultaneously, then moves to the next batch.

```sql
-- Default: up to 10 concurrent requests per chunk
SELECT json_extract(
    http_request('GET', 'http://api.example.com/item/' || id::VARCHAR, NULL, NULL, NULL),
    '$.response_status_code')::INTEGER AS status
FROM range(100) AS t(id);
```

```sql
-- Throttle to 3 concurrent requests
SET VARIABLE http_config = MAP {
    'default': '{"max_concurrent": 3}'
};

SELECT json_extract(
    http_request('GET', 'http://api.example.com/item/' || id::VARCHAR, NULL, NULL, NULL),
    '$.response_status_code')::INTEGER AS status
FROM range(100) AS t(id);
```

DuckDB's vectorized engine passes rows to scalar functions in chunks (up to
2048 rows). Within each chunk, the extension:

1. **Parses** all rows — resolves config, builds sessions, acquires rate limit tokens
2. **Executes** in sub-batches of `max_concurrent` via `MultiPerform` (libcurl event loop — no threads)
3. **Writes** all results back to the output vector

Rate limiting is enforced *before* each batch: the extension acquires one rate
limit token per request, sleeping if necessary, then fires the batch. If a
server responds with 429, the rate limiter's TAT (Theoretical Arrival Time) is
pushed forward by the `Retry-After` value, automatically slowing subsequent
batches.

Parallelism is automatic for data-driven workloads where the scalar function
is applied across multiple rows.

### Rate limiter diagnostics

The `http_rate_limit_stats()` table function returns a snapshot of per-host
rate limiter state. Call it after running requests to see how the rate limiter
behaved.

```sql
SELECT * FROM http_rate_limit_stats();
```

| Column | Type | Description |
|--------|------|-------------|
| `host` | VARCHAR | Hostname key |
| `rate_limit` | VARCHAR | Configured rate spec (e.g. `20/s`) |
| `rate_rps` | DOUBLE | Requests per second (parsed) |
| `burst` | DOUBLE | Burst capacity |
| `requests` | BIGINT | Total requests recorded |
| `paced` | BIGINT | Times the caller had to sleep before sending |
| `total_wait_seconds` | DOUBLE | Cumulative time spent waiting for rate limit tokens |
| `throttled_429` | BIGINT | Times a 429 response pushed back the rate limiter |
| `backlog_seconds` | DOUBLE | How far ahead the TAT is from now (positive = backlogged) |
| `total_responses` | BIGINT | Total HTTP responses received |
| `total_response_bytes` | BIGINT | Total response body bytes received |
| `total_elapsed` | DOUBLE | Sum of all request durations (seconds) |
| `min_elapsed` | DOUBLE | Fastest request (seconds) |
| `max_elapsed` | DOUBLE | Slowest request (seconds) |
| `errors` | BIGINT | Responses with non-2xx status codes |

When a `global_rate_limit` is configured, a `(global)` row appears with
aggregate counts across all hosts.

Example workflow:

```sql
-- Fire some requests
SELECT count(*) FROM (
    SELECT http_request('GET', 'http://localhost:8444/fast', NULL, NULL, NULL) AS r
    FROM range(50) AS t(id)
);

-- Inspect rate limiter and request stats
SELECT host, requests, total_responses, total_response_bytes,
       round(total_elapsed, 3) AS total_s,
       round(min_elapsed, 4) AS min_s,
       round(max_elapsed, 4) AS max_s,
       errors, paced, throttled_429
FROM http_rate_limit_stats();
```

Example with a global rate limiter:

```sql
SET VARIABLE http_config = MAP {
    'default': '{"global_rate_limit": "10/s", "rate_limit": "100/s", "max_concurrent": 5}'
};

SELECT json_extract(
    http_request('GET', 'http://api.example.com/item/' || id::VARCHAR, NULL, NULL, NULL),
    '$.response_status_code')::INTEGER AS status
FROM range(15) AS t(id);

SELECT * FROM http_rate_limit_stats();
-- (global)   | 15 requests | 1955 bytes | paced=1 | pacing_s=0.986
-- localhost  | 15 requests | 1955 bytes | paced=0
```

## Negotiate (SPNEGO/Kerberos) Authentication

### `negotiate_auth_header(url)`

Returns the `Authorization` header value for SPNEGO/Kerberos authentication.
Requires a valid Kerberos ticket (`kinit` or OS-level SSO). The URL must be
HTTPS.

```sql
SELECT negotiate_auth_header('https://intranet.example.com/api/data');
-- Returns: 'Negotiate YIIGhgYJKoZI...'
```

Use it to authenticate HTTP requests to Kerberos-protected services:

```sql
SELECT r.response_status_code, r.response_body
FROM (SELECT http_get('https://intranet.example.com/api/data',
    headers := MAP {'Authorization': negotiate_auth_header('https://intranet.example.com/api/data')}) AS r);
```

Or configure it globally so all requests to a host auto-authenticate:

```sql
SET VARIABLE http_config = MAP {
    'https://intranet.example.com/': '{"auth_type": "negotiate"}'
};

-- No explicit headers needed — the token is generated and injected automatically
SELECT r.response_status_code
FROM (SELECT http_get('https://intranet.example.com/api/data') AS r);
```

### `negotiate_auth_header_json(url)`

Returns a JSON object with the token and debugging metadata about the
authentication process. Useful for diagnosing Kerberos issues.

```sql
SELECT negotiate_auth_header_json('https://intranet.example.com/api/data');
```

Returns:

```json
{
    "token": "YIIGhgYJKoZIhvcSAQICAQBuggY...",
    "header": "Negotiate YIIGhgYJKoZIhvcSAQICAQBuggY...",
    "url": "https://intranet.example.com/api/data",
    "hostname": "intranet.example.com",
    "spn": "HTTP@intranet.example.com",
    "provider": "GSS-API",
    "library": "/System/Library/Frameworks/GSS.framework/Versions/Current/GSS"
}
```

The fields:

| Field | Description |
|-------|-------------|
| `token` | Base64-encoded SPNEGO token |
| `header` | Complete `Authorization` header value (`Negotiate <token>`) |
| `url` | The URL the token was generated for |
| `hostname` | Hostname extracted from the URL |
| `spn` | Service Principal Name used (`HTTP@hostname`) |
| `provider` | Authentication provider (`GSS-API` on macOS/Linux, `SSPI` on Windows) |
| `library` | Path to the loaded security library |

This is particularly useful for verifying that the correct SPN is being
constructed, that the right security library is loaded, and that the hostname
extraction is working as expected.

## Building

```bash
make
```

This configures cmake, builds the extension, and stamps the metadata for
DuckDB to load it.

## Testing

### Automated tests

```bash
make test_release
```

The sqllogictest suite (`test/sql/http_client.test`) covers error cases for
Negotiate auth, table functions against httpbin.org, and scalar function usage
including data-driven queries.

### Concurrency testing with the Flask server

A Flask server (`test/flask_concurrency_server.py`) instruments concurrent
connections to verify parallel execution behavior. It tracks per-request
arrival/departure times, thread identity, and peak concurrency.

```bash
# Terminal 1: start the concurrency test server
python3 test/flask_concurrency_server.py
# Listens on http://localhost:8444
```

Endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /slow/<path>?delay=0.5` | Responds after a configurable delay (default 0.5s). Tracks concurrency. |
| `GET /fast` | Responds immediately. For throughput measurement. |
| `GET /stats` | Returns JSON with `total_requests`, `peak_concurrent_connections`, and per-request log. |
| `GET /reset` | Resets all counters and logs. |
| `GET /health` | Health check. |

#### Verify parallel execution

```bash
# Terminal 2: reset and run 10 requests with 0.3s delay each
curl -s http://localhost:8444/reset > /dev/null

duckdb -unsigned -cmd "LOAD 'build/release/http_client.duckdb_extension';" -c "
SELECT id,
       json_extract(http_request('GET',
           'http://localhost:8444/slow/' || id::VARCHAR || '?delay=0.3',
           NULL, NULL, NULL), '\$.response_status_code')::INTEGER AS status
FROM range(10) AS t(id);
"

# Check what the server saw
curl -s http://localhost:8444/stats | python3 -m json.tool
```

With the default `max_concurrent=10`, all 10 requests arrive within
milliseconds of each other (wall-clock time ~0.3s, not 3.0s). The server
reports `peak_concurrent_connections: 10`.

#### Verify batching with max_concurrent

```bash
curl -s http://localhost:8444/reset > /dev/null

duckdb -unsigned -cmd "LOAD 'build/release/http_client.duckdb_extension';" -c "
SET VARIABLE http_config = MAP {
    'default': '{\"max_concurrent\": 3, \"rate_limit\": \"100/s\"}'
};

SELECT id,
       json_extract(http_request('GET',
           'http://localhost:8444/slow/' || id::VARCHAR || '?delay=0.3',
           NULL, NULL, NULL), '\$.response_status_code')::INTEGER AS status
FROM range(10) AS t(id);
"

curl -s http://localhost:8444/stats | python3 -m json.tool
```

The server reports `peak_concurrent_connections: 3`. Requests arrive in 4
batches of sizes [3, 3, 3, 1], with ~0.3s between batches (total wall-clock
~1.2s). This confirms that `max_concurrent` correctly limits parallelism.

#### Analyze batch timing

A quick script to summarize arrival batches from the server stats:

```bash
curl -s http://localhost:8444/stats | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f'Total requests: {data[\"total_requests\"]}')
print(f'Peak concurrent: {data[\"peak_concurrent_connections\"]}')
arrivals = sorted(r['arrived'] for r in data['request_log'])
print(f'Arrival span: {arrivals[-1] - arrivals[0]:.3f}s')
batches, batch = [], [arrivals[0]]
for a in arrivals[1:]:
    if a - batch[0] < 0.05:
        batch.append(a)
    else:
        batches.append(batch)
        batch = [a]
batches.append(batch)
print(f'Batches: {len(batches)} (sizes: {[len(b) for b in batches]})')
"
```

#### Verify rate limiter diagnostics after testing

```bash
duckdb -unsigned -cmd "LOAD 'build/release/http_client.duckdb_extension';" -c "
-- Run some requests first
SELECT count(*) FROM (
    SELECT http_request('GET', 'http://localhost:8444/fast', NULL, NULL, NULL)
    FROM range(20) AS t(id)
);

-- Inspect rate limiter
SELECT host, rate_limit, requests, paced, throttled_429,
       round(total_wait_seconds, 3) AS wait_s,
       round(backlog_seconds, 3) AS backlog_s
FROM http_rate_limit_stats();
"
```

### Manual testing with the Flask negotiate server

A test server is included for end-to-end Negotiate authentication testing:

```bash
# Start the test server (auto-generates self-signed cert)
python3 test/flask_negotiate_server.py

# In another terminal
duckdb -unsigned -cmd "LOAD 'build/release/http_client.duckdb_extension';" -c "
    -- Health check (no auth required)
    SELECT r.response_status_code
    FROM (SELECT http_get('https://localhost:8443/health') AS r);

    -- Authenticated request
    SELECT r.response_status_code, r.response_body
    FROM (SELECT http_get('https://localhost:8443/data.json',
        headers := MAP {'Authorization': negotiate_auth_header('https://localhost:8443/data.json')}) AS r);
"
```

## Note on authorship

The code and documentation in this repository were generated entirely by
Claude Opus 4.6 (Anthropic), under close human supervision. The project is a
vehicle for experimentation with designs, implementation techniques, and the
boundaries of AI-assisted software development — not a production-ready
artifact. Architectural decisions, API shape, and overall direction were
guided by the human; implementation was performed by the model.

## License

MIT

## Acknowledgments

- [sqlite-http](https://github.com/asg017/sqlite-http) by Alex Garcia — the
  model for HTTP-as-SQL-functions
- [pyspnego](https://github.com/jborean93/pyspnego) — used to validate the
  pre-flight Negotiate technique
- Richard E. Silverman — for suggesting the pre-flight Negotiate approach
