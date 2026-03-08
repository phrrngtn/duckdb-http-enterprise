# duckdb-http-client

A DuckDB extension providing HTTP client functions as composable SQL primitives.
Built on the [DuckDB C Extension API](https://github.com/duckdb/extension-template-c)
for binary compatibility across DuckDB versions.

Inspired by Alex Garcia's excellent [sqlite-http](https://github.com/asg017/sqlite-http)
(`http0`) extension for SQLite, which demonstrated how natural and powerful
HTTP-in-SQL can be when done as explicit table-valued and scalar functions
rather than as a transparent filesystem layer.

## Functions

### `negotiate_auth_header(url)`

Generates a pre-flight SPNEGO/Kerberos `Authorization: Negotiate` header
for the given HTTPS URL, using the current user's Kerberos ticket (from
`kinit` or OS-level SSO).

```sql
SELECT negotiate_auth_header('https://intranet.example.com/api/data');
-- Returns: 'Negotiate YIIGhgYJKoZI...'
```

Uses GSS-API (macOS/Linux, loaded via `dlopen`) or SSPI (Windows, linked
directly) — no build-time Kerberos dependencies required.

## Building

```bash
make
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
