# Design Notes: HTTP as a Composable Primitive in DuckDB

These are observations from building `duckdb-http-client`, a standalone C API
extension that provides explicit HTTP functions for DuckDB. They are offered as
notes from one particular approach, not as prescriptions.

## Inspiration

This extension is directly inspired by [sqlite-http](https://github.com/asg017/sqlite-http)
(also known as http0) by Alex Garcia. http0 demonstrated that explicit HTTP
functions in an embedded database — rather than transparent filesystem
abstraction — are a surprisingly natural fit. In particular, http0 showed that
a "serverless" client-library database can serve as a capable HTTP orchestrator
when the control flow is data-driven: the query defines what to fetch, rate
limiting governs the pace, and the results land directly in tables.

Our extension follows the same philosophy, adapted for DuckDB's type system
(MAP parameters for headers, JSON output, table macros for ergonomics).

## Context

This extension started as an attempt to add SPNEGO/Kerberos authentication to
the existing `httpfs` extension. We found it more natural to build a
general-purpose HTTP client as a separate extension, and SPNEGO support became
just one authentication method among several.

The result provides:

- Table functions (`http_get`, `http_post`, etc.) for interactive use
- A scalar function (`http_request`) for data-driven use in JOINs and
  expressions
- Per-host rate limiting (GCRA algorithm) applied transparently
- A scoped configuration system using DuckDB's `SET VARIABLE` mechanism
- Negotiate, Bearer, and manual header-based authentication

## An observation about layering

The current `httpfs` extension handles HTTP transport, S3 authentication, Azure
credential management, and virtual filesystem registration in a single package.
This works well for its primary use case: making `read_csv('s3://...')` and
similar patterns seamless.

Building our extension from scratch, we noticed that many of the pieces we
needed — HTTP transport, connection management, authentication, rate limiting —
are general-purpose concerns that could benefit other extensions and use cases
beyond filesystem access.

One possible factoring might look like:

```
┌─────────────────────────────────────────────┐
│  httpfs / S3 / Azure / GCS                  │  Filesystem abstraction
│  (translates file paths to HTTP requests)   │
├─────────────────────────────────────────────┤
│  http_client (core)                         │  HTTP transport primitive
│  (request execution, connection pooling,    │
│   rate limiting, auth dispatch)             │
├─────────────────────────────────────────────┤
│  Auth providers                             │  Pluggable authentication
│  (S3 signatures, Azure tokens, SPNEGO,      │
│   Bearer, API keys)                         │
└─────────────────────────────────────────────┘
```

In this model, `httpfs` would delegate HTTP operations to a shared transport
layer. Extensions that need HTTP access for non-filesystem purposes (REST API
calls, webhooks, health checks) would use the same infrastructure.

The current architecture has its own advantages: tight coupling between HTTP
and filesystem logic simplifies development and likely makes it easier to
handle S3's particular authentication and retry requirements. A layered
approach introduces abstraction boundaries that have real costs.

## What we learned from the C API boundary

Building with the C extension API rather than DuckDB's internal C++ APIs
surfaced some practical constraints.

**Configuration is the hard problem.** The C API does not expose the caller's
connection context to function implementations. Extensions cannot read
variables or secrets set by the user. We worked around this by implementing
user-facing functions as SQL macros that read `getvariable('http_config')` in
the caller's context and pass the resolved configuration to underlying C
functions as explicit parameters. This works well in practice, but it is a
workaround.

If future versions of the C API exposed limited access to the caller's
context — something like `duckdb_function_get_variable(info, name)` or
`duckdb_function_get_secret(info, type, scope)` — it would expand what C API
extensions can do. There are reasonable stability and encapsulation reasons not
to expose these; we note the gap without proposing a specific solution.

**SQL macros as an abstraction layer.** Registering SQL macros at extension load
time turned out to be a powerful pattern. The macros run in the caller's
connection context (so they can see variables and secrets), while the C
functions they wrap are pure executors that take all inputs as explicit
parameters. This separation happened to align well with the principle that
context resolution and computation should live at different layers.

**Scalar functions returning JSON may be more fundamental than table functions.**
DuckDB's JSON support is strong enough that a scalar function returning a JSON
envelope can be decomposed into any shape the caller needs. Table functions
provide nicer ergonomics for interactive use, but the scalar variant is the
one that composes with the rest of SQL — it works in expressions, JOINs, and
data-driven workflows where the set of URLs comes from a query. We provide
both, with the table functions implemented as thin macro wrappers.

## The cost of being external

Building this as a C API extension means we carry a second copy of libcurl (via
the cpr library), since DuckDB's statically-linked curl is not accessible to
extensions. This adds roughly 2MB of redundant binary. It illustrates the
practical cost of not having HTTP transport as a shared primitive.

## Acknowledgments

- [sqlite-http / http0](https://github.com/asg017/sqlite-http) by Alex Garcia,
  for demonstrating that explicit HTTP functions in an embedded database are a
  practical and powerful pattern.
- The DuckDB C extension API, whose stability guarantees and binary
  compatibility made this project feasible as an external extension.
- Richard E. Silverman, whose suggestion of the pre-flight approach to
  Negotiate authentication (generating the SPNEGO token before the HTTP
  request rather than relying on curl's built-in SPNEGO support) shaped the
  authentication design.
