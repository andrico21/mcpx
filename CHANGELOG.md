# Changelog

All notable changes to `rmcp-server-kit` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Breaking changes bump the **major** version.

## [Unreleased]

### Security

- **`src/auth.rs`** — Bearer-scheme parsing in the auth middleware is now case-insensitive per RFC 7235 §2.1 (e.g. `bearer …` and `BEARER …` are accepted alongside `Bearer …`). Previously these were silently rejected as `invalid_credential` and counted toward the auth-failure rate limit, which could cause spurious lockouts for spec-conformant clients.
- **`src/auth.rs`** — `AuthIdentity` and `ApiKeyEntry` now have manual `Debug` implementations that redact the raw bearer token, the JWT `sub` claim, and the Argon2id hash. This prevents secret material from leaking via `format!("{:?}", …)` or `tracing::debug!(?identity, …)` calls, and is enforced by new unit tests.
- **`src/oauth.rs`** — Added post-DNS SSRF screening for the initial OAuth/JWKS request target so hostnames resolving to blocked IP ranges are rejected before connect, mirroring CRL fetch hardening.
- **`src/oauth.rs`** — Added opt-in `strict_audience_validation` so operators can disable the legacy `azp` fallback and enforce `aud`-only audience checks for new deployments.
- **`src/transport.rs` / `src/oauth.rs`** — Added opt-in `require_auth_on_admin_endpoints` so OAuth `/introspect` and `/revoke` can be mounted behind the normal auth middleware while preserving legacy behavior by default.
- **`src/rbac.rs`** — RBAC and tool rate limiting now inspect JSON-RPC batch arrays and reject the full batch if any `tools/call` entry is denied.
- **`src/oauth.rs`** — Added `jwks_max_response_bytes` (default 1 MiB) and streaming JWKS reads so oversized responses are refused without unbounded allocation.

### Changed

- **`src/metrics.rs`** — `http_request_duration_seconds` now uses an explicit, latency-tuned bucket set (`[1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s]`) instead of the Prometheus default buckets, which were skewed toward web-page rather than RPC latency. The histogram name and labels are unchanged; existing dashboards keep working but will gain finer sub-100 ms resolution.
- **`src/tool_hooks.rs`** — `with_hooks` now documents that dropping the returned wrapper silently loses the configured hooks. The natural `#[must_use]` enforcement is deferred to the next minor-version bump (adding `#[must_use]` to a public function is a SemVer-minor change per cargo-semver-checks).
- **`README.md`** — Quick-start dependency line dropped the gratuitous `features = ["oauth"]` so a copy-paste install no longer pulls in OAuth, `jsonwebtoken`, and `reqwest` for users who only need the default transport. Optional features are now described in a separate note pointing at the Cargo features table.

### Documentation

- **`docs/ARCHITECTURE.md` / `docs/MINDMAP.md`** — Refreshed mTLS sections to match the current per-connection `TlsConnInfo` design (the previous text described the long-removed `RwLock<HashMap<SocketAddr, AuthIdentity>>` map).
- **`docs/ARCHITECTURE.md`** — Metrics section now lists only the metrics actually exported by `src/metrics.rs` (`http_requests_total`, `http_request_duration_seconds`) and points operators at `McpMetrics::registry` for custom collectors. The previous list named gauges and counters that were never implemented.

## [1.3.1] - 2026-04-21

First usable release of `rmcp-server-kit`. A reusable, production-grade
framework for building [Model Context Protocol](https://modelcontextprotocol.io/)
servers in Rust on top of the official `rmcp` SDK.

Consumers supply an `rmcp::handler::server::ServerHandler` implementation;
this crate provides Streamable HTTP transport, TLS / mTLS, structured
authentication (API key, mTLS, OAuth 2.1 JWT), RBAC with per-tool
argument allowlists, per-IP rate limiting, OWASP security headers,
structured observability, optional Prometheus metrics, admin
diagnostics, and graceful shutdown.

### Highlights

- **Transport** — Streamable HTTP (`/mcp`), `/healthz`, `/readyz`,
  `/version`, admin diagnostics, graceful shutdown, configurable TLS
  and mTLS. Optional `serve_stdio()` for local subprocess MCP.
- **Authentication** — API-key (Argon2id-hashed, constant-time verify),
  mTLS client certificates with subject→role mapping, OAuth 2.1 JWT
  validation against JWKS (feature `oauth`). Pre-auth rate limiting
  defends Argon2id against CPU-spray attacks.
- **mTLS revocation** — CDP-driven CRL fetching with bounded memory,
  bounded concurrency, and bounded discovery rate. Auto-discovers CRL
  URLs from the CA chain at startup and from connecting client certs
  during handshakes. Hot-reloadable via `ReloadHandle::refresh_crls()`.
- **RBAC** — `RbacPolicy` with default-deny, per-role allow/deny tool
  lists (glob-supported), per-tool argument allowlists, HMAC-SHA256
  argument-value redaction in deny logs, task-local accessors
  (`current_role`, `current_identity`, `current_token`, `current_sub`).
- **OAuth 2.1** — JWKS cache with refresh cooldown, configurable allowed
  algorithms (RS256/ES256 default; symmetric keys rejected), HTTPS-only
  redirect policy, custom CA support, optional OAuth proxy endpoints
  (`/authorize`, `/token`, `/register`, `/introspect`, `/revoke`).
- **SSRF hardening** — Validate-time literal-IP / userinfo rejection on
  every operator-supplied URL plus a runtime per-hop IP-range guard on
  every redirect closure (CRL, JWKS, OAuth admin traffic). Blocks
  private, loopback, link-local, multicast, broadcast, and cloud-
  metadata ranges.
- **Hardening defaults** — Per-IP token-bucket rate limiting (governor)
  with memory-bounded LRU eviction, request-body cap (default 1 MiB),
  request-timeout cap, OWASP security headers (HSTS, CSP, X-Frame-
  Options, etc.), configurable CORS and Host allow-lists, JWKS key cap
  (default 256), CRL response-body cap (default 5 MiB).
- **Hot reload** — Lock-free `arc-swap`-backed reload of API keys,
  RBAC policy, and CRL set without dropping in-flight requests.
- **Tool hooks** — Opt-in `HookedHandler` wrapping `ServerHandler` with
  async `before_call` / `after_call` hooks. After-hooks run on a
  spawned task with the parent span and RBAC task-locals re-installed.
  Configurable `max_result_bytes` cap.
- **Observability** — `tracing-subscriber` initialization with
  `EnvFilter`, JSON or pretty console output, optional audit-file
  sink. Sensitive values wrapped in `secrecy::SecretString` end-to-end.
- **Metrics** (feature `metrics`) — Prometheus registry served on a
  separate listener (request count, duration histogram, in-flight
  gauge, auth failures, RBAC denies).
- **Configuration** — Programmatic builder API on `McpServerConfig`
  with compile-time `Validated<T>` typestate, plus matching TOML
  schema in `src/config.rs`.

### Cargo features

- `oauth` (default off) — OAuth 2.1 JWT validation via JWKS plus
  optional OAuth proxy endpoints.
- `metrics` (default off) — Prometheus registry and `/metrics` endpoint.
- `test-helpers` (default off) — opt-in test-only constructors used by
  downstream integration suites; not part of the stable API surface.

### Minimum supported Rust

`rmcp-server-kit` targets stable Rust **1.95** or newer (`edition = "2024"`).

### Documentation

- [`README.md`](README.md) — quick start.
- [`docs/GUIDE.md`](docs/GUIDE.md) — end-to-end consumer guide and TOML schema.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — file-cited deep architecture map.
- [`docs/MINDMAP.md`](docs/MINDMAP.md) — visual project mindmap.
- [`AGENTS.md`](AGENTS.md) — repository navigation hub for AI agents.
- [`SECURITY.md`](SECURITY.md) — coordinated disclosure policy and
  hardening posture.
