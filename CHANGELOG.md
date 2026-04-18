# Changelog

All notable changes to `mcpx` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0: breaking changes bump the **minor** version.

## [Unreleased]

### Changed

- **[H-A1] Public API no longer leaks `anyhow`.** `serve()`,
  `serve_with_listener()`, `serve_stdio()`, `serve_metrics()`, and
  `McpMetrics::new()` now return `Result<_, McpxError>` instead of
  `anyhow::Result<_>` / `prometheus::Result<_>`. New `McpxError`
  variants `Tls(String)`, `Startup(String)`, and (under
  `feature = "metrics"`) `Metrics(String)` carry the wrapped detail.
  The opaque `McpxError::Other(anyhow::Error)` variant has been
  **removed**. Most call sites that propagate via `?` into
  `anyhow::Result<()>` will keep compiling because `McpxError` impls
  `std::error::Error`. Call sites that name the return type
  explicitly must switch to `mcpx::Result<()>` (newly re-exported at
  the crate root). See `examples/minimal_server.rs` for the
  recommended pattern.

### Added

- `mcpx::McpxError` and `mcpx::Result` re-exports at the crate root
  for ergonomic downstream usage.

## [0.11.0] - 2026-04-18

Operational hardening release. Closes the nine high-priority items from
the 1.0 release-readiness audit (BUG-NEW, H-S1-S4, H-T1-T4) and pushes
mcpx significantly closer to a 1.0-rc candidate. The next release
(0.12.0) will focus on the remaining public-API surface concerns
(error types, async hooks, `pub(crate)` demotion sweep).

This release contains **breaking changes** to several internal-leaning
public types (`RateLimitConfig` field additions, `KeyedLimiter` typedef
swap, `init_tracing` signature). Most consumers will not need to update
call sites; affected callers will see compile errors with clear
diagnostics. See "Changed" / "Removed" below for migration notes.

### Security

- **[H-S1] Pre-auth abuse gate.** Added a split-bucket per-source-IP
  rate limiter consulted *before* Argon2id verification so a bearer-key
  flood cannot CPU-spray the server. The pre-auth gate is configured
  via the new `RateLimitConfig::pre_auth_max_per_minute` field and
  defaults to `10  max_attempts_per_minute` when omitted. mTLS callers
  bypass the gate entirely (the TLS handshake already cost CPU).
- **[H-S2] Token secrecy end-to-end.** Raw bearer tokens are now wrapped
  in `secrecy::SecretString` from extraction through OAuth introspection
  and revocation, eliminating the in-process plaintext window where a
  panic backtrace or core dump could capture a live credential.
- **[H-S3] RBAC denial log redaction + identity propagation fix.**
  Per-argument allow-list rejections previously logged the raw rejected
  value. They now log `arg_hmac=<8-hex-chars>` (HMAC-SHA256 prefix)
  using either a per-process random salt or a stable operator-supplied
  salt (new `RbacConfig::redaction_salt: Option<SecretString>`). Also
  fixes a latent bug where `enforce_tool_policy()` reached for
  `current_identity()` *before* the task-locals were installed, dropping
  the identity from deny logs; the identity is now passed in
  explicitly.
- **[H-S4] mTLS revocation guidance.** `SECURITY.md` now loudly
  documents that mcpx does NOT validate CRL or OCSP for client
  certificates and points operators at supported workflows
  (cert-manager, Vault PKI, Smallstep step-ca with <=24h cert
  lifetimes, plus CA-rotation and network-layer enforcement).
  `docs/GUIDE.md` carries a parallel operator runbook section. New CI
  grep assertions ensure the guidance cannot silently disappear.
- **[H-T3] Memory-bounded rate limiters.** Both the per-IP auth limiter
  and the per-tool RBAC limiter now use a new
  `mcpx::bounded_limiter::BoundedKeyedLimiter<K>` with explicit LRU
  eviction (default cap: 10_000 keys, default idle eviction: 1h). A
  high-cardinality attacker can no longer exhaust server memory by
  cycling through a million spoofed source IPs. New
  `tests/limiter_memory.rs` (gated `#[ignore]`, run by the new
  `memory-bounds` CI job) feeds 1M IPs through a 10K-cap limiter and
  asserts RSS stays under 50 MiB.

### Added

- `mcpx::bounded_limiter` module exposing
  `BoundedKeyedLimiter<K>`, `BoundedLimiterError` (with
  `#[non_exhaustive]` `RateLimited` variant), and
  `BoundedLimiterConfig`.
- `RateLimitConfig::pre_auth_max_per_minute: Option<u32>` (H-S1).
- `RateLimitConfig::max_tracked_keys: Option<NonZeroUsize>` and
  `RateLimitConfig::idle_eviction: Option<Duration>` plus matching
  builder methods (H-T3).
- `RbacConfig::redaction_salt: Option<SecretString>` and
  `RbacPolicy::redact_arg(value: &str) -> String` (H-S3).
- `mcpx::auth::build_rate_limiter_with_bounds` and
  `mcpx::rbac::build_tool_rate_limiter_with_bounds` constructors that
  accept explicit eviction parameters (H-T3).
- Deterministic E2E harness: `mcpx::transport::ServerHarness` with
  `bind`/`router_for_tests`/readiness oneshot enabling tests to bind on
  port 0 and observe ready-state without polling (H-T1).
- `criterion = "0.5"` (dev-dependency, `cargo_bench_support` only) and
  `benches/rbac_redaction.rs` measuring `RbacPolicy::redact_arg`
  (~2.3 µs/iter locally, gated at 10 µs by the new
  `bench-thresholds` CI job).
- New CI jobs: `features-matrix` (5-variant build+test sweep),
  `semver-checks` (PRs only), `publish-dryrun` (main pushes),
  `bench-thresholds` (allowed-to-fail until first green), and
  `memory-bounds`. Existing `test` job now also runs `cargo test --doc`.
- Cross-platform `scripts/check-bench-threshold.{sh,ps1}` Criterion
  threshold checker.

### Changed

- **BREAKING**: `mcpx::observability::init_tracing` and
  `init_tracing_from_config` now return
  `Result<(), tracing_subscriber::util::TryInitError>` instead of
  panicking on the second call. The function remains callable from
  `main` with `let _ = init_tracing("info")` for back-compat (H-T2).
- **BREAKING**: `RateLimitConfig` now has additional fields. Construct
  with `RateLimitConfig::default()` + builder methods rather than
  struct-literal syntax. (H-S1, H-T3)
- **BREAKING**: The internal `KeyedLimiter` typedef was changed from a
  governor `RateLimiter` to `Arc<BoundedKeyedLimiter<IpAddr>>` /
  `Arc<BoundedKeyedLimiter<(IpAddr, String)>>`. Callers using
  `build_rate_limiter` / `build_tool_rate_limiter` continue to work;
  callers that previously named the governor type directly must
  migrate. (H-T3)
- **BREAKING**: `enforce_tool_policy` and the RBAC denial path now
  receive `&AuthIdentity` explicitly rather than reading from
  task-local state. External callers were unlikely (the function was
  effectively framework-internal), but the signature changed. (H-S3)
- Bearer token extraction and OAuth flows now propagate
  `secrecy::SecretString` end-to-end. Callers reading
  `current_token()` get a `Secret<String>` and must call `.expose_secret()`
  to obtain the raw value. (H-S2)
- `SECURITY.md` supported-versions table updated to
  `0.10.x` + `0.11.x`; coordinated-disclosure example tag format
  changed from `vX.Y.Z` to `X.Y.Z` to match the project's no-`v`-prefix
  tagging convention.

### Fixed

- **[BUG-NEW] Shutdown timeout double-signal.** `serve()` previously
  signalled the shutdown completion channel twice when the configured
  `shutdown_timeout` elapsed, causing a spurious panic in some hot-reload
  test scenarios. Now signals exactly once.

### Housekeeping

- 168 unit + integration tests pass; 2 ignored memory tests pass on
  release-mode opt-in. `cargo +nightly fmt --all -- --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo audit`, `cargo deny check`, and `cargo +nightly doc --no-deps
  --all-features` all clean.

## [0.10.0] - 2026-04-18

First release after the v0.9.30 public snapshot. Focused on closing the
four critical pre-1.0 release blockers (C1-C4) identified during the
release-readiness audit, plus ergonomic builders for the OAuth config
types.

### Security

- **C1 - Middleware ordering (breaking behaviour fix):** the origin
  allow-list check now runs on the outer router, before any other
  middleware, so unauthenticated requests with a bad `Origin` are
  rejected with `403` before hitting the auth or rate-limit layers. The
  MCP router's inner stack is now ordered
  `body-limit -> timeout -> auth -> rbac -> handler`, ensuring
  oversized bodies are rejected with `413` before authentication.
- **C2 - mTLS identity isolation (breaking API):** the shared
  `Arc<DashMap<SocketAddr, AuthIdentity>>` ("`MtlsIdentities`") used to
  ferry peer identities from the TLS acceptor to the auth middleware
  has been removed. Identities are now carried per-connection on a new
  `AuthenticatedTlsStream` wrapper and surfaced via `TlsConnInfo`,
  eliminating a potential cross-connection confusion window on address
  reuse.
- **C3 - OAuth admin endpoints gated by default (breaking behaviour
  fix):** `/introspect` and `/revoke` are no longer mounted and are no
  longer advertised in the authorization-server metadata document
  unless you explicitly opt in by setting
  `OAuthProxyConfig::expose_admin_endpoints = true`. Existing
  deployments that rely on these endpoints must set the new flag.
- **C4 - Release workflow glob:** the GitHub Actions release workflow
  tag filter was corrected so tagged releases actually trigger
  publishing.

### Added

- `OAuthConfig::builder(issuer, audience, jwks_uri)` and a fluent
  `OAuthConfigBuilder` (`scopes`, `scope`, `role_claim`,
  `role_mappings`, `role_mapping`, `jwks_cache_ttl`, `proxy`,
  `token_exchange`, `ca_cert_path`, `build`).
- `OAuthProxyConfig::builder(authorize_url, token_url, client_id)` and a
  fluent `OAuthProxyConfigBuilder` (`client_secret`,
  `introspection_url`, `revocation_url`, `expose_admin_endpoints`,
  `build`). Both builder types are `#[must_use]`.
- `OAuthProxyConfig::expose_admin_endpoints: bool` (serde-defaulted to
  `false`) - opt-in flag gating the admin endpoints described above.
- Regression test coverage in `tests/e2e.rs`:
  - `c1_origin_rejected_before_auth` - bad `Origin` -> 403, not 401.
  - `c1_body_limit_applies_before_rbac` - oversized body -> 413.
  - `c3_admin_endpoints_hidden_by_default` - metadata omits endpoints
    and `/introspect` / `/revoke` return 404.
  - `c3_admin_endpoints_exposed_when_enabled` - metadata advertises
    endpoints and they are mounted when opted in.
- New public type `mcpx::transport::AuthenticatedTlsStream` with
  `identity(&self) -> Option<&AuthIdentity>`.

### Changed

- `TlsConnInfo` changed from a tuple struct wrapping `SocketAddr` to a
  named-field struct `{ addr: SocketAddr, identity: Option<AuthIdentity> }`
  with a `pub const fn new(addr, identity)` constructor. Call sites
  using `.0` to access the address now use `.addr`.

### Removed

- `pub type MtlsIdentities` (the shared `Arc<DashMap<...>>` alias) -
  superseded by per-connection identity on `AuthenticatedTlsStream`.
- `AuthState.mtls_identities` field - no longer needed.

### Housekeeping

- Removed stale `RUSTSEC-2026-0097` entry from `deny.toml` (no longer
  matched by any crate in the dependency graph; `cargo-deny` was
  emitting an `advisory-not-detected` warning).
- Qualified `std::pin::Pin` usage consistently in `transport.rs`;
  dropped unused `HashMap` / `RwLock` imports left over from the
  pre-C2 identity cache.
- Full test suite (lib + e2e + doctests) passes cleanly under
  `cargo test --all-features`; `cargo +nightly fmt --all -- --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo audit`, and `cargo deny check` are all clean.

## [0.9.30] - 2026-04-17

### Added
- Initial public release as a standalone crate, extracted from the
  `atlassian-mcp-rs` monorepo.
- Streamable HTTP transport with TLS/mTLS, `/mcp`, `/healthz`, `/readyz`,
  and admin diagnostic endpoints.
- API-key, mTLS, and OAuth 2.1 JWT (feature `oauth`) authentication
  middleware.
- Role-based access control engine with per-tool allow-lists and
  per-role argument constraints.
- Per-IP rate limiting, request-body caps, OWASP security headers,
  configurable CORS and Host allow-lists.
- Optional Prometheus metrics (feature `metrics`).
- Opt-in tool-call hooks with a configurable result-size cap.
- OAuth 2.1 JWKS cache, token validation, and RFC 8693 token-exchange
  helpers (feature `oauth`).
