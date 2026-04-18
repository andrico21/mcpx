# Changelog

All notable changes to `mcpx` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0: breaking changes bump the **minor** version.

## [Unreleased]

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
