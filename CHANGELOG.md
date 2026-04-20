# Changelog

All notable changes to `rmcp-server-kit` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Starting with `1.0.0`, breaking changes bump the **major** version. Pre-1.0
releases (`0.x.y`) used the convention that breaking changes bumped the
**minor** version.

## [Unreleased]

## [2.0.0] - 2026-04-20

This major release contains a single breaking change: the return type of
`oauth::JwksCache::new` is narrowed from
`Result<Self, Box<dyn std::error::Error + Send + Sync>>` to
`Result<Self, McpxError>`. See [`docs/MIGRATION.md`](docs/MIGRATION.md#migrating-from-1x-to-20)
for the upgrade procedure. Most consumers — everyone who only uses
`serve()` / `serve_with_listener()` and lets the framework build the
JWKS cache internally — need **no source changes** and can upgrade by
bumping `Cargo.toml` to caret-`2`. Runtime behaviour is unchanged on
every code path.

### Breaking

- **`src/oauth.rs::JwksCache::new`:** Return type narrowed from
  `Result<Self, Box<dyn std::error::Error + Send + Sync>>` to
  `Result<Self, McpxError>`. The boxed `dyn Error` exposed three
  underlying failure modes (CA-bundle I/O, malformed PEM, HTTP-client
  build) that are now mapped to concrete `McpxError` variants:
  - CA bundle file unreadable (`std::io::Error`) → `McpxError::Io`
    (via existing `#[from]` impl).
  - CA bundle is not valid PEM (`reqwest::Error`) → `McpxError::Config`
    with the message `"OAuth CA bundle is not valid PEM: …"`.
  - HTTP client build failure (`reqwest::Error`) → `McpxError::Config`
    with the message `"OAuth HTTP client build failed: …"`.

  The `rustls`/`jsonwebtoken` `default_provider().install_default()`
  calls continue to ignore their `Result` (idempotent in-process
  initialization). Behaviour is unchanged on success and on every
  failure mode the constructor previously raised — only the *type* of
  the returned error narrowed.

  Internal call site `src/transport.rs` (auth-state construction in
  `serve()`) was simplified to propagate `McpxError` directly via `?`,
  removing the previous `std::io::Error::other(format!(...))` wrap.

  No new `McpxError` variants were introduced; the enum's
  `#[non_exhaustive]` marker is preserved.

## [1.1.0] - 2026-04-20

This minor release rolls up the Phase 1 documentation/CI hardening (originally
held in `[Unreleased]`) plus the Phase 2 additive correctness, performance,
security, and supply-chain improvements from the code-review remediation plan.
No breaking changes (`cargo semver-checks check-release` passes).

### Security

- **`src/oauth.rs::exchange_token`:** Sanitize all client-visible failure
  branches of the OAuth `/token` exchange endpoint. Upstream IdP error bodies,
  network failures, body-read failures, and JSON-parse failures previously
  could leak through `McpxError::Auth`/`McpxError::Json` into the HTTP
  response. Responses now carry only an RFC 6749 §5.2 / RFC 8693
  allowlisted `error` code (`invalid_request`, `invalid_client`,
  `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`,
  `invalid_scope`, `temporarily_unavailable`, `invalid_target`,
  `server_error`); the rich detail goes to `tracing::warn!`/`tracing::error!`
  for operator visibility. The `/token` proxy facade (Site A) and the admin
  proxy (Site B) are unchanged — they were already correct.

### Added

- **`src/auth.rs::verify_bearer_token`:** Promoted to `pub` and marked
  `#[must_use]`. This is purely additive (the function previously existed as
  `pub(crate)`) and makes constant-time API-key verification available to
  consumers writing custom middleware.
- **`tests/properties.rs`:** New property-test harness using `proptest`
  (`[dev-dependencies]`), covering three invariants:
  1. `generate_api_key` → `verify_bearer_token` round-trip succeeds in the
     presence of 0..4 decoy keys (64 cases; gated by Argon2id cost).
  2. `RbacPolicy::argument_allowed` agrees with set-membership for the
     literal-allowlist case (1024 cases).
  3. `RbacPolicy::argument_allowed` never panics on adversarial glob
     patterns (1024 cases).
- **CI:** Three advisory supply-chain jobs added to
  `.github/workflows/ci.yml` (`cargo-vet`, `cargo-machete`,
  `cargo-mutants`). The mutants job runs on `schedule` (nightly) and
  `workflow_dispatch` only and is scoped to the `rbac`, `auth`, and `oauth`
  modules. All three are advisory (`continue-on-error: true`).

### Changed

- **`src/oauth.rs::decode_claims`:** JWT decode is now wrapped in
  `tokio::task::spawn_blocking` to avoid stalling the async runtime under
  concurrent validation load. `JoinError` (panic / cancellation) maps to
  `JwtValidationFailure::Invalid` with a `tracing::error!` event.
- **`src/transport.rs` `/version` route:** The JSON body is now
  pre-serialized once at router build time into an `Arc<[u8]>`; per-request
  the handler `Arc::clone`s and returns the raw bytes with
  `Content-Type: application/json`. Eliminates per-request `serde_json`
  allocations on a hot health-check path.
- **`src/tool_hooks.rs::HookedHandler::spawn_after`:** The user-supplied
  after-hook future now (a) inherits the parent request's
  `tracing::Span::current()` via `Instrument`, and (b) re-establishes the
  RBAC task-local context (`role`, `identity`, `token`, `sub`) inside the
  spawned task so `current_role()` / `current_identity()` /
  `current_token()` / `current_sub()` continue to work from inside the
  after-hook body.
- **CI:** `cargo-audit` job now installs `cargo-audit` and runs
  `cargo generate-lockfile` before auditing, so the workflow no longer
  requires a committed `Cargo.lock` (libraries `.gitignore` it per the
  Cargo FAQ). Functionally equivalent to the previous
  `rustsec/audit-check` action.
- **CI:** `Benchmark thresholds` job now passes the required
  `<bench_hooked> <bench_bare> <max_overhead_ns>` arguments to
  `scripts/check-bench-overhead.sh`. The job was previously a no-op
  (script exited 2 with usage error), masked by `continue-on-error`.
- **Tests:** `shutdown_timeout_honored_on_first_signal` no longer races
  on a fixed `100ms` sleep; the `/slow` handler now signals via a
  `tokio::sync::oneshot` when it begins serving and the test waits up
  to 5s on that signal before triggering shutdown. Eliminates flakiness
  on slow CI runners.
- **Docs:** `src/observability.rs::open_audit_file` documents the
  external log-rotation expectation (logrotate / newsyslog with
  copytruncate) and the absence of any built-in SIGHUP-style reopen.
- **Docs:** `src/oauth.rs::JwksCache::new` annotates the synchronous
  `std::fs::read` of the CA bundle as intentional pre-startup blocking
  I/O.
- **Docs:** `deny.toml` documents the cargo-deny v2 policy posture and
  why the deprecated v1 keys (`vulnerability`, `unmaintained`,
  `notice`) are intentionally absent.

### Fixed

- Non-`oauth`-feature builds no longer warn about the unused
  `AuthFailureClass::ExpiredCredential` variant or the
  `unauthorized_response` parameter `fail`.
- `examples/oauth_server.rs` is now gated on the `oauth` cargo feature
  (was unconditionally compiled and broke `cargo test` without
  features).
- Fixed two broken markdown links in `docs/RUST_1_95_NOTES.md`
  (`../atlassian-mcp/...` → `../src/`, `../CLAUDE.md` →
  `../AGENTS.md`).

## [1.0.0] - 2026-04-19

- **Renamed crate from `mcpx` to `rmcp-server-kit`** (the `mcpx` name on crates.io was already taken by an unrelated project). Library import path is now `use rmcp_server_kit::...`. The `mcpx` GitHub repository name is unchanged.

First stable release. **No API changes versus `1.0.0-rc1`** — this
release promotes the RC to stable after the soak window.

From here, `rmcp-server-kit` follows standard Semantic Versioning:

- **MAJOR** (`2.0.0`) for breaking API changes.
- **MINOR** (`1.1.0`) for backwards-compatible feature additions.
- **PATCH** (`1.0.1`) for backwards-compatible bug fixes.

The pre-1.0 convention "breaking changes bump the **minor** version" no
longer applies.

### Soak items still tracked for future minor releases

- `OauthHttpClient::builder()` for advanced reqwest configuration.
- mTLS client cert in token exchange.
- `HttpClient` trait for swappable HTTP backends.
- Demoting `McpServerConfig` direct fields from `#[deprecated] pub` to
  `pub(crate)` (would be a `2.0.0` change).

## [1.0.0-rc1] - 2026-04-19

First release candidate for the `1.0.0` line. No functional changes
relative to `0.13.0`; this RC promotes the `0.13.0` API surface for
public stabilization review. The 1.0 series will be released after a
soak period and final review of:

- `OauthHttpClient` builder ergonomics (currently `::new()` only).
- Whether `McpServerConfig` direct field access should be demoted to
  `pub(crate)` (today: `#[deprecated]` with builder-only accessors).
- Generic `Validated<T>` as a public utility (today: only used for
  `McpServerConfig`).

If no issues surface during the RC window, `1.0.0` will follow with no
API changes versus this RC.

## [0.13.0] - 2026-04-19

### Changed

- **[H-B4] `serve()` and `serve_with_listener()` require `Validated<McpServerConfig>`** *(breaking)*.
  `McpServerConfig::validate()` now consumes `self` and returns
  `Result<Validated<McpServerConfig>, McpxError>`. The new
  `Validated<T>` wrapper is a typestate proof token: the only way to
  obtain `Validated<McpServerConfig>` is by calling `validate()`. This
  makes invalid server starts a *compile-time* error rather than a
  runtime one. `Validated<T>` derefs to `&T` for read-only access; use
  `.into_inner()` to recover the raw value (and re-validate before
  re-using). **Migration**:

  ```rust
  // Before (0.12.0)
  let config = McpServerConfig::new(...);
  serve(config, || MyHandler).await?;

  // After (0.13.0)
  let config = McpServerConfig::new(...);
  serve(config.validate()?, || MyHandler).await?;
  ```

- **[H-B1] OAuth handler signatures take `OauthHttpClient` instead of
  `reqwest::Client`** *(breaking)*. The public functions
  `oauth::handle_token`, `oauth::handle_introspect`,
  `oauth::handle_revoke`, and `oauth::exchange_token` now accept
  `&oauth::OauthHttpClient` (a thin wrapper around the underlying HTTP
  backend) instead of leaking `reqwest::Client` through the public API.
  This decouples downstream crates from the `reqwest` version rmcp-server-kit
  pins. Construct via `OauthHttpClient::new()` (10s connect / 30s
  total timeout). The wrapper is `Clone` (cheap, refcounted) and
  `Debug` (opaque). Internally, `install_oauth_proxy_routes` now
  builds one shared client and clones it across `/token`,
  `/introspect`, and `/revoke` instead of constructing three
  independent pools. **Migration**: replace
  `reqwest::Client::new()` with `rmcp_server_kit::oauth::OauthHttpClient::new()?`
  at OAuth proxy / token-exchange call sites.

### Deprecated

- **[H-B3] Direct field access on `McpServerConfig` is deprecated.** All
  `pub` fields now carry `#[deprecated(since = "0.13.0", note = "use
  McpServerConfig::with_*(); direct field access will become pub(crate)
  in 1.0")]`. Migrate `cfg.field = value;` writes to the matching
  `.with_field(value)` builder. The fields remain `pub` for the entire
  0.x line; they are slated to become `pub(crate)` at 1.0. A new
  `with_bind_addr` builder was added for parity. Existing builders
  (`with_auth`, `with_rbac`, `with_allowed_origins`,
  `with_readiness_check`, `with_max_request_body`,
  `with_shutdown_timeout`, `with_extra_router`, `with_public_url`,
  `with_tls`, etc.) are unchanged and remain the migration target.

### Removed

- **[H-B2] `ToolHookError` removed.** The legacy synchronous deny enum
  (deprecated since 0.12.0) is gone. Replace
  `ToolHookError::Deny(msg)` with
  `HookOutcome::Deny(rmcp::ErrorData::invalid_request(msg, None))`.

## [0.12.0] - 2026-04-19

### Changed

- **[H-A4] Tool hooks are now `async`.** `BeforeHook` and `AfterHook`
  are redefined as async function pointers returning
  `Pin<Box<dyn Future + Send>>` so hook bodies can `.await` (e.g.
  audit-log writes, RBAC lookups against an async store, metric
  emission via async clients). Hook return types changed:
  - `BeforeHook` returns `HookOutcome` (new enum with three variants:
    `Continue`, `Deny(rmcp::ErrorData)`, `Replace(Box<CallToolResult>)`)
    instead of the old `Result<(), ToolHookError>`. `Deny` and
    `Replace` short-circuit the inner handler. `Replace` is subject
    to the same `max_result_bytes` cap as inner results.
  - `AfterHook` receives a new `HookDisposition` enum
    (`InnerExecuted`, `InnerErrored`, `DeniedBefore`,
    `ReplacedBefore`, `ResultTooLarge`) so hooks can branch on
    actual outcome. After-hooks are dispatched via `tokio::spawn`
    so they never block the response path; panics inside an
    after-hook are caught by Tokio and isolated from the caller.
  - `ToolHookError` is `#[deprecated(since = "0.12.0")]` and will be
    removed in 0.13. Replace `ToolHookError::Deny(msg)` with
    `HookOutcome::Deny(rmcp::ErrorData::invalid_request(msg, None))`.
- **[H-A4] `ToolHooks` and `ToolCallContext` are `#[non_exhaustive]`.**
  Construct `ToolHooks` via `ToolHooks::new()` followed by chainable
  `with_max_result_bytes(n)`, `with_before(hook)`, `with_after(hook)`
  builder methods. Construct `ToolCallContext` via
  `ToolCallContext::for_tool(name)` (then mutate the public fields
  for additional context). Direct struct-literal construction is no
  longer supported from outside the crate, which lets us add fields
  in 0.x without further breaks.

### Added

- **[H-A4] Hook overhead microbenchmark + CI gate.** New
  `benches/hook_latency.rs` (criterion) measures bare vs. hooked
  closure-invocation latency. New `scripts/check-bench-overhead.{sh,ps1}`
  asserts `mean(hooked) - mean(bare) <= 2000 ns`. Observed overhead
  on the reference machine: ~700 ns (one async await + one
  `tokio::spawn` + Arc bookkeeping). The bench file documents why an
  absolute-overhead gate is more meaningful than the original 1.05x
  ratio gate at this measurement layer.

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
  explicitly must switch to `rmcp_server_kit::Result<()>` (newly re-exported at
  the crate root). See `examples/minimal_server.rs` for the
  recommended pattern.

- `rmcp_server_kit::McpxError` and `rmcp_server_kit::Result` re-exports at the crate root
  for ergonomic downstream usage.
- **[H-A2] Fluent builder + `validate()` on `McpServerConfig`.** The
  configuration struct now exposes ~18 chainable, `#[must_use]`
  builder methods (`with_auth`, `with_rbac`, `with_tls`,
  `with_public_url`, `with_allowed_origins`, `with_extra_router`,
  `with_readiness_check`, `with_max_request_body`,
  `with_request_timeout`, `with_shutdown_timeout`,
  `with_session_idle_timeout`, `with_sse_keep_alive`,
  `with_max_concurrent_requests`, `with_tool_rate_limit`,
  `with_reload_callback`, `enable_compression`, `enable_admin`,
  `enable_request_header_logging`, plus `with_metrics` under
  `feature = "metrics"`). A new `validate(&self) -> Result<(), McpxError>`
  method centralizes six pre-flight checks (admin↔auth dependency,
  TLS cert/key pairing, parseable `bind_addr`, well-formed
  `public_url` and `allowed_origins`, non-zero `max_request_body`)
  and is invoked automatically by `serve()` and
  `serve_with_listener()`. Existing direct-field-assignment call
  sites continue to compile unchanged (additive, non-breaking).
  See `examples/minimal_server.rs` for the recommended pattern.
- **[H-A3] Ergonomic `BoundedKeyedLimiter` constructors.** New
  `BoundedKeyedLimiter::with_per_minute(rpm, max_keys, idle)` and
  `with_per_second(rps, max_keys, idle)` build the per-key
  [`governor::Quota`] internally and clamp the rate to `>= 1` so a
  misconfigured `0` does not panic. The previous
  `BoundedKeyedLimiter::new(quota, ...)` is now `pub(crate)`; external
  callers must migrate to one of the new constructors.

### Removed

- **[H-A3] Internal-only types demoted from public API.** The
  following items leaked into the public surface of 0.11 but were
  never intended for downstream consumption. They are now
  `pub(crate)`:
  - `auth::AuthCounters`, `auth::KeyedLimiter`, `auth::TlsConnInfo`,
    `auth::AuthState`, `auth::build_rate_limiter`,
    `auth::build_pre_auth_limiter`, `auth::auth_middleware`
  - `rbac::ToolRateLimiter`, `rbac::build_tool_rate_limiter`,
    `rbac::build_tool_rate_limiter_with_bounds`,
    `rbac::rbac_middleware`
  - `transport::AuthenticatedTlsStream`
  - `admin::AdminState`, `admin::admin_router` (constructed only by
    `serve()` internally; never had a public constructor)
  - `bounded_limiter::BoundedKeyedLimiter::new` (use
    `with_per_minute` / `with_per_second` instead)

  This shrinks the public API contract toward 1.0. Public types that
  remain stable: `AuthIdentity`, `AuthMethod`, `AuthCountersSnapshot`,
  `ApiKeyEntry`, `ApiKeySummary`, `RbacPolicy`, `RbacRole`,
  `BoundedKeyedLimiter` (the type itself, just not its low-level
  constructor).

## [0.11.0] - 2026-04-18

Operational hardening release. Closes the nine high-priority items from
the 1.0 release-readiness audit (BUG-NEW, H-S1-S4, H-T1-T4) and pushes
rmcp-server-kit significantly closer to a 1.0-rc candidate. The next release
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
  documents that rmcp-server-kit does NOT validate CRL or OCSP for client
  certificates and points operators at supported workflows
  (cert-manager, Vault PKI, Smallstep step-ca with <=24h cert
  lifetimes, plus CA-rotation and network-layer enforcement).
  `docs/GUIDE.md` carries a parallel operator runbook section. New CI
  grep assertions ensure the guidance cannot silently disappear.
- **[H-T3] Memory-bounded rate limiters.** Both the per-IP auth limiter
  and the per-tool RBAC limiter now use a new
  `rmcp_server_kit::bounded_limiter::BoundedKeyedLimiter<K>` with explicit LRU
  eviction (default cap: 10_000 keys, default idle eviction: 1h). A
  high-cardinality attacker can no longer exhaust server memory by
  cycling through a million spoofed source IPs. New
  `tests/limiter_memory.rs` (gated `#[ignore]`, run by the new
  `memory-bounds` CI job) feeds 1M IPs through a 10K-cap limiter and
  asserts RSS stays under 50 MiB.

### Added

- `rmcp_server_kit::bounded_limiter` module exposing
  `BoundedKeyedLimiter<K>`, `BoundedLimiterError` (with
  `#[non_exhaustive]` `RateLimited` variant), and
  `BoundedLimiterConfig`.
- `RateLimitConfig::pre_auth_max_per_minute: Option<u32>` (H-S1).
- `RateLimitConfig::max_tracked_keys: Option<NonZeroUsize>` and
  `RateLimitConfig::idle_eviction: Option<Duration>` plus matching
  builder methods (H-T3).
- `RbacConfig::redaction_salt: Option<SecretString>` and
  `RbacPolicy::redact_arg(value: &str) -> String` (H-S3).
- `rmcp_server_kit::auth::build_rate_limiter_with_bounds` and
  `rmcp_server_kit::rbac::build_tool_rate_limiter_with_bounds` constructors that
  accept explicit eviction parameters (H-T3).
- Deterministic E2E harness: `rmcp_server_kit::transport::ServerHarness` with
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

- **BREAKING**: `rmcp_server_kit::observability::init_tracing` and
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
- New public type `rmcp_server_kit::transport::AuthenticatedTlsStream` with
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
