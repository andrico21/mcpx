# rmcp-server-kit Architecture

> **Audience**: AI agents and engineers who need to **modify** rmcp-server-kit safely.
> **Companion**: [`MINDMAP.md`](MINDMAP.md) for the visual view, [`../AGENTS.md`](../AGENTS.md) for the navigation hub, [`GUIDE.md`](GUIDE.md) for end-user usage.
>
> All file references use `file:line` against the working tree as of v0.12.0.
> Line numbers are approximate (±20) — they help localize, not replace `Read`.
> Citations are pinned by `tests/docs_citations.rs` so they fail loudly when
> a cited file disappears or shrinks below a referenced line.

---

## Table of contents

1. [Bird's-eye view](#1-birds-eye-view)
2. [Module map](#2-module-map)
3. [Request lifecycle (HTTP)](#3-request-lifecycle-http)
4. [Core types](#4-core-types)
5. [Authentication subsystem](#5-authentication-subsystem)
6. [RBAC subsystem](#6-rbac-subsystem)
7. [TLS / mTLS](#7-tls--mtls)
8. [OAuth 2.1 / JWKS (feature `oauth`)](#8-oauth-21--jwks-feature-oauth)
9. [Tool hooks (extension point)](#9-tool-hooks-extension-point)
10. [Admin diagnostics](#10-admin-diagnostics)
11. [Observability](#11-observability)
12. [Metrics (feature `metrics`)](#12-metrics-feature-metrics)
13. [Hot reload](#13-hot-reload)
14. [Error handling](#14-error-handling)
15. [Configuration](#15-configuration)
16. [Testing strategy](#16-testing-strategy)
17. [Critical invariants](#17-critical-invariants)

---

## 1. Bird's-eye view

`rmcp-server-kit` is a **library crate** providing a "batteries included" framework
around the MCP Streamable HTTP transport from the official Rust SDK
([`rmcp`](https://docs.rs/rmcp)). The consumer's job is to implement
`rmcp::handler::server::ServerHandler` and call `rmcp_server_kit::transport::serve()`.
Everything below the `serve()` call — listeners, TLS, middleware, auth,
RBAC, hooks, observability, metrics, admin endpoints — is rmcp-server-kit's
responsibility.

The crate has two transports:

| Transport          | Function                                            | Auth/RBAC/TLS  | Use case                                         |
|--------------------|-----------------------------------------------------|----------------|--------------------------------------------------|
| **Streamable HTTP**| `serve()` — `src/transport.rs:1004`                 | **Yes**        | Production network deployment                    |
| stdio              | `serve_stdio()` — `src/transport.rs:1863`           | **No**         | Local subprocess MCP (desktop apps, IDEs)        |

---

## 2. Module map

```
src/
├── lib.rs               crate root, re-exports public modules            (lib.rs:23-52)
├── transport.rs         ★ orchestrator: serve(), TLS listener, router    (~1300 LOC)
├── auth.rs              authn primitives: ApiKeyEntry, AuthState, mw     (~600+ LOC)
├── rbac.rs              authz: RbacPolicy, task-locals, mw, rate-limit   (~620+ LOC)
├── oauth.rs             OAuth 2.1 + JWKS cache (feature = "oauth")       (~640+ LOC)
├── admin.rs             /admin/* router + admin role middleware
├── tool_hooks.rs        opt-in HookedHandler wrapping ServerHandler
├── observability.rs     tracing init, JSON logging, audit-file sink
├── metrics.rs           prometheus registry + /metrics (feature = "metrics")
├── config.rs            TOML config structs and validation
├── error.rs             McpxError + axum IntoResponse
└── secret.rs            re-exports of `secrecy::Secret`
```

Dependency direction (top → bottom):

```
application (consumer crate)
    │
    ▼
transport ──┬─ auth ──┬─ oauth (feature)
            ├─ rbac   │
            ├─ admin ─┘
            ├─ tool_hooks
            ├─ observability
            ├─ metrics (feature)
            ├─ config
            ├─ error
            └─ secret
                │
                ▼
        rmcp + axum + tokio + rustls
```

`transport.rs` is the only module that imports nearly everything else.
There are **no circular dependencies**.

---

## 3. Request lifecycle (HTTP)

A complete HTTP request to `/mcp` flows through these layers, top-to-bottom
(outermost → innermost). The corresponding code lives in
`src/transport.rs:634-740` (middleware wiring inside `build_app_router`) and in each module.

```
TCP / TLS handshake                         src/transport.rs:1373-1545  (TlsListener)
   │  - mTLS: client cert verified, AuthIdentity stored in
   │    MtlsIdentities map keyed by peer SocketAddr
   ▼
axum Router                                  src/transport.rs:542-1000  (build_app_router)
   │
   ├── 1. Origin check                       src/transport.rs:1773
   │      Rejects 403 if Origin/Host not allowed (MCP spec requirement)
   │
   ├── 2. Security headers                   src/transport.rs:1704
   │      HSTS, CSP, X-Frame-Options=DENY, X-Content-Type-Options, ...
   │
   ├── 3. CORS / Compression / Timeouts      tower-http layers
   │      Body size cap (default 1 MiB)
   │
   ├── 4. Optional concurrency cap           src/transport.rs:897-913
   │      tower::limit::ConcurrencyLimitLayer + load_shed
   │
   ├── 5. Optional metrics middleware        src/metrics.rs (records
   │      request count, duration histograms, in-flight gauge)
   │
   ├── 6. Auth middleware                    src/auth.rs:846 (auth_middleware)
   │      Determines AuthIdentity from one of:
   │        a) Authorization: Bearer <api-key>  → Argon2 verify against
   │           AuthState.api_keys (ArcSwap<Vec>)
   │        b) mTLS — look up AuthIdentity in MtlsIdentities by peer addr
   │        c) Authorization: Bearer <jwt>      → JwksCache::validate
   │           (feature = "oauth")
   │      On success: sets task-locals via `current_role`, `current_identity`, …
   │
   ├── 7. RBAC middleware                    src/rbac.rs:584-700  (rbac_middleware) + 701-762 (enforce_tool_policy)
   │      For POSTs to /mcp:
   │        - Reads body up to limit
   │        - Parses JSON-RPC envelope
   │        - If method == "tools/call":
   │             RbacPolicy::check(role, tool_name)
   │             ArgumentAllowlist::argument_allowed(role, tool, args)
   │      Returns 403 on deny, 429 on rate-limit
   │
   ├── 8. Per-IP tool rate limiter           src/rbac.rs:53-78
   │      governor::RateLimiter keyed by ClientIp
   │
   ▼
rmcp StreamableHttpService                   src/transport.rs:555-580
   └── Your ServerHandler::call_tool(...)
        (optionally wrapped by HookedHandler — src/tool_hooks.rs:356-540)
       │
       │  Inside the handler you can call:
       │    rbac::current_role()      -> Option<String>
       │    rbac::current_identity()  -> Option<AuthIdentity>
       │    rbac::current_token()     -> Option<Secret<String>>
       │    rbac::current_sub()       -> Option<String>
       │  These read tokio task-locals set by the auth middleware.
       ▼
   Result serialized → response
       └── Security headers re-applied; metrics recorded; rate-limit counters update
```

Open endpoints (no auth):

| Path                                       | Handler                                       |
|--------------------------------------------|-----------------------------------------------|
| `GET  /healthz`                            | `transport::healthz` (~`src/transport.rs:1601`) |
| `GET  /readyz`                             | `transport::readyz`  (~`src/transport.rs:1623`) — runs configured readiness check |
| `GET  /version`                            | `transport::version_payload` (~`src/transport.rs:1612`) |
| `GET  /metrics`                            | served on a **separate listener** when `feature = "metrics"` (`src/metrics.rs:95`) |
| `GET  /.well-known/oauth-protected-resource` | feature = `oauth` (`src/transport.rs:826-832`) |
| `GET  /.well-known/oauth-authorization-server` | feature = `oauth` proxy (`src/transport.rs:1225-1230`) |

Authenticated endpoints:

| Path                | Auth | Notes                                          |
|---------------------|------|------------------------------------------------|
| `POST /mcp`         | Yes  | The MCP JSON-RPC endpoint (Streamable HTTP)    |
| `GET  /mcp`         | Yes  | SSE stream for server → client messages        |
| `*    /admin/*`     | Yes (role: `admin`) | `src/admin.rs:133-170`                        |
| `POST /authorize`, `/token`, `/register`, `/introspect`, `/revoke` | feature `oauth` proxy | `src/transport.rs:1214-1370` |

---

## 4. Core types

### `McpServerConfig` — `src/transport.rs:71-468`
Top-level builder-style config consumed by `serve()`. Holds:
- bind address (`SocketAddr`)
- server name + version
- optional TLS / mTLS paths
- optional `AuthConfig`, `RbacPolicy`, `OAuthConfig`
- `ToolHooks` (opt-in)
- limits (body size, request timeout, max concurrent reqs)
- admin enable flag and admin role
- optional readiness check callback (`Arc<dyn Fn() -> bool + Send + Sync>`)
- public URL (used in OAuth metadata responses)

### `ReloadHandle` — `src/transport.rs:470-510`
Returned (optionally) from `serve()` when the consumer needs runtime
hot-reload. Two methods:
- `reload_auth_keys(new_map)` — atomically swaps `AuthState.api_keys`
- `reload_rbac(new_policy)` — atomically swaps the `ArcSwap<RbacPolicy>`

Both use `arc-swap`, so live requests are not blocked or interrupted.

### `AuthIdentity` — `src/auth.rs:40-58`
Canonical caller record passed through the request scope:
```rust
pub struct AuthIdentity {
    pub name: String,                  // human-readable principal name
    pub role: String,                  // RBAC role (matched against RoleConfig)
    pub method: AuthMethod,            // ApiKey | Mtls | OAuth
    pub raw_token: Option<Secret<String>>, // present only for Bearer auth
    pub sub: Option<String>,           // OAuth subject claim, when applicable
}
```

### `RbacPolicy` — `src/rbac.rs:329-340`
Holds:
- `roles: HashMap<String, RoleConfig>` — per-role tool allow/deny rules
- default-deny semantics with explicit overrides
- per-tool argument allowlists
- per-IP rate limiter shared across the server

### `HookedHandler<H>` — `src/tool_hooks.rs:246-307`
Generic wrapper around a consumer's `ServerHandler` that runs:
- `before_call(name, args, identity)` — may rewrite args or short-circuit
- `after_call(name, result, identity)` — may rewrite or audit the result
- enforces `max_result_bytes` (returns an error if the serialized result exceeds the cap)

---

## 5. Authentication subsystem

**File**: `src/auth.rs` (~600 LOC).

### Construction
`AuthState` is built inside `build_app_router()` at `src/transport.rs:572-601`. It contains:
- `api_keys: ArcSwap<Vec<ApiKeyEntry>>` (`src/auth.rs:495-510`)
- `mtls: Arc<MtlsIdentities>` (the shared `RwLock<HashMap<SocketAddr, AuthIdentity>>`)
- `rate_limiter: Option<Arc<KeyedLimiter>>` — **post-failure backoff**:
  governor limit on *failed* auth attempts per IP. Consulted only after a
  credential check has run and rejected the caller.
- `pre_auth_limiter: Option<Arc<KeyedLimiter>>` — **pre-auth abuse gate**:
  governor limit on *unauthenticated* requests per IP, consulted *before*
  any Argon2id work runs. Defends the bearer-verification path against
  CPU-spray attacks (an attacker submitting a flood of invalid tokens to
  pin the CPU on Argon2id verification). Defaults to `10x` the
  post-failure quota when `pre_auth_max_per_minute` is unset on
  `RateLimitConfig`. **mTLS-authenticated requests bypass this gate
  entirely** (the TLS handshake already performed expensive crypto with a
  verified peer, so mTLS callers cannot be used to mount a CPU-spray
  attack).
- `jwks_cache: Option<Arc<JwksCache>>` (`src/oauth.rs:460-481`) when `feature=oauth` is on and `oauth.issuer_url` is configured

### API key flow
1. Client sends `Authorization: Bearer <api-key>`.
2. `auth_middleware` first runs the **pre-auth abuse gate** keyed by the
   request's source IP. If the gate is exhausted the middleware returns
   `429` immediately, *without* touching Argon2id (`src/auth.rs:846-913`,
   `src/auth.rs:870-880`).
3. Otherwise the middleware looks up the key by an indexed prefix
   (constant-time compare via `subtle`), then verifies Argon2id against
   `ApiKeyEntry.hash`.
4. On success, builds `AuthIdentity { method: ApiKey, role: entry.role, … }`.
5. On failure, the **post-failure backoff** limiter is consulted; if
   exhausted from one IP, the middleware returns `429`
   (`src/auth.rs:910-914`).

API keys are never logged. They are wrapped in `secrecy::SecretString`
and zeroized on drop. Bearer tokens accepted as OAuth JWTs are likewise
threaded as `SecretString` from `AuthIdentity.raw_token` through
`CURRENT_TOKEN` so that they never appear in `Debug` output.

### mTLS flow
1. The `TlsListener` validates the client cert chain (configured roots).
2. It extracts CN/SAN as `name`, derives `role` from the configured
   subject→role mapping, and stores `AuthIdentity { method: Mtls, … }`
   in `MtlsIdentities` keyed by **peer `SocketAddr`** (`src/transport.rs:1379-1543`).
3. `auth_middleware` picks up the identity by the request's `ConnectInfo<SocketAddr>`.

### OAuth JWT flow (feature = `oauth`)
See [§8](#8-oauth-21--jwks-feature-oauth).

### Helpers
- `generate_api_key()` — produces a fresh API key + Argon2 hash (used by
  e2e tests and tooling).
- `verify_api_key()` — constant-time Argon2 verification.

---

## 6. RBAC subsystem

**File**: `src/rbac.rs` (~620 LOC).

### Policy model
```
RbacPolicy {
    roles: HashMap<String, RoleConfig>,   // src/rbac.rs:329
}

RoleConfig {                              // src/rbac.rs:174-225
    allow_tools: Vec<String>,              // glob patterns supported
    deny_tools:  Vec<String>,              // deny overrides allow
    argument_allowlists: HashMap<String, ArgumentAllowlist>,  // per tool
    rate_limit: Option<RateLimit>,         // optional per-role override
}

ArgumentAllowlist {                       // src/rbac.rs:226-247
    fields: HashMap<String, FieldRule>,    // per JSON-RPC argument key
}
```

### Decision function
- `RbacPolicy::check(role, tool_name)` — pure allow/deny (`src/rbac.rs:420-462`)
- `ArgumentAllowlist::argument_allowed(args)` — JSON value match (`src/rbac.rs:464-580`)
- `RbacPolicy::redact_arg(value)` — HMAC-SHA256 of an argument value with
  the policy's salt, returning an 8-char hex prefix. Used to keep raw
  argument values out of deny logs.
- `enforce_tool_policy(policy, identity_name, role, params)` — combines
  allow/deny + argument-allowlist checks, emitting structured deny logs.
  `identity_name` is passed explicitly because the task-local context is
  installed *after* enforcement (see "Task-locals" below).

### Middleware
`rbac_middleware` (`src/rbac.rs:584-700`):
1. Extracts the role + identity name from the `AuthIdentity` request
   extension (set by the auth middleware).
2. For `POST /mcp`, reads the body (bounded by body-size layer), parses
   JSON-RPC, and inspects `method`. Only enforces on `tools/call`.
3. Calls `enforce_tool_policy(&policy, &identity_name, &role, params)`.
4. Calls the per-IP tool rate limiter (`build_tool_rate_limiter` at
   `src/rbac.rs:53-78`), returning `429` if exceeded.
5. On success, propagates the request downstream. The body is restored
   into the request so rmcp can read it again.

### Argument-value redaction
Deny logs for argument-allowlist violations never contain the raw value.
Instead, an HMAC-SHA256(salt, value) prefix (4 bytes / 8 hex chars) is
logged under the `arg_hmac` field. The salt is taken from
`RbacConfig::redaction_salt` (set in TOML for stable cross-restart
hashes) or, when absent, from a process-wide random salt generated on
first use. 32 bits is enough entropy for log-line correlation while
making preimage recovery infeasible. See `src/rbac.rs::redact_with_salt`.

### Task-locals
`tokio::task_local!` block at `src/rbac.rs:83-91` defines four task-locals:
- `CURRENT_ROLE: String`
- `CURRENT_IDENTITY: String`
- `CURRENT_TOKEN: SecretString`
- `CURRENT_SUB: String`

Public accessors (`src/rbac.rs:93-145`): `current_role()`, `current_identity()`,
`current_token()`, `current_sub()`. They return `Option<T>` because the
task-locals are absent outside the request scope.

`current_token()` returns `Option<SecretString>` (since 0.11). Call
`.expose_secret()` only when the raw value is genuinely required — e.g.
when constructing an outbound `Authorization` header for downstream
token passthrough.

> ⚠️ **These do NOT propagate across `tokio::spawn`.** Capture the value
> before spawning a child task.

---

## 7. TLS / mTLS

**Custom listener**: `TlsListener` in `src/transport.rs:1373-1543`, implementing
`axum::serve::Listener` so axum's hyper machinery accepts it as a drop-in
replacement for `TcpListener`.

Lifecycle:
1. `TlsListener::new(...)` reads PEM cert + key, builds a `rustls::ServerConfig`,
   optionally wraps with mTLS verification using configured root CAs.
2. On each `accept()` (`src/transport.rs:1545-1578`):
   - Performs the TLS handshake.
   - If the peer presented a cert, parses it (`x509-parser`), derives
     `AuthIdentity`, and writes to `MtlsIdentities` keyed by `SocketAddr`.
   - Returns the wrapped TLS stream + `ConnectInfo<TlsConnInfo>`.

Configuration toggles:
- TLS version: TLSv1.2+ (set in `rustls` features).
- Cipher suites: `rustls` defaults (ring crypto provider).
- mTLS: optional; when enabled, missing/invalid client cert → connection refused.

### CRL revocation (CDP-driven, since 1.2.0)

**File**: `src/mtls_revocation.rs` (~600 LOC). Active automatically whenever
`[mtls]` is configured and `crl_enabled = true` (the default).

Lifecycle:
1. `bootstrap_fetch(roots, config)` is called from `run_server` *before*
   the listener is built. It walks the configured CA chain, extracts every
   X.509 CRL Distribution Point (CDP) URL via `extract_cdp_urls`, fetches
   each via `reqwest` under a 10 s total deadline, and seeds the cache.
2. The returned `Arc<CrlSet>` owns:
   - `inner_verifier: ArcSwap<VerifierHandle>` — current
     `Arc<dyn ClientCertVerifier>` built from the latest CRL set; swapped
     atomically when CRLs refresh.
   - `cache: tokio::sync::RwLock<HashMap<String, CachedCrl>>` keyed by URL.
   - `discover_tx: mpsc::UnboundedSender<String>` — channel used by the
     handshake path to register newly observed CDP URLs for fetch.
   - `seen_urls: Mutex<HashSet<String>>` — dedupe of URLs already processed.
3. `DynamicClientCertVerifier` is the `Arc<dyn ClientCertVerifier>` handed
   to `rustls::ServerConfig`. Its 8 trait methods delegate to the inner
   verifier loaded from `inner_verifier.load()`. Because `tokio_rustls::TlsAcceptor`
   clones the verifier `Arc` from the `ServerConfig` at construction, the
   dynamic verifier MUST be the Arc handed to rustls; its inner verifier
   then swaps via the internal `ArcSwap`.
4. `run_crl_refresher(set, rx, shutdown)` is spawned by `run_server`. It:
   - Drains the `discover_tx` receiver and fetches any newly observed CDP URLs.
   - Re-fetches each cached CRL before its `nextUpdate`, clamped to
     `[10 min, 24 h]` (overridable via `crl_refresh_interval`).
   - On any successful fetch, rebuilds the inner verifier and `inner_verifier.store()`s it.
   - Honours `crl_fetch_timeout` per request and `crl_stale_grace` for cache
     eviction of long-expired CRLs.

Failure modes:
- Fetch failure / parse failure / expired-beyond-grace: cache entry is
  marked stale; if `crl_deny_on_unavailable = false` (default) handshakes
  continue with a `WARN` log; if `true`, handshakes that depend on the
  affected CRL are rejected.
- `crl_allow_http = false` rejects `http://` CDP URLs.
- `crl_end_entity_only = true` checks only the leaf, skipping intermediates.

### SSRF hardening (since 1.2.1)

`ssrf_guard` (`src/mtls_revocation.rs:73-200`) runs against every CDP URL
*before* the HTTP request is issued, rejecting non-`http(s)` schemes,
URLs with userinfo, and any host that resolves to a private/loopback/
link-local/multicast/unspecified/broadcast/cloud-metadata address (IPv4
and IPv6, including IPv4-mapped IPv6 and IPv4-compatible IPv6). The
fetcher also pins `redirect::Policy::none()` for CRL traffic — a CRL is
signed by the issuing CA, so following operator-unintended redirects has
no security benefit. Three knobs cap the blast radius even when a CDP is
reachable:

- `crl_max_concurrent_fetches` (default 4) — global parallel-fetch cap;
  per-host concurrency is independently hard-capped at 1 via
  `host_semaphores`.
- `crl_max_response_bytes` (default 5 MiB) — streams aborted mid-response
  when exceeded (defends against gzip-bomb amplification).
- `crl_discovery_rate_per_min` (default 60) — `governor`-based
  process-global rate limit on **new** CDP URLs admitted to the fetch
  pipeline.

### Discovery admission ordering (since 1.2.1)

`note_discovered_urls` (`src/mtls_revocation.rs:521-575`) implements a
strict commit-after-admission protocol to keep the discovery rate
limiter from "leaking" URLs:

1. Snapshot the candidate URL set.
2. Apply `ssrf_guard` to filter unreachable / hostile URLs.
3. For each survivor, attempt `discovery_rate_limiter.check()`.
4. **Only after** the limiter admits the URL **and** the
   `discover_tx.send(url)` succeeds, insert the URL into the
   `seen_urls` `HashSet`. If admission fails (limiter-throttled or
   channel closed), the URL is intentionally **left unseen** so a
   subsequent handshake observing the same URL can retry admission
   once the limiter window opens.

This ordering matters: a naive "mark seen, then attempt admission"
implementation would silently drop CDP URLs forever the first time the
rate limiter engaged, breaking revocation for the affected client
identities. The current ordering is verified by
`__test_check_discovery_rate` (`src/mtls_revocation.rs:666`) and by the
`__test_with_kept_receiver` helper used in unit tests.

Hot-reload: `ReloadHandle::refresh_crls()` (in `src/transport.rs`) sends a
sentinel through the discover channel that forces re-fetch of every cached
URL on the next refresher tick.

Test helper: `__test_with_prepopulated_crls(...)` (doc-hidden) lets `tests/e2e.rs`
seed a `CrlSet` with synthetic `rcgen`-generated CRLs and `wiremock`-served
CDP endpoints. Four e2e tests cover: unrevoked-allows, revoked-rejects,
fail-open on unreachable CDP, fail-closed on unreachable CDP.

**Plain HTTP fallback**: when no TLS cert is supplied, axum binds a
plain `TcpListener` (`src/transport.rs:1013-1057`). For production
deployments, TLS is strongly recommended.

---

## 8. OAuth 2.1 / JWKS (feature `oauth`)

**File**: `src/oauth.rs` (~640 LOC). Activated by `features = ["oauth"]`.

### Validation flow
1. Client sends `Authorization: Bearer <jwt>`.
2. `JwksCache::validate(token)` (`src/oauth.rs:569-647`):
   - Decodes the JWT header to get `kid` and `alg`.
   - `select_jwks_key()` looks up by `kid` in the cached JWKS
     (`src/oauth.rs:648-756`).
   - If not found, calls `refresh_with_cooldown()` (`src/oauth.rs:758-820`):
     - Enforces `JWKS_REFRESH_COOLDOWN` (~`src/oauth.rs:480`) so multiple
       invalid tokens cannot DoS the JWKS endpoint.
     - Deduplicates concurrent refreshes.
   - Validates signature, `iss`, `aud`, `exp`, `nbf` using `jsonwebtoken`.
3. Extracts the configured `role_claim` (or maps OAuth scopes to roles).
4. Builds `AuthIdentity { method: OAuth, role, sub, raw_token: Some(_), … }`.

### Optional OAuth 2.1 proxy
When `oauth.proxy` is configured, rmcp-server-kit mounts thin proxy endpoints under
the server's own URL (`src/transport.rs:1214-1230`):
- `/.well-known/oauth-authorization-server`
- `/authorize`, `/token`, `/register`, `/introspect`, `/revoke`

These let downstream MCP clients discover OAuth via the same origin as
`/mcp`, simplifying CORS and CSP configuration.

### Hardening defaults
- Allowed algorithms: configured per `OAuthConfig` (default: `RS256`, `ES256`).
- Symmetric keys (`HS*`) are rejected by default — protects against
  algorithm-confusion attacks.
- JWKS responses cached with TTL; stale-while-revalidate semantics.
- HTTPS-downgrade-rejecting redirect policy on `OauthHttpClient` (since
  1.2.1): HTTPS → HTTP redirects are denied unconditionally; HTTP → HTTP
  is allowed only when `oauth.allow_http_oauth_urls = true`.
- Prefer `OauthHttpClient::with_config(&OAuthConfig)` (since 1.2.1) over
  the deprecated `OauthHttpClient::new()` so the redirect policy and CA
  bundle are wired consistently.

### Trust boundary (1.2.x)

OAuth endpoint URLs (`issuer_url`, `jwks_uri`, discovery URLs) are
**operator-trusted configuration**. Per-hop DNS/private-IP SSRF guarding
is **not** applied to OAuth-bound fetches in 1.2.x — that hardening is
queued for 1.3.0 (extract `ssrf_guard` from `src/mtls_revocation.rs` and
apply it per redirect hop in `JwksCache`). Until then, never let tenants
or end-users influence OAuth endpoint URLs at runtime.

---

## 9. Tool hooks (extension point)

**File**: `src/tool_hooks.rs`.

```rust
pub trait ToolHooks: Send + Sync + 'static {
    fn before_call(&self, name: &str, args: &Value, identity: Option<&AuthIdentity>)
        -> Result<Value, McpxError>;
    fn after_call(&self, name: &str, result: &Value, identity: Option<&AuthIdentity>)
        -> Result<Value, McpxError>;
}
```

`HookedHandler<H>` implements `rmcp::ServerHandler` for any inner `H: ServerHandler`,
delegating most calls but intercepting `call_tool` (`src/tool_hooks.rs:421-540`):
1. Captures current identity from task-locals.
2. Calls `before_call` — may rewrite args, may return early with an error.
3. Calls inner handler.
4. Serializes result, checks `max_result_bytes` — error if exceeded.
5. Calls `after_call` — may redact / audit / transform.

Activated in `McpServerConfig` via `with_hooks(...)`. Skip if you don't need
custom audit/transformation.

---

## 10. Admin diagnostics

**File**: `src/admin.rs`.

Mounted under `/admin/*` only when `config.admin_enabled = true`. The
`require_admin_role` middleware (`src/admin.rs:133-170`) gates access to the
configured admin role (default: `"admin"`).

| Endpoint               | Returns                                                  |
|------------------------|----------------------------------------------------------|
| `GET /admin/status`    | server name, version, uptime, feature flags, peer count  |
| `GET /admin/auth/keys` | current API key metadata (name, role, expiry — never the secret) |
| `GET /admin/auth/counters` | per-IP auth attempts, success/failure counts          |
| `GET /admin/rbac`      | current RBAC policy snapshot                             |

Useful for debugging hot-reload state and verifying RBAC after a swap.

---

## 11. Observability

**File**: `src/observability.rs`.

`init_tracing_from_config(...)` (~`src/observability.rs:39-80`) initializes
`tracing-subscriber` with:
- `EnvFilter` from `RUST_LOG` (or supplied filter string)
- console layer (pretty when stdout is a TTY, JSON otherwise)
- optional **audit-file sink** (`src/observability.rs:133-180`) — appends
  structured JSON events to a path; useful for compliance/forensics.

Conventions used by rmcp-server-kit itself:
- `tracing::info!` for lifecycle events (server up/down, key reloads)
- `tracing::warn!` for soft denials (rate-limit hits, RBAC denies)
- `tracing::error!` for hard failures (TLS handshake errors, internal panics caught by axum)
- All sensitive fields are redacted (API keys, tokens, full bodies).

> ⚠️ **Never log a `Secret<T>` directly.** `Debug`/`Display` of `secrecy::Secret`
> prints `Secret([REDACTED])`, but `expose_secret()` is logged as plain
> text — never log the result of that call.

---

## 12. Metrics (feature `metrics`)

**File**: `src/metrics.rs`. Activated by `features = ["metrics"]`.

`McpMetrics` (`src/metrics.rs:26-93`) wraps a `prometheus::Registry` and
records standard server metrics:
- `rmcp_server_kit_requests_total{path, status}` (counter)
- `rmcp_server_kit_request_duration_seconds{path}` (histogram)
- `rmcp_server_kit_inflight_requests` (gauge)
- `rmcp_server_kit_auth_failures_total{method}` (counter)
- `rmcp_server_kit_rbac_denies_total{role, tool}` (counter)

The `/metrics` endpoint is served on a **separate listener** (often a
private bind address) configured via `MetricsConfig` — see
`src/metrics.rs::serve_metrics` (~`src/metrics.rs:95-180`). This isolates
operational telemetry from the public MCP listener.

---

## 13. Hot reload

Two ArcSwaps power runtime reconfiguration:

| State            | Type                           | Defined at                  |
|------------------|---------------------------------|-----------------------------|
| API keys         | `ArcSwap<Vec<ApiKeyEntry>>`     | `src/auth.rs:495-510`       |
| RBAC policy      | `ArcSwap<RbacPolicy>`           | `src/transport.rs:605-610`  |

Procedure:
1. Consumer calls `reload_handle.reload_auth_keys(new_map)` or
   `reload_rbac(new_policy)`.
2. The new value is wrapped in `Arc<…>` and atomically swapped.
3. New requests pick up the new value on next read; in-flight requests
   continue with whichever value they already loaded.

Why `arc-swap` and not `RwLock`?
- Reads are wait-free (no atomic write contention).
- Writers never block readers.
- The ~few-microsecond eventual-consistency window is acceptable for
  policy changes.

---

## 14. Error handling

**File**: `src/error.rs`.

```rust
#[derive(thiserror::Error, Debug)]
pub enum McpxError {
    Unauthorized(String),
    Forbidden(String),
    BadRequest(String),
    RateLimited,
    PayloadTooLarge,
    Internal(#[from] anyhow::Error),
    // ...
}
```

`impl IntoResponse for McpxError` (`src/error.rs:56-90`) maps each
variant to a sanitized HTTP response:
- Status code (`401`, `403`, `400`, `429`, `413`, `500`)
- Generic body (no internal details leaked to clients per OWASP)
- Logs the full cause via `tracing::error!` with structured fields

Inside handlers, `?` propagates errors. Never panic — the `panic = "deny"`
clippy lint enforces this.

---

## 15. Configuration

Two configuration surfaces:

**Programmatic** — `McpServerConfig::new(addr, name, version)` builder
(`src/transport.rs:155-468`). The consumer can set every field directly.

**TOML** — `src/config.rs` defines deserializable structs
(`AuthConfig`, `RbacConfigToml`, `OAuthConfigToml`, etc.) consumers can
load from a file. See [`docs/GUIDE.md`](GUIDE.md) for full schema and
examples.

Defaults (chosen for safe production posture):
- max body size: **1 MiB**
- request timeout: **30 s**
- TLS: required when not `127.0.0.1` (heuristic; can be overridden)
- admin role: `"admin"`
- security headers: full OWASP defaults applied

---

## 16. Testing strategy

**Unit tests** live next to code in `#[cfg(test)] mod tests { … }`. They
cover pure logic (config validation, error mapping, argument allowlist
matching, JWKS algorithm selection, etc.).

**Integration / E2E** tests live in `tests/e2e.rs`. They:
- Spawn `rmcp_server_kit::transport::serve(...)` on an **ephemeral port** via
  `spawn_server()` (`tests/e2e.rs:46-71`).
- Use `reqwest` to make real HTTP calls — origin checks, auth, RBAC,
  rate-limiting, readiness, body limits, TLS handshakes.
- Use `wiremock` for OAuth/JWKS upstreams.
- Generate test certs at runtime using `rcgen`.

Examples worth reading:
- `auth_accepts_valid_bearer` — `tests/e2e.rs:157-177`
- RBAC denial paths — `tests/e2e.rs:278-337`

> When changing behaviour, **add an E2E test first**. The unit tests in
> `auth.rs`/`rbac.rs` are useful but the E2E suite is what catches
> middleware-ordering regressions.

---

## 17. Critical invariants

These are **non-negotiable**. Breaking any of them is a security regression.

1. **Origin check runs before auth.** Reordering would allow unauthenticated
   browser-origin requests to hit the auth path and amplify timing oracles.
   Wired at `src/transport.rs:962-967`.

2. **Auth runs before RBAC.** Without an `AuthIdentity`, RBAC has no role
   to evaluate. The middleware order in `src/transport.rs:680-740`
   enforces this.

3. **Per-IP rate limiter sits inside auth.** Anonymous IPs cannot
   exhaust the rate-limit budget for authenticated callers.

4. **JWKS refresh is rate-limited.** Removing `JWKS_REFRESH_COOLDOWN`
   (`src/oauth.rs:480`) creates a DoS vector against the issuer's JWKS endpoint.

5. **No symmetric JWT algorithms by default.** `HS*` algorithms with a
   public JWKS would enable algorithm-confusion attacks. Don't add them
   to the default allow-list.

6. **mTLS identity map is keyed by `SocketAddr`, not by client name.**
   Two simultaneous connections from the same client get distinct entries.
   This is intentional and prevents identity hijack across connections.

7. **`stdio` transport bypasses ALL middleware** (auth, RBAC, TLS, origin).
   Document this loudly to consumers and never recommend it for network use.

8. **Secrets must use `secrecy::SecretString` (or `SecretBox<T>`).**
   Logging or `Debug`-printing the wrapped value yields `[REDACTED]`.
   Calling `.expose_secret()` and then logging the result re-leaks. Don't.

9. **No panics in production code paths.** `unwrap_used = "deny"`,
   `panic = "deny"`, `todo = "deny"`, `unimplemented = "deny"` are set
   in `Cargo.toml`. Use `Result<T, McpxError>`.

10. **`unsafe_code = "forbid"`** at the crate level. There is no `unsafe`
    in this codebase and there should never be.

---

## See also

- [`MINDMAP.md`](MINDMAP.md) — the same information, but visual.
- [`../AGENTS.md`](../AGENTS.md) — quick-orientation hub for agents.
- [`GUIDE.md`](GUIDE.md) — consumer-facing usage examples.
- [`../RUST_GUIDELINES.md`](../RUST_GUIDELINES.md) — coding standards.
