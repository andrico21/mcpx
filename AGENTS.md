# AGENTS.md — mcpx

> **Audience**: AI coding agents (and humans) working on the `rmcp-server-kit` crate.
> **Purpose**: Single source of truth for navigating, building, testing, and
> safely modifying this repository. Read this BEFORE making changes.
>
> **Companion docs**:
> - [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — deep architecture reference with file:line citations
> - [`docs/MINDMAP.md`](docs/MINDMAP.md) — visual mermaid mindmap of the whole project
> - [`docs/GUIDE.md`](docs/GUIDE.md) — end-user / consumer-facing guide
> - [`RUST_GUIDELINES.md`](RUST_GUIDELINES.md) — mandatory coding standards (DO/DON'T)

---

## 1. What is `rmcp-server-kit`?

`rmcp-server-kit` is a **production-grade reusable Rust framework for building
[Model Context Protocol](https://modelcontextprotocol.io/) (MCP) servers.**

Consumers supply an `rmcp::handler::server::ServerHandler` implementation;
`rmcp-server-kit` provides everything else: HTTP transport, TLS/mTLS, authentication
(API key / mTLS / OAuth 2.1 JWT), RBAC with per-tool argument allowlists,
per-IP rate limiting, OWASP-grade security headers, structured
observability, optional Prometheus metrics, admin diagnostics, and graceful
shutdown.

| Field         | Value                                                              |
|---------------|--------------------------------------------------------------------|
| Crate name    | `rmcp-server-kit`                                                  |
| Version       | `1.0.0` (see [`Cargo.toml`](Cargo.toml))                          |
| Edition       | `2024`                                                             |
| MSRV          | Rust **1.95.0**                                                    |
| License       | `MIT OR Apache-2.0` (dual)                                         |
| Crate type    | **Library** (no `src/main.rs`; runnable code lives in `examples/`) |
| Repository    | https://github.com/andrico21/rmcp-server-kit (canonical)           |
| Crates.io     | https://crates.io/crates/rmcp-server-kit                           |

---

## 2. Repository map (top 2-3 levels)

```
Z:\TempPersistent\mcpx\
├── src/                      Library source (THE crate)
│   ├── lib.rs                  Crate root - re-exports public modules
│   ├── transport.rs            ★ Server entry: serve(), serve_stdio(), TLS, router, middleware wiring
│   ├── auth.rs                 Authentication: API keys (Argon2), mTLS, AuthIdentity, AuthState
│   ├── rbac.rs                 RBAC engine: RbacPolicy, task-local context, per-tool argument allowlists
│   ├── oauth.rs                OAuth 2.1 JWT + JWKS cache (feature = "oauth")
│   ├── mtls_revocation.rs      CDP-driven CRL fetcher + cache + dynamic ClientCertVerifier (1.2.0+)
│   ├── admin.rs                Admin diagnostics router (/admin/*)
│   ├── tool_hooks.rs           Optional HookedHandler wrapper (before/after hooks, result-size cap)
│   ├── observability.rs        Tracing/JSON logging + audit-file sink
│   ├── metrics.rs              Prometheus registry + /metrics listener (feature = "metrics")
│   ├── config.rs               TOML configuration structs + validation
│   ├── error.rs                McpxError + IntoResponse mapping
│   └── secret.rs               Re-exports of `secrecy` wrappers
├── tests/
│   └── e2e.rs                Integration / E2E tests - spawns serve() on ephemeral ports
├── examples/
│   └── minimal_server.rs     Minimal runnable example (`cargo run --example minimal_server`)
├── docs/
│   ├── GUIDE.md              ★ Consumer-facing guide (architecture, TOML config, examples)
│   ├── ARCHITECTURE.md       ★ Deep architecture map for agents (file:line citations)
│   ├── MINDMAP.md            ★ Mermaid mindmap of the project
│   ├── MIGRATION.md          Version-migration notes
│   ├── RELEASING.md          Release process
│   └── RUST_1_95_NOTES.md    Notes on Rust 1.95 idioms used here
├── .github/workflows/        GitHub Actions CI (fmt, clippy, test, doc, deny, audit, MSRV)
├── .gitlab-ci.yml            GitLab mirror CI pipeline (build/test/lint/audit/publish)
├── .cargo/audit.toml         cargo-audit policy
├── Cargo.toml                Manifest (deps, features, lints)
├── clippy.toml               Clippy thresholds (cognitive complexity, etc.)
├── deny.toml                 cargo-deny policy (licenses, advisories, bans)
├── rustfmt.toml              rustfmt config (import grouping, granularity)
├── README.md                 Short quick-start
├── CHANGELOG.md              Release history
├── RUST_GUIDELINES.md        ★ MANDATORY - Coding standards. READ IT.
├── CONTRIBUTING.md           Contribution guide
├── CODE_OF_CONDUCT.md        Code of conduct
├── SECURITY.md               Security disclosure policy
└── LICENSE-{MIT,APACHE}      Dual license texts
```

★ = high-priority for orientation.

---

## 3. Tech stack

| Concern            | Crate(s)                                                      |
|--------------------|----------------------------------------------------------------|
| MCP protocol       | `rmcp` 1.5 (official Rust SDK; streamable-HTTP transport)      |
| Async runtime      | `tokio` 1, `tokio-util`                                        |
| HTTP framework     | `axum` 0.8, `tower`, `tower-http`, `http-body-util`            |
| TLS / mTLS         | `rustls` 0.23 (ring), `tokio-rustls`, `x509-parser`            |
| Serialization      | `serde`, `serde_json`, `toml`                                  |
| Errors             | `thiserror`, `anyhow`                                          |
| Observability      | `tracing`, `tracing-subscriber` (env-filter, json, fmt)        |
| Security           | `argon2` (API key hashing), `subtle`, `governor` (rate limit), `secrecy` |
| Hot reload         | `arc-swap` (lock-free pointer swap)                            |
| Util               | `humantime`, `base64`, `chrono`, `rand`                        |
| **OAuth (opt)**    | `jsonwebtoken`, `reqwest`, `urlencoding` (feature `oauth`)     |
| **Metrics (opt)**  | `prometheus` (feature `metrics`)                               |

**Cargo features**:
- `oauth` (off by default) — OAuth 2.1 JWT validation against JWKS + optional OAuth proxy endpoints.
- `metrics` (off by default) — Prometheus `/metrics` endpoint and recording middleware.

---

## 4. Build / test / run cheat sheet

> All commands assume cwd = `Z:\TempPersistent\mcpx`.
> Prefer the `rtk` wrapper (`Z:\TempPersistent\rtk.exe`) for token-efficient
> output in agent contexts — e.g. `Z:\TempPersistent\rtk.exe cargo build`.

| Goal                             | Command                                                              |
|----------------------------------|----------------------------------------------------------------------|
| Build (all features)             | `cargo build --all-features`                                         |
| Build (default features)         | `cargo build`                                                        |
| Run example server               | `cargo run --example minimal_server`                                 |
| Run all tests                    | `cargo test --all-features`                                          |
| Run unit tests only              | `cargo test --all-features --lib`                                    |
| Run E2E tests only               | `cargo test --all-features --test e2e`                               |
| Format check (CI)                | `cargo +nightly fmt --all -- --check`                                |
| Format apply                     | `cargo +nightly fmt --all`                                           |
| Lint (CI gate)                   | `cargo clippy --all-targets --all-features -- -D warnings`           |
| Build docs                       | `cargo +nightly doc --no-deps --all-features`                        |
| Supply-chain audit               | `cargo audit`                                                        |
| License/ban policy               | `cargo deny check`                                                   |
| MSRV check                       | `cargo +1.95.0 build --all-features`                                 |
| Semver check (library)           | `cargo semver-checks check-release`                                  |

**CI definition lives in**:
- `.github/workflows/ci.yml` (canonical)
- `.gitlab-ci.yml` (mirror)

---

## 5. Entry points (where to start reading)

There is **no** `src/main.rs`. rmcp-server-kit is a **library**; runnable code is in
consumer applications and `examples/`.

| Entry                                    | File                                                                  | Notes                                                                                                  |
|------------------------------------------|----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| Crate root / public API                  | [`src/lib.rs`](src/lib.rs)                                            | Re-exports all public modules                                                                          |
| **Server entry (HTTP)**                  | [`src/transport.rs`](src/transport.rs) — `serve()` (~line 220)        | The function consumers call. Wires rmcp + axum + middleware + TLS + admin + metrics                    |
| Server entry (stdio)                     | [`src/transport.rs`](src/transport.rs) — `serve_stdio()` (~line 1252) | For desktop/IDE clients. **Bypasses auth/RBAC/TLS** — use only for local subprocess MCP                |
| Config builder                           | [`src/transport.rs`](src/transport.rs) — `McpServerConfig::new` (~line 130) | Builder-style config struct                                                                       |
| Hot-reload handle                        | [`src/transport.rs`](src/transport.rs) — `ReloadHandle` (~line 172)   | `reload_auth_keys` / `reload_rbac` for runtime reconfig without restart                               |
| Runnable example                         | [`examples/minimal_server.rs`](examples/minimal_server.rs)            | Smallest possible consumer of `serve()`                                                                |
| E2E reference                            | [`tests/e2e.rs`](tests/e2e.rs)                                        | Real-world usage patterns; use as an integration cookbook                                              |

---

## 6. Mental model (90-second version)

```
                   ┌──────────────────────────────────┐
   HTTP request ─► │  TlsListener  (TLS / mTLS)       │  src/transport.rs:846
                   └────────────────┬─────────────────┘
                                    ▼
                   ┌──────────────────────────────────┐
                   │  axum Router                     │
                   │   ├── /healthz  (open)           │
                   │   ├── /readyz   (optional check) │
                   │   ├── /version  (open)           │
                   │   ├── /metrics  (separate listener, feature=metrics)
                   │   ├── /admin/*  (admin role)     │  src/admin.rs
                   │   ├── /.well-known/oauth-*       │  src/oauth.rs
                   │   └── /mcp     ── rmcp service ──┐
                   └────────────────┬─────────────────┘│
                                    ▼                  │
        Outermost ── Middleware chain ── Innermost     │
        (executed top-to-bottom on request)            │
                                                       │
        1. Origin check       src/transport.rs:1183    │  spec: MCP origin validation
        2. Security headers   src/transport.rs:1110    │  HSTS, CSP, X-Frame-Options, ...
        3. CORS / compression / body-size / timeouts   │  tower-http layers
        4. Optional concurrency cap + metrics          │
        5. Auth middleware    src/auth.rs              │  API key (Argon2) | mTLS | OAuth JWT
        6. RBAC middleware    src/rbac.rs              │  parses JSON-RPC, enforces tools/call policy
        7. Per-IP tool rate limiter (governor)         │
                                                       ▼
                   ┌──────────────────────────────────┐
                   │  rmcp StreamableHttpService       │  Streamable HTTP MCP protocol
                   │   └── ServerHandler (yours)      │  optionally wrapped by HookedHandler
                   └──────────────────────────────────┘
```

**State plane** (lock-free hot reload via `arc-swap`):
- `AuthState.api_keys: ArcSwap<HashMap<…>>` — swap API keys at runtime
- `rbac_swap: ArcSwap<RbacPolicy>` — swap RBAC policy at runtime
- `MtlsIdentities: RwLock<HashMap<SocketAddr, AuthIdentity>>` — populated by TLS acceptor, read by auth middleware
- Task-local: `current_role()`, `current_identity()`, `current_token()`, `current_sub()` — set by middleware, callable from inside tool handlers (`src/rbac.rs:46-75`)

For a much deeper version see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## 7. Coding standards (NON-NEGOTIABLE)

This crate enforces strict lints. See full guidance in [`RUST_GUIDELINES.md`](RUST_GUIDELINES.md).
The most-violated rules — all `deny`-level in `Cargo.toml`:

| Forbidden                                   | Use instead                                                       |
|---------------------------------------------|--------------------------------------------------------------------|
| `unwrap()` / `expect()` in production paths | `?`, `unwrap_or`, `unwrap_or_else`, `match`                        |
| `panic!()`, `todo!()`, `unimplemented!()`   | Return `Result<_, McpxError>` (see `src/error.rs`)                 |
| `println!()` / `eprintln!()` / `dbg!()`     | `tracing::{info,warn,error,debug}!` macros                         |
| `as any` ish casts                          | `TryFrom`, explicit conversion with error                          |
| `unsafe` code                               | Forbidden (`unsafe_code = "forbid"` at crate level)                |
| `.clone()` to dodge borrow checker          | Restructure ownership; borrow `&str`/`&[T]` not `&String`/`&Vec`   |
| `Box<Vec<T>>`, `Box<String>`, `Arc<String>` | Use `Vec<T>`, `String`, `Arc<str>`                                 |
| Wildcard `_ =>` on owned enums              | Exhaustive match (lint: `wildcard_enum_match_arm = "deny"`)        |
| Indexing `vec[i]`                           | `vec.get(i)?`, slice patterns (lint: `indexing_slicing = "deny"`)  |
| Holding `std::sync::Mutex` across `.await`  | `tokio::sync::Mutex`, or release lock before await                 |
| `std::fs` / `std::net` in async fn          | `tokio::fs` / `tokio::net`, or `tokio::task::spawn_blocking`       |

**Rust 1.95 idioms required**:
- `Vec::push_mut` / `VecDeque::push_{front,back}_mut` — return `&mut T`, avoid the `push` + `last_mut().unwrap()` anti-pattern.
- `Atomic*::update` / `try_update` over hand-rolled `compare_exchange` loops.
- `cfg_select!` macro instead of the `cfg-if` crate (don't proactively migrate existing `cfg-if` though).

---

## 8. Workflow rules for agents

### Before editing
1. Read [`RUST_GUIDELINES.md`](RUST_GUIDELINES.md) §1-9 (or the relevant subsection for your change).
2. Skim [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) to find the right module.
3. Run `cargo build --all-features` to confirm a clean baseline.

### While editing
1. **Add/change tests first** when modifying behaviour. E2E tests live in `tests/e2e.rs` and spawn a real server — that's the gold standard for integration coverage.
2. Match existing patterns. This codebase is **disciplined** (consistent style, lints enforced, full docs). Follow conventions strictly.
3. Use `tracing` for any output. Never `println!`/`eprintln!`/`dbg!`.
4. Wrap secrets in `secrecy::Secret<T>` (re-exported via `src/secret.rs`).
5. New public API surface → add doc comments; the `missing_docs = "warn"` lint requires them.
6. Public types in this library crate should be `#[non_exhaustive]` where future-extension is plausible (lints `exhaustive_enums`, `exhaustive_structs` warn otherwise).

### Before declaring done (evidence required)
- [ ] `cargo +nightly fmt --all -- --check` clean
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] `cargo test --all-features` passes (note any pre-existing failures — do NOT delete tests)
- [ ] `cargo doc --no-deps --all-features` builds without warnings
- [ ] If you touched the public API: `cargo semver-checks check-release` (or note the intentional break in CHANGELOG.md)
- [ ] Updated [`CHANGELOG.md`](CHANGELOG.md) under the unreleased section
- [ ] No new `unwrap()` / `expect()` / `panic!()` introduced (grep before commit)

### Never do
- Commit without explicit user request.
- Add `#[allow(clippy::unwrap_used)]` without a `// SAFETY/INVARIANT:` comment justifying why the value is guaranteed `Some`/`Ok`.
- Suppress warnings globally (`#![deny(warnings)]` in source — forbidden; warnings policy is set in Cargo.toml + CI flags).
- Add a dependency without checking `deny.toml` license allow-list.
- Disable certificate validation on TLS (`rustls` must use real roots).
- Log secrets, tokens, request bodies, or full identities. Redact first.
- Introduce `unsafe` (the crate is `unsafe_code = "forbid"`).

---

## 9. Where things live (quick lookup)

| I need to change…                              | Look in                                                |
|------------------------------------------------|--------------------------------------------------------|
| Server entry / router / middleware order       | `src/transport.rs` — `serve()` and surrounding helpers |
| API key authentication                         | `src/auth.rs` — `AuthState`, `ApiKeyEntry`, `auth_middleware` |
| mTLS identity extraction                       | `src/transport.rs` — `TlsListener::record_mtls_identity` (~line 921) |
| mTLS CRL revocation (CDP-driven)               | `src/mtls_revocation.rs` — `CrlSet`, `DynamicClientCertVerifier`, `bootstrap_fetch`, `run_crl_refresher` |
| OAuth JWT validation / JWKS cache              | `src/oauth.rs` — `JwksCache`, feature-gated           |
| RBAC policy evaluation                         | `src/rbac.rs` — `RbacPolicy::check`, `enforce_tool_policy` |
| Per-tool argument allowlist                    | `src/rbac.rs` — `ArgumentAllowlist`, `argument_allowed` |
| Per-IP tool rate limit                         | `src/rbac.rs` — `build_tool_rate_limiter`             |
| Tool-call hooks / result-size cap              | `src/tool_hooks.rs` — `HookedHandler::call_tool`      |
| Admin endpoints (`/admin/*`)                   | `src/admin.rs`                                        |
| Tracing init / audit log                       | `src/observability.rs`                                |
| Prometheus registry / `/metrics`               | `src/metrics.rs`                                      |
| Configuration struct (TOML schema)             | `src/config.rs` + `McpServerConfig` in `src/transport.rs` |
| Error type → HTTP status mapping               | `src/error.rs` — `McpxError::into_response`           |
| Origin / security headers / CORS               | `src/transport.rs` — `origin_check_middleware`, `security_headers_middleware` |
| Graceful shutdown (Ctrl-C / SIGTERM)           | `src/transport.rs` — `shutdown_signal()` (~line 1050) |
| Hot-reload of keys / RBAC                      | `src/transport.rs` — `ReloadHandle` (~line 172)       |

---

## 10. Common pitfalls (history of bites)

1. **Middleware order matters for security.** Origin check MUST run before auth so unauthenticated callers are rejected by origin first. Rate limit MUST be inside auth so anonymous storms don't amplify. See `src/transport.rs` middleware wiring around lines 309-409.
2. **JWKS refresh is rate-limited.** Don't remove the `JWKS_REFRESH_COOLDOWN` (`src/oauth.rs:283-290`) — invalid JWTs would otherwise DoS the JWKS endpoint.
3. **Task-local RBAC context only exists inside the request scope.** Calling `current_role()` from a `tokio::spawn`ed background task returns `None`. Capture the value before spawning.
4. **`stdio` transport bypasses everything.** `serve_stdio` does NOT enforce auth, RBAC, TLS, or origin checks. It's intended for trusted local subprocess scenarios only.
5. **mTLS identities are keyed by `SocketAddr`.** If a load balancer rewrites peer addresses you must terminate TLS at the LB and use a different identity-binding strategy.
6. **`ArcSwap` swaps are lock-free but eventually-consistent.** In-flight requests may use the previous policy. This is intentional. Do not switch to `RwLock`.

---

## 11. Glossary

| Term            | Meaning                                                                                          |
|-----------------|--------------------------------------------------------------------------------------------------|
| MCP             | Model Context Protocol — JSON-RPC-based protocol for LLM ↔ tool/server interaction               |
| `rmcp`          | Official Rust SDK for MCP                                                                         |
| Streamable HTTP | The MCP HTTP transport variant supporting SSE-style streaming                                     |
| RBAC            | Role-Based Access Control — here, per-role tool allow-lists with argument constraints             |
| JWKS            | JSON Web Key Set — public keys used to verify OAuth JWTs                                          |
| mTLS            | Mutual TLS — both client and server present certificates                                          |
| Hook            | Optional `before_call` / `after_call` callback for tool invocations (see `src/tool_hooks.rs`)    |
| Hot reload      | Atomic, lock-free swap of API keys or RBAC policy without server restart (via `arc-swap`)         |

---

## 12. Further reading

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — every type, module, file:line reference
- [`docs/MINDMAP.md`](docs/MINDMAP.md) — mermaid mindmap diagram
- [`docs/GUIDE.md`](docs/GUIDE.md) — how end-users configure and consume rmcp-server-kit
- [`docs/RUST_1_95_NOTES.md`](docs/RUST_1_95_NOTES.md) — Rust 1.95 idioms used here
- [`docs/MIGRATION.md`](docs/MIGRATION.md) — version-migration notes
- [`docs/RELEASING.md`](docs/RELEASING.md) — release process
- [Model Context Protocol spec](https://modelcontextprotocol.io/)
- [`rmcp` docs](https://docs.rs/rmcp)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
