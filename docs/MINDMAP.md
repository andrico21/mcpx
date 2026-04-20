# rmcp-server-kit — Project Mindmap

> Visual map of the `rmcp-server-kit` crate. Pair with [`AGENTS.md`](../AGENTS.md) and
> [`ARCHITECTURE.md`](ARCHITECTURE.md). All file:line references use the
> code as of `rmcp-server-kit` v0.9.30.

---

## High-level mindmap

```mermaid
mindmap
  root((rmcp-server-kit<br/>v0.9.30))
    Identity
      Library crate
      No src/main.rs
      Edition 2024
      MSRV 1.95.0
      Dual MIT / Apache-2.0
      Repos
        GitHub andrico21/rmcp-server-kit
        crates.io rmcp-server-kit
    Purpose
      Reusable framework
      MCP servers in Rust
      Streamable HTTP transport
      Wraps rmcp 1.5
      Consumers supply ServerHandler
    Modules src/
      lib.rs
        Crate root
        Re-exports public API
      transport.rs ★
        serve fn ~L220
        serve_stdio fn ~L1252
        McpServerConfig L46-169
        ReloadHandle ~L172
        TlsListener ~L846
        shutdown_signal ~L1050
        origin_check_middleware ~L1183
        security_headers_middleware ~L1110
      auth.rs
        AuthIdentity L36-53
        ApiKeyEntry L187-199
        AuthState L386-396
        Argon2 hashing
        auth_middleware
      rbac.rs
        RbacPolicy L259-269
        ArgumentAllowlist
        Task-locals L46-75
          current_role
          current_identity
          current_token
          current_sub
        rbac_middleware L431-535
        build_tool_rate_limiter
      oauth.rs feature=oauth
        JwksCache L264-370
        JWKS_REFRESH_COOLDOWN ~L283
        Discovery endpoints
        OAuth proxy routes
      tool_hooks.rs
        HookedHandler L117-137
        before_call hook
        after_call hook
        Result-size cap
      admin.rs
        /admin/* router
        Diagnostics
        Admin role gated
      observability.rs
        init_tracing
        JSON logs
        Audit-file sink
      metrics.rs feature=metrics
        Prometheus registry
        /metrics listener
        Recording middleware
      config.rs
        TOML schema
        Validation
      error.rs
        McpxError
        IntoResponse mapping
      secret.rs
        secrecy re-exports
    Endpoints
      Open
        /healthz
        /version
      Conditional
        /readyz
        /metrics feature=metrics
        /.well-known/oauth-* feature=oauth
      Admin gated
        /admin/*
      Authenticated
        /mcp rmcp service
    Auth modes
      API key
        Bearer token
        Argon2 hash compare
        ArcSwap hot reload
      mTLS
        TlsListener captures cert
        Keyed by SocketAddr
        x509-parser CN/SAN
        CDP-driven CRL revocation
          Auto-discover from CA chain + client certs
          reqwest fetcher + in-memory cache
          nextUpdate refresh clamped 10min..24h
          Hot-swap verifier via ArcSwap
          Fail-open default; fail-closed opt-in
          SSRF guard since 1.2.1
            scheme allowlist http/https only
            userinfo rejected
            private/loopback/link-local/metadata IPs blocked
            redirect=none for CRL traffic
            crl_max_concurrent_fetches default 4
            crl_max_response_bytes default 5 MiB
            crl_discovery_rate_per_min default 60
            commit-after-admission ordering
      OAuth 2.1 JWT
        JWKS verify
        Cache + cooldown
        Feature gated
        OauthHttpClient since 1.2.1
          with_config preferred
          new deprecated
          HTTPS to HTTP redirect rejected
          HTTP to HTTP gated by allow_http_oauth_urls
          Trust boundary issuer/jwks operator-only
          Per-hop SSRF guard deferred to 1.3.0
    Middleware order
      outer to inner
      1 Origin check
      2 Security headers
      3 CORS
      4 Compression
      5 Body size cap
      6 Timeouts
      7 Concurrency cap optional
      8 Metrics optional
      9 Auth
      10 RBAC
      11 Per-IP tool rate limit
      12 rmcp StreamableHttpService
    State plane
      ArcSwap lock-free
        AuthState.api_keys
        rbac_swap RbacPolicy
      RwLock
        MtlsIdentities by SocketAddr
      Task-local
        Set by middleware
        Read by tool handlers
        Does NOT cross spawn
    Hot reload
      ReloadHandle
        reload_auth_keys
        reload_rbac
      No restart needed
      Eventually consistent
    Cargo features
      oauth off-default
        jsonwebtoken
        reqwest
        urlencoding
      metrics off-default
        prometheus
    Tech stack
      Async tokio 1
      HTTP axum 0.8
      Tower middleware
      TLS rustls 0.23 ring
      Errors thiserror anyhow
      Tracing tracing-subscriber
      Hashing argon2
      Rate limit governor
      Secrets secrecy
      Hot swap arc-swap
      Serde + serde_json + toml
    Tests + Examples
      tests/e2e.rs
        spawn_server L46-71
        Real server on ephemeral ports
        Integration cookbook
      examples/minimal_server.rs
        Smallest consumer
        cargo run --example minimal_server
    Build / verify
      cargo build --all-features
      cargo test --all-features
      cargo +nightly fmt --all -- --check
      cargo clippy --all-targets --all-features -- -D warnings
      cargo doc --no-deps --all-features
      cargo audit
      cargo deny check
      cargo +1.95.0 build --all-features
      cargo semver-checks check-release
    CI / policy
      .github/workflows/ci.yml canonical
      .gitlab-ci.yml mirror
      clippy.toml thresholds
      deny.toml license + ban
      .cargo/audit.toml
      rustfmt.toml
    Coding standards
      RUST_GUIDELINES.md mandatory
      No unwrap / expect prod
      No panic / todo / unimplemented
      No println / eprintln / dbg
      No unsafe forbidden
      No clone to dodge borrowck
      No std::sync::Mutex across await
      Use tracing macros
      Use Result + McpxError
      Use Rust 1.95 idioms
        Vec::push_mut
        Atomic::update
        cfg_select!
    Docs in repo
      AGENTS.md hub
      docs/ARCHITECTURE.md deep ref
      docs/MINDMAP.md this file
      docs/GUIDE.md consumer guide
      docs/MIGRATION.md
      docs/RELEASING.md
      docs/RUST_1_95_NOTES.md
      README.md quick start
      CHANGELOG.md
      CONTRIBUTING.md
      SECURITY.md
      CODE_OF_CONDUCT.md
    Critical pitfalls
      Middleware order is security
      JWKS refresh rate-limited
      Task-local lost across spawn
      stdio bypasses ALL security
      mTLS keyed by SocketAddr
      ArcSwap eventually consistent
      Never log secrets / tokens
```

---

## Request lifecycle (sequence)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant TLS as TlsListener<br/>src/transport.rs:846
    participant R as axum Router
    participant O as origin_check<br/>src/transport.rs:1183
    participant H as security_headers<br/>src/transport.rs:1110
    participant A as auth_middleware<br/>src/auth.rs
    participant B as rbac_middleware<br/>src/rbac.rs:431
    participant L as per-IP rate limit<br/>governor
    participant M as rmcp Streamable<br/>HTTP service
    participant T as ServerHandler<br/>(consumer impl)

    C->>TLS: HTTPS connect (TLS / mTLS)
    TLS->>TLS: record_mtls_identity (if client cert)<br/>src/transport.rs:921
    TLS->>R: HTTP request + peer SocketAddr
    R->>O: route /mcp
    O->>H: origin allowed
    H->>A: security headers attached
    A->>A: API key (Argon2) | mTLS lookup | OAuth JWT
    A-->>R: 401 if invalid
    A->>B: AuthIdentity in task-local
    B->>B: parse JSON-RPC, check tool policy<br/>+ argument allowlist
    B-->>R: 403 if denied
    B->>L: per-IP per-tool token bucket
    L-->>R: 429 if exceeded
    L->>M: pass through
    M->>T: dispatch tools/call (optionally via HookedHandler)
    T-->>M: ToolResult
    M-->>C: JSON-RPC response (streamed)
```

---

## State + hot-reload plane

```mermaid
flowchart LR
    subgraph Admin["Admin / operator"]
        RH[ReloadHandle<br/>src/transport.rs:172]
    end

    subgraph SharedState["Shared state (lock-free / fine-grained)"]
        AKS[(ArcSwap&lt;ApiKeys&gt;<br/>AuthState.api_keys)]
        RBS[(ArcSwap&lt;RbacPolicy&gt;<br/>rbac_swap)]
        MTL[(RwLock&lt;MtlsIdentities&gt;<br/>by SocketAddr)]
    end

    subgraph Hot["Request-time consumers"]
        AM[auth_middleware<br/>src/auth.rs]
        BM[rbac_middleware<br/>src/rbac.rs:431]
        TL["Task-locals<br/>current_role / current_identity<br/>current_token / current_sub<br/>src/rbac.rs:46-75"]
        TH[HookedHandler<br/>src/tool_hooks.rs:117]
    end

    RH -- reload_auth_keys --> AKS
    RH -- reload_rbac --> RBS

    AKS --> AM
    MTL --> AM
    AM -- sets --> TL
    AM --> BM
    RBS --> BM
    BM -- enriches --> TL
    TL --> TH
    TH --> Consumer[Consumer ServerHandler]
```

---

## Module dependency graph

```mermaid
graph TD
    lib[lib.rs<br/>public API surface]
    transport[transport.rs<br/>★ serve / serve_stdio<br/>router + middleware + TLS]
    auth[auth.rs<br/>API key + mTLS + AuthState]
    rbac[rbac.rs<br/>policy + task-locals + rate limit]
    oauth["oauth.rs<br/>JWT + JWKS<br/>(feature=oauth)"]
    admin[admin.rs<br/>/admin/*]
    hooks[tool_hooks.rs<br/>HookedHandler]
    obs[observability.rs<br/>tracing + audit]
    metrics["metrics.rs<br/>Prometheus<br/>(feature=metrics)"]
    config[config.rs<br/>TOML schema]
    error[error.rs<br/>McpxError]
    secret[secret.rs<br/>secrecy re-exports]

    lib --> transport
    lib --> auth
    lib --> rbac
    lib --> oauth
    lib --> admin
    lib --> hooks
    lib --> obs
    lib --> metrics
    lib --> config
    lib --> error
    lib --> secret

    transport --> auth
    transport --> rbac
    transport --> oauth
    transport --> admin
    transport --> hooks
    transport --> obs
    transport --> metrics
    transport --> config
    transport --> error

    auth --> error
    auth --> secret
    rbac --> error
    rbac --> auth
    oauth --> error
    oauth --> auth
    admin --> auth
    admin --> rbac
    hooks --> error
    metrics --> error
    config --> error
```

---

## Key navigation table

| Area                              | Module / file                           | Notable symbols (file:line)                                                  |
|-----------------------------------|------------------------------------------|-------------------------------------------------------------------------------|
| Server entry (HTTP)               | `src/transport.rs`                       | `serve` ~L220, `McpServerConfig` L46-169, `ReloadHandle` ~L172               |
| Server entry (stdio, no auth)     | `src/transport.rs`                       | `serve_stdio` ~L1252                                                          |
| TLS / mTLS acceptor               | `src/transport.rs`                       | `TlsListener` ~L846, `record_mtls_identity` ~L921                            |
| Origin / security headers         | `src/transport.rs`                       | `origin_check_middleware` ~L1183, `security_headers_middleware` ~L1110       |
| Graceful shutdown                 | `src/transport.rs`                       | `shutdown_signal` ~L1050                                                      |
| API key + mTLS auth               | `src/auth.rs`                            | `AuthIdentity` L36-53, `ApiKeyEntry` L187-199, `AuthState` L386-396          |
| RBAC engine                       | `src/rbac.rs`                            | `RbacPolicy` L259-269, task-locals L46-75, `rbac_middleware` L431-535        |
| OAuth JWT / JWKS                  | `src/oauth.rs` (feature `oauth`)         | `JwksCache` L264-370, `JWKS_REFRESH_COOLDOWN` ~L283                          |
| Tool hooks / size cap             | `src/tool_hooks.rs`                      | `HookedHandler` L117-137                                                      |
| Admin diagnostics                 | `src/admin.rs`                           | `/admin/*` router                                                             |
| Tracing / audit log               | `src/observability.rs`                   | `init_tracing`                                                                |
| Prometheus metrics                | `src/metrics.rs` (feature `metrics`)     | registry + `/metrics` listener                                                |
| Configuration (TOML)              | `src/config.rs` + `src/transport.rs`     | TOML schema + `McpServerConfig`                                               |
| Error → HTTP mapping              | `src/error.rs`                           | `McpxError::into_response`                                                    |
| E2E reference                     | `tests/e2e.rs`                           | `spawn_server` L46-71                                                         |
| Runnable example                  | `examples/minimal_server.rs`             | smallest consumer of `serve()`                                                |

---

## How to read this mindmap

1. **Start at the root** — confirms crate identity (library, edition, MSRV).
2. **Modules branch** — every `src/*.rs` file with its key symbols and file:line refs.
3. **Endpoints / Auth modes / Middleware order** — runtime surface of the server.
4. **State plane / Hot reload** — how `ArcSwap` and task-locals coordinate.
5. **Critical pitfalls** — checklist before proposing any change.

For prose explanations of each branch, jump to the matching section in
[`ARCHITECTURE.md`](ARCHITECTURE.md). For workflow rules and "where do I
change X?" lookups, see [`AGENTS.md`](../AGENTS.md).
