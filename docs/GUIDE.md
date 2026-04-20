# rmcp-server-kit -- MCP Server Framework for Rust

A production-grade, reusable framework for building
[Model Context Protocol](https://modelcontextprotocol.io/) servers in Rust.
Provides Streamable HTTP transport with TLS/mTLS, structured observability,
authentication (Bearer / mTLS / OAuth 2.1 JWT), role-based access control
(RBAC), per-IP rate limiting, and Prometheus metrics -- all wired up and
ready to go.

You supply a `ServerHandler` implementation; rmcp-server-kit handles everything else.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Cargo Features](#cargo-features)
- [Architecture Overview](#architecture-overview)
- [Module Reference](#module-reference)
  - [transport](#transport) -- HTTP server, TLS, health endpoints
  - [auth](#auth) -- Authentication middleware
  - [rbac](#rbac) -- Role-based access control
  - [config](#config) -- Server and observability configuration
  - [error](#error) -- Error types
  - [observability](#observability) -- Tracing and logging
  - [oauth](#oauth) -- OAuth 2.1 JWT validation (feature-gated)
  - [metrics](#metrics) -- Prometheus metrics (feature-gated)
- [Additional Built-in Endpoints and Features](#additional-built-in-endpoints-and-features)
- [Full Example: Building a Custom MCP Server](#full-example-building-a-custom-mcp-server)
- [Client Usage Guide](#client-usage-guide)
- [Recipes](#recipes)
- [Configuration via TOML](#configuration-via-toml)
- [Testing Your Server](#testing-your-server)

---

## Quick Start

Add rmcp-server-kit to your `Cargo.toml`:

```toml
[dependencies]
rmcp-server-kit = { version = "1", features = ["oauth"] }
rmcp = { version = "1.5", features = ["server", "macros"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal"] }
```

Implement `ServerHandler` and call `serve()`:

```rust
use rmcp_server_kit::transport::{McpServerConfig, serve};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{ServerCapabilities, ServerInfo};

#[derive(Clone)]
struct MyHandler;

impl ServerHandler for MyHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

#[tokio::main]
async fn main() -> rmcp_server_kit::Result<()> {
    let _ = rmcp_server_kit::observability::init_tracing("info,my_server=debug");

    let config = McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0")
        .with_request_timeout(std::time::Duration::from_secs(30))
        .enable_request_header_logging();
    serve(config.validate()?, || MyHandler).await
}
```

This gives you `/healthz`, `/readyz`, and `/mcp` endpoints out of the box.

---

## Cargo Features

| Feature   | Default | Description |
|-----------|---------|-------------|
| `oauth`   | No      | OAuth 2.1 JWT validation via JWKS. Adds `jsonwebtoken` and `reqwest`. |
| `metrics` | No      | Prometheus metrics endpoint on a separate listener. Adds `prometheus`. |

Enable in `Cargo.toml`:

```toml
rmcp-server-kit = { version = "1", features = ["oauth", "metrics"] }
```

---

## Architecture Overview

```
                    +-----------+
                    |  Your App |   (bin crate)
                    |           |
                    | MyHandler |---implements---> rmcp::ServerHandler
                    +-----+-----+
                          |
                          | depends on
                          v
                    +-----------------+
                    | rmcp-server-kit |   (lib crate)
                    |                 |
                    | transport       |   Streamable HTTP + TLS/mTLS
                    | auth            |   Bearer, mTLS, OAuth JWT
                    | rbac            |   Role-based access control
                    | config          |   Server/observability config
                    | error           |   McpxError -> HTTP status codes
                    | metrics         |   Prometheus (optional)
                    | oauth           |   JWT/JWKS validation (optional)
                    +-----------------+
                          |
                          | uses
                          v
                    +-----------+
                    |   rmcp    |   Official MCP SDK
                    |   axum    |   HTTP framework
                    |  rustls   |   TLS
                    | governor  |   Rate limiting
                    |  argon2   |   Password hashing
                    +-----------+
```

**Key design rule:** rmcp-server-kit is generic. It has zero knowledge of your domain
(Podman, Docker, databases, etc.). Your crate supplies the `ServerHandler`;
rmcp-server-kit supplies the server infrastructure.

---

## Module Reference

### transport

The core module. Provides `serve()` which starts the full HTTP server stack.

#### `McpServerConfig`

Server configuration. All fields have safe defaults except `bind_addr`,
`name`, and `version`.

```rust
use rmcp_server_kit::transport::McpServerConfig;
use std::time::Duration;

// Builder style (recommended): chain `with_*` / `enable_*` methods.
let config = McpServerConfig::new("0.0.0.0:8443", "my-server", "1.0.0")
    // Optional: TLS (enables HTTPS)
    .with_tls("/etc/certs/server.crt", "/etc/certs/server.key")
    // Optional: DNS rebinding protection (MCP spec requirement)
    .with_allowed_origins([
        "http://localhost:3000",
        "https://myapp.example.com",
    ])
    // Optional: request limits
    .with_max_request_body(2 * 1024 * 1024) // 2 MiB
    .with_request_timeout(Duration::from_secs(60))
    .with_shutdown_timeout(Duration::from_secs(10))
    // Optional: per-IP tool rate limiting (calls/minute)
    .with_tool_rate_limit(60);

// Validate eagerly to surface misconfiguration before binding.
// `serve()` and `serve_with_listener()` also call this internally.
config.validate().expect("config valid");
```

> **Note**: Direct field assignment on `McpServerConfig` is still
> supported (the struct fields remain `pub`), but the builder is the
> recommended path because it is `#[must_use]`, chainable, and routes
> through `validate()` automatically when passed to `serve()`.

##### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind_addr` | `String` | (required) | Socket address, e.g. `"0.0.0.0:8443"` |
| `name` | `String` | (required) | Server name, returned in `/healthz` |
| `version` | `String` | (required) | Server version, returned in `/healthz` |
| `tls_cert_path` | `Option<PathBuf>` | `None` | PEM certificate for TLS |
| `tls_key_path` | `Option<PathBuf>` | `None` | PEM private key for TLS |
| `auth` | `Option<AuthConfig>` | `None` | Authentication config |
| `rbac` | `Option<Arc<RbacPolicy>>` | `None` | RBAC enforcement policy |
| `allowed_origins` | `Vec<String>` | `[]` | Allowed Origin header values |
| `tool_rate_limit` | `Option<u32>` | `None` | Max tool calls/min per IP |
| `readiness_check` | `Option<ReadinessCheck>` | `None` | Custom `/readyz` probe |
| `max_request_body` | `usize` | `1 MiB` | Max request body bytes |
| `request_timeout` | `Duration` | `120s` | Per-request timeout (408) |
| `shutdown_timeout` | `Duration` | `30s` | Graceful shutdown window |
| `metrics_enabled` | `bool` | `false` | Enable Prometheus (feature: `metrics`) |
| `metrics_bind` | `String` | `"127.0.0.1:9090"` | Metrics listener (feature: `metrics`) |

#### `serve()`

```rust
pub async fn serve<H, F>(config: McpServerConfig, handler_factory: F) -> rmcp_server_kit::Result<()>
where
    H: ServerHandler + 'static,
    F: Fn() -> H + Send + Sync + Clone + 'static,
```

Starts the HTTP server. The `handler_factory` is a closure that creates a
fresh handler for each MCP session. The server:

- Binds TCP (or TLS when cert/key provided)
- Registers `/healthz` (always 200), `/readyz` (custom or mirrors healthz),
  `/mcp` (MCP Streamable HTTP endpoint)
- Applies middleware layers: Origin validation -> Auth -> RBAC + tool
  rate-limit -> Request timeout -> Body size limit
- Listens for SIGTERM/SIGINT for graceful shutdown
- Cancels active MCP sessions on shutdown

#### `ReadinessCheck`

Custom readiness probe for `/readyz`:

```rust
use rmcp_server_kit::transport::ReadinessCheck;
use std::sync::Arc;

let check: ReadinessCheck = Arc::new(|| {
    Box::pin(async {
        let db_ok = check_database().await;
        serde_json::json!({
            "ready": db_ok,
            "database": if db_ok { "connected" } else { "unreachable" }
        })
    })
});

config.readiness_check = Some(check);
```

When the returned JSON has `"ready": false`, `/readyz` returns HTTP 503.

#### Health Endpoints

Both endpoints return JSON:

```
GET /healthz -> 200 {"status":"ok"}
GET /readyz  -> 200 {"ready":true,...} or 503 {"ready":false,"reason":"..."}
```

---

### auth

Authentication middleware supporting three methods (tried in priority order):

1. **mTLS client certificates** -- extracted during TLS handshake
2. **Bearer tokens** -- API keys verified against Argon2id hashes
3. **OAuth 2.1 JWT** -- validated against JWKS endpoint (feature: `oauth`)

#### `AuthConfig`

```rust
use rmcp_server_kit::auth::{AuthConfig, ApiKeyEntry, RateLimitConfig};

// Simple: just API keys
let auth = AuthConfig::with_keys(vec![
    ApiKeyEntry::new("deploy-bot", hash, "ops"),
    ApiKeyEntry::new("readonly", ro_hash, "viewer"),
]);

// With rate limiting
let auth = AuthConfig::with_keys(vec![
    ApiKeyEntry::new("admin", hash, "admin"),
])
.with_rate_limit(RateLimitConfig::new(30));
```

##### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Master switch (`with_keys()` sets true) |
| `api_keys` | `Vec<ApiKeyEntry>` | `[]` | Bearer token API keys |
| `mtls` | `Option<MtlsConfig>` | `None` | mTLS client cert config |
| `rate_limit` | `Option<RateLimitConfig>` | `None` | Auth attempt rate limit |
| `oauth` | `Option<OAuthConfig>` | `None` | OAuth 2.1 (feature: `oauth`) |

##### Constructors

| Method | Description |
|--------|-------------|
| `AuthConfig::default()` | Disabled (no auth enforced) |
| `AuthConfig::with_keys(keys)` | Enabled with API keys |
| `.with_rate_limit(config)` | Builder: attach rate limiting |

#### `ApiKeyEntry`

Represents a single API key. The `hash` field stores an Argon2id PHC string.

```rust
use rmcp_server_kit::auth::{generate_api_key, ApiKeyEntry};

// Generate a new key pair (returns Result<_, McpxError>)
let (plaintext_token, argon2id_hash) = generate_api_key()?;
// plaintext_token: 43-char base64url string (give to client)
// argon2id_hash:   PHC format string (store in config)

let key = ApiKeyEntry::new("my-key", argon2id_hash, "ops");

// With expiry
let key = ApiKeyEntry::new("temp-key", hash, "viewer")
    .with_expiry("2025-12-31T23:59:59Z");
```

#### `RateLimitConfig`

Per-source-IP rate limiting for authentication. rmcp-server-kit uses two independent
token-bucket limiters keyed by source IP:

1. **Pre-auth abuse gate** (`pre_auth_max_per_minute`, optional): consulted
   *before* any password-hash work runs. Throttles unauthenticated traffic
   from a single source IP so an attacker cannot pin the CPU on Argon2id by
   spraying invalid bearer tokens. Defaults to **10x** the post-failure
   quota when unset, and is disabled entirely if the wrapping
   `RateLimitConfig` is itself absent. mTLS-authenticated connections
   bypass this gate entirely (the TLS handshake already performed
   expensive crypto with a verified peer, so the CPU-spray vector does
   not apply).
2. **Post-failure backoff** (`max_attempts_per_minute`, required):
   consulted *after* an authentication attempt fails. Provides explicit
   backpressure on bad credentials.

```rust
use rmcp_server_kit::auth::RateLimitConfig;

// Default: 30 failed attempts/min and ~300 unauthenticated requests/min
// (10x default) per source IP.
let rate_limit = RateLimitConfig::new(30);

// Tighter pre-auth gate, e.g. for a public-facing instance:
let rate_limit = RateLimitConfig::new(30).with_pre_auth_max_per_minute(60);
```

When exceeded, the middleware returns HTTP 429 Too Many Requests.

#### `generate_api_key()`

```rust
pub fn generate_api_key() -> Result<(String, String), McpxError>
```

Returns `Ok((plaintext_token, argon2id_hash))`. The token is 256-bit random,
base64url-encoded (43 characters). Store the hash in your config file; give
the plaintext token to the client. The `Result` accommodates the rare case
where the OS RNG fails.

#### `AuthIdentity`

Populated by the auth middleware in request extensions upon successful
authentication. Available to your handler via `current_role()` and
`current_identity()` (see rbac module).

```rust
pub struct AuthIdentity {
    pub name: String,       // e.g. "deploy-bot" or mTLS CN
    pub role: String,       // e.g. "ops", "viewer", "admin"
    pub method: AuthMethod, // BearerToken, MtlsCertificate, OAuthJwt
}
```

#### `AuthMethod`

```rust
pub enum AuthMethod {
    BearerToken,
    MtlsCertificate,
    OAuthJwt,
}
```

#### `MtlsConfig`

For mutual TLS client certificate authentication:

```toml
# In your TOML config:
[server.auth.mtls]
ca_cert_path = "/etc/certs/client-ca.pem"
required = true
default_role = "operator"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ca_cert_path` | `PathBuf` | (required) | CA cert(s) for client cert verification |
| `required` | `bool` | `false` | If true, clients MUST present a cert |
| `default_role` | `String` | `"viewer"` | RBAC role for mTLS-authenticated clients |

#### `extract_mtls_identity()`

```rust
pub fn extract_mtls_identity(cert_der: &[u8], default_role: &str) -> Option<AuthIdentity>
```

Parses an X.509 DER certificate and extracts the Common Name (CN) or first
DNS SAN as the identity name. Used internally by the TLS acceptor.

#### Certificate lifecycle and revocation (operator runbook)

> ✅ **Since 1.2.0, rmcp-server-kit performs CDP-driven CRL revocation
> checking for client certificates by default whenever `[mtls]` is
> configured.** OCSP is **not** implemented. See
> [SECURITY.md](../SECURITY.md#certificate-revocation) for the full
> threat model.

CRL URLs are auto-discovered from the X.509 **CRL Distribution Points**
(CDP) extension on the configured CA chain (eagerly at startup, with a
10-second total bootstrap deadline) and from each new client certificate
observed during a TLS handshake (lazily). CRLs are cached in memory keyed
by URL and refreshed on a background task before `nextUpdate`, clamped to
`[10 min, 24 h]`. The underlying `rustls::ClientCertVerifier` is hot-swapped
via `ArcSwap` whenever fresh CRLs land, so handshakes always see the
latest revocation data without dropping in-flight connections.

**Default behaviour is fail-open**: if a CRL cannot be fetched or has
expired beyond `crl_stale_grace`, the handshake is still allowed and a
`WARN` log is emitted. Operators who require fail-closed semantics can set
`crl_deny_on_unavailable = true`.

`ReloadHandle::refresh_crls()` forces an immediate refresh of every
cached CRL — useful from an admin endpoint or a cron-driven probe.

##### CRL configuration (TOML, all defaults shown)

```toml
[mtls]
ca_cert_path = "/etc/certs/clients-ca.pem"

crl_enabled              = true     # set false to disable revocation entirely
crl_deny_on_unavailable  = false    # fail-open by default; set true for fail-closed
crl_allow_http           = true     # allow http:// CDP URLs (CRLs are signed by the CA)
crl_end_entity_only      = false    # check the full chain, not just the leaf
crl_enforce_expiration   = true     # reject CRLs whose nextUpdate is in the past (subject to grace)
crl_fetch_timeout        = "30s"    # per-fetch HTTP timeout
crl_stale_grace          = "24h"    # how long an expired CRL can still be trusted while we keep retrying
# crl_refresh_interval   = "1h"     # override the auto interval derived from nextUpdate

# SSRF / DoS hardening knobs (since 1.2.1; defaults shown):
crl_max_concurrent_fetches = 4         # global parallel CRL fetches across all hosts
                                       # (per-host concurrency is hard-capped at 1)
crl_max_response_bytes     = 5242880   # 5 MiB hard cap; streams aborted mid-response when exceeded
crl_discovery_rate_per_min = 60        # process-global rate limit on *new* CDP URLs admitted
                                       # to the fetch pipeline; URLs that lose the race are
                                       # NOT marked as seen and may retry on the next handshake
crl_max_host_semaphores    = 1024      # caps unique CDP hosts tracked (since 1.3.0)
crl_max_seen_urls          = 4096      # caps URL-deduplication map (since 1.3.0)
crl_max_cache_entries      = 1024      # caps parsed CRLs held in memory (since 1.3.0)
```

> **Tuning guidance.** The defaults are calibrated for a typical
> single-tenant deployment. Raise `crl_discovery_rate_per_min` when you
> expect bursts of *distinct* client identities pointing at many
> distinct CDP URLs (e.g. multi-PKI federations); leave it conservative
> when CDPs are few and stable. Lower `crl_max_response_bytes` if your
> CA publishes only small CRLs; raise it cautiously for very large
> revocation lists. `crl_max_concurrent_fetches` is the global SSRF
> blast-radius bound — keep it low. Raise `crl_max_seen_urls` and
> `crl_max_cache_entries` if your PKI hierarchy is unusually deep
> or diverse.

##### Defence-in-depth (still recommended even with CRL enabled)

CRL checking does not eliminate the value of the strategies below — combine
them for the strongest posture:

1. **Short-lived certificates (recommended).** Issue client certs with a
   maximum lifetime of **24 hours or less** so that compromised
   credentials expire on their own. Supported issuers:

   - **[cert-manager](https://cert-manager.io/)** — Kubernetes-native
     issuer; configure `Certificate.spec.duration: 24h` and
     `renewBefore: 8h`. Pair with the CSI driver to deliver short-lived
     certs to workload pods without restart.
   - **[HashiCorp Vault PKI](https://developer.hashicorp.com/vault/docs/secrets/pki)**
     — set `max_ttl` on the role to `24h` and have clients re-issue
     via `vault write pki/issue/<role>` on a cron / sidecar.
   - **[Smallstep `step-ca`](https://smallstep.com/docs/step-ca/)** —
     configure provisioner `claims.maxTLSCertDuration: 24h`; use
     `step ca renew --daemon` for hands-off rotation.

2. **CA rotation on compromise.** If a long-lived cert leaks, rotate
   the issuing CA and update `mtls.ca_cert_path` in your rmcp-server-kit config.
   Use `ReloadHandle::reload_*` (see `transport::ReloadHandle`) for a
   zero-downtime swap.

3. **Network-layer revocation.** Block compromised client identities at
   the load balancer, service mesh (Istio/Linkerd `AuthorizationPolicy`),
   or WAF. This is the only mechanism with sub-second propagation.

If your PKI publishes revocation only via OCSP (no CDP), CRL checking
will not protect you. Prefer the Bearer or OAuth 2.1 JWT auth methods,
which support immediate revocation via the RFC 7009 revocation endpoint
(`oauth.revocation_endpoint`) or by deleting the API key entry and
calling `ReloadHandle::reload_auth_keys`.

#### `build_rate_limiter()`

```rust
pub fn build_rate_limiter(config: &RateLimitConfig) -> Arc<KeyedLimiter>
```

Builds a per-source-IP rate limiter from config. Used internally by
`serve()`.

---

### rbac

Role-based access control with deny-overrides-allow semantics, per-tool
argument allowlists, and host-scoped visibility.

#### `RbacConfig`

```rust
use rmcp_server_kit::rbac::{RbacConfig, RoleConfig, ArgumentAllowlist};

let config = RbacConfig::with_roles(vec![
    // Admin: full access
    RoleConfig::new("admin", vec!["*".into()], vec!["*".into()]),

    // Ops: most tools, all hosts
    RoleConfig::new(
        "ops",
        vec!["container_*".into(), "image_*".into(), "pod_*".into()],
        vec!["*".into()],
    ),

    // Viewer: read-only, specific hosts only
    RoleConfig::new(
        "viewer",
        vec!["container_list".into(), "container_inspect".into()],
        vec!["prod-*".into()],
    ),

    // Restricted exec: can run only safe commands
    RoleConfig::new(
        "restricted",
        vec!["container_exec".into()],
        vec!["*".into()],
    )
    .with_argument_allowlists(vec![
        ArgumentAllowlist::new(
            "container_exec",
            "cmd",
            vec!["ls".into(), "cat".into(), "ps".into(), "df".into()],
        ),
    ]),
]);
```

##### Constructors

| Method | Description |
|--------|-------------|
| `RbacConfig::default()` | Disabled (all operations allowed) |
| `RbacConfig::with_roles(roles)` | Enabled with the given role definitions |

##### Optional fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `redaction_salt` | `Option<SecretString>` | `None` | Stable HMAC key used to redact denied argument values in deny logs. When omitted, a random per-process salt is used. See the `[rbac]` TOML example below. |

#### `RoleConfig`

A single role definition.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `String` | (required) | Role name, matched against `ApiKeyEntry.role` |
| `description` | `Option<String>` | `None` | Human-readable description |
| `allow` | `Vec<String>` | `[]` | Allowed operations; `["*"]` = all |
| `deny` | `Vec<String>` | `[]` | Denied operations (overrides allow) |
| `hosts` | `Vec<String>` | `["*"]` | Host glob patterns |
| `argument_allowlists` | `Vec<ArgumentAllowlist>` | `[]` | Per-tool argument constraints |

##### Constructors

| Method | Description |
|--------|-------------|
| `RoleConfig::new(name, allow, hosts)` | Create with required fields |
| `.with_argument_allowlists(vec)` | Builder: attach allowlists |

**Evaluation order:** deny is checked first (deny overrides allow).

#### `ArgumentAllowlist`

Constrains specific arguments on tool calls:

```rust
let allowlist = ArgumentAllowlist::new(
    "container_exec",  // tool name
    "cmd",             // argument key
    vec!["ls".into(), "cat".into()],  // permitted command prefixes
);
```

When a `tools/call` request arrives for the matched tool, the middleware
extracts the argument value, takes the first whitespace-delimited token (or
`/`-basename), and checks it against the allowlist. If not found, the request
is rejected with 403.

#### `RbacPolicy`

Compiled policy for fast lookups. Built from `RbacConfig` at startup.

```rust
use rmcp_server_kit::rbac::{RbacPolicy, RbacConfig, RbacDecision};
use std::sync::Arc;

let config = RbacConfig::with_roles(vec![/* ... */]);
let policy = Arc::new(RbacPolicy::new(&config));

// Check if a role can perform an operation
assert_eq!(
    policy.check_operation("admin", "container_delete"),
    RbacDecision::Allow,
);
assert_eq!(
    policy.check_operation("viewer", "container_delete"),
    RbacDecision::Deny,
);

// Check with host
assert_eq!(
    policy.check("viewer", "container_list", "prod-east"),
    RbacDecision::Allow,
);

// Check argument allowlist
assert!(policy.argument_allowed("restricted", "container_exec", "cmd", "ls -la"));
assert!(!policy.argument_allowed("restricted", "container_exec", "cmd", "rm -rf /"));

// Host visibility (for filtering list results)
assert!(policy.host_visible("viewer", "prod-east"));
assert!(!policy.host_visible("viewer", "dev-west"));
```

##### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `new(config)` | `Self` | Build from `RbacConfig` |
| `disabled()` | `Self` | Always-allow policy |
| `is_enabled()` | `bool` | Whether enforcement is active |
| `check_operation(role, op)` | `RbacDecision` | Check without host |
| `check(role, op, host)` | `RbacDecision` | Check with host |
| `host_visible(role, host)` | `bool` | For list filtering |
| `host_patterns(role)` | `Option<&[String]>` | Get host patterns |
| `argument_allowed(role, tool, arg, val)` | `bool` | Check per-tool allowlists |

#### Task-Local Accessors

Inside your tool handlers, retrieve the current caller's identity:

```rust
use rmcp_server_kit::rbac::{current_role, current_identity};

fn handle_tool_call() {
    if let Some(role) = current_role() {
        tracing::info!(%role, "caller role");
    }
    if let Some(name) = current_identity() {
        tracing::info!(identity = %name, "caller identity");
    }
}
```

These are set by the RBAC middleware for the duration of the request.

#### `RbacDecision`

```rust
pub enum RbacDecision {
    Allow,
    Deny,
}
```

#### `build_tool_rate_limiter()`

```rust
pub fn build_tool_rate_limiter(max_per_minute: u32) -> Arc<ToolRateLimiter>
```

Builds a per-source-IP rate limiter for tool invocations. You configure this
via `McpServerConfig.tool_rate_limit`; the function is used internally.

---

### config

Configuration structs for TOML-based server configuration. Useful when your
app loads config from a file rather than building `McpServerConfig`
programmatically.

#### `ServerConfig`

```toml
[server]
listen_addr = "0.0.0.0"
listen_port = 8443
tls_cert_path = "/etc/certs/server.crt"
tls_key_path = "/etc/certs/server.key"
allowed_origins = ["http://localhost:3000"]
tool_rate_limit = 120
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_addr` | `String` | `"127.0.0.1"` | Bind address |
| `listen_port` | `u16` | `8443` | Bind port |
| `tls_cert_path` | `Option<PathBuf>` | `None` | TLS certificate path |
| `tls_key_path` | `Option<PathBuf>` | `None` | TLS private key path |
| `shutdown_timeout` | `String` | `"30s"` | Humantime duration |
| `request_timeout` | `String` | `"120s"` | Humantime duration |
| `allowed_origins` | `Vec<String>` | `[]` | Origin validation |
| `stdio_enabled` | `bool` | `false` | Enable stdio transport |
| `tool_rate_limit` | `Option<u32>` | `None` | Tool calls/min per IP |

#### `ObservabilityConfig`

```toml
[observability]
log_level = "debug"
log_format = "json"
audit_log_path = "/var/log/my-server/audit.log"
metrics_enabled = true
metrics_bind = "127.0.0.1:9090"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log_level` | `String` | `"info"` | trace, debug, info, warn, error |
| `log_format` | `String` | `"json"` | json or pretty |
| `audit_log_path` | `Option<PathBuf>` | `None` | JSON audit log file |
| `metrics_enabled` | `bool` | `false` | Enable Prometheus |
| `metrics_bind` | `String` | `"127.0.0.1:9090"` | Metrics listener |

#### Validation

```rust
use rmcp_server_kit::config::{
    ServerConfig, ObservabilityConfig,
    validate_server_config, validate_observability_config,
};

let server: ServerConfig = toml::from_str(&config_str)?;
validate_server_config(&server)?;  // Checks port, TLS pairing, durations

let obs: ObservabilityConfig = toml::from_str(&config_str)?;
validate_observability_config(&obs)?;  // Checks log levels, formats
```

Returns `McpxError::Config` with a descriptive message on failure.

---

### error

#### `McpxError`

Central error type with automatic HTTP status code mapping:

```rust
pub enum McpxError {
    Config(String),          // -> 500 Internal Server Error
    Auth(String),            // -> 401 Unauthorized
    Rbac(String),            // -> 403 Forbidden
    RateLimited(String),     // -> 429 Too Many Requests
    Io(std::io::Error),      // -> 500
    Json(serde_json::Error), // -> 500
    Toml(toml::de::Error),   // -> 500
    Other(anyhow::Error),    // -> 500
}
```

Implements `IntoResponse` for axum, so you can return `McpxError` directly
from handlers and middleware.

#### `Result<T>`

```rust
pub type Result<T> = std::result::Result<T, McpxError>;
```

---

### observability

#### `init_tracing(default_filter)`

Simple tracing initialization. Returns `Result<(), TryInitError>` so it
is safe to call from tests or embedders that may have already installed
a global subscriber:

```rust
rmcp_server_kit::observability::init_tracing("info,my_crate=debug")?;
```

Respects `RUST_LOG` environment variable (takes precedence over the default).
The `Err` variant indicates that a global tracing subscriber was already
installed; production binaries can propagate the error, while embedders
that tolerate double-initialization can ignore it (`let _ = init_tracing(..)`).

#### `init_tracing_from_config(config)`

Full initialization from `ObservabilityConfig`. Same `Result` semantics
as [`init_tracing`]:

```rust
use rmcp_server_kit::config::ObservabilityConfig;

let obs: ObservabilityConfig = toml::from_str(&config_toml)?;
rmcp_server_kit::observability::init_tracing_from_config(&obs)?;
```

Features:
- JSON or pretty-printed output
- Optional JSON audit log file (append mode, auto-creates parent dirs)
- `RUST_LOG` env var takes precedence

---

### oauth

*Requires feature: `oauth`*

OAuth 2.1 JWT bearer token authentication with JWKS-based key rotation.

#### `OAuthConfig`

```toml
[server.auth.oauth]
issuer = "https://auth.example.com"
audience = "my-mcp-server"
jwks_uri = "https://auth.example.com/.well-known/jwks.json"
jwks_cache_ttl = "10m"

[[server.auth.oauth.scopes]]
scope = "mcp:admin"
role = "admin"

[[server.auth.oauth.scopes]]
scope = "mcp:read"
role = "viewer"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `issuer` | `String` | -- | Expected `iss` claim. |
| `audience` | `String` | -- | Expected `aud` claim. |
| `jwks_uri` | `String` | -- | JWKS endpoint URL. |
| `scopes` | `Vec<ScopeMapping>` | `[]` | OAuth scope -> RBAC role mapping. |
| `jwks_cache_ttl` | `String` | `"10m"` | JWKS cache refresh interval. |
| `max_jwks_keys` | `usize` | `256` | Fail-closed cap on public keys in a JWKS document (since 1.3.0). |
| `allow_http_oauth_urls` | `bool` | `false` | Permit `http://` issuer/JWKS/etc. for local dev only. |

#### SSRF and DoS Hardening (OAuth)

As of **1.3.0**, OAuth URL hardening operates in two layers:

- **At config-construction time**, `OAuthConfig::validate` rejects any of
  the six configured URL fields (`issuer`, `jwks_uri`, `authorization_endpoint`,
  `token_endpoint`, `revocation_endpoint`, `introspection_endpoint`) that
  contain HTTP userinfo (`user:pass@host`) or that use a literal IP host
  (IPv4 or IPv6). Operators must use DNS hostnames.
- **At runtime, on every HTTP redirect hop**, both the shared
  `OauthHttpClient` and the `JwksCache` redirect closures run a sync
  per-hop SSRF guard that rejects targets resolving to private, loopback,
  link-local, multicast, broadcast, unspecified, or cloud-metadata
  IP ranges. `https -> http` downgrades are always rejected; `http -> http`
  is permitted only when `allow_http_oauth_urls = true`.

There is also a fail-closed cap on the JWKS key count:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_jwks_keys` | `usize` | `256` | Fail-closed cap on public keys in a JWKS document. |

The redirect-hop limit (max 2) and per-request HTTP timeouts are enforced
internally and are not configurable knobs in 1.3.0.

---

### metrics

*Requires feature: `metrics`*

Prometheus metrics collection and exposition.

#### `McpMetrics`

```rust
use rmcp_server_kit::metrics::McpMetrics;

let metrics = McpMetrics::new()?;

// After handling some requests...
let prometheus_text = metrics.encode();
tracing::info!(%prometheus_text, "exposition snapshot");
```

Tracks:
- `http_requests_total` -- counter by method, path, status
- `http_request_duration_seconds` -- histogram by method, path

#### `serve_metrics()`

```rust
pub async fn serve_metrics(bind: String, metrics: Arc<McpMetrics>) -> rmcp_server_kit::Result<()>
```

Spawns a dedicated HTTP listener serving `/metrics` in Prometheus text format.
You don't call this directly -- rmcp-server-kit spawns it automatically when
`metrics_enabled = true` on `McpServerConfig`.

---

## Additional Built-in Endpoints and Features

### `/version`

Always-on unauthenticated endpoint that returns a small JSON payload
describing the running binary:

```json
{
  "name": "my-server",
  "version": "1.2.3",
  "build_sha": "abcdef0",
  "build_time": "2025-01-15T12:00:00Z",
  "rust_version": "rustc 1.95.0",
  "mcpx_version": "1.0.0"
}
```

`build_sha`, `build_time`, and `rust_version` are populated from the
`MCPX_BUILD_SHA`, `MCPX_BUILD_TIME`, and `MCPX_RUSTC_VERSION` build-time
environment variables.  Unset variables become `null`.

### Response compression

Set `compression_enabled = true` on `McpServerConfig` to enable gzip and
brotli content-encoding for responses larger than `compression_min_size`
bytes (default 1024). Compression is negotiated via `Accept-Encoding`.

### Global concurrency limit

Set `max_concurrent_requests = Some(N)` to cap in-flight HTTP requests
across the server. When the cap is reached, excess requests are shed
with `503 Service Unavailable` (JSON body `{"error":"overloaded"}`)
rather than queued.

### `/admin/*` diagnostic endpoints (opt-in)

When `admin_enabled = true` and an authenticated role equal to
`admin_role` (default `"admin"`) is configured, rmcp-server-kit exposes:

- `GET /admin/status` -- server name, version, uptime.
- `GET /admin/auth/keys` -- names, roles, and expiry of configured API
  keys (never the hashes).
- `GET /admin/auth/counters` -- authentication success/failure counters.
- `GET /admin/rbac` -- the live RBAC policy summary.

All four require a caller with the admin role; every other role gets
`403 forbidden`. The endpoints participate in the normal auth/RBAC
middleware stack, so anonymous access is never possible.

`admin_enabled = true` with no configured authentication fails at
startup with a configuration error.

### `Secret<T>` re-exports

`rmcp_server_kit::secret` re-exports `ExposeSecret`, `SecretBox`, and `SecretString`
from [`secrecy`]. Prefer these wrappers for any secret-bearing fields
added to application config structs so that `Debug` and serialization
never leak plaintext.

### OAuth 2.1 introspection (RFC 7662) and revocation (RFC 7009)

Set `OAuthProxyConfig::introspection_url` and/or
`OAuthProxyConfig::revocation_url` to upstream endpoint URLs and rmcp-server-kit
will expose matching local proxies:

- `POST /introspect` -- forwards the form body to the upstream
  introspection endpoint, injecting `client_id` (and
  `client_secret` for confidential clients) before forwarding.
- `POST /revoke` -- same shape for token revocation.

The Authorization Server Metadata document
(`/.well-known/oauth-authorization-server`) automatically advertises
`introspection_endpoint` and `revocation_endpoint` only when the
corresponding URLs are configured.

### Tool hooks and result-size cap

`rmcp_server_kit::tool_hooks::HookedHandler` is an opt-in wrapper around any
`ServerHandler` that adds:

- An async `before` hook that returns `HookOutcome::Continue` (proceed),
  `HookOutcome::Deny(rmcp::ErrorData)` (short-circuit with a
  structured JSON-RPC error), or
  `HookOutcome::Replace(Box<rmcp::model::CallToolResult>)`
  (short-circuit with a synthesized result).
- An async `after` hook that observes each completed call along with
  the approximate serialized result size in bytes and a
  `HookDisposition` describing what actually happened
  (`InnerExecuted`, `InnerErrored`, `DeniedBefore`, `ReplacedBefore`,
  `ResultTooLarge`). After-hooks run via `tokio::spawn`, so they never
  block the response path; panics inside them are isolated from the
  caller.
- A hard `max_result_bytes` cap: oversized tool results (whether
  produced by the inner handler or returned via `Replace`) are
  swapped for a structured `result_too_large` error before reaching
  the client.

Applications opt in at their handler-factory callsite using the
fluent `ToolHooks::new()` builder (the struct is `#[non_exhaustive]`,
so direct struct-literal construction is no longer supported):

```rust
use std::sync::Arc;
use rmcp_server_kit::tool_hooks::{HookOutcome, ToolHooks, with_hooks};

let hooks = Arc::new(
    ToolHooks::new()
        .with_max_result_bytes(256 * 1024)
        .with_before(Arc::new(|ctx| Box::pin(async move {
            // Example: deny calls to any tool whose name starts with
            // "danger_" unless the caller is in the "admin" role.
            if ctx.tool_name.starts_with("danger_")
                && ctx.role.as_deref() != Some("admin")
            {
                return HookOutcome::Deny(rmcp::ErrorData::invalid_request(
                    "tool restricted to admin role",
                    None,
                ));
            }
            HookOutcome::Continue
        })))
        .with_after(Arc::new(|ctx, disposition, size_bytes| {
            let tool = ctx.tool_name.clone();
            Box::pin(async move {
                tracing::info!(
                    %tool,
                    ?disposition,
                    size_bytes,
                    "tool call observed"
                );
            })
        })),
);

let handler = with_hooks(MyHandler::new(), hooks);
// ...pass `handler` to `serve()`...
```

`rmcp_server_kit::serve()` itself never wraps handlers automatically.

---

## Full Example: Building a Custom MCP Server

A complete server with auth, RBAC, custom tools, and readiness probe:

```rust
use std::sync::Arc;

use rmcp_server_kit::auth::{AuthConfig, ApiKeyEntry, RateLimitConfig, generate_api_key};
use rmcp_server_kit::rbac::{RbacConfig, RbacPolicy, RoleConfig, current_role};
use rmcp_server_kit::transport::{McpServerConfig, serve};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{tool, Error as McpError};

#[derive(Clone)]
struct MyHandler;

#[tool(tool_box)]
impl MyHandler {
    /// Greet a user by name.
    #[tool(description = "Say hello")]
    async fn greet(&self, #[tool(param)] name: String) -> Result<String, McpError> {
        let role = current_role().unwrap_or_else(|| "unknown".into());
        Ok(format!("Hello, {name}! (caller role: {role})"))
    }

    /// List available items (safe for viewers).
    #[tool(description = "List items")]
    async fn list_items(&self) -> Result<String, McpError> {
        Ok("item-1, item-2, item-3".into())
    }
}

#[tool(tool_box)]
impl ServerHandler for MyHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

#[tokio::main]
async fn main() -> rmcp_server_kit::Result<()> {
    let _ = rmcp_server_kit::observability::init_tracing("info");

    // Generate API keys (in production, store hashes in a config file)
    let (admin_token, admin_hash) = generate_api_key()?;
    let (viewer_token, viewer_hash) = generate_api_key()?;
    tracing::info!(token = %admin_token, "admin token (rotate before production)");
    tracing::info!(token = %viewer_token, "viewer token (rotate before production)");

    // Authentication
    let auth = AuthConfig::with_keys(vec![
        ApiKeyEntry::new("admin-key", admin_hash, "admin"),
        ApiKeyEntry::new("viewer-key", viewer_hash, "viewer"),
    ])
    .with_rate_limit(RateLimitConfig::new(30));

    // RBAC
    let rbac = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
        RoleConfig::new("admin", vec!["*".into()], vec!["*".into()]),
        RoleConfig::new("viewer", vec!["list_items".into()], vec!["*".into()]),
    ])));

    // Server config
    let mut config = McpServerConfig::new("0.0.0.0:8443", "my-mcp-server", "1.0.0");
    config.auth = Some(auth);
    config.rbac = Some(rbac);
    config.allowed_origins = vec!["http://localhost:3000".into()];
    config.tool_rate_limit = Some(120);

    // Optional: TLS
    // config.tls_cert_path = Some("/etc/certs/server.crt".into());
    // config.tls_key_path = Some("/etc/certs/server.key".into());

    serve(config.validate()?, || MyHandler).await
}
```

---

## Client Usage Guide

### Health Check

```bash
curl http://127.0.0.1:8443/healthz
# {"status":"ok","name":"my-mcp-server","version":"1.0.0"}
```

### Readiness Check

```bash
curl http://127.0.0.1:8443/readyz
# 200: {"status":"ok","name":"my-mcp-server","version":"1.0.0"}
# 503: {"ready":false,"reason":"database unreachable"}
```

### MCP Initialize (required before tool calls)

```bash
curl -X POST http://127.0.0.1:8443/mcp \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "my-client", "version": "0.1"}
    }
  }'
```

> **Important:** The `Accept: application/json, text/event-stream` header is
> required by the MCP Streamable HTTP transport. Without it, you receive
> 406 Not Acceptable.

### List Available Tools

```bash
curl -X POST http://127.0.0.1:8443/mcp \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

### Call a Tool

```bash
curl -X POST http://127.0.0.1:8443/mcp \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "greet",
      "arguments": {"name": "World"}
    }
  }'
```

### Error Responses

| HTTP Status | Meaning | Cause |
|-------------|---------|-------|
| 200 | Success | Valid MCP response (may contain JSON-RPC error) |
| 401 | Unauthorized | Missing, invalid, or expired credentials |
| 403 | Forbidden | RBAC denied the operation, or origin rejected |
| 406 | Not Acceptable | Missing required `Accept` header |
| 408 | Request Timeout | Request exceeded `request_timeout` |
| 413 | Payload Too Large | Body exceeded `max_request_body` |
| 429 | Too Many Requests | Auth or tool rate limit exceeded |

### Using with MCP Clients

rmcp-server-kit implements the standard MCP Streamable HTTP transport, so any compliant
MCP client works:

```json
{
  "mcpServers": {
    "my-server": {
      "url": "http://127.0.0.1:8443/mcp",
      "headers": {
        "Authorization": "Bearer <TOKEN>"
      }
    }
  }
}
```

---

## Recipes

Short, copy-pasteable snippets for the most common production setups. Each
recipe shows only the wiring relevant to that feature; assemble them inside
the `Quick Start` `main()` skeleton.

Two of these recipes are also available as runnable examples in the
repository:

```bash
cargo run --example api_key_rbac
cargo run --example oauth_server --features oauth
```

### Recipe 1: OAuth 2.1 resource server (JWT validation)

Validate `Authorization: Bearer <jwt>` against a remote JWKS and map scopes
onto RBAC roles. Requires the `oauth` feature.

```rust,ignore
use std::sync::Arc;
use rmcp_server_kit::auth::AuthConfig;
use rmcp_server_kit::oauth::OAuthConfig;
use rmcp_server_kit::rbac::{RbacConfig, RbacPolicy, RoleConfig};
use rmcp_server_kit::transport::McpServerConfig;

let oauth = OAuthConfig::builder(
    "https://auth.example.com/",
    "my-mcp-server",
    "https://auth.example.com/.well-known/jwks.json",
)
.scope("mcp:admin", "admin")
.scope("mcp:read", "viewer")
.build();

let mut auth = AuthConfig::with_keys(vec![]);
auth.oauth = Some(oauth);

let rbac = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
    RoleConfig::new("admin", vec!["*".into()], vec!["*".into()]),
    RoleConfig::new("viewer", vec!["resource_list".into()], vec!["*".into()]),
])));

let config = McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0")
    .with_auth(auth)
    .with_rbac(rbac)
    .with_public_url("http://127.0.0.1:8080");
```

### Recipe 2: OAuth proxy + token exchange + introspection

Expose `/oauth/authorize`, `/oauth/token`, `/oauth/introspect`, and
`/oauth/revoke` endpoints that proxy to your IdP, optionally exchanging
the client's token for a downstream service token (RFC 8693). Requires
`oauth`.

```rust,ignore
use rmcp_server_kit::oauth::{OAuthConfig, OAuthProxyConfig, TokenExchangeConfig};
use secrecy::SecretString;

let proxy = OAuthProxyConfig::builder(
    "https://auth.example.com/oauth/authorize",
    "https://auth.example.com/oauth/token",
    "my-client-id",
)
.client_secret(SecretString::new("my-client-secret".into()))
.introspection_url("https://auth.example.com/oauth/introspect")
.revocation_url("https://auth.example.com/oauth/revoke")
.expose_admin_endpoints(true)
.build();

let token_exchange = TokenExchangeConfig::new(
    "https://downstream.example.com/oauth/token",
    "downstream-client-id",
    SecretString::new("downstream-secret".into()),
    None,                                     // optional client cert (mTLS)
    "downstream-audience",
);

let oauth = OAuthConfig::builder(
    "https://auth.example.com/",
    "my-mcp-server",
    "https://auth.example.com/.well-known/jwks.json",
)
.proxy(proxy)
.token_exchange(token_exchange)
.build();
```

Inside a tool handler, retrieve the (already-exchanged) downstream token via:

```rust,ignore
if let Some(token) = rmcp_server_kit::rbac::current_token() {
    // use token.expose_secret() as Authorization header
}
```

### Recipe 3: API key + RBAC + per-tool argument allowlist

Argon2-hashed API keys with role-based tool allowlists and per-argument
constraints.

```rust,ignore
use std::sync::Arc;
use rmcp_server_kit::auth::{ApiKeyEntry, AuthConfig, generate_api_key};
use rmcp_server_kit::rbac::{ArgumentAllowlist, RbacConfig, RbacPolicy, RoleConfig};

// In production, load pre-generated PHC hashes from config instead.
let (admin_token, admin_hash) = generate_api_key()?;
let (viewer_token, viewer_hash) = generate_api_key()?;

let auth = AuthConfig::with_keys(vec![
    ApiKeyEntry::new("admin-key", admin_hash, "admin"),
    ApiKeyEntry::new("viewer-key", viewer_hash, "viewer"),
]);

let viewer = RoleConfig::new(
    "viewer",
    vec!["echo".into(), "resource_list".into()],
    vec!["*".into()],
)
.with_argument_allowlists(vec![ArgumentAllowlist::new(
    "echo", "message", vec!["hello".into(), "ping".into()],
)]);

let rbac = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
    RoleConfig::new("admin", vec!["*".into()], vec!["*".into()]),
    viewer,
])));
```

### Recipe 4: mTLS server (client certificate authentication)

Require client certificates signed by a known CA. Identity (CN) and role
are extracted from the cert. Combine with API keys / OAuth for hybrid auth,
or use mTLS-only by leaving `api_keys` empty.

```rust,ignore
use std::path::PathBuf;
use rmcp_server_kit::auth::{AuthConfig, MtlsConfig};

let mut auth = AuthConfig::with_keys(vec![]);
auth.mtls = Some(MtlsConfig {
    ca_cert_path: PathBuf::from("/etc/certs/client-ca.pem"),
    required: true,                  // reject connections without a client cert
    default_role: "operator".into(), // role used when cert CN has no explicit mapping
});

let config = McpServerConfig::new("127.0.0.1:8443", "my-server", "0.1.0")
    .with_auth(auth)
    .with_tls("/etc/certs/server.crt", "/etc/certs/server.key");
```

### Recipe 5: Prometheus metrics

Expose a `/metrics` endpoint on a separate listener (so it can bind to a
private interface or different port). Requires the `metrics` feature.

```rust,ignore
let config = McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0")
    .with_metrics("127.0.0.1:9090".parse().unwrap());
```

The registry exposes request counters, latency histograms, auth/RBAC
outcomes, and tool-call metrics out of the box. Add your own metrics by
registering them against `rmcp_server_kit::metrics::registry()`.

### Recipe 6: Tool hooks (audit + deny + result-size cap)

Wrap a `ServerHandler` with async `before` / `after` hooks to audit every
tool invocation, deny calls based on runtime state, and cap result sizes.

```rust,ignore
use std::sync::Arc;
use rmcp_server_kit::tool_hooks::{HookOutcome, ToolHooks, with_hooks};

let hooks = Arc::new(
    ToolHooks::new()
        .with_max_result_bytes(1_048_576) // 1 MiB cap on tool results
        .with_before(Arc::new(|ctx| {
            Box::pin(async move {
                tracing::info!(tool = %ctx.tool_name, role = ?ctx.role, "tool call");
                // Return HookOutcome::Deny(...) to reject, or
                // HookOutcome::Replace(Box::new(result)) to short-circuit.
                HookOutcome::Continue
            })
        }))
        .with_after(Arc::new(|ctx, disposition, bytes| {
            Box::pin(async move {
                tracing::info!(
                    tool = %ctx.tool_name,
                    ?disposition,
                    bytes,
                    "tool call finished"
                );
            })
        })),
);

let handler_factory = move || with_hooks(MyHandler, Arc::clone(&hooks));
serve(config.validate()?, handler_factory).await
```

---



rmcp-server-kit config structs derive `Deserialize`, so you can load them directly from
TOML. A complete example:

```toml
[server]
listen_addr = "0.0.0.0"
listen_port = 8443
tls_cert_path = "/etc/certs/server.crt"
tls_key_path = "/etc/certs/server.key"
shutdown_timeout = "30s"
request_timeout = "120s"
allowed_origins = ["http://localhost:3000", "https://myapp.example.com"]
tool_rate_limit = 120

[server.auth]
enabled = true

[[server.auth.api_keys]]
name = "admin-key"
hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
role = "admin"

[[server.auth.api_keys]]
name = "viewer-key"
hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
role = "viewer"
expires_at = "2025-12-31T23:59:59Z"

[server.auth.mtls]
ca_cert_path = "/etc/certs/client-ca.pem"
required = false
default_role = "operator"

[server.auth.rate_limit]
max_attempts_per_minute = 30
# Optional: cap on unauthenticated requests/min per source IP, consulted
# BEFORE Argon2id verification runs. Protects against CPU-spray attacks.
# Defaults to 10 * max_attempts_per_minute when omitted. mTLS callers
# bypass this gate entirely.
# pre_auth_max_per_minute = 300

# OAuth 2.1 (requires 'oauth' feature)
[server.auth.oauth]
issuer = "https://auth.example.com"
audience = "my-mcp-server"
jwks_uri = "https://auth.example.com/.well-known/jwks.json"
jwks_cache_ttl = "10m"

[[server.auth.oauth.scopes]]
scope = "mcp:admin"
role = "admin"

[[server.auth.oauth.scopes]]
scope = "mcp:read"
role = "viewer"

[rbac]
enabled = true
# Optional: stable HMAC key used to redact argument values in deny logs.
# When an argument fails the per-tool allowlist, the denied value is
# logged as `arg_hmac=<8-hex-chars>` (HMAC-SHA256 prefix) instead of the
# raw value, so log readers can correlate repeats without seeing the
# secret. When omitted, a random per-process salt is used (so the same
# input hashes differently across restarts). Set this to a long random
# string from your secret manager if you want stable correlation.
# redaction_salt = "replace-with-long-random-string-from-secrets-manager"

[[rbac.roles]]
name = "admin"
allow = ["*"]
hosts = ["*"]

[[rbac.roles]]
name = "ops"
allow = ["container_*", "image_*", "pod_*"]
deny = ["container_delete"]
hosts = ["prod-*", "staging-*"]

[[rbac.roles]]
name = "viewer"
allow = ["container_list", "container_inspect", "image_list"]
hosts = ["prod-*"]

[[rbac.roles]]
name = "restricted"
allow = ["container_exec"]
hosts = ["*"]

[[rbac.roles.argument_allowlists]]
tool = "container_exec"
argument = "cmd"
allowed = ["ls", "cat", "ps", "df", "top"]

[observability]
log_level = "info"
log_format = "json"
audit_log_path = "/var/log/my-server/audit.log"
metrics_enabled = true
metrics_bind = "127.0.0.1:9090"
```

---

## Testing Your Server

rmcp-server-kit includes 114 tests (unit, integration, and end-to-end). For your own
server, you can write similar e2e tests using `reqwest`:

```rust
use rmcp_server_kit::auth::{AuthConfig, ApiKeyEntry, generate_api_key};
use rmcp_server_kit::transport::{McpServerConfig, serve};
use std::time::Duration;

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn spawn_test_server(config: McpServerConfig) -> String {
    let port = config.bind_addr.rsplit_once(':').unwrap().1.to_string();
    let base = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        let _ = serve(config.validate().expect("test config valid"), || MyHandler).await;
    });

    // Wait for startup
    for _ in 0..50 {
        if reqwest::get(&format!("{base}/healthz")).await.is_ok() {
            return base;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server did not start");
}

#[tokio::test]
async fn test_health() {
    let port = free_port().await;
    let config = McpServerConfig::new(format!("127.0.0.1:{port}"), "test", "0.1");
    let base = spawn_test_server(config).await;

    let resp = reqwest::get(&format!("{base}/healthz")).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_auth_rejects_unauthenticated() {
    let port = free_port().await;
    let mut config = McpServerConfig::new(format!("127.0.0.1:{port}"), "test", "0.1");
    config.auth = Some(AuthConfig::with_keys(vec![]));
    let base = spawn_test_server(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(&format!("{base}/mcp"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}
```

Run the rmcp-server-kit test suite:

```bash
# All tests (requires all features)
cargo test -p rmcp-server-kit --all-features

# Just e2e tests
cargo test -p rmcp-server-kit --all-features --test e2e

# Just unit tests
cargo test -p rmcp-server-kit --all-features --lib
```
