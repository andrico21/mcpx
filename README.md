# rmcp-server-kit

[![Crates.io](https://img.shields.io/crates/v/rmcp-server-kit.svg)](https://crates.io/crates/rmcp-server-kit)
[![Docs.rs](https://docs.rs/rmcp-server-kit/badge.svg)](https://docs.rs/rmcp-server-kit)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**rmcp-server-kit** is a production-grade, reusable framework for building
[Model Context Protocol](https://modelcontextprotocol.io/) servers in Rust.
It provides a Streamable HTTP transport with TLS/mTLS, structured
observability, authentication (Bearer / mTLS / OAuth 2.1 JWT), role-based
access control (RBAC), per-IP rate limiting, and optional Prometheus
metrics -- all wired up and ready to go.

You supply a `rmcp::handler::server::ServerHandler` implementation; rmcp-server-kit
handles everything else.

## Quick Start

```toml
[dependencies]
rmcp-server-kit = { version = "1", features = ["oauth"] }
rmcp = { version = "1.5", features = ["server", "macros"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal"] }
```

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

Full API documentation and worked examples live in
[docs/GUIDE.md](docs/GUIDE.md). Two runnable end-to-end examples ship in
the repository:

```bash
cargo run --example minimal_server
cargo run --example api_key_rbac
cargo run --example oauth_server --features oauth
```

### Common configurations

**API key + RBAC + per-tool argument allowlist:**

```rust,ignore
use rmcp_server_kit::auth::{ApiKeyEntry, AuthConfig, generate_api_key};
use rmcp_server_kit::rbac::{ArgumentAllowlist, RbacConfig, RbacPolicy, RoleConfig};
use std::sync::Arc;

let (token, hash) = generate_api_key()?;
let auth = AuthConfig::with_keys(vec![
    ApiKeyEntry::new("viewer-key", hash, "viewer"),
]);
let viewer = RoleConfig::new("viewer", vec!["echo".into()], vec!["*".into()])
    .with_argument_allowlists(vec![ArgumentAllowlist::new(
        "echo", "message", vec!["hello".into(), "ping".into()],
    )]);
let rbac = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![viewer])));
```

**OAuth 2.1 resource server (JWT validation against JWKS):**

```rust,ignore
use rmcp_server_kit::auth::AuthConfig;
use rmcp_server_kit::oauth::OAuthConfig;

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
```

**Prometheus metrics on a separate listener:**

```rust,ignore
let config = McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0")
    .with_metrics("127.0.0.1:9090".parse().unwrap());
```

**TLS:**

```rust,ignore
let config = McpServerConfig::new("127.0.0.1:8443", "my-server", "0.1.0")
    .with_tls("/etc/certs/server.crt", "/etc/certs/server.key");
```

## Features

- **Transport**: Streamable HTTP (`/mcp`), health (`/healthz`, `/readyz`),
  admin diagnostics, graceful shutdown, configurable TLS and mTLS.
- **Auth**: API-key (Argon2 hashed), mTLS client certs, OAuth 2.1 JWT
  validation against JWKS (feature-gated).
- **RBAC**: Tool-scoped allow-lists with per-role argument constraints and
  task-local `current_role()` / `current_identity()` accessors.
- **Observability**: Tracing, JSON logs, optional audit-file sink.
- **Hardening**: Per-IP rate limiting (governor), request-body caps,
  OWASP security headers, configurable CORS and Host allow-lists.
- **Metrics**: Prometheus `/metrics` endpoint (opt-in via `metrics`
  feature).

## Cargo features

| Feature   | Default | Description                                    |
|-----------|---------|------------------------------------------------|
| `oauth`   | No      | OAuth 2.1 JWT validation via JWKS.             |
| `metrics` | No      | Prometheus metrics registry and `/metrics`.    |

## Minimum supported Rust

`rmcp-server-kit` targets stable Rust **1.95** or newer (tracks `edition = "2024"`).

## Repositories

`rmcp-server-kit` is published to two mirrors with identical contents; either may
be used as a git dependency.

- **GitHub** (canonical, public): <https://github.com/andrico21/mcpx>
- **GitLab** (internal mirror): <[REDACTED]>

The canonical release artifact is the [`rmcp-server-kit` crate on crates.io](https://crates.io/crates/rmcp-server-kit).

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.
