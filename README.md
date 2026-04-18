# mcpx

[![Crates.io](https://img.shields.io/crates/v/mcpx.svg)](https://crates.io/crates/mcpx)
[![Docs.rs](https://docs.rs/mcpx/badge.svg)](https://docs.rs/mcpx)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**mcpx** is a production-grade, reusable framework for building
[Model Context Protocol](https://modelcontextprotocol.io/) servers in Rust.
It provides a Streamable HTTP transport with TLS/mTLS, structured
observability, authentication (Bearer / mTLS / OAuth 2.1 JWT), role-based
access control (RBAC), per-IP rate limiting, and optional Prometheus
metrics -- all wired up and ready to go.

You supply a `rmcp::handler::server::ServerHandler` implementation; mcpx
handles everything else.

## Quick Start

```toml
[dependencies]
mcpx = { version = "0.10", features = ["oauth"] }
rmcp = { version = "1.5", features = ["server", "macros"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal"] }
```

```rust
use mcpx::transport::{McpServerConfig, serve};
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
async fn main() -> anyhow::Result<()> {
    let _ = mcpx::observability::init_tracing("info,my_server=debug");
    let config = McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0");
    serve(config, || MyHandler).await
}
```

Full API documentation and worked examples live in
[docs/GUIDE.md](docs/GUIDE.md).

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

`mcpx` targets stable Rust **1.95** or newer (tracks `edition = "2024"`).

## Repositories

`mcpx` is published to two mirrors with identical contents; either may
be used as a git dependency.

- **GitHub** (canonical, public): <https://github.com/andrico21/mcpx>
- **GitLab** (internal mirror): <[REDACTED]>

The canonical release artifact is the [`mcpx` crate on crates.io](https://crates.io/crates/mcpx).

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
