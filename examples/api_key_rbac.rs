//! API key + RBAC + per-tool argument allowlist example.
//!
//! Demonstrates the most common production setup:
//!
//! - Argon2-hashed API keys (issued at startup for demo purposes; in production
//!   you would load pre-generated hashes from config).
//! - Two roles (`admin`, `viewer`) with distinct tool allow-lists.
//! - A per-tool argument allowlist constraining the `viewer` role so it can
//!   only call `echo` with `message` ∈ {`hello`, `ping`}.
//!
//! Run with:
//!
//! ```bash
//! cargo run --example api_key_rbac
//! ```
//!
//! Then call the server (the freshly-generated tokens are printed at startup):
//!
//! ```bash
//! curl -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:8080/mcp
//! ```

use std::sync::Arc;

use rmcp::{
    handler::server::ServerHandler,
    model::{ServerCapabilities, ServerInfo},
};
use rmcp_server_kit::{
    auth::{ApiKeyEntry, AuthConfig, generate_api_key},
    rbac::{ArgumentAllowlist, RbacConfig, RbacPolicy, RoleConfig},
    transport::{McpServerConfig, serve},
};

#[derive(Clone)]
struct DemoHandler;

impl ServerHandler for DemoHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> rmcp_server_kit::Result<()> {
    let _ = rmcp_server_kit::observability::init_tracing("info,rmcp_server_kit=debug");

    // 1. Generate two API keys. `generate_api_key` returns the plaintext token
    //    (give to the client) and an Argon2id PHC hash (store in config).
    let (admin_token, admin_hash) = generate_api_key()?;
    let (viewer_token, viewer_hash) = generate_api_key()?;

    // For demo purposes only — never log plaintext tokens in production.
    tracing::info!(%admin_token, "admin token (demo only)");
    tracing::info!(%viewer_token, "viewer token (demo only)");

    let auth = AuthConfig::with_keys(vec![
        ApiKeyEntry::new("admin-key", admin_hash, "admin"),
        ApiKeyEntry::new("viewer-key", viewer_hash, "viewer"),
    ]);

    // 2. RBAC: admin can call anything; viewer is restricted to `echo` and
    //    `resource_list`, and `echo`'s `message` argument is allowlisted.
    let viewer = RoleConfig::new(
        "viewer",
        vec!["echo".into(), "resource_list".into()],
        vec!["*".into()],
    )
    .with_argument_allowlists(vec![ArgumentAllowlist::new(
        "echo",
        "message",
        vec!["hello".into(), "ping".into()],
    )]);

    let rbac = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
        RoleConfig::new("admin", vec!["*".into()], vec!["*".into()]),
        viewer,
    ])));

    let config = McpServerConfig::new(
        "127.0.0.1:8080",
        "rmcp-server-kit-api-key-rbac-example",
        env!("CARGO_PKG_VERSION"),
    )
    .with_auth(auth)
    .with_rbac(rbac);

    serve(config.validate()?, || DemoHandler).await
}
