//! OAuth 2.1 resource-server example.
//!
//! Validates incoming `Authorization: Bearer <jwt>` tokens against a remote
//! JWKS endpoint and maps OAuth scopes onto rmcp-server-kit RBAC roles. Requires the
//! `oauth` Cargo feature.
//!
//! Run with:
//!
//! ```bash
//! cargo run --example oauth_server --features oauth
//! ```
//!
//! Then call the server with a JWT issued by your identity provider:
//!
//! ```bash
//! curl -H "Authorization: Bearer $JWT" http://127.0.0.1:8080/mcp
//! ```
//!
//! Replace the placeholder issuer / audience / JWKS URL below with values
//! from your identity provider (Auth0, Okta, Keycloak, Entra ID, …).

use std::sync::Arc;

use rmcp::{
    handler::server::ServerHandler,
    model::{ServerCapabilities, ServerInfo},
};
use rmcp_server_kit::{
    auth::AuthConfig,
    oauth::OAuthConfig,
    rbac::{RbacConfig, RbacPolicy, RoleConfig},
    transport::{McpServerConfig, serve},
};

#[derive(Clone)]
struct OAuthHandler;

impl ServerHandler for OAuthHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> rmcp_server_kit::Result<()> {
    let _ = rmcp_server_kit::observability::init_tracing("info,rmcp_server_kit=debug");

    // 1. Build the OAuth resource-server config. The audience must match the
    //    `aud` claim your IdP issues for this MCP server.
    let oauth = OAuthConfig::builder(
        "https://auth.example.com/",
        "rmcp-server-kit-oauth-example",
        "https://auth.example.com/.well-known/jwks.json",
    )
    .scope("mcp:admin", "admin")
    .scope("mcp:read", "viewer")
    .build();

    // 2. Plug OAuth into AuthConfig. No API keys needed when using OAuth.
    let mut auth = AuthConfig::with_keys(vec![]);
    auth.oauth = Some(oauth);

    // 3. RBAC policy: roles must match what `.scope(_, role)` mapped above.
    let rbac = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
        RoleConfig::new("admin", vec!["*".into()], vec!["*".into()]),
        RoleConfig::new("viewer", vec!["resource_list".into()], vec!["*".into()]),
    ])));

    let config = McpServerConfig::new(
        "127.0.0.1:8080",
        "rmcp-server-kit-oauth-example",
        env!("CARGO_PKG_VERSION"),
    )
    .with_auth(auth)
    .with_rbac(rbac)
    .with_public_url("http://127.0.0.1:8080");

    serve(config.validate()?, || OAuthHandler).await
}
