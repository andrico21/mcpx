#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! End-to-end tests for the mcpx HTTP server stack.
//!
//! Spins up a real `serve()` instance on an ephemeral port with a minimal
//! `ServerHandler` and makes HTTP requests against it.

use std::{sync::Arc, time::Duration};

use mcpx::{
    auth::{ApiKeyEntry, AuthConfig, RateLimitConfig},
    rbac::{ArgumentAllowlist, RbacConfig, RbacPolicy, RoleConfig},
    transport::McpServerConfig,
};
use rmcp::{
    handler::server::ServerHandler,
    model::{ServerCapabilities, ServerInfo},
};

// -- Minimal test handler --

#[derive(Clone)]
struct TestHandler;

impl ServerHandler for TestHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

// -- Test helpers --

/// Find a free ephemeral port.
async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Spawn a server and return its base URL. The server runs until the test
/// drops (tokio runtime shutdown aborts the task).
async fn spawn_server(config: McpServerConfig) -> String {
    // Ensure ring crypto provider is available for reqwest's TLS.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let port = config.bind_addr.rsplit_once(':').unwrap().1.to_owned();
    let base = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        if let Err(e) = mcpx::transport::serve(config, || TestHandler).await {
            eprintln!("server error: {e}");
        }
    });

    // Wait for the listener to be ready.
    for _ in 0..50 {
        if reqwest::get(&format!("{base}/healthz")).await.is_ok() {
            return base;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server did not start within 2.5s");
}

fn config_on_port(port: u16) -> McpServerConfig {
    let mut cfg = McpServerConfig::new(format!("127.0.0.1:{port}"), "test-mcpx", "0.0.1");
    cfg.shutdown_timeout = Duration::from_millis(100);
    cfg
}

// ==========================================================================
// Health endpoints
// ==========================================================================

#[tokio::test]
async fn healthz_returns_ok() {
    let port = free_port().await;
    let base = spawn_server(config_on_port(port)).await;

    let resp = reqwest::get(&format!("{base}/healthz")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["status"], "ok");
    assert!(
        json.get("name").is_none(),
        "healthz must not expose server name"
    );
    assert!(
        json.get("version").is_none(),
        "healthz must not expose version"
    );
}

#[tokio::test]
async fn readyz_mirrors_healthz_when_no_check() {
    let port = free_port().await;
    let base = spawn_server(config_on_port(port)).await;

    let resp = reqwest::get(&format!("{base}/readyz")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn readyz_returns_503_when_not_ready() {
    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.readiness_check = Some(Arc::new(|| {
        Box::pin(async { serde_json::json!({"ready": false, "reason": "starting"}) })
    }));
    let base = spawn_server(cfg).await;

    let resp = reqwest::get(&format!("{base}/readyz")).await.unwrap();
    assert_eq!(resp.status(), 503);
}

// ==========================================================================
// Auth enforcement
// ==========================================================================

fn test_auth_config(keys: Vec<ApiKeyEntry>) -> AuthConfig {
    AuthConfig::with_keys(keys)
}

#[tokio::test]
async fn auth_rejects_unauthenticated_mcp() {
    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.auth = Some(test_auth_config(vec![]));
    let base = spawn_server(cfg).await;

    // /healthz is always open.
    let resp = reqwest::get(&format!("{base}/healthz")).await.unwrap();
    assert_eq!(resp.status(), 200);

    // /mcp without credentials returns 401.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/mcp"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn auth_accepts_valid_bearer() {
    let (token, hash) = mcpx::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("e2e-key", hash, "ops")];

    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.auth = Some(test_auth_config(keys));
    let base = spawn_server(cfg).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}"#)
        .send()
        .await
        .unwrap();
    // Should get a valid MCP response (200), not 401.
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn auth_rejects_wrong_bearer() {
    let (_token, hash) = mcpx::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("e2e-key", hash, "ops")];

    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.auth = Some(test_auth_config(keys));
    let base = spawn_server(cfg).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/mcp"))
        .header("authorization", "Bearer wrong-token")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ==========================================================================
// Origin validation
// ==========================================================================

#[tokio::test]
async fn origin_allowed_passes() {
    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.allowed_origins = vec!["http://localhost:3000".into()];
    let base = spawn_server(cfg).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/mcp"))
        .header("origin", "http://localhost:3000")
        .body("{}")
        .send()
        .await
        .unwrap();
    // Not 403 (origin passes). Might be 4xx for other reasons (no auth, bad body),
    // but definitely not origin-rejected.
    assert_ne!(resp.status(), 403);
}

#[tokio::test]
async fn origin_rejected() {
    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.allowed_origins = vec!["http://localhost:3000".into()];
    let base = spawn_server(cfg).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/mcp"))
        .header("origin", "http://evil.example.com")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn no_origin_header_passes() {
    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.allowed_origins = vec!["http://localhost:3000".into()];
    let base = spawn_server(cfg).await;

    // No Origin header -- non-browser client, should pass.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/mcp"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 403);
}

// ==========================================================================
// RBAC enforcement (auth + RBAC together)
// ==========================================================================

fn tool_call_body(tool: &str, args: &serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": args
        }
    })
    .to_string()
}

#[tokio::test]
async fn rbac_denies_unpermitted_tool() {
    let (token, hash) = mcpx::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("viewer-key", hash, "viewer")];

    let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
        RoleConfig::new("viewer", vec!["resource_list".into()], vec!["*".into()]),
    ])));

    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.auth = Some(test_auth_config(keys));
    cfg.rbac = Some(policy);
    let base = spawn_server(cfg).await;

    let client = reqwest::Client::new();

    // Attempt a tool not in the viewer's allow list.
    let resp = client
        .post(format!("{base}/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(tool_call_body("resource_delete", &serde_json::json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn rbac_allows_permitted_tool() {
    let (token, hash) = mcpx::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("ops-key", hash, "ops")];

    let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
        RoleConfig::new("ops", vec!["*".into()], vec!["*".into()]),
    ])));

    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.auth = Some(test_auth_config(keys));
    cfg.rbac = Some(policy);
    let base = spawn_server(cfg).await;

    let client = reqwest::Client::new();

    // Ops role with wildcard allow -- should pass RBAC.
    // The tool doesn't exist on the handler, so MCP returns an error *response*
    // (not an HTTP error), meaning HTTP 200 with a JSON-RPC error body.
    let resp = client
        .post(format!("{base}/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(tool_call_body("resource_list", &serde_json::json!({})))
        .send()
        .await
        .unwrap();
    // Should NOT be 403 (RBAC passed).
    assert_ne!(resp.status(), 403);
}

#[tokio::test]
async fn rbac_argument_allowlist_enforced() {
    let (token, hash) = mcpx::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("exec-key", hash, "restricted")];

    let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
        RoleConfig::new(
            "restricted",
            vec!["container_exec".into()],
            vec!["*".into()],
        )
        .with_argument_allowlists(vec![ArgumentAllowlist::new(
            "container_exec",
            "cmd",
            vec!["ls".into(), "cat".into(), "ps".into()],
        )]),
    ])));

    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.auth = Some(test_auth_config(keys));
    cfg.rbac = Some(policy);
    let base = spawn_server(cfg).await;

    let client = reqwest::Client::new();

    // Allowed command: ls
    let resp = client
        .post(format!("{base}/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(tool_call_body(
            "container_exec",
            &serde_json::json!({"cmd": "ls -la"}),
        ))
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 403, "allowed cmd 'ls' should not be denied");

    // Denied command: rm
    let resp = client
        .post(format!("{base}/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(tool_call_body(
            "container_exec",
            &serde_json::json!({"cmd": "rm -rf /"}),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "denied cmd 'rm' should be rejected");
}

// ==========================================================================
// Auth rate limiting
// ==========================================================================

#[tokio::test]
async fn auth_rate_limit_triggers() {
    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.auth = Some(AuthConfig::with_keys(vec![]).with_rate_limit(RateLimitConfig::new(2)));
    let base = spawn_server(cfg).await;

    let client = reqwest::Client::new();
    let url = format!("{base}/mcp");

    // First 2 requests: 401 (auth fails, but not rate limited).
    for i in 0..2 {
        let resp = client.post(&url).body("{}").send().await.unwrap();
        assert_eq!(resp.status(), 401, "request {i} should be 401");
    }

    // Third request: should be 429 (rate limited).
    let resp = client.post(&url).body("{}").send().await.unwrap();
    assert_eq!(resp.status(), 429, "request 3 should be rate limited");
}
