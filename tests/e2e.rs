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

// ==========================================================================
// C1 regression: middleware ordering
// ==========================================================================

/// Regression test for C1: origin check MUST execute before auth so that a
/// caller presenting a forbidden Origin header is rejected with 403 BEFORE
/// any auth challenge (401) is surfaced. This prevents information leakage
/// about whether auth is configured and matches the documented "outer" vs
/// "inner" middleware semantics.
#[tokio::test]
async fn c1_origin_rejected_before_auth() {
    let (_token, hash) = mcpx::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("guard-key", hash, "ops")];

    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.auth = Some(test_auth_config(keys));
    cfg.allowed_origins = vec!["http://localhost:3000".into()];
    let base = spawn_server(cfg).await;

    let client = reqwest::Client::new();
    // No Authorization header + bad Origin. If auth ran first we'd get 401.
    // Origin running outermost must short-circuit to 403.
    let resp = client
        .post(format!("{base}/mcp"))
        .header("origin", "http://evil.example.com")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "bad Origin must be rejected (403) before auth challenge (401)"
    );
}

/// Regression test for C1: the request-body size limit MUST execute before
/// RBAC parses the JSON-RPC body. Otherwise an oversized payload would be
/// fully buffered by RBAC before the size gate fires. We send a payload
/// larger than the configured cap and expect 413 Payload Too Large.
#[tokio::test]
async fn c1_body_limit_applies_before_rbac() {
    let (token, hash) = mcpx::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("ops-key", hash, "ops")];
    let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
        RoleConfig::new("ops", vec!["*".into()], vec!["*".into()]),
    ])));

    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.auth = Some(test_auth_config(keys));
    cfg.rbac = Some(policy);
    // 512 byte cap — much smaller than default 1 MiB.
    cfg.max_request_body = 512;
    let base = spawn_server(cfg).await;

    // Build a 16 KiB JSON-RPC body (well over 512).
    let padding = "A".repeat(16 * 1024);
    let oversized = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"x","arguments":{{"pad":"{padding}"}}}}}}"#
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(oversized)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        413,
        "oversized body must be rejected with 413 before RBAC buffers it"
    );
}

// ==========================================================================
// C3 regression: OAuth admin endpoints gated by expose_admin_endpoints
// ==========================================================================

#[cfg(feature = "oauth")]
fn oauth_cfg_with_proxy(expose: bool) -> mcpx::oauth::OAuthConfig {
    // OAuthConfig and OAuthProxyConfig are `#[non_exhaustive]`, so we build
    // them via serde from a TOML-equivalent JSON document. This is the same
    // path real consumers take when loading from a config file.
    let json = serde_json::json!({
        "issuer": "https://upstream.example/",
        "audience": "mcpx-test",
        "jwks_uri": "https://upstream.example/.well-known/jwks.json",
        "jwks_cache_ttl": "10m",
        "proxy": {
            "authorize_url": "https://upstream.example/authorize",
            "token_url": "https://upstream.example/token",
            "client_id": "mcp-client",
            "introspection_url": "https://upstream.example/introspect",
            "revocation_url": "https://upstream.example/revoke",
            "expose_admin_endpoints": expose,
        }
    });
    serde_json::from_value(json).expect("oauth config deserialization")
}

/// Regression test for C3: by default (`expose_admin_endpoints = false`),
/// `/introspect` and `/revoke` must NOT be mounted and must NOT be
/// advertised in the authorization-server metadata document. This is the
/// secure default — unauthenticated endpoints that proxy to the upstream
/// `IdP` must be explicitly opted in to.
#[cfg(feature = "oauth")]
#[tokio::test]
async fn c3_admin_endpoints_hidden_by_default() {
    let port = free_port().await;
    let mut cfg = config_on_port(port);
    let mut auth = AuthConfig::with_keys(vec![]);
    auth.oauth = Some(oauth_cfg_with_proxy(false));
    cfg.auth = Some(auth);
    cfg.public_url = Some(format!("http://127.0.0.1:{port}"));
    let base = spawn_server(cfg).await;

    // Metadata must NOT advertise the admin endpoints.
    let meta: serde_json::Value =
        reqwest::get(&format!("{base}/.well-known/oauth-authorization-server"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert!(
        meta.get("introspection_endpoint").is_none(),
        "introspection must not be advertised by default"
    );
    assert!(
        meta.get("revocation_endpoint").is_none(),
        "revocation must not be advertised by default"
    );

    // Endpoints must 404 (not mounted).
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/introspect"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("token=abc")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "/introspect must 404 by default");

    let resp = client
        .post(format!("{base}/revoke"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("token=abc")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "/revoke must 404 by default");
}

/// Regression test for C3: when `expose_admin_endpoints = true`, the
/// endpoints ARE advertised in metadata and ARE mounted (i.e. no longer
/// 404). We don't assert a specific upstream response because no real
/// `IdP` is reachable — we only assert non-404, proving the route is live.
#[cfg(feature = "oauth")]
#[tokio::test]
async fn c3_admin_endpoints_exposed_when_enabled() {
    let port = free_port().await;
    let mut cfg = config_on_port(port);
    let mut auth = AuthConfig::with_keys(vec![]);
    auth.oauth = Some(oauth_cfg_with_proxy(true));
    cfg.auth = Some(auth);
    cfg.public_url = Some(format!("http://127.0.0.1:{port}"));
    let base = spawn_server(cfg).await;

    let meta: serde_json::Value =
        reqwest::get(&format!("{base}/.well-known/oauth-authorization-server"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert!(
        meta.get("introspection_endpoint").is_some(),
        "introspection must be advertised when expose_admin_endpoints=true"
    );
    assert!(
        meta.get("revocation_endpoint").is_some(),
        "revocation must be advertised when expose_admin_endpoints=true"
    );

    // Endpoint is mounted: response should NOT be 404. Upstream is
    // unreachable so we expect a bad-gateway / error response, but the
    // route itself is live.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/introspect"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("token=abc")
        .send()
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        404,
        "/introspect must be mounted when expose_admin_endpoints=true"
    );
}
