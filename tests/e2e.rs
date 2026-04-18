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

use std::{net::SocketAddr, sync::Arc, time::Duration};

use mcpx::{
    auth::{ApiKeyEntry, AuthConfig, RateLimitConfig},
    rbac::{ArgumentAllowlist, RbacConfig, RbacPolicy, RoleConfig},
    transport::McpServerConfig,
};
use rmcp::{
    handler::server::ServerHandler,
    model::{ServerCapabilities, ServerInfo},
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_util::sync::CancellationToken;

// -- Minimal test handler --

#[derive(Clone)]
struct TestHandler;

impl ServerHandler for TestHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

// -- Test helpers --

/// Find a free ephemeral port. Retained for legacy call-sites that
/// build a config from a port number; new tests should prefer
/// [`spawn_server`] which uses port 0 + pre-bound listener.
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Handle to a server spawned via [`spawn_server`]. Drop the harness
/// (or call [`ServerHarness::shutdown`]) to terminate the server
/// deterministically.
#[allow(
    dead_code,
    reason = "shutdown() and join field are used by the BUG-NEW shutdown_timeout test added in the same release"
)]
struct ServerHarness {
    /// Base URL (`http://127.0.0.1:<port>`). Always contains the
    /// actually-bound port -- safe to use immediately.
    base: String,
    /// Cancellation token wired into `serve_with_listener`'s shutdown
    /// path. Cancelling triggers the same graceful drain as a real
    /// `SIGTERM`.
    shutdown: CancellationToken,
    /// Join handle for the server task. `None` after [`Self::shutdown`]
    /// joins it.
    join: Option<JoinHandle<mcpx::Result<()>>>,
}

#[allow(
    dead_code,
    reason = "shutdown() is used by the BUG-NEW shutdown_timeout test added in the same release"
)]
impl ServerHarness {
    /// Cancel the shutdown token, await the server task, and return
    /// the server's final result. Safe to call multiple times: only
    /// the first invocation joins.
    async fn shutdown(&mut self) -> anyhow::Result<()> {
        self.shutdown.cancel();
        match self.join.take() {
            Some(h) => match h.await {
                Ok(server_res) => server_res.map_err(anyhow::Error::from),
                Err(join_err) => Err(join_err.into()),
            },
            None => Ok(()),
        }
    }
}

impl Drop for ServerHarness {
    fn drop(&mut self) {
        // Ensure the server task does not outlive the test even if
        // the test forgot to call `shutdown`.
        self.shutdown.cancel();
    }
}

impl std::fmt::Display for ServerHarness {
    /// Display formats as the harness's base URL so existing test
    /// call-sites (`format!("{base}/healthz")`) keep working when
    /// `base` is a [`ServerHarness`] rather than a `String`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.base)
    }
}

/// Spawn a server on an ephemeral port using
/// [`mcpx::transport::serve_with_listener`] and return a
/// [`ServerHarness`] once the server has signalled readiness.
///
/// Replaces the previous "spawn + poll `/healthz` for 2.5s" pattern
/// with a deterministic readiness oneshot, eliminating start-up
/// races and removing the need for `config_on_port` to know the port
/// ahead of time.
async fn spawn_server(mut config: McpServerConfig) -> ServerHarness {
    // Ensure ring crypto provider is available for reqwest's TLS.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    // Bind the listener up front so the server has nothing to fail on
    // address-in-use, and we know the actual port immediately.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound: SocketAddr = listener.local_addr().unwrap();
    // Keep config.bind_addr aligned with the real port for any
    // public_url derivation paths that read it.
    config.bind_addr = bound.to_string();

    let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
    let shutdown = CancellationToken::new();
    let shutdown_for_server = shutdown.clone();

    let join = tokio::spawn(async move {
        mcpx::transport::serve_with_listener(
            listener,
            config,
            || TestHandler,
            Some(ready_tx),
            Some(shutdown_for_server),
        )
        .await
    });

    // Deterministic readiness: wait for serve_with_listener to signal
    // *after* router build, *before* accept loop. No polling loop, no
    // sleep races.
    let signalled: SocketAddr = tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .expect("server did not signal readiness within 5s")
        .expect("server task aborted before readiness signal");
    assert_eq!(
        signalled, bound,
        "ready_tx address mismatched the pre-bound listener"
    );

    ServerHarness {
        base: format!("http://{bound}"),
        shutdown,
        join: Some(join),
    }
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

// ==========================================================================
// BUG-NEW: shutdown timeout double-signal regression test
// ==========================================================================

/// Regression test for the shutdown double-signal bug fixed in 0.11.0.
///
/// **Bug**: Both branches of the shutdown `tokio::select!` in
/// `run_server` previously awaited `shutdown_signal()` independently.
/// Because `shutdown_signal` resolves once per future and consumes one
/// signal, the force-exit timer was tied to a *second* signal that
/// would never come. Under a single SIGTERM with an in-flight request,
/// graceful drain hung forever.
///
/// **What this test verifies**:
/// 1. With a long-running in-flight request and a 500ms shutdown
///    timeout, cancelling the harness's `CancellationToken` (the same
///    code path a real SIGTERM would trigger after BUG-NEW's fix)
///    causes the server to exit within ~500ms.
/// 2. The server actually waits at least most of the graceful window
///    (~450ms) instead of insta-killing the in-flight request -- this
///    catches an over-correction that would skip graceful drain
///    entirely.
///
/// **Cross-platform note**: real `SIGTERM` / Ctrl+C is intentionally
/// NOT used here (Windows portability). Production `shutdown_signal()`
/// still wires SIGTERM/SIGINT; this test exercises the same internal
/// cancellation path via the unified `CancellationToken` from H-T1.
#[tokio::test]
async fn shutdown_timeout_honored_on_first_signal() {
    use std::time::Instant;

    use axum::routing::get;

    // Build a server with a *short* graceful deadline (500ms) and an
    // extra route that sleeps 10s server-side -- representing an
    // in-flight tool call that will not finish before the deadline.
    let port = free_port().await;
    let mut cfg = config_on_port(port);
    cfg.shutdown_timeout = Duration::from_millis(500);
    cfg.extra_router = Some(axum::Router::new().route(
        "/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            "done"
        }),
    ));

    let mut harness = spawn_server(cfg).await;
    let base = harness.base.clone();

    // Fire the long-running request in the background. It MUST be
    // in-flight when we trigger shutdown; otherwise graceful drain
    // would complete instantly regardless of the bug.
    let slow_url = format!("{base}/slow");
    let in_flight = tokio::spawn(async move {
        // We don't care about the response -- only that the request
        // was accepted and is occupying server resources during
        // shutdown.
        let _ = reqwest::get(&slow_url).await;
    });

    // Give the request a moment to actually reach the server before
    // we trigger shutdown. 100ms is well under the 500ms deadline.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Trigger graceful shutdown. With BUG-NEW fixed, this is
    // semantically identical to a single SIGTERM.
    let start = Instant::now();
    let res = tokio::time::timeout(Duration::from_secs(2), harness.shutdown()).await;
    let elapsed = start.elapsed();

    // Outer timeout MUST NOT fire -- if it did, the server hung past
    // both its graceful window and the cushion, which is the bug.
    let server_result = res.expect("server failed to shut down within 2s -- BUG-NEW regression");

    // The server should exit cleanly (an error here would indicate a
    // fault unrelated to this bug; surface it loudly).
    server_result.expect("server returned an error during shutdown");

    // Best-effort: drain the background HTTP task. It may complete
    // with an error (connection reset by force-exit) or succeed if
    // the runtime aborted it -- either is acceptable.
    in_flight.abort();
    let _ = in_flight.await;

    // Lower bound: the server actually waited (most of) the graceful
    // window. 450ms = 500ms - 50ms scheduling/cleanup slack. Catches
    // an over-correction that skips graceful drain.
    assert!(
        elapsed >= Duration::from_millis(450),
        "shutdown completed in {elapsed:?}, expected >= 450ms (server skipped graceful drain)"
    );

    // Upper bound: the server did NOT hang. 1500ms = 500ms graceful +
    // 1000ms generous slack for CI scheduling jitter (the bug used to
    // hang indefinitely; any value materially below the 2s outer
    // timeout proves the fix).
    assert!(
        elapsed < Duration::from_millis(1500),
        "shutdown took {elapsed:?}, expected < 1500ms (BUG-NEW regression)"
    );
}
