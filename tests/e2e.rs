#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! End-to-end tests for the rmcp-server-kit HTTP server stack.
//!
//! Spins up a real `serve()` instance on an ephemeral port with a minimal
//! `ServerHandler` and makes HTTP requests against it.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use rmcp::{
    handler::server::ServerHandler,
    model::{ServerCapabilities, ServerInfo},
};
use rmcp_server_kit::{
    auth::{ApiKeyEntry, AuthConfig, RateLimitConfig},
    rbac::{ArgumentAllowlist, RbacConfig, RbacPolicy, RoleConfig},
    transport::McpServerConfig,
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
    join: Option<JoinHandle<rmcp_server_kit::Result<()>>>,
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
/// [`rmcp_server_kit::transport::serve_with_listener`] and return a
/// [`ServerHarness`] once the server has signalled readiness.
///
/// Replaces the previous "spawn + poll `/healthz` for 2.5s" pattern
/// with a deterministic readiness oneshot, eliminating start-up
/// races and removing the need for `config_on_port` to know the port
/// ahead of time.
async fn spawn_server(config: McpServerConfig) -> ServerHarness {
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
    let config = config.with_bind_addr(bound.to_string());

    let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
    let shutdown = CancellationToken::new();
    let shutdown_for_server = shutdown.clone();

    let join = tokio::spawn(async move {
        rmcp_server_kit::transport::serve_with_listener(
            listener,
            config.validate().expect("test config valid"),
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
    McpServerConfig::new(format!("127.0.0.1:{port}"), "test-rmcp-server-kit", "0.0.1")
        .with_shutdown_timeout(Duration::from_millis(100))
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
    let cfg = config_on_port(port).with_readiness_check(Arc::new(|| {
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
    let cfg = config_on_port(port).with_auth(test_auth_config(vec![]));
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
    let (token, hash) = rmcp_server_kit::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("e2e-key", hash, "ops")];

    let port = free_port().await;
    let cfg = config_on_port(port).with_auth(test_auth_config(keys));
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
    let (_token, hash) = rmcp_server_kit::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("e2e-key", hash, "ops")];

    let port = free_port().await;
    let cfg = config_on_port(port).with_auth(test_auth_config(keys));
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
    let cfg = config_on_port(port).with_allowed_origins(["http://localhost:3000"]);
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
    let cfg = config_on_port(port).with_allowed_origins(["http://localhost:3000"]);
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
    let cfg = config_on_port(port).with_allowed_origins(["http://localhost:3000"]);
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
    let (token, hash) = rmcp_server_kit::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("viewer-key", hash, "viewer")];

    let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
        RoleConfig::new("viewer", vec!["resource_list".into()], vec!["*".into()]),
    ])));

    let port = free_port().await;
    let cfg = config_on_port(port)
        .with_auth(test_auth_config(keys))
        .with_rbac(policy);
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
    let (token, hash) = rmcp_server_kit::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("ops-key", hash, "ops")];

    let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
        RoleConfig::new("ops", vec!["*".into()], vec!["*".into()]),
    ])));

    let port = free_port().await;
    let cfg = config_on_port(port)
        .with_auth(test_auth_config(keys))
        .with_rbac(policy);
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
    let (token, hash) = rmcp_server_kit::auth::generate_api_key().unwrap();
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
    let cfg = config_on_port(port)
        .with_auth(test_auth_config(keys))
        .with_rbac(policy);
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
    let cfg = config_on_port(port)
        .with_auth(AuthConfig::with_keys(vec![]).with_rate_limit(RateLimitConfig::new(2)));
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

mod crl_tests {
    use std::{net::IpAddr, path::PathBuf};

    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
        CrlDistributionPoint, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair,
        KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber, date_time_ymd,
    };
    use rmcp_server_kit::{
        auth::{AuthConfig, MtlsConfig},
        mtls_revocation::{CrlSet, DynamicClientCertVerifier},
    };
    use rustls::{
        RootCertStore,
        pki_types::{CertificateRevocationListDer, UnixTime},
        server::danger::ClientCertVerifier as _,
    };
    use wiremock::MockServer;

    use super::*;

    struct TestPki {
        ca_pem: String,
        server_cert_pem: String,
        server_key_pem: String,
        client_cert_pem: String,
        client_key_pem: String,
        client_der: rustls::pki_types::CertificateDer<'static>,
        ca_der: rustls::pki_types::CertificateDer<'static>,
        crl_der: CertificateRevocationListDer<'static>,
    }

    struct TlsMaterialPaths {
        _dir: PathBuf,
        ca_cert: PathBuf,
        server_cert: PathBuf,
        server_key: PathBuf,
    }

    fn build_certified_ca() -> CertifiedIssuer<'static, KeyPair> {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "test-ca");

        let ca_key = KeyPair::generate().expect("ca key");
        CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca self-signed")
    }

    fn build_end_entity_params(
        common_name: &str,
        serial: u64,
        cdp_url: &str,
        usages: Vec<ExtendedKeyUsagePurpose>,
    ) -> CertificateParams {
        let mut params = CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
        params.serial_number = Some(SerialNumber::from(serial));
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(IpAddr::from([127, 0, 0, 1])));
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = usages;
        params.use_authority_key_identifier_extension = true;
        params.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![cdp_url.to_owned()],
        }];
        params
    }

    fn build_crl(
        issuer: &Issuer<'_, KeyPair>,
        revoked_serials: &[u64],
    ) -> CertificateRevocationListDer<'static> {
        let revoked_certs = revoked_serials
            .iter()
            .map(|serial| RevokedCertParams {
                serial_number: SerialNumber::from(*serial),
                revocation_time: date_time_ymd(2026, 1, 2),
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect::<Vec<_>>();

        CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 1, 1),
            next_update: date_time_ymd(2027, 1, 1),
            crl_number: SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(issuer)
        .expect("crl signed")
        .into()
    }

    fn build_test_pki(cdp_url: &str, client_serial: u64, revoked_serials: &[u64]) -> TestPki {
        let ca = build_certified_ca();

        let server_key = KeyPair::generate().expect("server key");
        let server_cert = build_end_entity_params(
            "localhost",
            11,
            cdp_url,
            vec![ExtendedKeyUsagePurpose::ServerAuth],
        )
        .signed_by(&server_key, &ca)
        .expect("server cert");

        let client_key = KeyPair::generate().expect("client key");
        let client_cert = build_end_entity_params(
            "mtls-client",
            client_serial,
            cdp_url,
            vec![ExtendedKeyUsagePurpose::ClientAuth],
        )
        .signed_by(&client_key, &ca)
        .expect("client cert");

        TestPki {
            ca_pem: ca.pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
            client_der: client_cert.der().clone(),
            ca_der: ca.der().clone(),
            crl_der: build_crl(&ca, revoked_serials),
        }
    }

    async fn write_tls_materials(pki: &TestPki, suffix: &str) -> TlsMaterialPaths {
        let dir = std::env::temp_dir().join(format!(
            "rmcp-server-kit-crl-{suffix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        tokio::fs::create_dir_all(&dir)
            .await
            .expect("create temp dir");

        let ca_cert = dir.join("ca.pem");
        let server_cert = dir.join("server.pem");
        let server_key = dir.join("server.key");

        tokio::fs::write(&ca_cert, &pki.ca_pem)
            .await
            .expect("write ca pem");
        tokio::fs::write(&server_cert, &pki.server_cert_pem)
            .await
            .expect("write server cert pem");
        tokio::fs::write(&server_key, &pki.server_key_pem)
            .await
            .expect("write server key pem");

        TlsMaterialPaths {
            _dir: dir,
            ca_cert,
            server_cert,
            server_key,
        }
    }

    fn build_mtls_auth_config(ca_cert_path: &PathBuf, deny_on_unavailable: bool) -> AuthConfig {
        serde_json::from_value(serde_json::json!({
            "enabled": true,
            "api_keys": [],
            "mtls": {
                "ca_cert_path": ca_cert_path,
                "required": true,
                "default_role": "viewer",
                "crl_enabled": true,
                "crl_deny_on_unavailable": deny_on_unavailable,
                "crl_allow_http": true,
                "crl_enforce_expiration": true,
                "crl_end_entity_only": false,
                "crl_fetch_timeout": "1s",
                "crl_stale_grace": "24h"
            }
        }))
        .expect("mtls auth config")
    }

    fn build_verifier_mtls_config(ca_cert_path: &str) -> MtlsConfig {
        serde_json::from_value(serde_json::json!({
            "ca_cert_path": ca_cert_path,
            "required": true,
            "default_role": "viewer",
            "crl_enabled": true,
            "crl_deny_on_unavailable": false,
            "crl_allow_http": true,
            "crl_enforce_expiration": true,
            "crl_end_entity_only": false,
            "crl_fetch_timeout": "30s",
            "crl_stale_grace": "24h"
        }))
        .expect("verifier mtls config")
    }

    fn build_verifier(pki: &TestPki) -> DynamicClientCertVerifier {
        let mut roots = RootCertStore::empty();
        roots.add(pki.ca_der.clone()).expect("root add");
        let crl_set = CrlSet::__test_with_prepopulated_crls(
            Arc::new(roots),
            build_verifier_mtls_config("memory://ca.pem"),
            vec![pki.crl_der.clone()],
        )
        .expect("crl set");
        DynamicClientCertVerifier::new(crl_set)
    }

    async fn spawn_tls_server(config: McpServerConfig) -> ServerHarness {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound: SocketAddr = listener.local_addr().unwrap();
        let config = config.with_bind_addr(bound.to_string());

        let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
        let shutdown = CancellationToken::new();
        let shutdown_for_server = shutdown.clone();

        let join = tokio::spawn(async move {
            rmcp_server_kit::transport::serve_with_listener(
                listener,
                config.validate().expect("tls test config valid"),
                || TestHandler,
                Some(ready_tx),
                Some(shutdown_for_server),
            )
            .await
        });

        let signalled: SocketAddr = tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .expect("tls server readiness")
            .expect("tls server task aborted");

        ServerHarness {
            base: format!("https://localhost:{}", signalled.port()),
            shutdown,
            join: Some(join),
        }
    }

    fn build_mtls_client(pki: &TestPki) -> reqwest::Client {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let ca_cert = reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).expect("ca cert");
        let identity = reqwest::Identity::from_pem(
            format!(
                "{}{}{}",
                pki.client_cert_pem, pki.ca_pem, pki.client_key_pem
            )
            .as_bytes(),
        )
        .expect("client identity");

        reqwest::Client::builder()
            .add_root_certificate(ca_cert)
            .identity(identity)
            .build()
            .expect("mtls reqwest client")
    }

    #[tokio::test]
    async fn crl_allows_unrevoked_client() {
        let mock_server = MockServer::start().await;
        let pki = build_test_pki(&format!("{}/ca.crl", mock_server.uri()), 100, &[]);
        let verifier = build_verifier(&pki);

        let result = verifier.verify_client_cert(&pki.client_der, &[], UnixTime::now());
        assert!(result.is_ok(), "unrevoked client cert should verify");
    }

    #[tokio::test]
    async fn crl_rejects_revoked_client() {
        let mock_server = MockServer::start().await;
        let pki = build_test_pki(&format!("{}/ca.crl", mock_server.uri()), 101, &[101]);
        let verifier = build_verifier(&pki);

        let result = verifier.verify_client_cert(&pki.client_der, &[], UnixTime::now());
        assert!(
            result.is_err(),
            "revoked client cert should fail verification"
        );
    }

    #[tokio::test]
    async fn crl_fail_open_when_cdp_unreachable() {
        let pki = build_test_pki("http://127.0.0.1:1/unreachable.crl", 102, &[]);
        let paths = write_tls_materials(&pki, "fail-open").await;
        let auth = build_mtls_auth_config(&paths.ca_cert, false);

        let port = free_port().await;
        let cfg = config_on_port(port)
            .with_tls(&paths.server_cert, &paths.server_key)
            .with_auth(auth);
        let mut harness = spawn_tls_server(cfg).await;

        let client = build_mtls_client(&pki);
        let response = client
            .get(format!("{}/healthz", harness.base))
            .send()
            .await
            .expect("fail-open request should succeed");

        assert_eq!(response.status(), 200);
        harness.shutdown().await.expect("shutdown fail-open server");
    }

    #[tokio::test]
    async fn crl_fail_closed_when_cdp_unreachable() {
        let pki = build_test_pki("http://127.0.0.1:1/unreachable.crl", 103, &[]);
        let paths = write_tls_materials(&pki, "fail-closed").await;
        let auth = build_mtls_auth_config(&paths.ca_cert, true);

        let port = free_port().await;
        let cfg = config_on_port(port)
            .with_tls(&paths.server_cert, &paths.server_key)
            .with_auth(auth);
        let mut harness = spawn_tls_server(cfg).await;

        let client = build_mtls_client(&pki);
        let response = client.get(format!("{}/healthz", harness.base)).send().await;

        assert!(
            response.is_err(),
            "fail-closed request should fail during handshake"
        );
        harness
            .shutdown()
            .await
            .expect("shutdown fail-closed server");
    }
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
    let (_token, hash) = rmcp_server_kit::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("guard-key", hash, "ops")];

    let port = free_port().await;
    let cfg = config_on_port(port)
        .with_auth(test_auth_config(keys))
        .with_allowed_origins(["http://localhost:3000"]);
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
    let (token, hash) = rmcp_server_kit::auth::generate_api_key().unwrap();
    let keys = vec![ApiKeyEntry::new("ops-key", hash, "ops")];
    let policy = Arc::new(RbacPolicy::new(&RbacConfig::with_roles(vec![
        RoleConfig::new("ops", vec!["*".into()], vec!["*".into()]),
    ])));

    let port = free_port().await;
    let cfg = config_on_port(port)
        .with_auth(test_auth_config(keys))
        .with_rbac(policy)
        // 512 byte cap — much smaller than default 1 MiB.
        .with_max_request_body(512);
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
fn oauth_cfg_with_proxy(expose: bool) -> rmcp_server_kit::oauth::OAuthConfig {
    // OAuthConfig and OAuthProxyConfig are `#[non_exhaustive]`, so we build
    // them via serde from a TOML-equivalent JSON document. This is the same
    // path real consumers take when loading from a config file.
    let json = serde_json::json!({
        "issuer": "https://upstream.example/",
        "audience": "rmcp-server-kit-test",
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
    let mut auth = AuthConfig::with_keys(vec![]);
    auth.oauth = Some(oauth_cfg_with_proxy(false));
    let cfg = config_on_port(port)
        .with_auth(auth)
        .with_public_url(format!("http://127.0.0.1:{port}"));
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
    let mut auth = AuthConfig::with_keys(vec![]);
    auth.oauth = Some(oauth_cfg_with_proxy(true));
    let cfg = config_on_port(port)
        .with_auth(auth)
        .with_public_url(format!("http://127.0.0.1:{port}"));
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
    use std::{sync::Mutex, time::Instant};

    use axum::{extract::State, routing::get};
    use tokio::sync::oneshot;

    // Build a server with a *short* graceful deadline (500ms) and an
    // extra route that sleeps 10s server-side -- representing an
    // in-flight tool call that will not finish before the deadline.
    //
    // The handler signals via a oneshot channel as soon as it begins
    // executing, so the test can wait for the request to be
    // *deterministically* in-flight before triggering shutdown
    // (eliminates the prior race where slow CI scheduling could let
    // shutdown fire before the server even saw the request).
    let port = free_port().await;
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let started_state = Arc::new(Mutex::new(Some(started_tx)));
    let cfg = config_on_port(port)
        .with_shutdown_timeout(Duration::from_millis(500))
        .with_extra_router(
            axum::Router::new()
                .route(
                    "/slow",
                    get(
                        |State(state): State<Arc<Mutex<Option<oneshot::Sender<()>>>>>| async move {
                            // Signal exactly once that we've begun
                            // serving the request.
                            if let Ok(mut guard) = state.lock()
                                && let Some(tx) = guard.take()
                            {
                                let _ = tx.send(());
                            }
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            "done"
                        },
                    ),
                )
                .with_state(started_state),
        );

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

    // Wait deterministically until the handler has started executing
    // server-side (replaces the prior fixed 100ms sleep, which was
    // race-prone on slow CI runners). Bound the wait so a real
    // regression in request acceptance still surfaces as a test
    // failure rather than a hang.
    tokio::time::timeout(Duration::from_secs(5), started_rx)
        .await
        .expect("/slow handler did not start within 5s -- request never reached the server")
        .expect("started_tx dropped without sending");

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

// ==========================================================================
// H-A2: McpServerConfig builder + validate()
// ==========================================================================

/// Builder methods produce the same effective config as direct field
/// assignment. Asserts a representative subset of fields touched by
/// every common builder so future drift surfaces here first.
#[tokio::test]
#[allow(
    deprecated,
    reason = "intentionally exercises the deprecated direct-field-write path to verify builder equivalence; this test IS the equivalence proof"
)]
async fn builder_matches_direct_field_assignment() {
    let port = free_port().await;
    let bind = format!("127.0.0.1:{port}");

    let manual = {
        let mut cfg = McpServerConfig::new(&bind, "test", "0.0.1");
        cfg.allowed_origins = vec!["http://localhost:3000".into()];
        cfg.public_url = Some("http://example.com".into());
        cfg.max_request_body = 4096;
        cfg.request_timeout = Duration::from_secs(7);
        cfg.shutdown_timeout = Duration::from_secs(11);
        cfg.session_idle_timeout = Duration::from_mins(2);
        cfg.sse_keep_alive = Duration::from_secs(3);
        cfg.tool_rate_limit = Some(42);
        cfg.max_concurrent_requests = Some(99);
        cfg.compression_enabled = true;
        cfg.compression_min_size = 256;
        cfg.log_request_headers = true;
        cfg.admin_enabled = false;
        cfg.admin_role = "ops".to_owned();
        cfg
    };

    let built = McpServerConfig::new(&bind, "test", "0.0.1")
        .with_allowed_origins(["http://localhost:3000"])
        .with_public_url("http://example.com")
        .with_max_request_body(4096)
        .with_request_timeout(Duration::from_secs(7))
        .with_shutdown_timeout(Duration::from_secs(11))
        .with_session_idle_timeout(Duration::from_mins(2))
        .with_sse_keep_alive(Duration::from_secs(3))
        .with_tool_rate_limit(42)
        .with_max_concurrent_requests(99)
        .enable_compression(256)
        .enable_request_header_logging()
        .enable_admin("ops");
    // `enable_admin` flips admin_enabled=true; manual leaves it false.
    // Compare every other field; admin_enabled is asserted separately.
    assert_eq!(manual.bind_addr, built.bind_addr);
    assert_eq!(manual.allowed_origins, built.allowed_origins);
    assert_eq!(manual.public_url, built.public_url);
    assert_eq!(manual.max_request_body, built.max_request_body);
    assert_eq!(manual.request_timeout, built.request_timeout);
    assert_eq!(manual.shutdown_timeout, built.shutdown_timeout);
    assert_eq!(manual.session_idle_timeout, built.session_idle_timeout);
    assert_eq!(manual.sse_keep_alive, built.sse_keep_alive);
    assert_eq!(manual.tool_rate_limit, built.tool_rate_limit);
    assert_eq!(
        manual.max_concurrent_requests,
        built.max_concurrent_requests
    );
    assert_eq!(manual.compression_enabled, built.compression_enabled);
    assert_eq!(manual.compression_min_size, built.compression_min_size);
    assert_eq!(manual.log_request_headers, built.log_request_headers);
    assert_eq!(manual.admin_role, built.admin_role);
    assert!(built.admin_enabled, "enable_admin should set the flag");
    assert!(
        manual.validate().is_ok(),
        "manual config must validate cleanly"
    );
}

/// `enable_admin` without a corresponding `with_auth(...).enabled = true`
/// must be rejected by `validate()` as `McpxError::Config`. With the
/// typestate `Validated<McpServerConfig>` proof token, `serve()` cannot
/// even be called with an invalid config -- the rejection happens at
/// `validate()` time, statically preventing exposing `/admin/*` without
/// authentication.
#[tokio::test]
async fn validate_rejects_admin_without_auth() {
    let cfg = McpServerConfig::new("127.0.0.1:0", "test", "0.0.1").enable_admin("admin");
    let err = cfg.validate().expect_err("must reject admin without auth");
    assert!(
        matches!(err, rmcp_server_kit::McpxError::Config(ref msg) if msg.contains("admin")),
        "expected McpxError::Config mentioning admin, got: {err}"
    );
}

/// Setting only the TLS cert (or only the key) must be rejected by
/// `validate()`. Both paths must be present together or absent together.
#[tokio::test]
#[allow(
    deprecated,
    reason = "intentionally exercises direct field writes to test partial-pair rejection (no builder sets only one of the pair)"
)]
async fn validate_rejects_partial_tls_pair() {
    let mut cfg = McpServerConfig::new("127.0.0.1:0", "test", "0.0.1");
    cfg.tls_cert_path = Some(std::path::PathBuf::from("/tmp/cert.pem"));
    let err = cfg
        .validate()
        .expect_err("cert without key must be rejected");
    assert!(matches!(err, rmcp_server_kit::McpxError::Config(ref m) if m.contains("tls_key_path")));

    let mut cfg = McpServerConfig::new("127.0.0.1:0", "test", "0.0.1");
    cfg.tls_key_path = Some(std::path::PathBuf::from("/tmp/key.pem"));
    let err = cfg
        .validate()
        .expect_err("key without cert must be rejected");
    assert!(
        matches!(err, rmcp_server_kit::McpxError::Config(ref m) if m.contains("tls_cert_path"))
    );

    // Both set together: only the *file existence* matters at startup,
    // not validate() -- so this should pass validation.
    let cfg = McpServerConfig::new("127.0.0.1:0", "test", "0.0.1")
        .with_tls("/tmp/cert.pem", "/tmp/key.pem");
    cfg.validate().expect("paired cert+key must validate");
}

/// Bad `bind_addr` / `public_url` / origin / zero body cap must each be
/// rejected with a descriptive `McpxError::Config`.
#[tokio::test]
async fn validate_rejects_other_misconfig() {
    // Unparseable bind_addr
    let cfg = McpServerConfig::new("not-a-socket-addr", "t", "0");
    let err = cfg.validate().expect_err("must reject bad bind_addr");
    assert!(matches!(err, rmcp_server_kit::McpxError::Config(ref m) if m.contains("bind_addr")));

    // public_url without scheme
    let cfg =
        McpServerConfig::new("127.0.0.1:0", "t", "0").with_public_url("example.com/no-scheme");
    let err = cfg
        .validate()
        .expect_err("must reject schemeless public_url");
    assert!(matches!(err, rmcp_server_kit::McpxError::Config(ref m) if m.contains("public_url")));

    // origin without scheme
    let cfg = McpServerConfig::new("127.0.0.1:0", "t", "0").with_allowed_origins(["localhost"]);
    let err = cfg.validate().expect_err("must reject schemeless origin");
    assert!(
        matches!(err, rmcp_server_kit::McpxError::Config(ref m) if m.contains("allowed_origins"))
    );

    // zero body cap
    let cfg = McpServerConfig::new("127.0.0.1:0", "t", "0").with_max_request_body(0);
    let err = cfg.validate().expect_err("must reject zero body cap");
    assert!(
        matches!(err, rmcp_server_kit::McpxError::Config(ref m) if m.contains("max_request_body"))
    );
}

// ==========================================================================
// HookedHandler integration (H-A4)
// ==========================================================================

/// Spin up a server whose factory wraps `TestHandler` in a
/// [`rmcp_server_kit::tool_hooks::HookedHandler`].  This proves the new async hook
/// types satisfy `serve_with_listener`'s `ServerHandler` bound and that
/// hook plumbing does not break the basic transport path.
#[tokio::test]
async fn hooked_handler_serves_healthz() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rmcp_server_kit::tool_hooks::{AfterHook, BeforeHook, HookOutcome, ToolHooks, with_hooks};

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let port = free_port().await;
    let cfg = config_on_port(port);

    let before_calls = Arc::new(AtomicUsize::new(0));
    let after_calls = Arc::new(AtomicUsize::new(0));
    let bc = Arc::clone(&before_calls);
    let ac = Arc::clone(&after_calls);

    let before: BeforeHook = Arc::new(move |_ctx| {
        let bc = Arc::clone(&bc);
        Box::pin(async move {
            bc.fetch_add(1, Ordering::Relaxed);
            HookOutcome::Continue
        })
    });
    let after: AfterHook = Arc::new(move |_ctx, _disp, _bytes| {
        let ac = Arc::clone(&ac);
        Box::pin(async move {
            ac.fetch_add(1, Ordering::Relaxed);
        })
    });

    let hooks = Arc::new(
        ToolHooks::new()
            .with_max_result_bytes(64 * 1024)
            .with_before(before)
            .with_after(after),
    );

    // Custom spawn flow because the standard `spawn_server` factory
    // returns the bare TestHandler; we need it wrapped in HookedHandler.
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let bound: SocketAddr = listener.local_addr().unwrap();
    let cfg = cfg.with_bind_addr(bound.to_string());

    let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
    let shutdown = CancellationToken::new();
    let shutdown_for_server = shutdown.clone();
    let hooks_for_factory = Arc::clone(&hooks);

    let join = tokio::spawn(async move {
        rmcp_server_kit::transport::serve_with_listener(
            listener,
            cfg.validate().expect("test config valid"),
            move || with_hooks(TestHandler, Arc::clone(&hooks_for_factory)),
            Some(ready_tx),
            Some(shutdown_for_server),
        )
        .await
    });

    let _signalled: SocketAddr = tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .expect("server did not signal readiness within 5s")
        .expect("server task aborted before readiness signal");

    let resp = reqwest::get(&format!("http://{bound}/healthz"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Hooks haven't fired (no /mcp tools/call traffic), but the server
    // is alive and the wrapped handler is being served.
    assert_eq!(before_calls.load(Ordering::Relaxed), 0);
    assert_eq!(after_calls.load(Ordering::Relaxed), 0);

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// Constructing all three [`rmcp_server_kit::tool_hooks::HookOutcome`] variants
/// must compile and round-trip through the public API.  This guards
/// against accidental visibility regressions on the new enum during
/// future refactors.
#[test]
fn hook_outcome_variants_are_constructible() {
    use rmcp::{
        ErrorData,
        model::{CallToolResult, Content},
    };
    use rmcp_server_kit::tool_hooks::HookOutcome;

    let _ = HookOutcome::Continue;
    let _ = HookOutcome::Deny(ErrorData::invalid_request("denied", None));
    let _ = HookOutcome::Replace(Box::new(CallToolResult::success(vec![Content::text(
        "x".to_owned(),
    )])));
}
