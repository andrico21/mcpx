//! Integration tests for the `OauthHttpClient` hardening shipped in
//! 1.2.1 (B1). The constructor `OauthHttpClient::with_config(&OAuthConfig)`
//! must:
//!
//! - Reject any redirect that downgrades the scheme from `https` to
//!   `http`, even when `allow_http_oauth_urls = true` (downgrade
//!   defence — Test 1A).
//! - Reject redirects to non-HTTP(S) schemes such as `ftp://` (Test 1B).
//! - Reject more than two consecutive redirects (Test 1C).
//! - Honour `OAuthConfig::ca_cert_path` so that OAuth-bound HTTP traffic
//!   trusts enterprise/internal CAs (Test 2-positive).
//! - Surface a `Startup` error if `ca_cert_path` cannot be read
//!   (Test 2-negative).
//!
//! The tests exercise the *real* `OauthHttpClient::with_config` and route
//! requests through the hidden `__test_get` accessor so that the
//! redirect policy and TLS trust store cannot be bypassed by going
//! through any other code path.
//!
//! ## Why a hand-rolled TLS server?
//!
//! `wiremock` cannot terminate TLS, so Test 1A and Test 2 spin up a
//! tiny one-shot TLS server that:
//!
//! 1. Listens on an ephemeral 127.0.0.1 port.
//! 2. Performs a single TLS handshake using a self-signed leaf cert
//!    bound to the SAN `localhost`.
//! 3. Reads the request line + headers, then writes a fixed HTTP/1.1
//!    response.
//!
//! This is intentionally minimal — no `hyper`, no `tower`, no
//! routing — so the test surface remains the redirect policy and TLS
//! trust path themselves.

#![allow(clippy::expect_used, reason = "tests")]
#![allow(clippy::unwrap_used, reason = "tests")]
#![allow(clippy::panic, reason = "tests")]
#![allow(clippy::print_stdout, reason = "tests")]
#![allow(clippy::print_stderr, reason = "tests")]
#![allow(clippy::indexing_slicing, reason = "tests")]
#![allow(dead_code, reason = "PEM fields kept for symmetry / future tests")]
#![cfg(feature = "oauth")]

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rmcp_server_kit::oauth::{OAuthConfig, OauthHttpClient};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

// ---------------------------------------------------------------------------
// PKI & TLS helpers
// ---------------------------------------------------------------------------

/// A self-signed CA together with a leaf certificate signed by it for
/// the SAN `localhost`. Both are returned as PEM strings so callers
/// can either feed them straight into rustls or write the CA to disk
/// and point `ca_cert_path` at it.
struct TestPki {
    /// PEM-encoded CA certificate (single cert).
    ca_pem: String,
    /// PEM-encoded leaf certificate chain (single cert).
    leaf_cert_pem: String,
    /// PEM-encoded PKCS#8 private key for the leaf certificate.
    leaf_key_pem: String,
    /// DER-encoded leaf certificate (kept so we can build a rustls
    /// `ServerConfig` without reparsing PEM).
    leaf_cert_der: Vec<u8>,
    /// DER-encoded PKCS#8 private key.
    leaf_key_der: Vec<u8>,
}

fn build_test_pki() -> TestPki {
    // CA.
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "oauth-test-ca");
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_issuer: CertifiedIssuer<'static, KeyPair> =
        CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca self-signed");

    // Leaf, bound to the SAN `localhost`.
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "oauth-test-leaf");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_issuer)
        .expect("leaf signed");

    let ca_pem = ca_issuer.as_ref().pem();
    let leaf_cert_pem = leaf_cert.pem();
    let leaf_key_pem = leaf_key.serialize_pem();
    let leaf_cert_der = leaf_cert.der().to_vec();
    let leaf_key_der = leaf_key.serialize_der();

    TestPki {
        ca_pem,
        leaf_cert_pem,
        leaf_key_pem,
        leaf_cert_der,
        leaf_key_der,
    }
}

/// Install ring crypto provider once per process. `reqwest` is built
/// with `rustls-no-provider`; tokio-rustls also needs a provider for
/// the test server side.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a rustls `ServerConfig` for the supplied leaf cert + key.
fn build_server_config(pki: &TestPki) -> Arc<ServerConfig> {
    let cert = CertificateDer::from(pki.leaf_cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.leaf_key_der.clone()));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");
    Arc::new(config)
}

/// One-shot TLS server. Accepts a single connection, performs the
/// handshake, reads the request until the end-of-headers `\r\n\r\n`
/// marker, then writes `response_bytes` and closes. Returns the
/// `https://localhost:PORT/` base URL once the listener is bound.
///
/// The server lives on a detached task; the caller does not need to
/// join it (it terminates after one request or after a 5-second
/// timeout).
async fn spawn_one_shot_tls(pki: &TestPki, response_bytes: Vec<u8>) -> String {
    install_crypto_provider();
    let server_config = build_server_config(pki);
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();

    tokio::spawn(async move {
        let accept_fut = listener.accept();
        let (tcp, _peer) = match tokio::time::timeout(Duration::from_secs(5), accept_fut).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                eprintln!("test tls accept error: {e}");
                return;
            }
            Err(_) => {
                eprintln!("test tls accept timed out");
                return;
            }
        };
        let mut tls_stream = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("test tls handshake error: {e}");
                return;
            }
        };

        // Read until end of HTTP headers; cap at 16 KiB to avoid
        // unbounded memory if the client misbehaves.
        let mut buf = vec![0u8; 16 * 1024];
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = match tokio::time::timeout(
                Duration::from_secs(5),
                tls_stream.read(&mut buf[filled..]),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    eprintln!("test tls read error: {e}");
                    return;
                }
                Err(_) => {
                    eprintln!("test tls read timed out");
                    return;
                }
            };
            filled += n;
            if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        if let Err(e) = tls_stream.write_all(&response_bytes).await {
            eprintln!("test tls write error: {e}");
            return;
        }
        let _ = tls_stream.shutdown().await;
    });

    format!("https://localhost:{port}/")
}

/// Build an `OauthHttpClient` with `ca_cert_path` pointing at a temp
/// file containing the PKI's CA. `allow_http_oauth_urls` is
/// configurable so the downgrade test can still set it to `true` and
/// prove that the downgrade is rejected anyway.
fn build_client_with_ca(pki: &TestPki, allow_http: bool) -> (OauthHttpClient, PathBuf) {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let ca_path = dir.join(format!("rmcp-oauth-ca-{pid}-{nanos}.pem"));
    std::fs::write(&ca_path, pki.ca_pem.as_bytes()).expect("write ca pem");

    let mut config = OAuthConfig::default();
    config.ca_cert_path = Some(ca_path.clone());
    config.allow_http_oauth_urls = allow_http;
    let client = OauthHttpClient::with_config(&config).expect("client builds");
    (client, ca_path)
}

/// Used by Test 2 (positive CA) -- references the unused PEM helpers
/// to keep `clippy::dead_code` quiet without `#[allow]` attributes.
fn consume_pem(pki: &TestPki) {
    let _ = (&pki.leaf_cert_pem, &pki.leaf_key_pem);
}

/// Stringify an error chain by walking `source()` so messages set via
/// `reqwest::redirect::Attempt::error(...)` (which live on the inner
/// source) become visible to assertions. `format!("{err:#}")` only
/// renders reqwest's outer wrapper ("error following redirect for url
/// (...)") which omits the redirect-policy reason.
fn render_error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut current = err.source();
    while let Some(inner) = current {
        out.push_str(" :: ");
        out.push_str(&inner.to_string());
        current = inner.source();
    }
    out.to_lowercase()
}

// ---------------------------------------------------------------------------
// Test 1A: https -> http downgrade rejected even when allow_http=true
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redirect_downgrade_https_to_http_is_rejected() {
    let pki = build_test_pki();
    consume_pem(&pki);

    // The TLS server replies with a 302 whose Location header points
    // back at a plain-HTTP URL on `attacker.invalid`. Resolution would
    // fail regardless, but the redirect policy must reject the attempt
    // *before* DNS — we assert that by inspecting the error message.
    let response_bytes = b"HTTP/1.1 302 Found\r\n\
        Location: http://attacker.invalid/exfil\r\n\
        Content-Length: 0\r\n\
        Connection: close\r\n\r\n"
        .to_vec();
    let url = spawn_one_shot_tls(&pki, response_bytes).await;

    let (client, _ca_path) = build_client_with_ca(&pki, /* allow_http */ true);
    let result = client.__test_get(&url).await;

    let err = result.expect_err("downgrade must be rejected");
    let rendered = render_error_chain(&err);
    assert!(
        rendered.contains("downgrade") || rendered.contains("https -> http"),
        "expected downgrade error, got: {rendered}"
    );
    // The redirect-policy error is reported by reqwest as a redirect error.
    assert!(
        err.is_redirect(),
        "expected reqwest::Error::is_redirect()=true, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 1B: redirect to non-HTTP(S) scheme rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redirect_to_non_http_scheme_is_rejected() {
    install_crypto_provider();
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/redir"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "ftp://attacker.invalid/loot"),
        )
        .mount(&mock)
        .await;

    // allow_http=true so the *original* http://... request is permitted.
    // The follow-up to ftp:// must still be refused.
    let mut config = OAuthConfig::default();
    config.allow_http_oauth_urls = true;
    let client = OauthHttpClient::with_config(&config).expect("client builds");

    let url = format!("{}/redir", mock.uri());
    let result = client.__test_get(&url).await;
    let err = result.expect_err("non-HTTP(S) redirect must be rejected");
    let rendered = render_error_chain(&err);
    assert!(
        rendered.contains("non-http") || rendered.contains("refused") || rendered.contains("ftp"),
        "expected non-HTTP(S) error, got: {rendered}"
    );
    assert!(err.is_redirect(), "expected redirect-error, got {err:?}");
}

// ---------------------------------------------------------------------------
// Test 1C: too many redirects rejected (cap = 2 hops)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redirect_chain_capped_at_two_hops() {
    install_crypto_provider();
    let mock = MockServer::start().await;
    let base = mock.uri().replace("127.0.0.1", "localhost");

    // /a -> /b -> /c -> /d (3 hops). The policy permits up to 2.
    let to_b = format!("{base}/b");
    let to_c = format!("{base}/c");
    let to_d = format!("{base}/d");
    Mock::given(method("GET"))
        .and(path("/a"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", to_b.as_str()))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/b"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", to_c.as_str()))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/c"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", to_d.as_str()))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/d"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;

    let mut config = OAuthConfig::default();
    config.allow_http_oauth_urls = true;
    let client = OauthHttpClient::with_config(&config).expect("client builds");

    let url = format!("{base}/a");
    let result = client.__test_get(&url).await;
    let err = result.expect_err("3-hop redirect must be rejected");
    let rendered = render_error_chain(&err);
    assert!(
        rendered.contains("too many redirects") || rendered.contains("max 2"),
        "expected redirect-cap error, got: {rendered}"
    );
    assert!(err.is_redirect(), "expected redirect-error, got {err:?}");
}

// ---------------------------------------------------------------------------
// Test 2 (positive): ca_cert_path is honoured by OauthHttpClient
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ca_cert_path_is_applied_to_oauth_http_client() {
    let pki = build_test_pki();

    // Server replies 200 OK with empty body.
    let response_bytes = b"HTTP/1.1 200 OK\r\n\
        Content-Length: 0\r\n\
        Connection: close\r\n\r\n"
        .to_vec();
    let url = spawn_one_shot_tls(&pki, response_bytes).await;

    // With ca_cert_path set, the request must succeed.
    let (client, _ca_path) = build_client_with_ca(&pki, /* allow_http */ false);
    let response = client
        .__test_get(&url)
        .await
        .expect("request with custom CA must succeed");
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn missing_ca_cert_path_makes_self_signed_request_fail() {
    // Same server, but the client is built WITHOUT ca_cert_path. The
    // self-signed leaf is not trusted by the system roots, so the
    // handshake must fail.
    let pki = build_test_pki();
    let response_bytes = b"HTTP/1.1 200 OK\r\n\
        Content-Length: 0\r\n\
        Connection: close\r\n\r\n"
        .to_vec();
    let url = spawn_one_shot_tls(&pki, response_bytes).await;

    let config = OAuthConfig::default();
    let client = OauthHttpClient::with_config(&config).expect("client builds");
    let result = client.__test_get(&url).await;
    let err = result.expect_err("untrusted self-signed leaf must be rejected");
    // We don't assert a specific error string (rustls phrasing varies
    // across versions); only that a connect-time failure surfaced.
    assert!(
        err.is_connect() || err.is_request() || err.is_builder() || err.is_decode(),
        "expected TLS-layer failure, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 2 (negative): nonexistent ca_cert_path returns Startup error
// ---------------------------------------------------------------------------

#[test]
fn nonexistent_ca_cert_path_returns_startup_error() {
    let mut config = OAuthConfig::default();
    config.ca_cert_path = Some(PathBuf::from(
        "Z:/this/path/definitely/does/not/exist/ca.pem",
    ));
    let err = OauthHttpClient::with_config(&config).expect_err("must fail to read CA");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("ca_cert_path") || rendered.contains("read"),
        "expected ca_cert_path read error, got: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// 1.3.0 hardening: per-hop SSRF guard in redirect policies
// ---------------------------------------------------------------------------
//
// The 1.2.1 redirect policies on both `OauthHttpClient::build` and
// `JwksCache::new` only enforce scheme + hop-count. An attacker can
// still redirect a validator to `https://10.0.0.1/` or
// `https://127.0.0.1/` — both pass scheme + hop checks. 1.3.0 adds a
// sync literal-IP guard (`redirect_target_reason`) that rejects
// private / loopback / link-local / cloud-metadata destinations, plus
// a userinfo check.

#[tokio::test]
async fn rejects_per_hop_redirect_to_private_ip_oauth_client() {
    install_crypto_provider();
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/redir"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://10.0.0.1/internal"),
        )
        .mount(&mock)
        .await;

    let mut config = OAuthConfig::default();
    config.allow_http_oauth_urls = true;
    let client = OauthHttpClient::with_config(&config).expect("client builds");

    let url = format!("{}/redir", mock.uri());
    let result = client.__test_get(&url).await;
    let err = result.expect_err("redirect to private IP must be rejected");
    let rendered = render_error_chain(&err);
    assert!(
        rendered.contains("redirect target forbidden")
            || rendered.contains("private")
            || rendered.contains("rfc1918"),
        "expected redirect-target-forbidden error (per-hop SSRF guard), got: {rendered}"
    );
    assert!(
        err.is_redirect(),
        "expected reqwest::Error::is_redirect()=true, got {err:?}"
    );
}

#[tokio::test]
async fn rejects_per_hop_redirect_to_loopback_oauth_client() {
    // Same guard, loopback target. Covered separately because
    // `redirect_target_reason` returns distinct reasons for the two
    // categories; we want proof both branches fire.
    install_crypto_provider();
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/redir"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://127.0.0.1/admin"),
        )
        .mount(&mock)
        .await;

    let mut config = OAuthConfig::default();
    config.allow_http_oauth_urls = true;
    let client = OauthHttpClient::with_config(&config).expect("client builds");

    let url = format!("{}/redir", mock.uri());
    let result = client.__test_get(&url).await;
    let err = result.expect_err("redirect to loopback must be rejected");
    let rendered = render_error_chain(&err);
    assert!(
        rendered.contains("redirect target forbidden") || rendered.contains("loopback"),
        "expected loopback redirect rejection, got: {rendered}"
    );
    assert!(err.is_redirect(), "expected redirect-error, got {err:?}");
}

#[tokio::test]
async fn rejects_redirect_with_userinfo_oauth_client() {
    install_crypto_provider();
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/redir"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://evil@example.com/pwn"),
        )
        .mount(&mock)
        .await;

    let mut config = OAuthConfig::default();
    config.allow_http_oauth_urls = true;
    let client = OauthHttpClient::with_config(&config).expect("client builds");

    let url = format!("{}/redir", mock.uri());
    let result = client.__test_get(&url).await;
    let err = result.expect_err("redirect with userinfo must be rejected");
    let rendered = render_error_chain(&err);
    assert!(
        rendered.contains("redirect target forbidden")
            || rendered.contains("userinfo")
            || rendered.contains("credentials"),
        "expected userinfo redirect rejection, got: {rendered}"
    );
    assert!(err.is_redirect(), "expected redirect-error, got {err:?}");
}

#[tokio::test]
async fn redirect_to_http_with_userinfo_rejected_when_http_allowed() {
    install_crypto_provider();
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/redir"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", "http://user:pass@example.com/pwn"),
        )
        .mount(&mock)
        .await;

    let mut config = OAuthConfig::default();
    config.allow_http_oauth_urls = true;
    let client = OauthHttpClient::with_config(&config).expect("client builds");

    let url = format!("{}/redir", mock.uri());
    let result = client.__test_get(&url).await;
    let err = result.expect_err("http redirect with userinfo must be rejected");
    let rendered = render_error_chain(&err);
    assert!(
        rendered.contains("redirect target forbidden")
            || rendered.contains("userinfo")
            || rendered.contains("credentials"),
        "expected userinfo redirect rejection, got: {rendered}"
    );
    assert!(err.is_redirect(), "expected redirect-error, got {err:?}");
}
