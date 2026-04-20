//! 1.3.0 Oracle B3: exercise JWKS redirect SSRF protection through the
//! real `JwksCache::new()` client and refresh path.

#![allow(clippy::expect_used, reason = "tests")]
#![allow(clippy::unwrap_used, reason = "tests")]
#![allow(clippy::panic, reason = "tests")]
#![cfg(feature = "oauth")]

use rmcp_server_kit::oauth::{JwksCache, OAuthConfig};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[tokio::test]
async fn jwks_cache_redirect_to_private_ip_rejected() {
    install_crypto_provider();

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://127.0.0.1:1/jwks"),
        )
        .mount(&mock)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock.uri());
    let mut config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
    config.allow_http_oauth_urls = true;

    let cache = JwksCache::new(&config).expect("construct cache");
    let err = cache
        .__test_refresh_now()
        .await
        .expect_err("redirect to loopback/private IP must be rejected");
    assert!(
        err.contains("failed to fetch or parse JWKS"),
        "refresh should fail cleanly when redirect policy rejects target; got: {err}"
    );
    assert!(
        !cache.__test_has_kid("kid-0").await,
        "cache must remain untouched after redirect rejection"
    );
}

#[tokio::test]
async fn jwks_cache_redirect_to_userinfo_rejected() {
    install_crypto_provider();

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", "https://user:pass@example.com/jwks"),
        )
        .mount(&mock)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock.uri());
    let mut config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
    config.allow_http_oauth_urls = true;

    let cache = JwksCache::new(&config).expect("construct cache");
    let err = cache
        .__test_refresh_now()
        .await
        .expect_err("redirect with userinfo must be rejected");
    assert!(
        err.contains("failed to fetch or parse JWKS"),
        "refresh should fail cleanly when redirect policy rejects target; got: {err}"
    );
    assert!(
        !cache.__test_has_kid("kid-0").await,
        "cache must remain untouched after redirect rejection"
    );
}
