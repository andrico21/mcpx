//! 1.3.0 Oracle B3: exercise JWKS redirect SSRF protection through the
//! real `JwksCache::new()` client and refresh path.

#![allow(clippy::expect_used, reason = "tests")]
#![allow(clippy::unwrap_used, reason = "tests")]
#![allow(clippy::panic, reason = "tests")]
#![cfg(all(feature = "oauth", feature = "test-helpers"))]

use rmcp_server_kit::oauth::{JwksCache, OAuthConfig};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn synthetic_jwks(n: usize) -> Value {
    let keys: Vec<Value> = (0..n)
        .map(|i| {
            json!({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": format!("kid-{i}"),
                "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS-uo-0Rwm9uYCKu_yvfZm9LDJ7zXYf8DrK9tYmoPSt4K3fhfB9m9k9MhE7_tR5sQkOA0OiYuVLxbBR-g3nL5yGgGSsj5lmNS_4F9zMzJgJWK5A7K6sH8zDjpwcTWfTUqB2c9yw0yDkBYMHRDHeozs9ybyoUNt4fT7aVRMVAjEhCEPJmSmnyfH_5w",
                "e": "AQAB"
            })
        })
        .collect();
    json!({ "keys": keys })
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

#[tokio::test]
async fn jwks_cache_http_to_http_redirect_followed_when_http_allowed() {
    install_crypto_provider();

    let mock = MockServer::start().await;
    let base = mock.uri().replace("127.0.0.1", "localhost");
    let jwks_doc = synthetic_jwks(1);
    let redirect_target = format!("{base}/jwks-followed.json");

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", redirect_target.as_str()),
        )
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks-followed.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_doc))
        .mount(&mock)
        .await;

    let jwks_uri = format!("{base}/.well-known/jwks.json");
    let mut config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
    config.allow_http_oauth_urls = true;

    let cache = JwksCache::new(&config).expect("construct cache");
    cache
        .__test_refresh_now()
        .await
        .expect("http-to-http redirect should be followed when allow_http=true");
    assert!(
        cache.__test_has_kid("kid-0").await,
        "cache must populate after allowed http-to-http redirect"
    );
}

#[tokio::test]
async fn jwks_cache_http_to_http_redirect_rejected_when_http_disallowed() {
    install_crypto_provider();

    let mock = MockServer::start().await;
    let base = mock.uri().replace("127.0.0.1", "localhost");
    let redirect_target = format!("{base}/jwks-followed.json");

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", redirect_target.as_str()),
        )
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks-followed.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(synthetic_jwks(1)))
        .mount(&mock)
        .await;

    let jwks_uri = format!("{base}/.well-known/jwks.json");
    let config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();

    let cache = JwksCache::new(&config).expect("construct cache");
    let err = cache
        .__test_refresh_now()
        .await
        .expect_err("http-to-http redirect must be rejected when allow_http=false");
    assert!(
        err.contains("failed to fetch or parse JWKS"),
        "refresh should fail cleanly when redirect policy rejects target; got: {err}"
    );
    assert!(
        !cache.__test_has_kid("kid-0").await,
        "cache must remain untouched after disallowed http-to-http redirect"
    );
}
