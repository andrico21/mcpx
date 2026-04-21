//! 1.3.0 hardening: JWKS key-count soft cap (Deliverable 6).
//!
//! `JwksCache::refresh_inner` MUST refuse to populate the in-memory
//! key cache when the upstream JWKS document carries more keys than
//! [`OAuthConfig::max_jwks_keys`] (default 256). The failure mode is
//! **fail-closed** — no keys are installed, so subsequent
//! `validate_token` calls still reject the JWT. Silent truncation
//! would cause sporadic auth failures and hide the misconfiguration.
//!
//! Failing-first TDD surface — requires these NEW helpers:
//!
//! * `OAuthConfig::max_jwks_keys: usize` (`#[serde(default)]`, default 256)
//! * `fn build_key_cache(&JwkSet, usize) -> Result<JwksKeyCache, String>`
//!   returning `Err(msg)` containing the literal substring
//!   `"jwks_key_count_exceeds_cap"` on breach.
//! * `impl JwksCache { pub async fn __test_refresh_now(&self) -> Result<(), String> }`
//! * `impl JwksCache { pub async fn __test_has_kid(&self, kid: &str) -> bool }`

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

/// Build a synthetic JWKS document with `n` RSA keys. The key material
/// is bogus (short base64url `"AQAB"` / `"dummy"`) because the test
/// exercises the cap path — `build_key_cache` rejects on length BEFORE
/// it would attempt key decoding, so invalid key bytes are fine.
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

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[tokio::test]
async fn jwks_rejects_excess_keys_fail_closed() {
    install_crypto_provider();

    // Wiremock serves a JWKS document with 300 RSA keys.
    let mock = MockServer::start().await;
    let jwks_doc = synthetic_jwks(300);
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_doc))
        .mount(&mock)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock.uri());
    let mut config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
    // Permit plain-HTTP wiremock origin for this test (validate() does
    // not otherwise allow http:// jwks URIs). The allow_http flag is
    // orthogonal to the key-cap hardening under test.
    config.allow_http_oauth_urls = true;
    // Cap = 256; document has 300 → must reject fail-closed.
    config.max_jwks_keys = 256;

    // `JwksCache::new` does NOT fetch — only builds the reqwest client.
    let cache = JwksCache::new(&config)
        .expect("construct cache")
        .__test_allow_loopback_ssrf();

    // Drive the refresh path that would normally happen on first
    // validate_token() call. The new __test_refresh_now helper surfaces
    // the `build_key_cache` error string verbatim.
    let result = cache.__test_refresh_now().await;

    let err = result.expect_err("300 keys must exceed cap=256");
    assert!(
        err.contains("jwks_key_count_exceeds_cap"),
        "refresh error must contain literal `jwks_key_count_exceeds_cap`; got: {err}"
    );

    // Fail-closed: cache MUST be empty afterwards. No keys were installed.
    assert!(
        !cache.__test_has_kid("kid-0").await,
        "cache must remain empty on cap breach (fail-closed, no silent truncation)"
    );
    assert!(
        !cache.__test_has_kid("kid-255").await,
        "cache must remain empty on cap breach (fail-closed, not first-N truncation)"
    );
    assert!(
        !cache.__test_has_kid("kid-299").await,
        "cache must remain empty on cap breach (fail-closed, not last-N)"
    );
}

#[tokio::test]
async fn jwks_at_cap_populates_successfully() {
    install_crypto_provider();

    // Exactly at the cap → populate as normal.
    let mock = MockServer::start().await;
    let jwks_doc = synthetic_jwks(8);
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_doc))
        .mount(&mock)
        .await;

    let jwks_uri = format!("{}/.well-known/jwks.json", mock.uri());
    let mut config = OAuthConfig::builder("https://issuer.example.com/", "aud", &jwks_uri).build();
    config.allow_http_oauth_urls = true;
    config.max_jwks_keys = 8;

    let cache = JwksCache::new(&config)
        .expect("construct cache")
        .__test_allow_loopback_ssrf();
    cache
        .__test_refresh_now()
        .await
        .expect("refresh at cap must succeed");

    assert!(
        cache.__test_has_kid("kid-0").await,
        "cache must contain first kid after successful refresh"
    );
    assert!(
        cache.__test_has_kid("kid-7").await,
        "cache must contain last kid after successful refresh"
    );
}
