//! 1.3.0 hardening: bounded growth on `CrlSet` unbounded maps.
//!
//! Failing-first TDD suite covering four new invariants:
//!
//! 1. `seen_urls` is capped at `MtlsConfig::crl_max_seen_urls` (silent
//!    drop + warn log when exceeded).
//! 2. `host_semaphores` is capped at `MtlsConfig::crl_max_host_semaphores`
//!    and returns a **loud** [`McpxError::Config`] whose message contains
//!    the literal substring `"crl_host_semaphore_cap_exceeded"` when the
//!    cap is breached on the request hot path.
//! 3. `cache` is capped at `MtlsConfig::crl_max_cache_entries` (silent
//!    drop + warn log — newest-rejected, not LRU-evicted).
//! 4. Stale-removal path (`refresh_urls` error branch) also clears the
//!    affected URL from `seen_urls`, enabling retry after transient
//!    attacker floods.
//!
//! Requires the following NEW test accessors (see plan deliverables):
//!
//! * `CrlSet::__test_host_semaphore_count(&self) -> usize`
//! * `CrlSet::__test_cache_len(&self) -> usize`
//! * `CrlSet::__test_cache_contains(&self, &str) -> bool`
//! * `CrlSet::__test_trigger_fetch(&self, &str) -> Result<(), McpxError>`

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
#![cfg(feature = "test-helpers")]

use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rmcp_server_kit::{auth::MtlsConfig, mtls_revocation::CrlSet};
use rustls::RootCertStore;

fn build_ca_root() -> rustls::pki_types::CertificateDer<'static> {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(DnType::CommonName, "mapbounds-ca");
    let key = KeyPair::generate().expect("ca key");
    let issuer: CertifiedIssuer<'static, KeyPair> =
        CertifiedIssuer::self_signed(params, key).expect("ca self-signed");
    issuer.der().clone()
}

fn install_ring_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build an `MtlsConfig` with tight caps and liberal everything else,
/// so the test focuses on the cap under test and nothing collateral
/// interferes.
fn bounded_config(
    max_host_semaphores: usize,
    max_seen_urls: usize,
    max_cache_entries: usize,
) -> MtlsConfig {
    serde_json::from_value(serde_json::json!({
        "ca_cert_path": "memory://ca.pem",
        "required": true,
        "default_role": "viewer",
        "crl_enabled": true,
        "crl_deny_on_unavailable": false,
        "crl_allow_http": true,
        "crl_enforce_expiration": true,
        "crl_end_entity_only": false,
        "crl_fetch_timeout": "30s",
        "crl_stale_grace": "24h",
        "crl_max_concurrent_fetches": 4,
        "crl_max_response_bytes": 5_242_880u64,
        // Very high so rate limiting doesn't interact with these tests.
        "crl_discovery_rate_per_min": 10_000u32,
        "crl_max_host_semaphores": max_host_semaphores,
        "crl_max_seen_urls": max_seen_urls,
        "crl_max_cache_entries": max_cache_entries,
    }))
    .expect("bounded mtls config")
}

fn empty_crl_set(
    max_host_semaphores: usize,
    max_seen_urls: usize,
    max_cache_entries: usize,
) -> Arc<CrlSet> {
    install_ring_provider();
    let mut roots = RootCertStore::empty();
    roots.add(build_ca_root()).expect("add ca root");
    let roots = Arc::new(roots);
    CrlSet::__test_with_prepopulated_crls(
        roots,
        bounded_config(max_host_semaphores, max_seen_urls, max_cache_entries),
        vec![],
    )
    .expect("empty CRL set")
}

#[tokio::test]
async fn seen_urls_hard_cap_drops_excess() {
    // Cap seen_urls at 4; present 6 unique URLs; only the first 4 must
    // be marked seen. No error is surfaced (silent-drop + warn).
    let set = empty_crl_set(1024, 4, 1024);

    let urls: Vec<String> = (0..6)
        .map(|i| format!("https://host{i}.example.test/crl"))
        .collect();

    // Submit in one batch — the implementation MUST drop admissions
    // beyond the cap rather than grow the set unboundedly.
    let _ = set.__test_note_discovered_urls(&urls);

    for (i, u) in urls.iter().enumerate() {
        if i < 4 {
            assert!(
                set.__test_is_seen(u),
                "URL #{i} within cap must be marked seen: {u}"
            );
        } else {
            assert!(
                !set.__test_is_seen(u),
                "URL #{i} beyond cap must NOT be marked seen: {u}"
            );
        }
    }
}

#[tokio::test]
async fn host_semaphores_hard_cap_returns_error() {
    // Cap host_semaphores at 2; trigger fetches against 3 distinct
    // hosts. The third MUST return an Err whose message contains the
    // literal `crl_host_semaphore_cap_exceeded` substring.
    let set = empty_crl_set(2, 4096, 1024);

    let r1 = set
        .__test_trigger_fetch("https://h1.example.test/crl")
        .await;
    // OK-or-network-error is fine; we only care the cap did NOT fire.
    assert_not_cap_err(&r1, "first host must not hit host-semaphore cap");

    let r2 = set
        .__test_trigger_fetch("https://h2.example.test/crl")
        .await;
    assert_not_cap_err(&r2, "second host must not hit host-semaphore cap");

    let r3 = set
        .__test_trigger_fetch("https://h3.example.test/crl")
        .await;
    let err = r3.expect_err("third host MUST exceed host_semaphores cap");
    let msg = err.to_string();
    assert!(
        msg.contains("crl_host_semaphore_cap_exceeded"),
        "error message must contain literal substring `crl_host_semaphore_cap_exceeded`; got: {msg}"
    );

    assert!(
        set.__test_host_semaphore_count() <= 2,
        "host_semaphores count must stay <= cap; was {}",
        set.__test_host_semaphore_count()
    );
}

fn assert_not_cap_err(r: &Result<(), rmcp_server_kit::error::McpxError>, ctx: &str) {
    if let Err(e) = r {
        assert!(
            !e.to_string().contains("crl_host_semaphore_cap_exceeded"),
            "{ctx}: unexpectedly hit host-semaphore cap: {e}"
        );
    }
}

#[tokio::test]
async fn cache_hard_cap_drops_newest() {
    // Cap cache at 2; attempt to insert 3 distinct successful entries.
    // Only the first two are retained; the third is dropped (newest-
    // rejected, not LRU-evicted).
    use std::time::SystemTime;

    use rmcp_server_kit::mtls_revocation::CachedCrl;

    let set = empty_crl_set(1024, 4096, 2);

    let now = SystemTime::now();

    // NB: We need a public test-only helper to insert into the cache
    // without running HTTP. We reuse the convention of existing
    // __test_* helpers. This helper is part of the 1.3.0 deliverables.
    for url in [
        "https://a.example.test/crl",
        "https://b.example.test/crl",
        "https://c.example.test/crl",
    ] {
        set.__test_insert_cache(url, CachedCrl::__test_synthetic(now))
            .await;
    }

    assert_eq!(
        set.__test_cache_len(),
        2,
        "cache len must be clamped to cap"
    );
    assert!(
        set.__test_cache_contains("https://a.example.test/crl"),
        "first insert must be retained"
    );
    assert!(
        set.__test_cache_contains("https://b.example.test/crl"),
        "second insert must be retained"
    );
    assert!(
        !set.__test_cache_contains("https://c.example.test/crl"),
        "third insert (newest beyond cap) must be rejected"
    );
}

#[tokio::test]
async fn stale_removal_also_clears_seen() {
    // Prepopulate seen_urls and cache with the same URL; make the
    // cached entry appear stale beyond the grace window; trigger a
    // refresh that fails; assert BOTH seen_urls and cache drop the
    // URL (current 1.2.1 only drops from cache + cached_urls).
    use std::time::{Duration, SystemTime};

    use rmcp_server_kit::mtls_revocation::CachedCrl;

    let set = empty_crl_set(1024, 4096, 1024);
    let url = "https://stale.example.test/crl";

    // Mark URL as seen via the production path (simulating a prior
    // handshake's discovery).
    let _ = set.__test_note_discovered_urls(&[url.to_string()]);
    assert!(set.__test_is_seen(url), "precondition: URL should be seen");

    // Insert a stale cache entry whose next_update + grace is in the
    // past, so the refresh loop treats fetch-failure as removable.
    let past = SystemTime::now() - Duration::from_secs(60 * 60 * 24 * 30); // 30 days ago
    set.__test_insert_cache(url, CachedCrl::__test_stale(past))
        .await;
    assert!(
        set.__test_cache_contains(url),
        "precondition: URL should be cached"
    );

    // Refresh will fail (network-unreachable mocked host) and the
    // stale-grace predicate will match, so production code must
    // remove the entry AND clear seen_urls.
    let _ = set.__test_trigger_refresh_url(url).await;

    assert!(
        !set.__test_cache_contains(url),
        "stale refresh failure must drop URL from cache"
    );
    assert!(
        !set.__test_is_seen(url),
        "stale refresh failure must also clear seen_urls (1.3.0 invariant)"
    );
}
