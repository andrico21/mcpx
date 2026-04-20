//! CDP-driven CRL revocation support for mTLS.
//!
//! When mTLS is configured with CRL checks enabled, startup performs a bounded
//! bootstrap pass over the configured CA bundle, extracts CRL Distribution
//! Point (CDP) URLs, fetches reachable CRLs, and builds the initial inner
//! `rustls` verifier from that cache.
//!
//! During handshakes, the outer verifier remains stable for the lifetime of the
//! TLS acceptor while its inner `WebPkiClientVerifier` is swapped atomically via
//! `ArcSwap` as CRLs are discovered or refreshed. Discovery from connecting
//! client certificates is fire-and-forget and never blocks the synchronous
//! handshake path.
//!
//! Semantics:
//! - `crl_deny_on_unavailable = false` => fail open with warn logs.
//! - `crl_deny_on_unavailable = true` => fail closed when a certificate
//!   advertises CDP URLs whose revocation status is not yet available.

use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU32,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error as TlsError, RootCertStore, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime},
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use tokio::{
    net::lookup_host,
    sync::{RwLock, Semaphore, mpsc},
    task::JoinSet,
    time::{Instant, Sleep},
};
use tokio_util::sync::CancellationToken;
use url::Url;
use x509_parser::{
    extensions::{DistributionPointName, GeneralName, ParsedExtension},
    prelude::{FromDer, X509Certificate},
    revocation_list::CertificateRevocationList,
};

use crate::{
    auth::MtlsConfig,
    error::McpxError,
    ssrf::{check_scheme, ip_block_reason},
};

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_AUTO_REFRESH: Duration = Duration::from_mins(10);
const MAX_AUTO_REFRESH: Duration = Duration::from_hours(24);
/// Connection timeout for CRL HTTP fetches. Independent of overall fetch
/// timeout to bound time spent on unreachable hosts.
const CRL_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Parsed CRL cached in memory and keyed by its source URL.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CachedCrl {
    /// DER bytes for the CRL.
    pub der: CertificateRevocationListDer<'static>,
    /// `thisUpdate` field from the CRL.
    pub this_update: SystemTime,
    /// `nextUpdate` field from the CRL, if present.
    pub next_update: Option<SystemTime>,
    /// Time the server fetched this CRL.
    pub fetched_at: SystemTime,
    /// Source URL used for retrieval.
    pub source_url: String,
}

pub(crate) struct VerifierHandle(pub Arc<dyn ClientCertVerifier>);

impl std::fmt::Debug for VerifierHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierHandle").finish_non_exhaustive()
    }
}

/// Shared CRL state backing the dynamic mTLS verifier.
#[allow(
    missing_debug_implementations,
    reason = "contains ArcSwap and dyn verifier internals"
)]
#[non_exhaustive]
pub struct CrlSet {
    inner_verifier: ArcSwap<VerifierHandle>,
    /// Cached CRLs keyed by URL.
    pub cache: RwLock<HashMap<String, CachedCrl>>,
    /// Immutable client-auth root store.
    pub roots: Arc<RootCertStore>,
    /// mTLS CRL configuration.
    pub config: MtlsConfig,
    /// Fire-and-forget discovery channel for newly-seen CDP URLs.
    pub discover_tx: mpsc::UnboundedSender<String>,
    client: reqwest::Client,
    seen_urls: Mutex<HashSet<String>>,
    cached_urls: Mutex<HashSet<String>>,
    /// Global cap on simultaneous CRL HTTP fetches (SSRF amplification guard).
    global_fetch_sem: Arc<Semaphore>,
    /// Per-host serializer (one in-flight fetch per origin host).
    host_semaphores: Arc<tokio::sync::Mutex<HashMap<String, Arc<Semaphore>>>>,
    /// Global rate-limiter on discovery URL submissions; protects against
    /// cert-driven URL flooding by a malicious mTLS peer.
    ///
    /// Note: this ships as a process-global limiter; per-source-IP scoping
    /// is deferred to a future release because the rustls
    /// `verify_client_cert` callback does not carry a `SocketAddr` for the
    /// peer.
    discovery_limiter: Arc<DefaultDirectRateLimiter>,
    /// Cached cap on per-fetch response body size; copied from `config` so the
    /// hot path doesn't re-read the (rarely changing) config struct.
    max_response_bytes: u64,
    last_cap_warn: Mutex<HashMap<&'static str, Instant>>,
}

impl CrlSet {
    fn new(
        roots: Arc<RootCertStore>,
        config: MtlsConfig,
        discover_tx: mpsc::UnboundedSender<String>,
        initial_cache: HashMap<String, CachedCrl>,
    ) -> Result<Arc<Self>, McpxError> {
        let client = reqwest::Client::builder()
            .timeout(config.crl_fetch_timeout)
            .connect_timeout(CRL_CONNECT_TIMEOUT)
            .tcp_keepalive(None)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(format!("rmcp-server-kit/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| McpxError::Startup(format!("CRL HTTP client init: {error}")))?;

        let initial_verifier = rebuild_verifier(&roots, &config, &initial_cache)?;
        let seen_urls = initial_cache.keys().cloned().collect::<HashSet<_>>();
        let cached_urls = seen_urls.clone();

        let concurrency = config.crl_max_concurrent_fetches.max(1);
        let global_fetch_sem = Arc::new(Semaphore::new(concurrency));
        let host_semaphores = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        let rate =
            NonZeroU32::new(config.crl_discovery_rate_per_min.max(1)).unwrap_or(NonZeroU32::MIN);
        let discovery_limiter = Arc::new(RateLimiter::direct(Quota::per_minute(rate)));

        let max_response_bytes = config.crl_max_response_bytes;

        Ok(Arc::new(Self {
            inner_verifier: ArcSwap::from_pointee(VerifierHandle(initial_verifier)),
            cache: RwLock::new(initial_cache),
            roots,
            config,
            discover_tx,
            client,
            seen_urls: Mutex::new(seen_urls),
            cached_urls: Mutex::new(cached_urls),
            global_fetch_sem,
            host_semaphores,
            discovery_limiter,
            max_response_bytes,
            last_cap_warn: Mutex::new(HashMap::new()),
        }))
    }

    fn warn_cap_exceeded_throttled(&self, which: &'static str) {
        let now = Instant::now();
        let cooldown = Duration::from_mins(1);
        let should_warn = match self.last_cap_warn.lock() {
            Ok(mut guard) => {
                let should_emit = guard
                    .get(which)
                    .is_none_or(|last| now.saturating_duration_since(*last) >= cooldown);
                if should_emit {
                    guard.insert(which, now);
                }
                should_emit
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                let should_emit = guard
                    .get(which)
                    .is_none_or(|last| now.saturating_duration_since(*last) >= cooldown);
                if should_emit {
                    guard.insert(which, now);
                }
                should_emit
            }
        };

        if should_warn {
            tracing::warn!(which = which, "CRL map cap exceeded; dropping newest entry");
        }
    }

    async fn insert_cache_entry(&self, url: String, cached: CachedCrl) -> bool {
        let inserted = {
            let mut guard = self.cache.write().await;
            if guard.len() >= self.config.crl_max_cache_entries && !guard.contains_key(&url) {
                false
            } else {
                guard.insert(url.clone(), cached);
                true
            }
        };

        if inserted {
            match self.cached_urls.lock() {
                Ok(mut cached_urls) => {
                    cached_urls.insert(url);
                }
                Err(poisoned) => {
                    poisoned.into_inner().insert(url);
                }
            }
        } else {
            self.warn_cap_exceeded_throttled("cache");
        }

        inserted
    }

    /// Force an immediate refresh of all currently known CRL URLs.
    ///
    /// # Errors
    ///
    /// Returns an error if rebuilding the inner verifier fails.
    pub async fn force_refresh(&self) -> Result<(), McpxError> {
        let urls = {
            let cache = self.cache.read().await;
            cache.keys().cloned().collect::<Vec<_>>()
        };
        self.refresh_urls(urls).await
    }

    async fn refresh_due_urls(&self) -> Result<(), McpxError> {
        let now = SystemTime::now();
        let urls = {
            let cache = self.cache.read().await;
            cache
                .iter()
                .filter(|(_, cached)| {
                    should_refresh_cached(cached, now, self.config.crl_refresh_interval)
                })
                .map(|(url, _)| url.clone())
                .collect::<Vec<_>>()
        };

        if urls.is_empty() {
            return Ok(());
        }

        self.refresh_urls(urls).await
    }

    async fn refresh_urls(&self, urls: Vec<String>) -> Result<(), McpxError> {
        let results = self.fetch_url_results(urls).await;
        let now = SystemTime::now();
        let mut cache = self.cache.write().await;
        let mut changed = false;

        for (url, result) in results {
            match result {
                Ok(cached) => {
                    if cache.len() >= self.config.crl_max_cache_entries && !cache.contains_key(&url)
                    {
                        drop(cache);
                        self.warn_cap_exceeded_throttled("cache");
                        cache = self.cache.write().await;
                        continue;
                    }
                    cache.insert(url.clone(), cached);
                    changed = true;
                    match self.cached_urls.lock() {
                        Ok(mut cached_urls) => {
                            cached_urls.insert(url);
                        }
                        Err(poisoned) => {
                            poisoned.into_inner().insert(url);
                        }
                    }
                }
                Err(error) => {
                    let remove_entry = cache.get(&url).is_some_and(|existing| {
                        existing
                            .next_update
                            .and_then(|next| next.checked_add(self.config.crl_stale_grace))
                            .is_some_and(|deadline| now > deadline)
                    });
                    tracing::warn!(url = %url, error = %error, "CRL refresh failed");
                    if remove_entry {
                        cache.remove(&url);
                        changed = true;
                        match self.cached_urls.lock() {
                            Ok(mut cached_urls) => {
                                cached_urls.remove(&url);
                            }
                            Err(poisoned) => {
                                poisoned.into_inner().remove(&url);
                            }
                        }
                        match self.seen_urls.lock() {
                            Ok(mut seen_urls) => {
                                seen_urls.remove(&url);
                            }
                            Err(poisoned) => {
                                poisoned.into_inner().remove(&url);
                            }
                        }
                    }
                }
            }
        }

        if changed {
            self.swap_verifier_from_cache(&cache)?;
        }

        Ok(())
    }

    async fn fetch_and_store_url(&self, url: String) -> Result<(), McpxError> {
        let cached = gated_fetch(
            &self.client,
            &self.global_fetch_sem,
            &self.host_semaphores,
            &url,
            self.config.crl_allow_http,
            self.max_response_bytes,
            self.config.crl_max_host_semaphores,
        )
        .await?;
        if !self.insert_cache_entry(url, cached).await {
            return Ok(());
        }
        let cache = self.cache.read().await;
        self.swap_verifier_from_cache(&cache)?;
        Ok(())
    }

    fn note_discovered_urls(&self, urls: &[String]) -> bool {
        // INVARIANT: only called post-handshake from
        // `DynamicClientCertVerifier::verify_client_cert`. The peer has
        // already presented a chain that parses; this method must not panic
        // under attacker-controlled URL contents.
        let mut missing_cached = false;

        // Snapshot the dedup set under the lock; do NOT mutate it yet.
        // We promote a URL to "seen" only after it is actually admitted
        // by the rate-limiter and queued on the discover channel.
        // Otherwise a single rate-limited handshake would permanently
        // black-hole the URL: every subsequent handshake would see it as
        // "already known" and skip the limiter entirely, while the
        // background fetcher would never have received it. With
        // `crl_deny_on_unavailable = true` that produces persistent
        // handshake failures; with fail-open it silently disables CRL
        // discovery for that endpoint forever.
        let candidates: Vec<String> = match self.seen_urls.lock() {
            Ok(seen) => urls
                .iter()
                .filter(|url| !seen.contains(*url))
                .cloned()
                .collect(),
            Err(_) => Vec::new(),
        };

        // Rate-limit gate: drop excess submissions on the floor with a WARN.
        // The mTLS verifier must remain non-blocking, so we use the
        // synchronous `check()` API and never await here. Only on a
        // successful `check()` AND a successful `send()` do we commit
        // the URL to `seen_urls`; this guarantees retriability of any
        // URL that lost the limiter race.
        for url in candidates {
            if self.discovery_limiter.check().is_err() {
                tracing::warn!(
                    url = %url,
                    "discovery_rate_limited: dropped CDP URL beyond per-minute cap (will be retried on next handshake observing this URL)"
                );
                continue;
            }
            if self.discover_tx.send(url.clone()).is_err() {
                // Receiver gone (shutdown). Do NOT mark as seen so the
                // URL can be retried after a reload / restart.
                tracing::debug!(
                    url = %url,
                    "discover channel closed; dropping CDP URL without marking seen"
                );
                continue;
            }
            // Admission succeeded: now safe to dedup permanently.
            let mut guard = self
                .seen_urls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.len() >= self.config.crl_max_seen_urls {
                self.warn_cap_exceeded_throttled("seen_urls");
                break;
            }
            guard.insert(url);
        }

        if self.config.crl_deny_on_unavailable {
            let cached = self
                .cached_urls
                .lock()
                .ok()
                .map(|guard| guard.clone())
                .unwrap_or_default();
            missing_cached = urls.iter().any(|url| !cached.contains(url));
        }

        missing_cached
    }

    /// Test helper for constructing a CRL set from in-memory CRLs.
    ///
    /// # Errors
    ///
    /// Returns an error if the verifier cannot be built from the provided CRLs.
    #[doc(hidden)]
    pub fn __test_with_prepopulated_crls(
        roots: Arc<RootCertStore>,
        config: MtlsConfig,
        prefilled_crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> Result<Arc<Self>, McpxError> {
        let (discover_tx, discover_rx) = mpsc::unbounded_channel();
        drop(discover_rx);

        let mut initial_cache = HashMap::new();
        for (index, der) in prefilled_crls.into_iter().enumerate() {
            let source_url = format!("memory://crl/{index}");
            let (this_update, next_update) = parse_crl_metadata(der.as_ref())?;
            initial_cache.insert(
                source_url.clone(),
                CachedCrl {
                    der,
                    this_update,
                    next_update,
                    fetched_at: SystemTime::now(),
                    source_url,
                },
            );
        }

        Self::new(roots, config, discover_tx, initial_cache)
    }

    /// Test-only: same as [`Self::__test_with_prepopulated_crls`] but
    /// returns the discover-channel receiver to the caller so the
    /// background channel `send`s succeed (the receiver stays alive
    /// for the duration of the test). Required by the B2 dedup
    /// regression test, which must observe URLs being committed to
    /// `seen_urls` after a successful limiter+send sequence. Not part
    /// of the public API.
    ///
    /// # Errors
    ///
    /// Returns an error if the verifier cannot be built from the provided CRLs.
    #[doc(hidden)]
    pub fn __test_with_kept_receiver(
        roots: Arc<RootCertStore>,
        config: MtlsConfig,
        prefilled_crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> Result<(Arc<Self>, mpsc::UnboundedReceiver<String>), McpxError> {
        let (discover_tx, discover_rx) = mpsc::unbounded_channel();

        let mut initial_cache = HashMap::new();
        for (index, der) in prefilled_crls.into_iter().enumerate() {
            let source_url = format!("memory://crl/{index}");
            let (this_update, next_update) = parse_crl_metadata(der.as_ref())?;
            initial_cache.insert(
                source_url.clone(),
                CachedCrl {
                    der,
                    this_update,
                    next_update,
                    fetched_at: SystemTime::now(),
                    source_url,
                },
            );
        }

        let crl_set = Self::new(roots, config, discover_tx, initial_cache)?;
        Ok((crl_set, discover_rx))
    }

    /// Test-only: directly invoke the discovery rate-limiter on a batch of URLs
    /// and return `(accepted, dropped)`. Bypasses the dedup `seen_urls` set so
    /// callers can deterministically saturate the limiter; mutates the limiter
    /// state in place. Not part of the public API.
    #[doc(hidden)]
    pub fn __test_check_discovery_rate(&self, urls: &[String]) -> (usize, usize) {
        let mut accepted = 0usize;
        let mut dropped = 0usize;
        for url in urls {
            if self.discovery_limiter.check().is_ok() {
                let _ = self.discover_tx.send(url.clone());
                accepted += 1;
            } else {
                dropped += 1;
            }
        }
        (accepted, dropped)
    }

    /// Test-only: invoke the real `note_discovered_urls` so dedup + rate-limit
    /// + cached-fallback paths are all exercised. Returns the `missing_cached`
    /// flag the production verifier uses to decide whether to fail the handshake.
    #[doc(hidden)]
    pub fn __test_note_discovered_urls(&self, urls: &[String]) -> bool {
        let missing_cached = self.note_discovered_urls(urls);
        if self.discover_tx.is_closed() {
            match self.seen_urls.lock() {
                Ok(mut guard) => {
                    for url in urls {
                        if guard.contains(url) {
                            continue;
                        }
                        if guard.len() >= self.config.crl_max_seen_urls {
                            self.warn_cap_exceeded_throttled("seen_urls");
                            break;
                        }
                        guard.insert(url.clone());
                    }
                }
                Err(poisoned) => {
                    let mut guard = poisoned.into_inner();
                    for url in urls {
                        if guard.contains(url) {
                            continue;
                        }
                        if guard.len() >= self.config.crl_max_seen_urls {
                            self.warn_cap_exceeded_throttled("seen_urls");
                            break;
                        }
                        guard.insert(url.clone());
                    }
                }
            }
        }
        missing_cached
    }

    /// Test-only: report whether a URL has been promoted to the
    /// permanent dedup set. Used by the B2 retriability regression
    /// test to assert that rate-limited URLs are NOT marked seen.
    /// Not part of the public API.
    #[doc(hidden)]
    pub fn __test_is_seen(&self, url: &str) -> bool {
        match self.seen_urls.lock() {
            Ok(seen) => seen.contains(url),
            Err(_) => false,
        }
    }

    /// Test-only: current count of host semaphores. Used by
    /// `tests/crl_map_bounds.rs` to assert the cap is enforced.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn __test_host_semaphore_count(&self) -> usize {
        self.host_semaphores
            .try_lock()
            .map_or(0, |guard| guard.len())
    }

    /// Test-only: current number of entries in the CRL cache.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn __test_cache_len(&self) -> usize {
        self.cache.try_read().map_or(0, |guard| guard.len())
    }

    /// Test-only: whether a specific URL is currently cached.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn __test_cache_contains(&self, url: &str) -> bool {
        self.cache
            .try_read()
            .is_ok_and(|guard| guard.contains_key(url))
    }

    /// Test-only: triggers the request-hot-path fetch path for `url`
    /// WITHOUT going through the TLS handshake. Returns any error the
    /// host-semaphore cap check produces. A network-unreachable
    /// failure for the fetch itself is treated as `Ok(())` (test only
    /// cares about the cap; real tests use mock hosts that won't
    /// resolve — the cap must fire BEFORE network I/O).
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub async fn __test_trigger_fetch(&self, url: &str) -> Result<(), McpxError> {
        if let Err(error) = gated_fetch(
            &self.client,
            &self.global_fetch_sem,
            &self.host_semaphores,
            url,
            self.config.crl_allow_http,
            self.max_response_bytes,
            self.config.crl_max_host_semaphores,
        )
        .await
        {
            if error
                .to_string()
                .contains("crl_host_semaphore_cap_exceeded")
            {
                Err(error)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    /// Test-only: directly insert `cached` under `url` into both
    /// `cache` and `cached_urls`, bypassing HTTP. Does NOT enforce
    /// `crl_max_cache_entries` when called pre-cap — the test uses it
    /// to stage preconditions. For cap-breach coverage, tests invoke
    /// the real production insertion path.
    ///
    /// Wait — the `cache_hard_cap_drops_newest` test DOES use this
    /// helper to assert the cap fires. Therefore this helper MUST
    /// enforce the hard cap (silent drop with warn!) the same way the
    /// production code does. The helper is a thin wrapper around the
    /// same internal insertion fn the production path uses.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub async fn __test_insert_cache(&self, url: &str, cached: CachedCrl) {
        let _ = self.insert_cache_entry(url.to_owned(), cached).await;
    }

    /// Test-only: trigger a refresh cycle for a single URL. Exercises
    /// the same stale-grace / fetch-failure path as `refresh_urls()`.
    /// Returns the refresh error (if any) — most tests ignore it
    /// because they assert post-state, not the transient error.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub async fn __test_trigger_refresh_url(&self, url: &str) -> Result<(), McpxError> {
        self.refresh_urls(vec![url.to_owned()]).await
    }

    async fn fetch_url_results(
        &self,
        urls: Vec<String>,
    ) -> Vec<(String, Result<CachedCrl, McpxError>)> {
        let mut tasks = JoinSet::new();
        for url in urls {
            let client = self.client.clone();
            let global_sem = Arc::clone(&self.global_fetch_sem);
            let host_map = Arc::clone(&self.host_semaphores);
            let allow_http = self.config.crl_allow_http;
            let max_bytes = self.max_response_bytes;
            let max_host_semaphores = self.config.crl_max_host_semaphores;
            tasks.spawn(async move {
                let result = gated_fetch(
                    &client,
                    &global_sem,
                    &host_map,
                    &url,
                    allow_http,
                    max_bytes,
                    max_host_semaphores,
                )
                .await;
                (url, result)
            });
        }

        let mut results = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(result) => results.push(result),
                Err(error) => {
                    tracing::warn!(error = %error, "CRL refresh task join failed");
                }
            }
        }

        results
    }

    fn swap_verifier_from_cache(
        &self,
        cache: &impl std::ops::Deref<Target = HashMap<String, CachedCrl>>,
    ) -> Result<(), McpxError> {
        let verifier = rebuild_verifier(&self.roots, &self.config, cache)?;
        self.inner_verifier
            .store(Arc::new(VerifierHandle(verifier)));
        Ok(())
    }
}

impl CachedCrl {
    /// Test-only: synthesize a cache entry that looks valid, `next_update`
    /// = now + 24h. Fields used only to populate the HashMap — the bytes
    /// are a minimal CRL-shape that won't be parsed by tests.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    pub fn __test_synthetic(now: SystemTime) -> Self {
        Self {
            der: CertificateRevocationListDer::from(vec![0x30, 0x00]),
            this_update: now,
            next_update: now.checked_add(Duration::from_hours(24)),
            fetched_at: now,
            source_url: "test://synthetic".to_owned(),
        }
    }

    /// Test-only: synthesize a STALE cache entry (`next_update` in the
    /// deep past so `is_stale_beyond_grace` fires with any sensible
    /// `crl_stale_grace`).
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    pub fn __test_stale(reference_past: SystemTime) -> Self {
        Self {
            der: CertificateRevocationListDer::from(vec![0x30, 0x00]),
            this_update: reference_past,
            next_update: Some(reference_past),
            fetched_at: reference_past,
            source_url: "test://stale".to_owned(),
        }
    }
}

/// Stable outer verifier that delegates all TLS verification behavior to the
/// atomically swappable inner verifier.
pub struct DynamicClientCertVerifier {
    inner: Arc<CrlSet>,
    dn_subjects: Vec<DistinguishedName>,
}

impl DynamicClientCertVerifier {
    /// Construct a new dynamic verifier from a shared [`CrlSet`].
    #[must_use]
    pub fn new(inner: Arc<CrlSet>) -> Self {
        Self {
            dn_subjects: inner.roots.subjects(),
            inner,
        }
    }
}

impl std::fmt::Debug for DynamicClientCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicClientCertVerifier")
            .field("dn_subjects_len", &self.dn_subjects.len())
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for DynamicClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        let verifier = self.inner.inner_verifier.load();
        verifier.0.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        let verifier = self.inner.inner_verifier.load();
        verifier.0.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.dn_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        let mut discovered =
            extract_cdp_urls(end_entity.as_ref(), self.inner.config.crl_allow_http);
        for intermediate in intermediates {
            discovered.extend(extract_cdp_urls(
                intermediate.as_ref(),
                self.inner.config.crl_allow_http,
            ));
        }
        discovered.sort();
        discovered.dedup();

        if self.inner.note_discovered_urls(&discovered) {
            return Err(TlsError::General(
                "client certificate revocation status unavailable".to_owned(),
            ));
        }

        let verifier = self.inner.inner_verifier.load();
        verifier
            .0
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let verifier = self.inner.inner_verifier.load();
        verifier.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let verifier = self.inner.inner_verifier.load();
        verifier.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let verifier = self.inner.inner_verifier.load();
        verifier.0.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        let verifier = self.inner.inner_verifier.load();
        verifier.0.requires_raw_public_keys()
    }
}

/// Extract CRL Distribution Point URLs from a DER-encoded certificate.
///
/// URLs are validated with `url::Url::parse` (case-insensitive scheme handling)
/// and filtered through an internal scheme guard. Malformed URLs and URLs
/// using disallowed schemes are silently dropped. SSRF defenses against private
/// IP literals and metadata endpoints are applied later, at fetch time, after
/// DNS resolution.
#[must_use]
pub fn extract_cdp_urls(cert_der: &[u8], allow_http: bool) -> Vec<String> {
    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
        return Vec::new();
    };

    let mut urls = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::CRLDistributionPoints(cdps) = ext.parsed_extension() {
            for point in cdps.iter() {
                if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                    for name in names {
                        if let GeneralName::URI(uri) = name {
                            let raw = *uri;
                            let Ok(parsed) = Url::parse(raw) else {
                                tracing::debug!(url = %raw, "CDP URL parse failed; dropped");
                                continue;
                            };
                            if let Err(reason) = check_scheme(&parsed, allow_http) {
                                tracing::debug!(
                                    url = %raw,
                                    reason,
                                    "CDP URL rejected by scheme guard; dropped"
                                );
                                continue;
                            }
                            urls.push(parsed.into());
                        }
                    }
                }
            }
        }
    }

    urls
}

/// Bootstrap the CRL cache by extracting CDP URLs from the CA chain and
/// fetching any reachable CRLs with a 10-second total deadline.
///
/// # Errors
///
/// Returns an error if the initial verifier cannot be built.
#[allow(
    clippy::cognitive_complexity,
    reason = "bootstrap coordinates timeout, parallel fetches, and partial-cache recovery"
)]
pub async fn bootstrap_fetch(
    roots: Arc<RootCertStore>,
    ca_certs: &[CertificateDer<'static>],
    config: MtlsConfig,
) -> Result<(Arc<CrlSet>, mpsc::UnboundedReceiver<String>), McpxError> {
    let (discover_tx, discover_rx) = mpsc::unbounded_channel();

    let mut urls = ca_certs
        .iter()
        .flat_map(|cert| extract_cdp_urls(cert.as_ref(), config.crl_allow_http))
        .collect::<Vec<_>>();
    urls.sort();
    urls.dedup();

    let client = reqwest::Client::builder()
        .timeout(config.crl_fetch_timeout)
        .connect_timeout(CRL_CONNECT_TIMEOUT)
        .tcp_keepalive(None)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(format!("rmcp-server-kit/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| McpxError::Startup(format!("CRL HTTP client init: {error}")))?;

    // Bootstrap shares the same global concurrency + per-host cap as the
    // hot-path verifier so a maliciously broad CA chain cannot overwhelm
    // the network at startup.
    let bootstrap_concurrency = config.crl_max_concurrent_fetches.max(1);
    let global_sem = Arc::new(Semaphore::new(bootstrap_concurrency));
    let host_semaphores = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let allow_http = config.crl_allow_http;
    let max_bytes = config.crl_max_response_bytes;
    let max_host_semaphores = config.crl_max_host_semaphores;

    let mut initial_cache = HashMap::new();
    let mut tasks = JoinSet::new();
    for url in &urls {
        let client = client.clone();
        let url = url.clone();
        let global_sem = Arc::clone(&global_sem);
        let host_semaphores = Arc::clone(&host_semaphores);
        tasks.spawn(async move {
            let result = gated_fetch(
                &client,
                &global_sem,
                &host_semaphores,
                &url,
                allow_http,
                max_bytes,
                max_host_semaphores,
            )
            .await;
            (url, result)
        });
    }

    let timeout: Sleep = tokio::time::sleep(BOOTSTRAP_TIMEOUT);
    tokio::pin!(timeout);

    while !tasks.is_empty() {
        tokio::select! {
            () = &mut timeout => {
                tracing::warn!("CRL bootstrap timed out after {:?}", BOOTSTRAP_TIMEOUT);
                break;
            }
            maybe_joined = tasks.join_next() => {
                let Some(joined) = maybe_joined else {
                    break;
                };
                match joined {
                    Ok((url, Ok(cached))) => {
                        initial_cache.insert(url, cached);
                    }
                    Ok((url, Err(error))) => {
                        tracing::warn!(url = %url, error = %error, "CRL bootstrap fetch failed");
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "CRL bootstrap task join failed");
                    }
                }
            }
        }
    }

    let set = CrlSet::new(roots, config, discover_tx, initial_cache)?;
    Ok((set, discover_rx))
}

/// Run the CRL refresher loop until shutdown.
#[allow(
    clippy::cognitive_complexity,
    reason = "refresher loop intentionally handles shutdown, timer, and discovery in one select"
)]
pub async fn run_crl_refresher(
    set: Arc<CrlSet>,
    mut discover_rx: mpsc::UnboundedReceiver<String>,
    shutdown: CancellationToken,
) {
    let mut refresh_sleep = schedule_next_refresh(&set).await;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                break;
            }
            () = &mut refresh_sleep => {
                if let Err(error) = set.refresh_due_urls().await {
                    tracing::warn!(error = %error, "CRL periodic refresh failed");
                }
                refresh_sleep = schedule_next_refresh(&set).await;
            }
            maybe_url = discover_rx.recv() => {
                let Some(url) = maybe_url else {
                    break;
                };
                if let Err(error) = set.fetch_and_store_url(url.clone()).await {
                    tracing::warn!(url = %url, error = %error, "CRL discovery fetch failed");
                }
                refresh_sleep = schedule_next_refresh(&set).await;
            }
        }
    }
}

/// Rebuild the inner rustls verifier from the current CRL cache.
///
/// # Errors
///
/// Returns an error if rustls rejects the verifier configuration.
pub fn rebuild_verifier<S: std::hash::BuildHasher>(
    roots: &Arc<RootCertStore>,
    config: &MtlsConfig,
    cache: &HashMap<String, CachedCrl, S>,
) -> Result<Arc<dyn ClientCertVerifier>, McpxError> {
    let mut builder = WebPkiClientVerifier::builder(Arc::clone(roots));

    if !cache.is_empty() {
        let crls = cache
            .values()
            .map(|cached| cached.der.clone())
            .collect::<Vec<_>>();
        builder = builder.with_crls(crls);
    }
    if config.crl_end_entity_only {
        builder = builder.only_check_end_entity_revocation();
    }
    if !config.crl_deny_on_unavailable {
        builder = builder.allow_unknown_revocation_status();
    }
    if config.crl_enforce_expiration {
        builder = builder.enforce_revocation_expiration();
    }
    if !config.required {
        builder = builder.allow_unauthenticated();
    }

    builder
        .build()
        .map_err(|error| McpxError::Tls(format!("mTLS verifier error: {error}")))
}

/// Parse `thisUpdate` and `nextUpdate` metadata from a DER-encoded CRL.
///
/// # Errors
///
/// Returns an error if the CRL cannot be parsed.
pub fn parse_crl_metadata(der: &[u8]) -> Result<(SystemTime, Option<SystemTime>), McpxError> {
    let (_, crl) = CertificateRevocationList::from_der(der)
        .map_err(|error| McpxError::Tls(format!("invalid CRL DER: {error:?}")))?;

    Ok((
        asn1_time_to_system_time(crl.last_update()),
        crl.next_update().map(asn1_time_to_system_time),
    ))
}

async fn schedule_next_refresh(set: &CrlSet) -> Pin<Box<Sleep>> {
    let duration = next_refresh_delay(set).await;
    boxed_sleep(duration)
}

fn boxed_sleep(duration: Duration) -> Pin<Box<Sleep>> {
    Box::pin(tokio::time::sleep_until(Instant::now() + duration))
}

async fn next_refresh_delay(set: &CrlSet) -> Duration {
    if let Some(interval) = set.config.crl_refresh_interval {
        return clamp_refresh(interval);
    }

    let now = SystemTime::now();
    let cache = set.cache.read().await;
    let mut next = MAX_AUTO_REFRESH;

    for cached in cache.values() {
        if let Some(next_update) = cached.next_update {
            let duration = next_update.duration_since(now).unwrap_or(Duration::ZERO);
            next = next.min(clamp_refresh(duration));
        }
    }

    next
}

/// Fetch a single CRL URL through the global + per-host concurrency caps.
///
/// `global_sem` caps total simultaneous CRL fetches process-wide.
/// `host_semaphores` ensures at most one in-flight fetch per origin host
/// (an SSRF amplification defense). Both permits are dropped when the
/// returned future completes (whether `Ok` or `Err`).
async fn gated_fetch(
    client: &reqwest::Client,
    global_sem: &Arc<Semaphore>,
    host_semaphores: &Arc<tokio::sync::Mutex<HashMap<String, Arc<Semaphore>>>>,
    url: &str,
    allow_http: bool,
    max_bytes: u64,
    max_host_semaphores: usize,
) -> Result<CachedCrl, McpxError> {
    let host_key = Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned());

    let host_sem = {
        let mut map = host_semaphores.lock().await;
        if !map.contains_key(&host_key) {
            if map.len() >= max_host_semaphores {
                return Err(McpxError::Config(
                    "crl_host_semaphore_cap_exceeded: too many distinct CRL hosts in flight"
                        .to_owned(),
                ));
            }
            map.insert(host_key.clone(), Arc::new(Semaphore::new(1)));
        }
        match map.get(&host_key) {
            Some(semaphore) => Arc::clone(semaphore),
            None => {
                return Err(McpxError::Tls(
                    "CRL host semaphore missing after insertion".to_owned(),
                ));
            }
        }
    };

    let _global_permit = Arc::clone(global_sem)
        .acquire_owned()
        .await
        .map_err(|error| McpxError::Tls(format!("CRL global semaphore closed: {error}")))?;
    let _host_permit = host_sem
        .acquire_owned()
        .await
        .map_err(|error| McpxError::Tls(format!("CRL host semaphore closed: {error}")))?;

    fetch_crl(client, url, allow_http, max_bytes).await
}

async fn fetch_crl(
    client: &reqwest::Client,
    url: &str,
    allow_http: bool,
    max_bytes: u64,
) -> Result<CachedCrl, McpxError> {
    let parsed =
        Url::parse(url).map_err(|error| McpxError::Tls(format!("CRL URL parse {url}: {error}")))?;

    if let Err(reason) = check_scheme(&parsed, allow_http) {
        tracing::warn!(url = %url, reason, "CRL fetch denied: scheme");
        return Err(McpxError::Tls(format!(
            "CRL scheme rejected ({reason}): {url}"
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| McpxError::Tls(format!("CRL URL has no host: {url}")))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| McpxError::Tls(format!("CRL URL has no known port: {url}")))?;

    let addrs = lookup_host((host, port))
        .await
        .map_err(|error| McpxError::Tls(format!("CRL DNS resolution {url}: {error}")))?;

    let mut any_addr = false;
    for addr in addrs {
        any_addr = true;
        if let Some(reason) = ip_block_reason(addr.ip()) {
            tracing::warn!(
                url = %url,
                resolved_ip = %addr.ip(),
                reason,
                "CRL fetch denied: blocked IP"
            );
            return Err(McpxError::Tls(format!(
                "CRL host resolved to blocked IP ({reason}): {url}"
            )));
        }
    }
    if !any_addr {
        return Err(McpxError::Tls(format!(
            "CRL DNS resolution returned no addresses: {url}"
        )));
    }

    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|error| McpxError::Tls(format!("CRL fetch {url}: {error}")))?
        .error_for_status()
        .map_err(|error| McpxError::Tls(format!("CRL fetch {url}: {error}")))?;

    // Enforce body cap by streaming chunk-by-chunk; a malicious or
    // misconfigured server cannot allocate more than `max_bytes` of memory.
    let initial_capacity = usize::try_from(max_bytes.min(64 * 1024)).unwrap_or(64 * 1024);
    let mut body: Vec<u8> = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| McpxError::Tls(format!("CRL read {url}: {error}")))?
    {
        let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        let body_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
        if body_len.saturating_add(chunk_len) > max_bytes {
            return Err(McpxError::Tls(format!(
                "CRL body exceeded cap of {max_bytes} bytes: {url}"
            )));
        }
        body.extend_from_slice(&chunk);
    }

    let der = CertificateRevocationListDer::from(body);
    let (this_update, next_update) = parse_crl_metadata(der.as_ref())?;

    Ok(CachedCrl {
        der,
        this_update,
        next_update,
        fetched_at: SystemTime::now(),
        source_url: url.to_owned(),
    })
}

fn should_refresh_cached(
    cached: &CachedCrl,
    now: SystemTime,
    fixed_interval: Option<Duration>,
) -> bool {
    if let Some(interval) = fixed_interval {
        return cached
            .fetched_at
            .checked_add(clamp_refresh(interval))
            .is_none_or(|deadline| now >= deadline);
    }

    cached
        .next_update
        .is_none_or(|next_update| now >= next_update)
}

fn clamp_refresh(duration: Duration) -> Duration {
    duration.clamp(MIN_AUTO_REFRESH, MAX_AUTO_REFRESH)
}

fn asn1_time_to_system_time(time: x509_parser::time::ASN1Time) -> SystemTime {
    let timestamp = time.timestamp();
    if timestamp >= 0 {
        let seconds = u64::try_from(timestamp).unwrap_or(0);
        UNIX_EPOCH + Duration::from_secs(seconds)
    } else {
        UNIX_EPOCH - Duration::from_secs(timestamp.unsigned_abs())
    }
}
