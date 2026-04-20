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
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
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
    sync::{RwLock, mpsc},
    task::JoinSet,
    time::{Instant, Sleep},
};
use tokio_util::sync::CancellationToken;
use x509_parser::{
    extensions::{DistributionPointName, GeneralName, ParsedExtension},
    prelude::{FromDer, X509Certificate},
    revocation_list::CertificateRevocationList,
};

use crate::{auth::MtlsConfig, error::McpxError};

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_AUTO_REFRESH: Duration = Duration::from_mins(10);
const MAX_AUTO_REFRESH: Duration = Duration::from_hours(24);

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
            .user_agent(format!("rmcp-server-kit/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| McpxError::Startup(format!("CRL HTTP client init: {error}")))?;

        let initial_verifier = rebuild_verifier(&roots, &config, &initial_cache)?;
        let seen_urls = initial_cache.keys().cloned().collect::<HashSet<_>>();
        let cached_urls = seen_urls.clone();

        Ok(Arc::new(Self {
            inner_verifier: ArcSwap::from_pointee(VerifierHandle(initial_verifier)),
            cache: RwLock::new(initial_cache),
            roots,
            config,
            discover_tx,
            client,
            seen_urls: Mutex::new(seen_urls),
            cached_urls: Mutex::new(cached_urls),
        }))
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
                    cache.insert(url.clone(), cached);
                    changed = true;
                    if let Ok(mut cached_urls) = self.cached_urls.lock() {
                        cached_urls.insert(url);
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
                        if let Ok(mut cached_urls) = self.cached_urls.lock() {
                            cached_urls.remove(&url);
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
        let cached = fetch_crl(&self.client, &url).await?;
        let mut cache = self.cache.write().await;
        cache.insert(url.clone(), cached);
        if let Ok(mut cached_urls) = self.cached_urls.lock() {
            cached_urls.insert(url);
        }
        self.swap_verifier_from_cache(&cache)?;
        Ok(())
    }

    fn note_discovered_urls(&self, urls: &[String]) -> bool {
        let mut missing_cached = false;

        if let Ok(mut seen) = self.seen_urls.lock() {
            for url in urls {
                if seen.insert(url.clone()) {
                    let _ = self.discover_tx.send(url.clone());
                }
            }
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

    async fn fetch_url_results(
        &self,
        urls: Vec<String>,
    ) -> Vec<(String, Result<CachedCrl, McpxError>)> {
        let mut tasks = JoinSet::new();
        for url in urls {
            let client = self.client.clone();
            tasks.spawn(async move {
                let result = fetch_crl(&client, &url).await;
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
                            let value = (*uri).to_owned();
                            let is_https = value.starts_with("https://");
                            let is_http = value.starts_with("http://");
                            if is_https || (is_http && allow_http) {
                                urls.push(value);
                            }
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
        .user_agent(format!("rmcp-server-kit/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| McpxError::Startup(format!("CRL HTTP client init: {error}")))?;

    let mut initial_cache = HashMap::new();
    let mut tasks = JoinSet::new();
    for url in &urls {
        let client = client.clone();
        let url = url.clone();
        tasks.spawn(async move {
            let result = fetch_crl(&client, &url).await;
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

async fn fetch_crl(client: &reqwest::Client, url: &str) -> Result<CachedCrl, McpxError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| McpxError::Tls(format!("CRL fetch {url}: {error}")))?;
    let response = response
        .error_for_status()
        .map_err(|error| McpxError::Tls(format!("CRL fetch {url}: {error}")))?;
    let body = response
        .bytes()
        .await
        .map_err(|error| McpxError::Tls(format!("CRL read {url}: {error}")))?;
    let der = CertificateRevocationListDer::from(body.to_vec());
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
