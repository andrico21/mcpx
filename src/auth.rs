//! Authentication middleware for MCP servers.
//!
//! Supports multiple authentication methods tried in priority order:
//! 1. mTLS client certificate (if configured and peer cert present)
//! 2. Bearer token (API key) with Argon2id hash verification
//!
//! Includes per-source-IP rate limiting on authentication attempts.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::SecretString;
use serde::Deserialize;
use x509_parser::prelude::*;

use crate::{bounded_limiter::BoundedKeyedLimiter, error::McpxError};

/// Identity of an authenticated caller.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AuthIdentity {
    /// Human-readable identity name (e.g. API key label or cert CN).
    pub name: String,
    /// RBAC role associated with this identity.
    pub role: String,
    /// Which authentication mechanism produced this identity.
    pub method: AuthMethod,
    /// Raw bearer token from the `Authorization` header, wrapped in
    /// [`SecretString`] so it is never accidentally logged or serialized.
    /// Present for OAuth JWT; `None` for mTLS and API-key auth.
    /// Tool handlers use this for downstream token passthrough via
    /// [`crate::rbac::current_token`].
    pub raw_token: Option<SecretString>,
    /// JWT `sub` claim (stable user identifier, e.g. Keycloak UUID).
    /// Used for token store keying. `None` for non-JWT auth.
    pub sub: Option<String>,
}

/// How the caller authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMethod {
    /// Bearer API key (Argon2id-hashed, configured statically).
    BearerToken,
    /// Mutual TLS client certificate.
    MtlsCertificate,
    /// OAuth 2.1 JWT bearer token (validated via JWKS).
    OAuthJwt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthFailureClass {
    MissingCredential,
    InvalidCredential,
    #[cfg_attr(not(feature = "oauth"), allow(dead_code))]
    ExpiredCredential,
    /// Source IP exceeded the post-failure backoff limit.
    RateLimited,
    /// Source IP exceeded the pre-auth abuse gate (rejected before any
    /// password-hash work — see [`AuthState::pre_auth_limiter`]).
    PreAuthGate,
}

impl AuthFailureClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingCredential => "missing_credential",
            Self::InvalidCredential => "invalid_credential",
            Self::ExpiredCredential => "expired_credential",
            Self::RateLimited => "rate_limited",
            Self::PreAuthGate => "pre_auth_gate",
        }
    }

    fn bearer_error(self) -> (&'static str, &'static str) {
        match self {
            Self::MissingCredential => (
                "invalid_request",
                "missing bearer token or mTLS client certificate",
            ),
            Self::InvalidCredential => ("invalid_token", "token is invalid"),
            Self::ExpiredCredential => ("invalid_token", "token is expired"),
            Self::RateLimited => ("invalid_request", "too many failed authentication attempts"),
            Self::PreAuthGate => (
                "invalid_request",
                "too many unauthenticated requests from this source",
            ),
        }
    }

    fn response_body(self) -> &'static str {
        match self {
            Self::MissingCredential => "unauthorized: missing credential",
            Self::InvalidCredential => "unauthorized: invalid credential",
            Self::ExpiredCredential => "unauthorized: expired credential",
            Self::RateLimited => "rate limited",
            Self::PreAuthGate => "rate limited (pre-auth)",
        }
    }
}

/// Snapshot of authentication success/failure counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct AuthCountersSnapshot {
    /// Successful mTLS authentications.
    pub success_mtls: u64,
    /// Successful bearer-token authentications.
    pub success_bearer: u64,
    /// Successful OAuth JWT authentications.
    pub success_oauth_jwt: u64,
    /// Failures because no credential was presented.
    pub failure_missing_credential: u64,
    /// Failures because the credential was malformed or wrong.
    pub failure_invalid_credential: u64,
    /// Failures because the credential had expired.
    pub failure_expired_credential: u64,
    /// Failures because the source IP was rate-limited (post-failure backoff).
    pub failure_rate_limited: u64,
    /// Failures because the source IP exceeded the pre-auth abuse gate.
    /// These never reach the password-hash verification path.
    pub failure_pre_auth_gate: u64,
}

/// Internal atomic counters backing [`AuthCountersSnapshot`].
#[derive(Debug, Default)]
pub(crate) struct AuthCounters {
    success_mtls: AtomicU64,
    success_bearer: AtomicU64,
    success_oauth_jwt: AtomicU64,
    failure_missing_credential: AtomicU64,
    failure_invalid_credential: AtomicU64,
    failure_expired_credential: AtomicU64,
    failure_rate_limited: AtomicU64,
    failure_pre_auth_gate: AtomicU64,
}

impl AuthCounters {
    fn record_success(&self, method: AuthMethod) {
        match method {
            AuthMethod::MtlsCertificate => {
                self.success_mtls.fetch_add(1, Ordering::Relaxed);
            }
            AuthMethod::BearerToken => {
                self.success_bearer.fetch_add(1, Ordering::Relaxed);
            }
            AuthMethod::OAuthJwt => {
                self.success_oauth_jwt.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn record_failure(&self, class: AuthFailureClass) {
        match class {
            AuthFailureClass::MissingCredential => {
                self.failure_missing_credential
                    .fetch_add(1, Ordering::Relaxed);
            }
            AuthFailureClass::InvalidCredential => {
                self.failure_invalid_credential
                    .fetch_add(1, Ordering::Relaxed);
            }
            AuthFailureClass::ExpiredCredential => {
                self.failure_expired_credential
                    .fetch_add(1, Ordering::Relaxed);
            }
            AuthFailureClass::RateLimited => {
                self.failure_rate_limited.fetch_add(1, Ordering::Relaxed);
            }
            AuthFailureClass::PreAuthGate => {
                self.failure_pre_auth_gate.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> AuthCountersSnapshot {
        AuthCountersSnapshot {
            success_mtls: self.success_mtls.load(Ordering::Relaxed),
            success_bearer: self.success_bearer.load(Ordering::Relaxed),
            success_oauth_jwt: self.success_oauth_jwt.load(Ordering::Relaxed),
            failure_missing_credential: self.failure_missing_credential.load(Ordering::Relaxed),
            failure_invalid_credential: self.failure_invalid_credential.load(Ordering::Relaxed),
            failure_expired_credential: self.failure_expired_credential.load(Ordering::Relaxed),
            failure_rate_limited: self.failure_rate_limited.load(Ordering::Relaxed),
            failure_pre_auth_gate: self.failure_pre_auth_gate.load(Ordering::Relaxed),
        }
    }
}

/// A single API key entry (stored as Argon2id hash in config).
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct ApiKeyEntry {
    /// Human-readable key label (used in logs and audit records).
    pub name: String,
    /// Argon2id hash of the token (PHC string format).
    pub hash: String,
    /// RBAC role granted when this key authenticates successfully.
    pub role: String,
    /// Optional expiry in RFC 3339 format.
    pub expires_at: Option<String>,
}

impl ApiKeyEntry {
    /// Create a new API key entry (no expiry).
    #[must_use]
    pub fn new(name: impl Into<String>, hash: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            hash: hash.into(),
            role: role.into(),
            expires_at: None,
        }
    }

    /// Set an RFC 3339 expiry on this key.
    #[must_use]
    pub fn with_expiry(mut self, expires_at: impl Into<String>) -> Self {
        self.expires_at = Some(expires_at.into());
        self
    }
}

/// mTLS client certificate authentication configuration.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct MtlsConfig {
    /// Path to CA certificate(s) for verifying client certs (PEM format).
    pub ca_cert_path: PathBuf,
    /// If true, clients MUST present a valid certificate.
    /// If false, client certs are optional (verified if presented).
    #[serde(default)]
    pub required: bool,
    /// Default RBAC role for mTLS-authenticated clients.
    /// The client cert CN becomes the identity name.
    #[serde(default = "default_mtls_role")]
    pub default_role: String,
}

fn default_mtls_role() -> String {
    "viewer".into()
}

/// Rate limiting configuration for authentication attempts.
///
/// rmcp-server-kit uses two independent per-IP token-bucket limiters for auth:
///
/// 1. **Pre-auth abuse gate** ([`Self::pre_auth_max_per_minute`]): consulted
///    *before* any password-hash work. Throttles unauthenticated traffic from
///    a single source IP so an attacker cannot pin the CPU on Argon2id by
///    spraying invalid bearer tokens. Sized generously (default = 10× the
///    post-failure quota) so legitimate clients are unaffected. mTLS-
///    authenticated connections bypass this gate entirely (the TLS handshake
///    already performed expensive crypto with a verified peer).
/// 2. **Post-failure backoff** ([`Self::max_attempts_per_minute`]): consulted
///    *after* an authentication attempt fails. Provides explicit backpressure
///    on bad credentials.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct RateLimitConfig {
    /// Maximum failed authentication attempts per source IP per minute.
    /// Successful authentications do not consume this budget.
    #[serde(default = "default_max_attempts")]
    pub max_attempts_per_minute: u32,
    /// Maximum *unauthenticated* requests per source IP per minute admitted
    /// to the password-hash verification path. When `None`, defaults to
    /// `max_attempts_per_minute * 10` at limiter-construction time.
    ///
    /// Set higher than [`Self::max_attempts_per_minute`] so honest clients
    /// retrying with the wrong key never trip this gate; its purpose is only
    /// to bound CPU usage under spray attacks.
    #[serde(default)]
    pub pre_auth_max_per_minute: Option<u32>,
    /// Hard cap on the number of distinct source IPs tracked per limiter.
    /// When reached, idle entries are pruned first; if still full, the
    /// oldest (LRU) entry is evicted to make room for the new one. This
    /// bounds memory under IP-spray attacks. Default: `10_000`.
    #[serde(default = "default_max_tracked_keys")]
    pub max_tracked_keys: usize,
    /// Per-IP entries idle for longer than this are eligible for
    /// opportunistic pruning. Default: 15 minutes.
    #[serde(default = "default_idle_eviction", with = "humantime_serde")]
    pub idle_eviction: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts_per_minute: default_max_attempts(),
            pre_auth_max_per_minute: None,
            max_tracked_keys: default_max_tracked_keys(),
            idle_eviction: default_idle_eviction(),
        }
    }
}

impl RateLimitConfig {
    /// Create a rate limit config with the given max failed attempts per minute.
    /// Pre-auth gate defaults to `10x` this value at limiter-construction time.
    /// Memory-bound defaults are `10_000` tracked keys with 15-minute idle eviction.
    #[must_use]
    pub fn new(max_attempts_per_minute: u32) -> Self {
        Self {
            max_attempts_per_minute,
            ..Self::default()
        }
    }

    /// Override the pre-auth abuse-gate quota (per source IP per minute).
    /// When unset, defaults to `max_attempts_per_minute * 10`.
    #[must_use]
    pub fn with_pre_auth_max_per_minute(mut self, quota: u32) -> Self {
        self.pre_auth_max_per_minute = Some(quota);
        self
    }

    /// Override the per-limiter cap on tracked source-IP keys (default `10_000`).
    #[must_use]
    pub fn with_max_tracked_keys(mut self, max: usize) -> Self {
        self.max_tracked_keys = max;
        self
    }

    /// Override the idle-eviction window (default 15 minutes).
    #[must_use]
    pub fn with_idle_eviction(mut self, idle: Duration) -> Self {
        self.idle_eviction = idle;
        self
    }
}

fn default_max_attempts() -> u32 {
    30
}

fn default_max_tracked_keys() -> usize {
    10_000
}

fn default_idle_eviction() -> Duration {
    Duration::from_mins(15)
}

/// Authentication configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[non_exhaustive]
pub struct AuthConfig {
    /// Master switch - when false, all requests are allowed through.
    #[serde(default)]
    pub enabled: bool,
    /// Bearer token API keys.
    #[serde(default)]
    pub api_keys: Vec<ApiKeyEntry>,
    /// mTLS client certificate authentication.
    pub mtls: Option<MtlsConfig>,
    /// Rate limiting for auth attempts.
    pub rate_limit: Option<RateLimitConfig>,
    /// OAuth 2.1 JWT bearer token authentication.
    #[cfg(feature = "oauth")]
    pub oauth: Option<crate::oauth::OAuthConfig>,
}

impl AuthConfig {
    /// Create an enabled auth config with the given API keys.
    #[must_use]
    pub fn with_keys(keys: Vec<ApiKeyEntry>) -> Self {
        Self {
            enabled: true,
            api_keys: keys,
            mtls: None,
            rate_limit: None,
            #[cfg(feature = "oauth")]
            oauth: None,
        }
    }

    /// Set rate limiting on this auth config.
    #[must_use]
    pub fn with_rate_limit(mut self, rate_limit: RateLimitConfig) -> Self {
        self.rate_limit = Some(rate_limit);
        self
    }
}

/// Summary of a single API key suitable for admin endpoints.
///
/// Intentionally omits the Argon2id hash - only metadata is exposed.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct ApiKeySummary {
    /// Human-readable key label.
    pub name: String,
    /// RBAC role granted when this key authenticates.
    pub role: String,
    /// Optional RFC 3339 expiry timestamp.
    pub expires_at: Option<String>,
}

/// Snapshot of the enabled authentication methods for admin endpoints.
#[derive(Debug, Clone, serde::Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "this is a flat summary of independent auth-method booleans"
)]
#[non_exhaustive]
pub struct AuthConfigSummary {
    /// Master enabled flag from config.
    pub enabled: bool,
    /// Whether API-key bearer auth is configured.
    pub bearer: bool,
    /// Whether mTLS client auth is configured.
    pub mtls: bool,
    /// Whether OAuth JWT validation is configured.
    pub oauth: bool,
    /// Current API-key list (no hashes).
    pub api_keys: Vec<ApiKeySummary>,
}

impl AuthConfig {
    /// Produce a hash-free summary of the auth config for admin endpoints.
    #[must_use]
    pub fn summary(&self) -> AuthConfigSummary {
        AuthConfigSummary {
            enabled: self.enabled,
            bearer: !self.api_keys.is_empty(),
            mtls: self.mtls.is_some(),
            #[cfg(feature = "oauth")]
            oauth: self.oauth.is_some(),
            #[cfg(not(feature = "oauth"))]
            oauth: false,
            api_keys: self
                .api_keys
                .iter()
                .map(|k| ApiKeySummary {
                    name: k.name.clone(),
                    role: k.role.clone(),
                    expires_at: k.expires_at.clone(),
                })
                .collect(),
        }
    }
}

/// Keyed rate limiter type (per source IP). Memory-bounded by
/// [`RateLimitConfig::max_tracked_keys`] to defend against IP-spray `DoS`.
pub(crate) type KeyedLimiter = BoundedKeyedLimiter<IpAddr>;

/// Connection info for TLS connections, carrying the peer socket address
/// and (when mTLS is configured) the verified client identity extracted
/// from the peer certificate during the TLS handshake.
///
/// Defined as a local type so we can implement axum's `Connected` trait
/// for our custom `TlsListener` without orphan rule issues. The `identity`
/// field travels with the connection itself (via the wrapping IO type),
/// so there is no shared map to race against, no port-reuse aliasing, and
/// no eviction policy to maintain.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub(crate) struct TlsConnInfo {
    /// Remote peer socket address.
    pub addr: SocketAddr,
    /// Verified mTLS client identity, if a client certificate was presented
    /// and successfully extracted during the TLS handshake.
    pub identity: Option<AuthIdentity>,
}

impl TlsConnInfo {
    /// Construct a new [`TlsConnInfo`].
    #[must_use]
    pub(crate) const fn new(addr: SocketAddr, identity: Option<AuthIdentity>) -> Self {
        Self { addr, identity }
    }
}

/// Shared state for the auth middleware.
///
/// `api_keys` uses [`ArcSwap`] so the SIGHUP handler can atomically
/// swap in a new key list without blocking in-flight requests.
#[allow(
    missing_debug_implementations,
    reason = "contains governor RateLimiter and JwksCache without Debug impls"
)]
#[non_exhaustive]
pub(crate) struct AuthState {
    /// Active set of API keys (hot-swappable).
    pub api_keys: ArcSwap<Vec<ApiKeyEntry>>,
    /// Optional per-IP post-failure rate limiter (consulted *after* auth fails).
    pub rate_limiter: Option<Arc<KeyedLimiter>>,
    /// Optional per-IP pre-auth abuse gate (consulted *before* password-hash work).
    /// mTLS-authenticated connections bypass this gate.
    pub pre_auth_limiter: Option<Arc<KeyedLimiter>>,
    #[cfg(feature = "oauth")]
    /// Optional JWKS cache for OAuth JWT validation.
    pub jwks_cache: Option<Arc<crate::oauth::JwksCache>>,
    /// Tracks identity names that have already been logged at INFO level.
    /// Subsequent auths for the same identity are logged at DEBUG.
    pub seen_identities: Mutex<HashSet<String>>,
    /// Lightweight in-memory auth success/failure counters for diagnostics.
    pub counters: AuthCounters,
}

impl AuthState {
    /// Atomically replace the API key list (lock-free, wait-free).
    ///
    /// New requests immediately see the updated keys.
    /// In-flight requests that already loaded the old list finish
    /// using it -- no torn reads.
    pub(crate) fn reload_keys(&self, keys: Vec<ApiKeyEntry>) {
        let count = keys.len();
        self.api_keys.store(Arc::new(keys));
        tracing::info!(keys = count, "API keys reloaded");
    }

    /// Snapshot auth counters for diagnostics and tests.
    #[must_use]
    pub(crate) fn counters_snapshot(&self) -> AuthCountersSnapshot {
        self.counters.snapshot()
    }

    /// Produce the admin-endpoint list of API keys (metadata only, no hashes).
    #[must_use]
    pub(crate) fn api_key_summaries(&self) -> Vec<ApiKeySummary> {
        self.api_keys
            .load()
            .iter()
            .map(|k| ApiKeySummary {
                name: k.name.clone(),
                role: k.role.clone(),
                expires_at: k.expires_at.clone(),
            })
            .collect()
    }

    /// Log auth success: INFO on first occurrence per identity, DEBUG after.
    fn log_auth(&self, id: &AuthIdentity, method: &str) {
        self.counters.record_success(id.method);
        let first = self
            .seen_identities
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.name.clone());
        if first {
            tracing::info!(name = %id.name, role = %id.role, "{method} authenticated");
        } else {
            tracing::debug!(name = %id.name, role = %id.role, "{method} authenticated");
        }
    }
}

/// Default auth rate limit: 30 attempts per minute per source IP.
// SAFETY: unwrap() is safe - literal 30 is provably non-zero (const-evaluated).
const DEFAULT_AUTH_RATE: NonZeroU32 = NonZeroU32::new(30).unwrap();

/// Create a post-failure rate limiter from config.
#[must_use]
pub(crate) fn build_rate_limiter(config: &RateLimitConfig) -> Arc<KeyedLimiter> {
    let quota = governor::Quota::per_minute(
        NonZeroU32::new(config.max_attempts_per_minute).unwrap_or(DEFAULT_AUTH_RATE),
    );
    Arc::new(BoundedKeyedLimiter::new(
        quota,
        config.max_tracked_keys,
        config.idle_eviction,
    ))
}

/// Create a pre-auth abuse-gate rate limiter from config.
///
/// Quota: `pre_auth_max_per_minute` if set, otherwise
/// `max_attempts_per_minute * 10` (capped at `u32::MAX`). The 10× factor
/// keeps the gate generous enough for honest retries while still bounding
/// attacker CPU on Argon2 verification.
#[must_use]
pub(crate) fn build_pre_auth_limiter(config: &RateLimitConfig) -> Arc<KeyedLimiter> {
    let resolved = config.pre_auth_max_per_minute.unwrap_or_else(|| {
        config
            .max_attempts_per_minute
            .saturating_mul(PRE_AUTH_DEFAULT_MULTIPLIER)
    });
    let quota =
        governor::Quota::per_minute(NonZeroU32::new(resolved).unwrap_or(DEFAULT_PRE_AUTH_RATE));
    Arc::new(BoundedKeyedLimiter::new(
        quota,
        config.max_tracked_keys,
        config.idle_eviction,
    ))
}

/// Default multiplier applied to `max_attempts_per_minute` when the operator
/// does not set `pre_auth_max_per_minute` explicitly.
const PRE_AUTH_DEFAULT_MULTIPLIER: u32 = 10;

/// Default pre-auth abuse-gate rate (used only if both the configured value
/// and the multiplied fallback are zero, which `NonZeroU32::new` rejects).
// SAFETY: unwrap() is safe - literal 300 is provably non-zero (const-evaluated).
const DEFAULT_PRE_AUTH_RATE: NonZeroU32 = NonZeroU32::new(300).unwrap();

/// Parse an mTLS client certificate and extract an `AuthIdentity`.
///
/// Reads the Subject CN as the identity name. Falls back to the first
/// DNS SAN if CN is absent. The role is taken from the `MtlsConfig`.
#[must_use]
pub fn extract_mtls_identity(cert_der: &[u8], default_role: &str) -> Option<AuthIdentity> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

    // Try CN from Subject first.
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(String::from);

    // Fall back to first DNS SAN.
    let name = cn.or_else(|| {
        cert.subject_alternative_name()
            .ok()
            .flatten()
            .and_then(|san| {
                #[allow(clippy::wildcard_enum_match_arm)]
                san.value.general_names.iter().find_map(|gn| match gn {
                    GeneralName::DNSName(dns) => Some((*dns).to_owned()),
                    _ => None,
                })
            })
    })?;

    // Reject identities with characters unsafe for logging and RBAC matching.
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '.' | '_' | '@'))
    {
        tracing::warn!(cn = %name, "mTLS identity rejected: invalid characters in CN/SAN");
        return None;
    }

    Some(AuthIdentity {
        name,
        role: default_role.to_owned(),
        method: AuthMethod::MtlsCertificate,
        raw_token: None,
        sub: None,
    })
}

/// Verify a bearer token against configured API keys.
///
/// Argon2id verification is CPU-intensive, so this should be called via
/// `spawn_blocking`. Returns the matching identity if the token is valid.
fn verify_bearer_token(token: &str, keys: &[ApiKeyEntry]) -> Option<AuthIdentity> {
    let now = chrono::Utc::now();

    // Always iterate ALL keys to completion to prevent timing side-channels
    // that reveal how many keys exist or which position matched.
    let mut result: Option<AuthIdentity> = None;

    for key in keys {
        // Check expiry
        if let Some(ref expires) = key.expires_at
            && let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires)
            && exp < now
        {
            continue;
        }

        // Argon2id verification (constant-time internally).
        // Keep the first match but continue checking remaining keys.
        if result.is_none()
            && let Ok(parsed_hash) = PasswordHash::new(&key.hash)
            && Argon2::default()
                .verify_password(token.as_bytes(), &parsed_hash)
                .is_ok()
        {
            result = Some(AuthIdentity {
                name: key.name.clone(),
                role: key.role.clone(),
                method: AuthMethod::BearerToken,
                raw_token: None,
                sub: None,
            });
        }
    }
    result
}

/// Generate a new API key: 256-bit random token + Argon2id hash.
///
/// Returns `(plaintext_token, argon2id_hash_phc_string)`.
/// The plaintext is shown once to the user and never stored.
///
/// # Errors
///
/// Returns an error if salt encoding or Argon2id hashing fails
/// (should not happen with valid inputs, but we avoid panicking).
pub fn generate_api_key() -> Result<(String, String), McpxError> {
    let mut token_bytes = [0u8; 32];
    rand::fill(&mut token_bytes);
    let token = URL_SAFE_NO_PAD.encode(token_bytes);

    // Generate 16 random bytes for salt, encode as base64 for SaltString.
    let mut salt_bytes = [0u8; 16];
    rand::fill(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| McpxError::Auth(format!("salt encoding failed: {e}")))?;
    let hash = Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .map_err(|e| McpxError::Auth(format!("argon2id hashing failed: {e}")))?
        .to_string();

    Ok((token, hash))
}

fn build_www_authenticate_value(
    advertise_resource_metadata: bool,
    failure: AuthFailureClass,
) -> String {
    let (error, error_description) = failure.bearer_error();
    if advertise_resource_metadata {
        return format!(
            "Bearer resource_metadata=\"/.well-known/oauth-protected-resource\", error=\"{error}\", error_description=\"{error_description}\""
        );
    }
    format!("Bearer error=\"{error}\", error_description=\"{error_description}\"")
}

fn auth_method_label(method: AuthMethod) -> &'static str {
    match method {
        AuthMethod::MtlsCertificate => "mTLS",
        AuthMethod::BearerToken => "bearer token",
        AuthMethod::OAuthJwt => "OAuth JWT",
    }
}

#[cfg_attr(not(feature = "oauth"), allow(unused_variables))]
fn unauthorized_response(state: &AuthState, failure_class: AuthFailureClass) -> Response {
    #[cfg(feature = "oauth")]
    let advertise_resource_metadata = state.jwks_cache.is_some();
    #[cfg(not(feature = "oauth"))]
    let advertise_resource_metadata = false;

    let challenge = build_www_authenticate_value(advertise_resource_metadata, failure_class);
    (
        axum::http::StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, challenge)],
        failure_class.response_body(),
    )
        .into_response()
}

async fn authenticate_bearer_identity(
    state: &AuthState,
    token: &str,
) -> Result<AuthIdentity, AuthFailureClass> {
    let mut failure_class = AuthFailureClass::MissingCredential;

    #[cfg(feature = "oauth")]
    if let Some(ref cache) = state.jwks_cache
        && crate::oauth::looks_like_jwt(token)
    {
        match cache.validate_token_with_reason(token).await {
            Ok(mut id) => {
                id.raw_token = Some(SecretString::from(token.to_owned()));
                return Ok(id);
            }
            Err(crate::oauth::JwtValidationFailure::Expired) => {
                failure_class = AuthFailureClass::ExpiredCredential;
            }
            Err(crate::oauth::JwtValidationFailure::Invalid) => {
                failure_class = AuthFailureClass::InvalidCredential;
            }
        }
    }

    let token = token.to_owned();
    let keys = state.api_keys.load_full(); // Arc clone, lock-free

    // Argon2id is CPU-bound - offload to blocking thread pool.
    let identity = tokio::task::spawn_blocking(move || verify_bearer_token(&token, &keys))
        .await
        .ok()
        .flatten();

    if let Some(id) = identity {
        return Ok(id);
    }

    if failure_class == AuthFailureClass::MissingCredential {
        failure_class = AuthFailureClass::InvalidCredential;
    }

    Err(failure_class)
}

/// Consult the pre-auth abuse gate for the given peer.
///
/// Returns `Some(response)` if the request should be rejected (limiter
/// configured AND quota exhausted for this source IP). Returns `None`
/// otherwise (limiter absent, peer address unknown, or quota available),
/// in which case the caller should proceed with credential verification.
///
/// Side effects on rejection: increments the `pre_auth_gate` failure
/// counter and emits a warn-level log. mTLS-authenticated requests must
/// be admitted by the caller *before* invoking this helper.
fn pre_auth_gate(state: &AuthState, peer_addr: Option<SocketAddr>) -> Option<Response> {
    let limiter = state.pre_auth_limiter.as_ref()?;
    let addr = peer_addr?;
    if limiter.check_key(&addr.ip()).is_ok() {
        return None;
    }
    state.counters.record_failure(AuthFailureClass::PreAuthGate);
    tracing::warn!(
        ip = %addr.ip(),
        "auth rate limited by pre-auth gate (request rejected before credential verification)"
    );
    Some(
        McpxError::RateLimited("too many unauthenticated requests from this source".into())
            .into_response(),
    )
}

/// Axum middleware that enforces authentication.
///
/// Tries authentication methods in priority order:
/// 1. mTLS client certificate identity (populated by TLS acceptor)
/// 2. Bearer token from `Authorization` header
///
/// Failed authentication attempts are rate-limited per source IP.
/// Successful authentications do not consume rate limit budget.
pub(crate) async fn auth_middleware(
    state: Arc<AuthState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Extract peer address (and any mTLS identity) from ConnectInfo.
    // Plain TCP: ConnectInfo<SocketAddr>. TLS / mTLS: ConnectInfo<TlsConnInfo>,
    // which carries the verified identity directly on the connection — no
    // shared map, no port-reuse aliasing.
    let tls_info = req.extensions().get::<ConnectInfo<TlsConnInfo>>().cloned();
    let peer_addr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0)
        .or_else(|| tls_info.as_ref().map(|ci| ci.0.addr));

    // 1. Try mTLS identity (extracted by the TLS acceptor during handshake
    //    and attached to the connection itself).
    //
    //    mTLS connections bypass the pre-auth abuse gate below: the TLS
    //    handshake already performed expensive crypto with a verified peer,
    //    so we trust them not to be a CPU-spray attacker.
    if let Some(id) = tls_info.and_then(|ci| ci.0.identity) {
        state.log_auth(&id, "mTLS");
        let mut req = req;
        req.extensions_mut().insert(id);
        return next.run(req).await;
    }

    // 2. Pre-auth abuse gate: rejects CPU-spray attacks BEFORE the Argon2id
    //    verification path runs. Keyed by source IP. mTLS connections (above)
    //    are exempt; this gate only protects the bearer/JWT verification path.
    if let Some(blocked) = pre_auth_gate(&state, peer_addr) {
        return blocked;
    }

    let failure_class = if let Some(value) = req.headers().get(header::AUTHORIZATION) {
        match value.to_str().ok().and_then(|v| v.strip_prefix("Bearer ")) {
            Some(token) => match authenticate_bearer_identity(&state, token).await {
                Ok(id) => {
                    state.log_auth(&id, auth_method_label(id.method));
                    let mut req = req;
                    req.extensions_mut().insert(id);
                    return next.run(req).await;
                }
                Err(class) => class,
            },
            None => AuthFailureClass::InvalidCredential,
        }
    } else {
        AuthFailureClass::MissingCredential
    };

    tracing::warn!(failure_class = %failure_class.as_str(), "auth failed");

    // Rate limit check (applied after auth failure only).
    // Successful authentications do not consume rate limit budget.
    if let (Some(limiter), Some(addr)) = (&state.rate_limiter, peer_addr)
        && limiter.check_key(&addr.ip()).is_err()
    {
        state.counters.record_failure(AuthFailureClass::RateLimited);
        tracing::warn!(ip = %addr.ip(), "auth rate limited after repeated failures");
        return McpxError::RateLimited("too many failed authentication attempts".into())
            .into_response();
    }

    state.counters.record_failure(failure_class);
    unauthorized_response(&state, failure_class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify_api_key() {
        let (token, hash) = generate_api_key().unwrap();

        // Token is 43 chars (256-bit base64url, no padding)
        assert_eq!(token.len(), 43);

        // Hash is a valid PHC string
        assert!(hash.starts_with("$argon2id$"));

        // Verification succeeds with correct token
        let keys = vec![ApiKeyEntry {
            name: "test".into(),
            hash,
            role: "viewer".into(),
            expires_at: None,
        }];
        let id = verify_bearer_token(&token, &keys);
        assert!(id.is_some());
        let id = id.unwrap();
        assert_eq!(id.name, "test");
        assert_eq!(id.role, "viewer");
        assert_eq!(id.method, AuthMethod::BearerToken);
    }

    #[test]
    fn wrong_token_rejected() {
        let (_token, hash) = generate_api_key().unwrap();
        let keys = vec![ApiKeyEntry {
            name: "test".into(),
            hash,
            role: "viewer".into(),
            expires_at: None,
        }];
        assert!(verify_bearer_token("wrong-token", &keys).is_none());
    }

    #[test]
    fn expired_key_rejected() {
        let (token, hash) = generate_api_key().unwrap();
        let keys = vec![ApiKeyEntry {
            name: "test".into(),
            hash,
            role: "viewer".into(),
            expires_at: Some("2020-01-01T00:00:00Z".into()),
        }];
        assert!(verify_bearer_token(&token, &keys).is_none());
    }

    #[test]
    fn future_expiry_accepted() {
        let (token, hash) = generate_api_key().unwrap();
        let keys = vec![ApiKeyEntry {
            name: "test".into(),
            hash,
            role: "viewer".into(),
            expires_at: Some("2099-01-01T00:00:00Z".into()),
        }];
        assert!(verify_bearer_token(&token, &keys).is_some());
    }

    #[test]
    fn multiple_keys_first_match_wins() {
        let (token, hash) = generate_api_key().unwrap();
        let keys = vec![
            ApiKeyEntry {
                name: "wrong".into(),
                hash: "$argon2id$v=19$m=19456,t=2,p=1$invalid$invalid".into(),
                role: "ops".into(),
                expires_at: None,
            },
            ApiKeyEntry {
                name: "correct".into(),
                hash,
                role: "deploy".into(),
                expires_at: None,
            },
        ];
        let id = verify_bearer_token(&token, &keys).unwrap();
        assert_eq!(id.name, "correct");
        assert_eq!(id.role, "deploy");
    }

    #[test]
    fn rate_limiter_allows_within_quota() {
        let config = RateLimitConfig {
            max_attempts_per_minute: 5,
            pre_auth_max_per_minute: None,
            ..Default::default()
        };
        let limiter = build_rate_limiter(&config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // First 5 should succeed.
        for _ in 0..5 {
            assert!(limiter.check_key(&ip).is_ok());
        }
        // 6th should fail.
        assert!(limiter.check_key(&ip).is_err());
    }

    #[test]
    fn rate_limiter_separate_ips() {
        let config = RateLimitConfig {
            max_attempts_per_minute: 2,
            pre_auth_max_per_minute: None,
            ..Default::default()
        };
        let limiter = build_rate_limiter(&config);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        // Exhaust ip1's quota.
        assert!(limiter.check_key(&ip1).is_ok());
        assert!(limiter.check_key(&ip1).is_ok());
        assert!(limiter.check_key(&ip1).is_err());

        // ip2 should still have quota.
        assert!(limiter.check_key(&ip2).is_ok());
    }

    #[test]
    fn extract_mtls_identity_from_cn() {
        // Generate a cert with explicit CN.
        let mut params = rcgen::CertificateParams::new(vec!["test-client.local".into()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-client");
        let cert = params
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        let der = cert.der();

        let id = extract_mtls_identity(der, "ops").unwrap();
        assert_eq!(id.name, "test-client");
        assert_eq!(id.role, "ops");
        assert_eq!(id.method, AuthMethod::MtlsCertificate);
    }

    #[test]
    fn extract_mtls_identity_falls_back_to_san() {
        // Cert with no CN but has a DNS SAN.
        let mut params =
            rcgen::CertificateParams::new(vec!["san-only.example.com".into()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        // No CN set - should fall back to DNS SAN.
        let cert = params
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        let der = cert.der();

        let id = extract_mtls_identity(der, "viewer").unwrap();
        assert_eq!(id.name, "san-only.example.com");
        assert_eq!(id.role, "viewer");
    }

    #[test]
    fn extract_mtls_identity_invalid_der() {
        assert!(extract_mtls_identity(b"not-a-cert", "viewer").is_none());
    }

    // -- auth_middleware integration tests --

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt as _;

    fn auth_router(state: Arc<AuthState>) -> axum::Router {
        axum::Router::new()
            .route("/mcp", axum::routing::post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let s = Arc::clone(&state);
                auth_middleware(s, req, next)
            }))
    }

    fn test_auth_state(keys: Vec<ApiKeyEntry>) -> Arc<AuthState> {
        Arc::new(AuthState {
            api_keys: ArcSwap::new(Arc::new(keys)),
            rate_limiter: None,
            pre_auth_limiter: None,
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: Mutex::new(HashSet::new()),
            counters: AuthCounters::default(),
        })
    }

    #[tokio::test]
    async fn middleware_rejects_no_credentials() {
        let state = test_auth_state(vec![]);
        let app = auth_router(Arc::clone(&state));
        let req = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let challenge = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(challenge.contains("error=\"invalid_request\""));

        let counters = state.counters_snapshot();
        assert_eq!(counters.failure_missing_credential, 1);
    }

    #[tokio::test]
    async fn middleware_accepts_valid_bearer() {
        let (token, hash) = generate_api_key().unwrap();
        let keys = vec![ApiKeyEntry {
            name: "test-key".into(),
            hash,
            role: "ops".into(),
            expires_at: None,
        }];
        let state = test_auth_state(keys);
        let app = auth_router(Arc::clone(&state));
        let req = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let counters = state.counters_snapshot();
        assert_eq!(counters.success_bearer, 1);
    }

    #[tokio::test]
    async fn middleware_rejects_wrong_bearer() {
        let (_token, hash) = generate_api_key().unwrap();
        let keys = vec![ApiKeyEntry {
            name: "test-key".into(),
            hash,
            role: "ops".into(),
            expires_at: None,
        }];
        let state = test_auth_state(keys);
        let app = auth_router(Arc::clone(&state));
        let req = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .header("authorization", "Bearer wrong-token-here")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let challenge = resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(challenge.contains("error=\"invalid_token\""));

        let counters = state.counters_snapshot();
        assert_eq!(counters.failure_invalid_credential, 1);
    }

    #[tokio::test]
    async fn middleware_rate_limits() {
        let state = Arc::new(AuthState {
            api_keys: ArcSwap::new(Arc::new(vec![])),
            rate_limiter: Some(build_rate_limiter(&RateLimitConfig {
                max_attempts_per_minute: 1,
                pre_auth_max_per_minute: None,
                ..Default::default()
            })),
            pre_auth_limiter: None,
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: Mutex::new(HashSet::new()),
            counters: AuthCounters::default(),
        });
        let app = auth_router(state);

        // First request: UNAUTHORIZED (no credentials, but not rate limited)
        let req = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Second request from same "IP" (no ConnectInfo in test, so peer_addr is None
        // and rate limiter won't fire). That's expected -- rate limiting requires
        // ConnectInfo which isn't available in unit tests without a real server.
        // This test verifies the middleware wiring doesn't panic.
    }

    /// Verify that rate limit semantics: only failed auth attempts consume budget.
    ///
    /// This is a unit test of the limiter behavior. The middleware integration
    /// is that on auth failure, `check_key` is called; on auth success, it is NOT.
    /// Full e2e tests verify the middleware routing but require `ConnectInfo`.
    #[test]
    fn rate_limit_semantics_failed_only() {
        let config = RateLimitConfig {
            max_attempts_per_minute: 3,
            pre_auth_max_per_minute: None,
            ..Default::default()
        };
        let limiter = build_rate_limiter(&config);
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Simulate: 3 failed attempts should exhaust quota.
        assert!(
            limiter.check_key(&ip).is_ok(),
            "failure 1 should be allowed"
        );
        assert!(
            limiter.check_key(&ip).is_ok(),
            "failure 2 should be allowed"
        );
        assert!(
            limiter.check_key(&ip).is_ok(),
            "failure 3 should be allowed"
        );
        assert!(
            limiter.check_key(&ip).is_err(),
            "failure 4 should be blocked"
        );

        // In the actual middleware flow:
        // - Successful auth: verify_bearer_token returns Some, we return early
        //   WITHOUT calling check_key, so no budget consumed.
        // - Failed auth: verify_bearer_token returns None, we call check_key
        //   THEN return 401, so budget is consumed.
        //
        // This means N successful requests followed by M failed requests
        // will only count M toward the rate limit, not N+M.
    }

    // -- pre-auth abuse gate (H-S1) --

    /// The pre-auth gate must default to ~10x the post-failure quota so honest
    /// retry storms never trip it but a Argon2-spray attacker is throttled.
    #[test]
    fn pre_auth_default_multiplier_is_10x() {
        let config = RateLimitConfig {
            max_attempts_per_minute: 5,
            pre_auth_max_per_minute: None,
            ..Default::default()
        };
        let limiter = build_pre_auth_limiter(&config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Quota should be 50 (5 * 10), not 5. We expect the first 50 to pass.
        for i in 0..50 {
            assert!(
                limiter.check_key(&ip).is_ok(),
                "pre-auth attempt {i} (of expected 50) should be allowed under default 10x multiplier"
            );
        }
        // The 51st attempt must be blocked: confirms quota is bounded, not infinite.
        assert!(
            limiter.check_key(&ip).is_err(),
            "pre-auth attempt 51 should be blocked (quota is 50, not unbounded)"
        );
    }

    /// An explicit `pre_auth_max_per_minute` override must win over the
    /// 10x-multiplier default.
    #[test]
    fn pre_auth_explicit_override_wins() {
        let config = RateLimitConfig {
            max_attempts_per_minute: 100,     // would default to 1000 pre-auth quota
            pre_auth_max_per_minute: Some(2), // but operator caps at 2
            ..Default::default()
        };
        let limiter = build_pre_auth_limiter(&config);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();

        assert!(limiter.check_key(&ip).is_ok(), "attempt 1 allowed");
        assert!(limiter.check_key(&ip).is_ok(), "attempt 2 allowed");
        assert!(
            limiter.check_key(&ip).is_err(),
            "attempt 3 must be blocked (explicit override of 2 wins over 10x default of 1000)"
        );
    }

    /// End-to-end: the pre-auth gate must reject before the bearer-verification
    /// path runs. We exhaust the gate's quota (Some(1)) with one bad-bearer
    /// request, then the second request must be rejected with 429 + the
    /// `pre_auth_gate` failure counter incremented (NOT
    /// `failure_invalid_credential`, which would prove Argon2 ran).
    #[tokio::test]
    async fn pre_auth_gate_blocks_before_argon2_verification() {
        let (_token, hash) = generate_api_key().unwrap();
        let keys = vec![ApiKeyEntry {
            name: "test-key".into(),
            hash,
            role: "ops".into(),
            expires_at: None,
        }];
        let config = RateLimitConfig {
            max_attempts_per_minute: 100,
            pre_auth_max_per_minute: Some(1),
            ..Default::default()
        };
        let state = Arc::new(AuthState {
            api_keys: ArcSwap::new(Arc::new(keys)),
            rate_limiter: None,
            pre_auth_limiter: Some(build_pre_auth_limiter(&config)),
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: Mutex::new(HashSet::new()),
            counters: AuthCounters::default(),
        });
        let app = auth_router(Arc::clone(&state));
        let peer: SocketAddr = "10.0.0.10:54321".parse().unwrap();

        // First bad-bearer request: gate has quota, bearer verification runs,
        // returns 401 (invalid credential).
        let mut req1 = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .header("authorization", "Bearer obviously-not-a-real-token")
            .body(Body::empty())
            .unwrap();
        req1.extensions_mut().insert(ConnectInfo(peer));
        let resp1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(
            resp1.status(),
            StatusCode::UNAUTHORIZED,
            "first attempt: gate has quota, falls through to bearer auth which fails with 401"
        );

        // Second bad-bearer request from same IP: gate quota exhausted, must
        // reject with 429 BEFORE the Argon2 verification path runs.
        let mut req2 = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .header("authorization", "Bearer also-not-a-real-token")
            .body(Body::empty())
            .unwrap();
        req2.extensions_mut().insert(ConnectInfo(peer));
        let resp2 = app.oneshot(req2).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "second attempt from same IP: pre-auth gate must reject with 429"
        );

        let counters = state.counters_snapshot();
        assert_eq!(
            counters.failure_pre_auth_gate, 1,
            "exactly one request must have been rejected by the pre-auth gate"
        );
        // Critical: Argon2 verification must NOT have run on the gated request.
        // The first request's 401 increments `failure_invalid_credential` to 1;
        // the second (gated) request must NOT increment it further.
        assert_eq!(
            counters.failure_invalid_credential, 1,
            "bearer verification must run exactly once (only the un-gated first request)"
        );
    }

    /// mTLS-authenticated requests must bypass the pre-auth gate entirely.
    /// The TLS handshake already performed expensive crypto with a verified
    /// peer, so mTLS callers should never be throttled by this gate.
    ///
    /// Setup: a pre-auth gate with quota 1 (very tight). Submit two mTLS
    /// requests in quick succession from the same IP. Both must succeed.
    #[tokio::test]
    async fn pre_auth_gate_does_not_throttle_mtls() {
        let config = RateLimitConfig {
            max_attempts_per_minute: 100,
            pre_auth_max_per_minute: Some(1), // tight: would block 2nd plain request
            ..Default::default()
        };
        let state = Arc::new(AuthState {
            api_keys: ArcSwap::new(Arc::new(vec![])),
            rate_limiter: None,
            pre_auth_limiter: Some(build_pre_auth_limiter(&config)),
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: Mutex::new(HashSet::new()),
            counters: AuthCounters::default(),
        });
        let app = auth_router(Arc::clone(&state));
        let peer: SocketAddr = "10.0.0.20:54321".parse().unwrap();
        let identity = AuthIdentity {
            name: "cn=test-client".into(),
            role: "viewer".into(),
            method: AuthMethod::MtlsCertificate,
            raw_token: None,
            sub: None,
        };
        let tls_info = TlsConnInfo::new(peer, Some(identity));

        for i in 0..3 {
            let mut req = Request::builder()
                .method(axum::http::Method::POST)
                .uri("/mcp")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(tls_info.clone()));
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "mTLS request {i} must succeed: pre-auth gate must not apply to mTLS callers"
            );
        }

        let counters = state.counters_snapshot();
        assert_eq!(
            counters.failure_pre_auth_gate, 0,
            "pre-auth gate counter must remain at zero: mTLS bypasses the gate"
        );
        assert_eq!(
            counters.success_mtls, 3,
            "all three mTLS requests must have been counted as successful"
        );
    }
}
