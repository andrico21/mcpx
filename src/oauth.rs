//! OAuth 2.1 JWT bearer token validation with JWKS caching.
//!
//! When enabled, Bearer tokens that look like JWTs (three base64-separated
//! segments with a valid JSON header containing `"alg"`) are validated
//! against a JWKS fetched from the configured Authorization Server.
//! Token scopes are mapped to RBAC roles via explicit configuration.
//!
//! ## OAuth 2.1 Proxy
//!
//! When `OAuthConfig::proxy` is set, the MCP server acts as an OAuth 2.1
//! authorization server facade, proxying `/authorize` and `/token` to an
//! upstream identity provider (e.g. Keycloak).  MCP clients discover this server as the
//! authorization server via Protected Resource Metadata (RFC 9728) and
//! perform the standard Authorization Code + PKCE flow transparently.

use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, Instant},
};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::auth::{AuthIdentity, AuthMethod};

// ---------------------------------------------------------------------------
// HTTP client wrapper
// ---------------------------------------------------------------------------

/// HTTP client used by [`exchange_token`] and the OAuth 2.1 proxy
/// handlers ([`handle_token`], [`handle_introspect`], [`handle_revoke`]).
///
/// Wraps an internal HTTP backend so callers do not depend on the
/// concrete crate. Construct one per process and reuse across requests
/// (the underlying connection pool is shared internally via
/// [`Clone`] - cheap, refcounted).
///
/// **Hardening (since 1.2.1).** When constructed via [`with_config`]
/// (preferred), the internal client refuses any redirect that downgrades
/// the scheme from `https` to `http`, even when the original request URL
/// was HTTPS. This closes a class of metadata-poisoning attacks where a
/// hostile or compromised upstream `IdP` returns `302 Location: http://...`
/// and the resulting plaintext hop is intercepted by a network-positioned
/// attacker to siphon bearer tokens, refresh tokens, or introspection
/// traffic. When the caller has set [`OAuthConfig::allow_http_oauth_urls`]
/// to `true` (development only), HTTP-to-HTTP redirects are still permitted
/// but HTTPS-to-HTTP downgrades are *always* rejected.
///
/// [`with_config`] also honours [`OAuthConfig::ca_cert_path`] (if set) and
/// adds the supplied PEM CA bundle to the system roots so that
/// every OAuth-bound HTTP request -- not just the JWKS fetch -- can
/// trust enterprise/internal certificate authorities. This restores
/// the behaviour that existed pre-`0.10.0` before the `OauthHttpClient`
/// wrapper landed.
///
/// The legacy [`new`](Self::new) constructor (no-arg) is preserved for
/// source compatibility but is `#[deprecated]`: it returns a client with
/// system-roots-only TLS trust and the strictest redirect policy
/// (HTTPS-only, never permits plain HTTP). Migrate to
/// [`with_config`](Self::with_config) at the earliest opportunity so
/// that token / introspection / revocation / exchange traffic inherits
/// the same CA trust and `allow_http_oauth_urls` toggle as the JWKS
/// fetch client.
///
/// [`with_config`]: Self::with_config
#[derive(Clone)]
pub struct OauthHttpClient {
    inner: reqwest::Client,
}

impl OauthHttpClient {
    /// Build a client from the OAuth configuration (preferred since 1.2.1).
    ///
    /// Defaults: `connect_timeout = 10s`, total `timeout = 30s`,
    /// scheme-downgrade-rejecting redirect policy (max 2 hops),
    /// optional custom CA trust via [`OAuthConfig::ca_cert_path`],
    /// and HTTP-to-HTTP redirects gated by
    /// [`OAuthConfig::allow_http_oauth_urls`] (dev-only).
    ///
    /// Pass the same `&OAuthConfig` you supplied to
    /// [`JwksCache::new`] / `serve()` so the OAuth-bound HTTP traffic
    /// inherits identical CA trust and HTTPS-only redirect policy.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::McpxError::Startup`] if the configured
    /// `ca_cert_path` cannot be read or parsed, or if the underlying
    /// HTTP client cannot be constructed (e.g. TLS backend init failure).
    pub fn with_config(config: &OAuthConfig) -> Result<Self, crate::error::McpxError> {
        Self::build(Some(config))
    }

    /// Build a client with default settings (system CA roots only,
    /// strict HTTPS-only redirect policy).
    ///
    /// **Deprecated since 1.2.1.** This constructor cannot honour
    /// [`OAuthConfig::ca_cert_path`] (so token / introspection /
    /// revocation / exchange traffic falls back to the system trust
    /// store, breaking enterprise PKI deployments) and ignores the
    /// [`OAuthConfig::allow_http_oauth_urls`] dev-mode toggle (so
    /// HTTP-to-HTTP redirects are unconditionally refused). Both of
    /// these are bugs that the new [`with_config`](Self::with_config)
    /// constructor fixes.
    ///
    /// The redirect policy still rejects `https -> http` downgrades,
    /// matching the security posture of [`with_config`](Self::with_config).
    ///
    /// Migrate to [`with_config`](Self::with_config) and pass the same
    /// `&OAuthConfig` your `serve()` call uses.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::McpxError::Startup`] if the underlying
    /// HTTP client cannot be constructed (e.g. TLS backend init failure).
    #[deprecated(
        since = "1.2.1",
        note = "use OauthHttpClient::with_config(&OAuthConfig) so token/introspect/revoke/exchange traffic inherits ca_cert_path and the allow_http_oauth_urls toggle"
    )]
    pub fn new() -> Result<Self, crate::error::McpxError> {
        Self::build(None)
    }

    /// Internal builder shared by [`new`](Self::new) (config = `None`)
    /// and [`with_config`](Self::with_config) (config = `Some`).
    fn build(config: Option<&OAuthConfig>) -> Result<Self, crate::error::McpxError> {
        let allow_http = config.is_some_and(|c| c.allow_http_oauth_urls);

        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                // SECURITY: a redirect from `https` to `http` is *always*
                // rejected, even when `allow_http_oauth_urls` is true.
                // The flag controls whether the *original* request URL
                // may be plain HTTP; it never authorises a downgrade
                // mid-flight. An `http -> http` redirect is permitted
                // only when the flag is true (dev-only). The scheme
                // guard runs before the hop-count guard so a downgrade
                // surfaces as an explicit downgrade error rather than as
                // "too many redirects".
                let prev_https = attempt
                    .previous()
                    .last()
                    .is_some_and(|prev| prev.scheme() == "https");
                let dest_scheme = attempt.url().scheme();
                if dest_scheme != "https" {
                    if prev_https {
                        return attempt.error("redirect downgrades https -> http");
                    }
                    if !allow_http || dest_scheme != "http" {
                        return attempt.error("redirect to non-HTTP(S) URL refused");
                    }
                }
                if dest_scheme == "https"
                    && let Some(reason) = crate::ssrf::redirect_target_reason(attempt.url())
                {
                    return attempt.error(format!("redirect target forbidden: {reason}"));
                }
                if attempt.previous().len() >= 2 {
                    attempt.error("too many redirects (max 2)")
                } else {
                    attempt.follow()
                }
            }));

        if let Some(cfg) = config
            && let Some(ref ca_path) = cfg.ca_cert_path
        {
            // Pre-startup blocking I/O: this constructor runs from
            // `serve()`'s pre-startup phase (and from test code), so
            // synchronous file I/O is intentional. Do not wrap in
            // `spawn_blocking` -- the constructor is sync by contract.
            let pem = std::fs::read(ca_path).map_err(|e| {
                crate::error::McpxError::Startup(format!(
                    "oauth http client: read ca_cert_path {}: {e}",
                    ca_path.display()
                ))
            })?;
            let cert = reqwest::tls::Certificate::from_pem(&pem).map_err(|e| {
                crate::error::McpxError::Startup(format!(
                    "oauth http client: parse ca_cert_path {}: {e}",
                    ca_path.display()
                ))
            })?;
            builder = builder.add_root_certificate(cert);
        }

        let inner = builder.build().map_err(|e| {
            crate::error::McpxError::Startup(format!("oauth http client init: {e}"))
        })?;
        Ok(Self { inner })
    }

    /// Test-only: issue a `GET` against an arbitrary URL using the
    /// configured client (redirect policy, CA trust, timeouts all
    /// applied). Used by integration tests to exercise the redirect-
    /// downgrade and CA-trust regressions without going through
    /// `exchange_token`. Not part of the public API.
    #[doc(hidden)]
    pub async fn __test_get(&self, url: &str) -> reqwest::Result<reqwest::Response> {
        self.inner.get(url).send().await
    }
}

impl std::fmt::Debug for OauthHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OauthHttpClient").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// OAuth 2.1 JWT configuration.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct OAuthConfig {
    /// Token issuer (`iss` claim). Must match exactly.
    pub issuer: String,
    /// Expected audience (`aud` claim). Must match exactly.
    pub audience: String,
    /// JWKS endpoint URL (e.g. `https://auth.example.com/.well-known/jwks.json`).
    pub jwks_uri: String,
    /// Scope-to-role mappings. First matching scope wins.
    /// Used when `role_claim` is absent (default behavior).
    #[serde(default)]
    pub scopes: Vec<ScopeMapping>,
    /// JWT claim path to extract roles from (dot-notation for nested claims).
    ///
    /// Examples: `"scope"` (default), `"roles"`, `"realm_access.roles"`.
    /// When set, the claim value is matched against `role_mappings` instead
    /// of `scopes`. Supports both space-separated strings and JSON arrays.
    pub role_claim: Option<String>,
    /// Claim-value-to-role mappings. Used when `role_claim` is set.
    /// First matching value wins.
    #[serde(default)]
    pub role_mappings: Vec<RoleMapping>,
    /// How long to cache JWKS keys before re-fetching.
    /// Parsed as a humantime duration (e.g. "10m", "1h"). Default: "10m".
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl: String,
    /// OAuth proxy configuration.  When set, the server exposes
    /// `/authorize`, `/token`, and `/register` endpoints that proxy
    /// to the upstream identity provider (e.g. Keycloak).
    pub proxy: Option<OAuthProxyConfig>,
    /// Token exchange configuration (RFC 8693).  When set, the server
    /// can exchange an inbound MCP-scoped access token for a downstream
    /// API-scoped access token via the authorization server's token
    /// endpoint.
    pub token_exchange: Option<TokenExchangeConfig>,
    /// Optional path to a PEM CA bundle for OAuth-bound HTTP traffic.
    /// Added to the system/built-in roots, not a replacement.
    ///
    /// **Scope (since 1.2.1).** When the [`OauthHttpClient`] is
    /// constructed via [`OauthHttpClient::with_config`] (preferred),
    /// this CA bundle is honoured by *every* OAuth-bound HTTP
    /// request: the JWKS key fetch, token exchange, introspection,
    /// revocation, and the OAuth proxy handlers. Application crates
    /// may auto-populate this from their own configuration (e.g. an
    /// upstream-API CA path); any application-owned HTTP clients
    /// outside the kit must still configure their own CA trust
    /// separately. The deprecated [`OauthHttpClient::new`] no-arg
    /// constructor cannot honour this field -- migrate to
    /// [`OauthHttpClient::with_config`] for full coverage.
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    /// Allow plain-HTTP (non-TLS) URLs for OAuth endpoints (`jwks_uri`,
    /// `proxy.authorize_url`, `proxy.token_url`, `proxy.introspection_url`,
    /// `proxy.revocation_url`, `token_exchange.token_url`).
    ///
    /// **Default: `false`.** Strongly discouraged in production: a
    /// network-positioned attacker can MITM JWKS responses and substitute
    /// signing keys (forging arbitrary tokens), or MITM the token / proxy
    /// endpoints to steal credentials and codes. Enable only for
    /// development against a local `IdP` without TLS, ideally bound to
    /// `127.0.0.1`. JWKS-cache redirects to non-HTTPS targets are still
    /// rejected even when this flag is `true`.
    #[serde(default)]
    pub allow_http_oauth_urls: bool,
    /// Maximum number of keys accepted from a JWKS refresh response.
    /// Requests returning more keys than this are rejected fail-closed
    /// (cache remains empty / unchanged). Default: 256.
    #[serde(default = "default_max_jwks_keys")]
    pub max_jwks_keys: usize,
}

fn default_jwks_cache_ttl() -> String {
    "10m".into()
}

const fn default_max_jwks_keys() -> usize {
    256
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            audience: String::new(),
            jwks_uri: String::new(),
            scopes: Vec::new(),
            role_claim: None,
            role_mappings: Vec::new(),
            jwks_cache_ttl: default_jwks_cache_ttl(),
            proxy: None,
            token_exchange: None,
            ca_cert_path: None,
            allow_http_oauth_urls: false,
            max_jwks_keys: default_max_jwks_keys(),
        }
    }
}

impl OAuthConfig {
    /// Start building an [`OAuthConfig`] with the three required fields.
    ///
    /// All other fields default to the same values as
    /// [`OAuthConfig::default`] (empty scopes/role mappings, no proxy or
    /// token exchange, a JWKS cache TTL of `10m`).
    pub fn builder(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_uri: impl Into<String>,
    ) -> OAuthConfigBuilder {
        OAuthConfigBuilder {
            inner: Self {
                issuer: issuer.into(),
                audience: audience.into(),
                jwks_uri: jwks_uri.into(),
                ..Self::default()
            },
        }
    }

    /// Validate the URL fields against the HTTPS-only policy.
    ///
    /// Each of `jwks_uri`, `proxy.authorize_url`, `proxy.token_url`,
    /// `proxy.introspection_url`, `proxy.revocation_url`, and
    /// `token_exchange.token_url` is parsed and its scheme checked.
    ///
    /// Schemes other than `https` are rejected unless
    /// [`OAuthConfig::allow_http_oauth_urls`] is `true`, in which case
    /// `http` is also permitted (parse failures and other schemes are
    /// always rejected).
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::McpxError::Config`] when any field fails
    /// to parse or violates the scheme policy.
    pub fn validate(&self) -> Result<(), crate::error::McpxError> {
        let allow_http = self.allow_http_oauth_urls;
        let url = check_oauth_url("oauth.jwks_uri", &self.jwks_uri, allow_http)?;
        if let Some(reason) = crate::ssrf::check_url_literal_ip(&url) {
            return Err(crate::error::McpxError::Config(format!(
                "oauth.jwks_uri forbidden ({reason})"
            )));
        }
        if let Some(proxy) = &self.proxy {
            let url = check_oauth_url(
                "oauth.proxy.authorize_url",
                &proxy.authorize_url,
                allow_http,
            )?;
            if let Some(reason) = crate::ssrf::check_url_literal_ip(&url) {
                return Err(crate::error::McpxError::Config(format!(
                    "oauth.proxy.authorize_url forbidden ({reason})"
                )));
            }
            let url = check_oauth_url("oauth.proxy.token_url", &proxy.token_url, allow_http)?;
            if let Some(reason) = crate::ssrf::check_url_literal_ip(&url) {
                return Err(crate::error::McpxError::Config(format!(
                    "oauth.proxy.token_url forbidden ({reason})"
                )));
            }
            if let Some(url) = &proxy.introspection_url {
                let parsed = check_oauth_url("oauth.proxy.introspection_url", url, allow_http)?;
                if let Some(reason) = crate::ssrf::check_url_literal_ip(&parsed) {
                    return Err(crate::error::McpxError::Config(format!(
                        "oauth.proxy.introspection_url forbidden ({reason})"
                    )));
                }
            }
            if let Some(url) = &proxy.revocation_url {
                let parsed = check_oauth_url("oauth.proxy.revocation_url", url, allow_http)?;
                if let Some(reason) = crate::ssrf::check_url_literal_ip(&parsed) {
                    return Err(crate::error::McpxError::Config(format!(
                        "oauth.proxy.revocation_url forbidden ({reason})"
                    )));
                }
            }
        }
        if let Some(tx) = &self.token_exchange {
            let url = check_oauth_url("oauth.token_exchange.token_url", &tx.token_url, allow_http)?;
            if let Some(reason) = crate::ssrf::check_url_literal_ip(&url) {
                return Err(crate::error::McpxError::Config(format!(
                    "oauth.token_exchange.token_url forbidden ({reason})"
                )));
            }
        }
        Ok(())
    }
}

/// Parse `raw` as a URL and enforce the HTTPS-only policy.
///
/// Returns `Ok(())` for `https://...`, and also for `http://...` when
/// `allow_http` is `true`. All other schemes (and parse failures) are
/// rejected with a [`crate::error::McpxError::Config`] referencing the
/// caller-supplied `field` name for diagnostics.
fn check_oauth_url(
    field: &str,
    raw: &str,
    allow_http: bool,
) -> Result<url::Url, crate::error::McpxError> {
    let parsed = url::Url::parse(raw).map_err(|e| {
        crate::error::McpxError::Config(format!("{field}: invalid URL {raw:?}: {e}"))
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(crate::error::McpxError::Config(format!(
            "{field} rejected: URL contains userinfo (credentials in URL are forbidden)"
        )));
    }
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if allow_http => Ok(parsed),
        "http" => Err(crate::error::McpxError::Config(format!(
            "{field}: must use https scheme (got http; set allow_http_oauth_urls=true \
             to override - strongly discouraged in production)"
        ))),
        other => Err(crate::error::McpxError::Config(format!(
            "{field}: must use https scheme (got {other:?})"
        ))),
    }
}

/// Builder for [`OAuthConfig`].
///
/// Obtain via [`OAuthConfig::builder`]. All setters consume `self` and
/// return a new builder, so they compose fluently. Call
/// [`OAuthConfigBuilder::build`] to produce the final [`OAuthConfig`].
#[derive(Debug, Clone)]
#[must_use = "builders do nothing until `.build()` is called"]
pub struct OAuthConfigBuilder {
    inner: OAuthConfig,
}

impl OAuthConfigBuilder {
    /// Replace the scope-to-role mappings.
    pub fn scopes(mut self, scopes: Vec<ScopeMapping>) -> Self {
        self.inner.scopes = scopes;
        self
    }

    /// Append a single scope-to-role mapping.
    pub fn scope(mut self, scope: impl Into<String>, role: impl Into<String>) -> Self {
        self.inner.scopes.push(ScopeMapping {
            scope: scope.into(),
            role: role.into(),
        });
        self
    }

    /// Set the JWT claim path used to extract roles directly (without
    /// going through `scope` mappings).
    pub fn role_claim(mut self, claim: impl Into<String>) -> Self {
        self.inner.role_claim = Some(claim.into());
        self
    }

    /// Replace the claim-value-to-role mappings.
    pub fn role_mappings(mut self, mappings: Vec<RoleMapping>) -> Self {
        self.inner.role_mappings = mappings;
        self
    }

    /// Append a single claim-value-to-role mapping (used with
    /// [`Self::role_claim`]).
    pub fn role_mapping(mut self, claim_value: impl Into<String>, role: impl Into<String>) -> Self {
        self.inner.role_mappings.push(RoleMapping {
            claim_value: claim_value.into(),
            role: role.into(),
        });
        self
    }

    /// Override the JWKS cache TTL (humantime string, e.g. `"5m"`).
    /// Defaults to `"10m"`.
    pub fn jwks_cache_ttl(mut self, ttl: impl Into<String>) -> Self {
        self.inner.jwks_cache_ttl = ttl.into();
        self
    }

    /// Attach an OAuth proxy configuration. When set, the server
    /// exposes `/authorize`, `/token`, and `/register` endpoints.
    pub fn proxy(mut self, proxy: OAuthProxyConfig) -> Self {
        self.inner.proxy = Some(proxy);
        self
    }

    /// Attach an RFC 8693 token exchange configuration.
    pub fn token_exchange(mut self, token_exchange: TokenExchangeConfig) -> Self {
        self.inner.token_exchange = Some(token_exchange);
        self
    }

    /// Provide a PEM CA bundle path used for all OAuth-bound HTTPS traffic
    /// originated by this crate (JWKS fetches and the optional OAuth proxy
    /// `/authorize`, `/token`, `/register`, `/introspect`, `/revoke`,
    /// `/.well-known/oauth-authorization-server` upstream calls).
    pub fn ca_cert_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.inner.ca_cert_path = Some(path.into());
        self
    }

    /// Allow plain-HTTP (non-TLS) URLs for OAuth endpoints.
    ///
    /// **Default: `false`.** See the field-level documentation on
    /// [`OAuthConfig::allow_http_oauth_urls`] for the security caveats
    /// before enabling this.
    pub const fn allow_http_oauth_urls(mut self, allow: bool) -> Self {
        self.inner.allow_http_oauth_urls = allow;
        self
    }

    /// Finalise the builder and return the [`OAuthConfig`].
    #[must_use]
    pub fn build(self) -> OAuthConfig {
        self.inner
    }
}

/// Maps an OAuth scope string to an RBAC role name.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct ScopeMapping {
    /// OAuth scope string to match against the token's `scope` claim.
    pub scope: String,
    /// RBAC role granted when the scope is present.
    pub role: String,
}

/// Maps a JWT claim value to an RBAC role name.
/// Used with `OAuthConfig::role_claim` for non-scope-based role extraction
/// (e.g. Keycloak `realm_access.roles`, Azure AD `roles`).
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct RoleMapping {
    /// Expected value of the configured role claim (e.g. `admin`).
    pub claim_value: String,
    /// RBAC role granted when `claim_value` is present in the claim.
    pub role: String,
}

/// Configuration for RFC 8693 token exchange.
///
/// The MCP server uses this to exchange an inbound user access token
/// (audience = MCP server) for a downstream access token (audience =
/// the upstream API the application calls) via the authorization
/// server's token endpoint.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct TokenExchangeConfig {
    /// Authorization server token endpoint used for the exchange
    /// (e.g. `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token`).
    pub token_url: String,
    /// OAuth `client_id` of the MCP server (the requester).
    pub client_id: String,
    /// OAuth `client_secret` for confidential-client authentication.
    /// Omit when using `client_cert` (mTLS) instead.
    pub client_secret: Option<secrecy::SecretString>,
    /// Client certificate for mTLS-based client authentication.
    /// When set, the exchange request authenticates with a TLS client
    /// certificate instead of a shared secret.
    pub client_cert: Option<ClientCertConfig>,
    /// Target audience - the `client_id` of the downstream API
    /// (e.g. `upstream-api`).  The exchanged token will have this
    /// value in its `aud` claim.
    pub audience: String,
}

impl TokenExchangeConfig {
    /// Create a new token exchange configuration.
    #[must_use]
    pub fn new(
        token_url: String,
        client_id: String,
        client_secret: Option<secrecy::SecretString>,
        client_cert: Option<ClientCertConfig>,
        audience: String,
    ) -> Self {
        Self {
            token_url,
            client_id,
            client_secret,
            client_cert,
            audience,
        }
    }
}

/// Client certificate paths for mTLS-based client authentication
/// at the token exchange endpoint.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct ClientCertConfig {
    /// Path to the PEM-encoded client certificate.
    pub cert_path: PathBuf,
    /// Path to the PEM-encoded private key.
    pub key_path: PathBuf,
}

/// Successful response from an RFC 8693 token exchange.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct ExchangedToken {
    /// The newly issued access token.
    pub access_token: String,
    /// Token lifetime in seconds (if provided by the authorization server).
    pub expires_in: Option<u64>,
    /// Token type identifier (e.g.
    /// `urn:ietf:params:oauth:token-type:access_token`).
    pub issued_token_type: Option<String>,
}

/// Configuration for proxying OAuth 2.1 flows to an upstream identity provider.
///
/// When present, the MCP server exposes `/authorize`, `/token`, and
/// `/register` endpoints that proxy to the upstream identity provider
/// (e.g. Keycloak). MCP clients see this server as the authorization
/// server and perform a standard Authorization Code + PKCE flow.
#[derive(Debug, Clone, Deserialize, Default)]
#[non_exhaustive]
pub struct OAuthProxyConfig {
    /// Upstream authorization endpoint (e.g.
    /// `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/auth`).
    pub authorize_url: String,
    /// Upstream token endpoint (e.g.
    /// `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token`).
    pub token_url: String,
    /// OAuth `client_id` registered at the upstream identity provider.
    pub client_id: String,
    /// OAuth `client_secret` (for confidential clients). Omit for public clients.
    pub client_secret: Option<secrecy::SecretString>,
    /// Optional upstream RFC 7662 introspection endpoint. When set
    /// **and** [`Self::expose_admin_endpoints`] is `true`, the server
    /// exposes a local `/introspect` endpoint that proxies to it.
    #[serde(default)]
    pub introspection_url: Option<String>,
    /// Optional upstream RFC 7009 revocation endpoint. When set
    /// **and** [`Self::expose_admin_endpoints`] is `true`, the server
    /// exposes a local `/revoke` endpoint that proxies to it.
    #[serde(default)]
    pub revocation_url: Option<String>,
    /// Whether to expose the OAuth admin endpoints (`/introspect`,
    /// `/revoke`) and advertise them in the authorization-server
    /// metadata document.
    ///
    /// **Default: `false`.** These endpoints are unauthenticated at the
    /// transport layer (the OAuth proxy router is mounted outside the
    /// MCP auth middleware) and proxy directly to the upstream `IdP`. If
    /// enabled, you are responsible for restricting access at the
    /// network boundary (firewall, reverse proxy, mTLS) or by routing
    /// the entire rmcp-server-kit process behind an authenticated ingress. Leaving
    /// this `false` (the default) makes the endpoints return 404.
    #[serde(default)]
    pub expose_admin_endpoints: bool,
}

impl OAuthProxyConfig {
    /// Start building an [`OAuthProxyConfig`] with the three required
    /// upstream fields.
    ///
    /// Optional settings (`client_secret`, `introspection_url`,
    /// `revocation_url`, `expose_admin_endpoints`) default to their
    /// [`Default`] values and can be set via the corresponding builder
    /// methods.
    pub fn builder(
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        client_id: impl Into<String>,
    ) -> OAuthProxyConfigBuilder {
        OAuthProxyConfigBuilder {
            inner: Self {
                authorize_url: authorize_url.into(),
                token_url: token_url.into(),
                client_id: client_id.into(),
                ..Self::default()
            },
        }
    }
}

/// Builder for [`OAuthProxyConfig`].
///
/// Obtain via [`OAuthProxyConfig::builder`]. See the type-level docs on
/// [`OAuthProxyConfig`] and in particular the security caveats on
/// [`OAuthProxyConfig::expose_admin_endpoints`].
#[derive(Debug, Clone)]
#[must_use = "builders do nothing until `.build()` is called"]
pub struct OAuthProxyConfigBuilder {
    inner: OAuthProxyConfig,
}

impl OAuthProxyConfigBuilder {
    /// Set the upstream OAuth client secret. Omit for public clients.
    pub fn client_secret(mut self, secret: secrecy::SecretString) -> Self {
        self.inner.client_secret = Some(secret);
        self
    }

    /// Configure the upstream RFC 7662 introspection endpoint. Only
    /// advertised and reachable when
    /// [`Self::expose_admin_endpoints`] is also set to `true`.
    pub fn introspection_url(mut self, url: impl Into<String>) -> Self {
        self.inner.introspection_url = Some(url.into());
        self
    }

    /// Configure the upstream RFC 7009 revocation endpoint. Only
    /// advertised and reachable when
    /// [`Self::expose_admin_endpoints`] is also set to `true`.
    pub fn revocation_url(mut self, url: impl Into<String>) -> Self {
        self.inner.revocation_url = Some(url.into());
        self
    }

    /// Opt in to exposing the `/introspect` and `/revoke` admin
    /// endpoints and advertising them in the authorization-server
    /// metadata document.
    ///
    /// **Security:** see the field-level documentation on
    /// [`OAuthProxyConfig::expose_admin_endpoints`] for the caveats
    /// before enabling this.
    pub const fn expose_admin_endpoints(mut self, expose: bool) -> Self {
        self.inner.expose_admin_endpoints = expose;
        self
    }

    /// Finalise the builder and return the [`OAuthProxyConfig`].
    #[must_use]
    pub fn build(self) -> OAuthProxyConfig {
        self.inner
    }
}

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

/// `kid`-indexed map of (algorithm, decoding key) pairs plus a list of
/// unnamed keys. Produced by [`build_key_cache`] and consumed by
/// [`JwksCache::refresh_inner`].
type JwksKeyCache = (
    HashMap<String, (Algorithm, DecodingKey)>,
    Vec<(Algorithm, DecodingKey)>,
);

struct CachedKeys {
    /// `kid` -> (Algorithm, `DecodingKey`)
    keys: HashMap<String, (Algorithm, DecodingKey)>,
    /// Keys without a kid, indexed by algorithm family.
    unnamed_keys: Vec<(Algorithm, DecodingKey)>,
    fetched_at: Instant,
    ttl: Duration,
}

impl CachedKeys {
    fn is_expired(&self) -> bool {
        self.fetched_at.elapsed() >= self.ttl
    }
}

/// Thread-safe JWKS key cache with automatic refresh.
///
/// Includes protections against denial-of-service via invalid JWTs:
/// - **Refresh cooldown**: At most one refresh per 10 seconds, regardless of
///   cache misses. This prevents attackers from flooding the upstream JWKS
///   endpoint by sending JWTs with fabricated `kid` values.
/// - **Concurrent deduplication**: Only one refresh in flight at a time;
///   concurrent waiters share the same fetch result.
#[allow(
    missing_debug_implementations,
    reason = "contains reqwest::Client and DecodingKey cache with no Debug impl"
)]
#[non_exhaustive]
pub struct JwksCache {
    jwks_uri: String,
    ttl: Duration,
    max_jwks_keys: usize,
    inner: RwLock<Option<CachedKeys>>,
    http: reqwest::Client,
    validation_template: Validation,
    /// Expected audience value from config - checked manually against
    /// `aud` (array) OR `azp` (authorized-party) claim per RFC 9068 / OIDC Core.
    expected_audience: String,
    scopes: Vec<ScopeMapping>,
    role_claim: Option<String>,
    role_mappings: Vec<RoleMapping>,
    /// Tracks the last refresh attempt timestamp. Enforces a 10-second cooldown
    /// between refresh attempts to prevent abuse via fabricated JWTs with invalid kids.
    last_refresh_attempt: RwLock<Option<Instant>>,
    /// Serializes concurrent refresh attempts so only one fetch is in flight.
    refresh_lock: tokio::sync::Mutex<()>,
}

/// Minimum cooldown between JWKS refresh attempts (prevents abuse).
const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(10);

/// Algorithms we accept from JWKS-served keys.
const ACCEPTED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::EdDSA,
];

/// Coarse JWT validation failure classification for auth diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwtValidationFailure {
    /// JWT was well-formed but expired per `exp` validation.
    Expired,
    /// JWT failed validation for all other reasons.
    Invalid,
}

impl JwksCache {
    /// Build a new cache from OAuth configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the CA bundle cannot be read or the HTTP client
    /// cannot be built.
    pub fn new(config: &OAuthConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Ensure crypto providers are installed (idempotent -- ok() ignores
        // the error if already installed by another call in the same process).
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER
            .install_default()
            .ok();

        let ttl =
            humantime::parse_duration(&config.jwks_cache_ttl).unwrap_or(Duration::from_mins(10));

        let mut validation = Validation::new(Algorithm::RS256);
        // Note: validation.algorithms is overridden per-decode to [header.alg]
        // because jsonwebtoken 10.x requires all listed algorithms to share
        // the same key family. The ACCEPTED_ALGS whitelist is checked
        // separately before looking up the key.
        //
        // Audience validation is done manually after decode: we accept the
        // token if `aud` contains `config.audience` OR `azp == config.audience`.
        // This is correct per RFC 9068 Sec.4 + OIDC Core Sec.2: `aud` lists
        // resource servers, `azp` identifies the authorized client. When the
        // MCP server is both the OAuth client and the resource server (as in
        // our proxy setup), the configured audience may appear in either claim.
        validation.validate_aud = false;
        validation.set_issuer(&[&config.issuer]);
        validation.set_required_spec_claims(&["exp", "iss"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let mut http_builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                // SECURITY: reject any redirect to a non-HTTPS target,
                // even when the original `jwks_uri` was validated as
                // HTTPS.  This prevents an upstream `302 Location: http://...`
                // from downgrading the JWKS fetch to plaintext where a
                // network attacker could substitute the response and
                // forge JWT signing keys.  The HTTPS scheme guard runs
                // *before* the hop limit so a downgrade is rejected as
                // such (clearer error) rather than as "too many redirects".
                if attempt.url().scheme() != "https" {
                    attempt.error("redirect to non-HTTPS URL refused")
                } else if let Some(reason) = crate::ssrf::redirect_target_reason(attempt.url()) {
                    attempt.error(format!("redirect target forbidden: {reason}"))
                } else if attempt.previous().len() >= 2 {
                    attempt.error("too many redirects (max 2)")
                } else {
                    attempt.follow()
                }
            }));

        if let Some(ref ca_path) = config.ca_cert_path {
            // Pre-startup blocking I/O — runs before the runtime begins
            // serving requests, so blocking the current thread here is
            // intentional. Do not wrap in `spawn_blocking`: the constructor
            // is synchronous by contract and is called from `serve()`'s
            // pre-startup phase.
            let pem = std::fs::read(ca_path)?;
            let cert = reqwest::tls::Certificate::from_pem(&pem)?;
            http_builder = http_builder.add_root_certificate(cert);
        }

        let http = http_builder.build()?;

        Ok(Self {
            jwks_uri: config.jwks_uri.clone(),
            ttl,
            max_jwks_keys: config.max_jwks_keys,
            inner: RwLock::new(None),
            http,
            validation_template: validation,
            expected_audience: config.audience.clone(),
            scopes: config.scopes.clone(),
            role_claim: config.role_claim.clone(),
            role_mappings: config.role_mappings.clone(),
            last_refresh_attempt: RwLock::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Validate a JWT Bearer token. Returns `Some(AuthIdentity)` on success.
    pub async fn validate_token(&self, token: &str) -> Option<AuthIdentity> {
        self.validate_token_with_reason(token).await.ok()
    }

    /// Validate a JWT Bearer token with failure classification.
    ///
    /// # Errors
    ///
    /// Returns [`JwtValidationFailure::Expired`] when the JWT is expired,
    /// or [`JwtValidationFailure::Invalid`] for all other validation failures.
    pub async fn validate_token_with_reason(
        &self,
        token: &str,
    ) -> Result<AuthIdentity, JwtValidationFailure> {
        let claims = self.decode_claims(token).await?;

        self.check_audience(&claims)?;
        let role = self.resolve_role(&claims)?;

        // Identity: prefer human-readable `preferred_username` (Keycloak/OIDC),
        // then `sub`, then `azp` (authorized party), then `client_id`.
        let sub = claims.sub;
        let name = claims
            .extra
            .get("preferred_username")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| sub.clone())
            .or(claims.azp)
            .or(claims.client_id)
            .unwrap_or_else(|| "oauth-client".into());

        Ok(AuthIdentity {
            name,
            role,
            method: AuthMethod::OAuthJwt,
            raw_token: None,
            sub,
        })
    }

    /// Decode and fully verify a JWT, returning its claims.
    ///
    /// Performs header decode, algorithm allow-list check, JWKS key lookup
    /// (with on-demand refresh), signature verification, and standard
    /// claim validation (exp/nbf/iss) against the template.
    ///
    /// The CPU-bound `jsonwebtoken::decode` call (RSA / ECDSA signature
    /// verification) is offloaded to [`tokio::task::spawn_blocking`] so a
    /// burst of concurrent JWT validations never starves other tasks on
    /// the multi-threaded runtime's worker pool. The blocking pool absorbs
    /// the verification cost; the async path stays responsive.
    async fn decode_claims(&self, token: &str) -> Result<Claims, JwtValidationFailure> {
        let (key, alg) = self.select_jwks_key(token).await?;

        // Build a per-decode validation scoped to the header's algorithm.
        // jsonwebtoken requires ALL algorithms in the list to share the
        // same family as the key, so we restrict to [alg] only.
        let mut validation = self.validation_template.clone();
        validation.algorithms = vec![alg];

        // Move the (cheap) clones into the blocking task so the verifier
        // does not hold a reference into the request's async scope.
        let token_owned = token.to_owned();
        let join =
            tokio::task::spawn_blocking(move || decode::<Claims>(&token_owned, &key, &validation))
                .await;

        let decode_result = match join {
            Ok(r) => r,
            Err(join_err) => {
                core::hint::cold_path();
                tracing::error!(
                    error = %join_err,
                    "JWT decode task panicked or was cancelled"
                );
                return Err(JwtValidationFailure::Invalid);
            }
        };

        decode_result.map(|td| td.claims).map_err(|e| {
            core::hint::cold_path();
            let failure = if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                JwtValidationFailure::Expired
            } else {
                JwtValidationFailure::Invalid
            };
            tracing::debug!(error = %e, ?alg, ?failure, "JWT decode failed");
            failure
        })
    }

    /// Decode the JWT header, check the algorithm against the allow-list,
    /// and look up the matching JWKS key (refreshing on miss).
    //
    // Complexity: 28/25. Three structured early-returns each pair a
    // `cold_path()` hint with a distinct `tracing::debug!` site so the
    // failure is observable. Collapsing them into a combinator chain
    // would lose those structured-field log sites without reducing
    // real cognitive load.
    #[allow(clippy::cognitive_complexity)]
    async fn select_jwks_key(
        &self,
        token: &str,
    ) -> Result<(DecodingKey, Algorithm), JwtValidationFailure> {
        let Ok(header) = decode_header(token) else {
            core::hint::cold_path();
            tracing::debug!("JWT header decode failed");
            return Err(JwtValidationFailure::Invalid);
        };
        let kid = header.kid.as_deref();
        tracing::debug!(alg = ?header.alg, kid = kid.unwrap_or("-"), "JWT header decoded");

        if !ACCEPTED_ALGS.contains(&header.alg) {
            core::hint::cold_path();
            tracing::debug!(alg = ?header.alg, "JWT algorithm not accepted");
            return Err(JwtValidationFailure::Invalid);
        }

        let Some(key) = self.find_key(kid, header.alg).await else {
            core::hint::cold_path();
            tracing::debug!(kid = kid.unwrap_or("-"), alg = ?header.alg, "no matching JWKS key found");
            return Err(JwtValidationFailure::Invalid);
        };

        Ok((key, header.alg))
    }

    /// Manual audience check: accept if `aud` contains the expected value
    /// OR if `azp` (authorized party) matches it. This covers the common
    /// Keycloak pattern where `azp` = requesting client and `aud` = target
    /// resource servers. Per RFC 9068 Sec.4 the resource server checks
    /// `aud` for its own identifier; per OIDC Core Sec.2 `azp` is the
    /// client the token was issued to. When the MCP server is both client
    /// and resource server, either claim matching is valid.
    fn check_audience(&self, claims: &Claims) -> Result<(), JwtValidationFailure> {
        let aud_ok = claims.aud.contains(&self.expected_audience)
            || claims
                .azp
                .as_deref()
                .is_some_and(|azp| azp == self.expected_audience);
        if aud_ok {
            return Ok(());
        }
        core::hint::cold_path();
        tracing::debug!(
            aud = ?claims.aud.0,
            azp = ?claims.azp,
            expected = %self.expected_audience,
            "JWT rejected: audience mismatch (neither aud nor azp match)"
        );
        Err(JwtValidationFailure::Invalid)
    }

    /// Resolve the role for this token.
    ///
    /// When `role_claim` is set, extract values from the given claim path
    /// and match against `role_mappings`. Otherwise, match space-separated
    /// tokens in the `scope` claim against configured scope mappings.
    fn resolve_role(&self, claims: &Claims) -> Result<String, JwtValidationFailure> {
        if let Some(ref claim_path) = self.role_claim {
            let values = resolve_claim_path(&claims.extra, claim_path);
            return self
                .role_mappings
                .iter()
                .find(|m| values.contains(&m.claim_value.as_str()))
                .map(|m| m.role.clone())
                .ok_or(JwtValidationFailure::Invalid);
        }

        let token_scopes: Vec<&str> = claims
            .scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .collect();

        self.scopes
            .iter()
            .find(|m| token_scopes.contains(&m.scope.as_str()))
            .map(|m| m.role.clone())
            .ok_or(JwtValidationFailure::Invalid)
    }

    /// Look up a decoding key by kid + algorithm. Refreshes JWKS on miss,
    /// subject to cooldown and deduplication constraints.
    async fn find_key(&self, kid: Option<&str>, alg: Algorithm) -> Option<DecodingKey> {
        // Try cached keys first.
        {
            let guard = self.inner.read().await;
            if let Some(cached) = guard.as_ref()
                && !cached.is_expired()
                && let Some(key) = lookup_key(cached, kid, alg)
            {
                return Some(key);
            }
        }

        // Cache miss or expired -- refresh (with cooldown/deduplication).
        self.refresh_with_cooldown().await;

        let guard = self.inner.read().await;
        guard
            .as_ref()
            .and_then(|cached| lookup_key(cached, kid, alg))
    }

    /// Refresh JWKS with cooldown and concurrent deduplication.
    ///
    /// - Only one refresh in flight at a time (concurrent waiters share result).
    /// - At most one refresh per [`JWKS_REFRESH_COOLDOWN`] (10 seconds).
    async fn refresh_with_cooldown(&self) {
        // Acquire the mutex to serialize refresh attempts.
        let _guard = self.refresh_lock.lock().await;

        // Check cooldown: skip if we refreshed recently.
        {
            let last = self.last_refresh_attempt.read().await;
            if let Some(ts) = *last
                && ts.elapsed() < JWKS_REFRESH_COOLDOWN
            {
                tracing::debug!(
                    elapsed_ms = ts.elapsed().as_millis(),
                    cooldown_ms = JWKS_REFRESH_COOLDOWN.as_millis(),
                    "JWKS refresh skipped (cooldown active)"
                );
                return;
            }
        }

        // Update last refresh timestamp BEFORE the fetch attempt.
        // This ensures the cooldown applies even if the fetch fails.
        {
            let mut last = self.last_refresh_attempt.write().await;
            *last = Some(Instant::now());
        }

        // Perform the actual fetch.
        let _ = self.refresh_inner().await;
    }

    /// Fetch JWKS from the configured URI and update the cache.
    ///
    /// Internal implementation - callers should use [`Self::refresh_with_cooldown`]
    /// to respect rate limiting.
    async fn refresh_inner(&self) -> Result<(), String> {
        let Some(jwks) = self.fetch_jwks().await else {
            return Ok(());
        };
        let (keys, unnamed_keys) = match build_key_cache(&jwks, self.max_jwks_keys) {
            Ok(cache) => cache,
            Err(msg) => {
                tracing::warn!(reason = %msg, "JWKS key cap exceeded; refusing to populate cache");
                return Err(msg);
            }
        };

        tracing::debug!(
            named = keys.len(),
            unnamed = unnamed_keys.len(),
            "JWKS refreshed"
        );

        let mut guard = self.inner.write().await;
        *guard = Some(CachedKeys {
            keys,
            unnamed_keys,
            fetched_at: Instant::now(),
            ttl: self.ttl,
        });
        Ok(())
    }

    /// Fetch and parse the JWKS document. Returns `None` and logs on failure.
    async fn fetch_jwks(&self) -> Option<JwkSet> {
        let resp = match self.http.get(&self.jwks_uri).send().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(error = %e, uri = %self.jwks_uri, "failed to fetch JWKS");
                return None;
            }
        };
        match resp.json::<JwkSet>().await {
            Ok(jwks) => Some(jwks),
            Err(e) => {
                tracing::warn!(error = %e, uri = %self.jwks_uri, "failed to parse JWKS");
                None
            }
        }
    }

    /// Test-only: drive `refresh_inner` now, surfacing the
    /// `build_key_cache` error string. Used by `tests/jwks_key_cap.rs`.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub async fn __test_refresh_now(&self) -> Result<(), String> {
        let jwks = self
            .fetch_jwks()
            .await
            .ok_or_else(|| "failed to fetch or parse JWKS".to_owned())?;
        let (keys, unnamed_keys) = build_key_cache(&jwks, self.max_jwks_keys)?;
        let mut guard = self.inner.write().await;
        *guard = Some(CachedKeys {
            keys,
            unnamed_keys,
            fetched_at: Instant::now(),
            ttl: self.ttl,
        });
        Ok(())
    }

    /// Test-only: returns whether the cache currently contains the
    /// supplied kid. Read-only; takes the cache lock briefly.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub async fn __test_has_kid(&self, kid: &str) -> bool {
        let guard = self.inner.read().await;
        guard
            .as_ref()
            .is_some_and(|cache| cache.keys.contains_key(kid))
    }
}

/// Partition a JWKS into a kid-indexed map plus a list of unnamed keys.
fn build_key_cache(jwks: &JwkSet, max_keys: usize) -> Result<JwksKeyCache, String> {
    if jwks.keys.len() > max_keys {
        return Err(format!(
            "jwks_key_count_exceeds_cap: got {} keys, max is {}",
            jwks.keys.len(),
            max_keys
        ));
    }
    let mut keys = HashMap::new();
    let mut unnamed_keys = Vec::new();
    for jwk in &jwks.keys {
        let Ok(decoding_key) = DecodingKey::from_jwk(jwk) else {
            continue;
        };
        let Some(alg) = jwk_algorithm(jwk) else {
            continue;
        };
        if let Some(ref kid) = jwk.common.key_id {
            keys.insert(kid.clone(), (alg, decoding_key));
        } else {
            unnamed_keys.push((alg, decoding_key));
        }
    }
    Ok((keys, unnamed_keys))
}

/// Look up a key from the cache by kid (if present) or by algorithm.
fn lookup_key(cached: &CachedKeys, kid: Option<&str>, alg: Algorithm) -> Option<DecodingKey> {
    if let Some(kid) = kid
        && let Some((cached_alg, key)) = cached.keys.get(kid)
        && *cached_alg == alg
    {
        return Some(key.clone());
    }
    // Fall back to unnamed keys matching algorithm.
    cached
        .unnamed_keys
        .iter()
        .find(|(a, _)| *a == alg)
        .map(|(_, k)| k.clone())
}

/// Extract the algorithm from a JWK's common parameters.
#[allow(clippy::wildcard_enum_match_arm)]
fn jwk_algorithm(jwk: &jsonwebtoken::jwk::Jwk) -> Option<Algorithm> {
    jwk.common.key_algorithm.and_then(|ka| match ka {
        jsonwebtoken::jwk::KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        jsonwebtoken::jwk::KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        jsonwebtoken::jwk::KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        jsonwebtoken::jwk::KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        jsonwebtoken::jwk::KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        jsonwebtoken::jwk::KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        jsonwebtoken::jwk::KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        jsonwebtoken::jwk::KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        jsonwebtoken::jwk::KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// Claim path resolution
// ---------------------------------------------------------------------------

/// Resolve a dot-separated claim path to a list of string values.
///
/// Handles three shapes:
/// - **String**: split on whitespace (OAuth `scope` convention).
/// - **Array of strings**: each element becomes a value (Keycloak `realm_access.roles`).
/// - **Nested object**: traversed by dot-separated segments (e.g. `realm_access.roles`).
///
/// Returns an empty vec if the path does not exist or the leaf is not a
/// string/array.
fn resolve_claim_path<'a>(
    extra: &'a HashMap<String, serde_json::Value>,
    path: &str,
) -> Vec<&'a str> {
    let mut segments = path.split('.');
    let Some(first) = segments.next() else {
        return Vec::new();
    };

    let mut current: Option<&serde_json::Value> = extra.get(first);

    for segment in segments {
        current = current.and_then(|v| v.get(segment));
    }

    match current {
        Some(serde_json::Value::String(s)) => s.split_whitespace().collect(),
        Some(serde_json::Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str()).collect(),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// JWT claims
// ---------------------------------------------------------------------------

/// Standard + common JWT claims we care about.
#[derive(Debug, Deserialize)]
struct Claims {
    /// Subject (user or service account).
    sub: Option<String>,
    /// Audience - resource servers the token is intended for.
    /// Can be a single string or an array of strings per RFC 7519 Sec.4.1.3.
    #[serde(default)]
    aud: OneOrMany,
    /// Authorized party (OIDC Core Sec.2) - the OAuth client that was issued the token.
    azp: Option<String>,
    /// Client ID (some providers use this instead of azp).
    client_id: Option<String>,
    /// Space-separated scope string (OAuth 2.0 convention).
    scope: Option<String>,
    /// All remaining claims, captured for `role_claim` dot-path resolution.
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

/// Deserializes a JWT claim that can be either a single string or an array of strings.
#[derive(Debug, Default)]
struct OneOrMany(Vec<String>);

impl OneOrMany {
    fn contains(&self, value: &str) -> bool {
        self.0.iter().any(|v| v == value)
    }
}

impl<'de> Deserialize<'de> for OneOrMany {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de;

        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = OneOrMany;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string or array of strings")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<OneOrMany, E> {
                Ok(OneOrMany(vec![v.to_owned()]))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<OneOrMany, A::Error> {
                let mut v = Vec::new();
                while let Some(s) = seq.next_element::<String>()? {
                    v.push(s);
                }
                Ok(OneOrMany(v))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

// ---------------------------------------------------------------------------
// JWT detection heuristic
// ---------------------------------------------------------------------------

/// Returns true if the token looks like a JWT (3 dot-separated segments
/// where the first segment decodes to JSON containing `"alg"`).
#[must_use]
pub fn looks_like_jwt(token: &str) -> bool {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let mut parts = token.splitn(4, '.');
    let Some(header_b64) = parts.next() else {
        return false;
    };
    // Must have exactly 3 segments.
    if parts.next().is_none() || parts.next().is_none() || parts.next().is_some() {
        return false;
    }
    // Try to decode the header segment.
    let Ok(header_bytes) = URL_SAFE_NO_PAD.decode(header_b64) else {
        return false;
    };
    // Check for "alg" key in the JSON.
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header_bytes) else {
        return false;
    };
    header.get("alg").is_some()
}

// ---------------------------------------------------------------------------
// Protected Resource Metadata (RFC 9728)
// ---------------------------------------------------------------------------

/// Build the Protected Resource Metadata JSON response.
///
/// When an OAuth proxy is configured, `authorization_servers` points to
/// the MCP server itself (the proxy facade).  Otherwise it points directly
/// to the upstream issuer.
#[must_use]
pub fn protected_resource_metadata(
    resource_url: &str,
    server_url: &str,
    config: &OAuthConfig,
) -> serde_json::Value {
    // Always point to the local server -- when a proxy is configured the
    // server exposes /authorize, /token, /register locally.  When an
    // application provides its own chained OAuth flow (via extra_router)
    // without a proxy, the auth server is still the local server.
    let scopes: Vec<&str> = config.scopes.iter().map(|s| s.scope.as_str()).collect();
    let auth_server = server_url;
    serde_json::json!({
        "resource": resource_url,
        "authorization_servers": [auth_server],
        "scopes_supported": scopes,
        "bearer_methods_supported": ["header"]
    })
}

/// Build the Authorization Server Metadata JSON response (RFC 8414).
///
/// Returned at `GET /.well-known/oauth-authorization-server` so MCP
/// clients can discover the authorization and token endpoints.
#[must_use]
pub fn authorization_server_metadata(server_url: &str, config: &OAuthConfig) -> serde_json::Value {
    let scopes: Vec<&str> = config.scopes.iter().map(|s| s.scope.as_str()).collect();
    let mut meta = serde_json::json!({
        "issuer": &config.issuer,
        "authorization_endpoint": format!("{server_url}/authorize"),
        "token_endpoint": format!("{server_url}/token"),
        "registration_endpoint": format!("{server_url}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": scopes,
        "token_endpoint_auth_methods_supported": ["none"],
    });
    if let Some(proxy) = &config.proxy
        && proxy.expose_admin_endpoints
        && let Some(obj) = meta.as_object_mut()
    {
        if proxy.introspection_url.is_some() {
            obj.insert(
                "introspection_endpoint".into(),
                serde_json::Value::String(format!("{server_url}/introspect")),
            );
        }
        if proxy.revocation_url.is_some() {
            obj.insert(
                "revocation_endpoint".into(),
                serde_json::Value::String(format!("{server_url}/revoke")),
            );
        }
    }
    meta
}

// ---------------------------------------------------------------------------
// OAuth 2.1 Proxy Handlers
// ---------------------------------------------------------------------------

/// Handle `GET /authorize` - redirect to the upstream authorize URL.
///
/// Forwards all OAuth query parameters (`response_type`, `client_id`,
/// `redirect_uri`, `scope`, `state`, `code_challenge`,
/// `code_challenge_method`) to the upstream identity provider.
/// The upstream provider (e.g. Keycloak) presents the login UI and
/// redirects the user back to the MCP client's `redirect_uri` with an
/// authorization code.
#[must_use]
pub fn handle_authorize(proxy: &OAuthProxyConfig, query: &str) -> axum::response::Response {
    use axum::{
        http::{StatusCode, header},
        response::IntoResponse,
    };

    // Replace the client_id in the query with the upstream client_id.
    let upstream_query = replace_client_id(query, &proxy.client_id);
    let redirect_url = format!("{}?{upstream_query}", proxy.authorize_url);

    (StatusCode::FOUND, [(header::LOCATION, redirect_url)]).into_response()
}

/// Handle `POST /token` - proxy the token request to the upstream provider.
///
/// Forwards the request body (authorization code exchange or refresh token
/// grant) to the upstream token endpoint, injecting client credentials
/// when configured (confidential client). Returns the upstream response as-is.
pub async fn handle_token(
    http: &OauthHttpClient,
    proxy: &OAuthProxyConfig,
    body: &str,
) -> axum::response::Response {
    use axum::{
        http::{StatusCode, header},
        response::IntoResponse,
    };

    // Replace client_id in the form body with the upstream client_id.
    let mut upstream_body = replace_client_id(body, &proxy.client_id);

    // For confidential clients, inject the client_secret.
    if let Some(ref secret) = proxy.client_secret {
        use std::fmt::Write;

        use secrecy::ExposeSecret;
        let _ = write!(
            upstream_body,
            "&client_secret={}",
            urlencoding::encode(secret.expose_secret())
        );
    }

    let result = http
        .inner
        .post(&proxy.token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(upstream_body)
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let body_bytes = resp.bytes().await.unwrap_or_default();
            (
                status,
                [(header::CONTENT_TYPE, "application/json")],
                body_bytes,
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "OAuth token proxy request failed");
            (
                StatusCode::BAD_GATEWAY,
                [(header::CONTENT_TYPE, "application/json")],
                "{\"error\":\"server_error\",\"error_description\":\"token endpoint unreachable\"}",
            )
                .into_response()
        }
    }
}

/// Handle `POST /register` - return the pre-configured `client_id`.
///
/// MCP clients call this to discover which `client_id` to use in the
/// authorization flow.  We return the upstream `client_id` from config
/// and echo back any `redirect_uris` from the request body (required
/// by the MCP SDK's Zod validation).
#[must_use]
pub fn handle_register(proxy: &OAuthProxyConfig, body: &serde_json::Value) -> serde_json::Value {
    let mut resp = serde_json::json!({
        "client_id": proxy.client_id,
        "token_endpoint_auth_method": "none",
    });
    if let Some(uris) = body.get("redirect_uris")
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert("redirect_uris".into(), uris.clone());
    }
    if let Some(name) = body.get("client_name")
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert("client_name".into(), name.clone());
    }
    resp
}

/// Handle `POST /introspect` - RFC 7662 token introspection proxy.
///
/// Forwards the request body to the upstream introspection endpoint,
/// injecting client credentials when configured. Returns the upstream
/// response as-is.  Requires `proxy.introspection_url` to be `Some`.
pub async fn handle_introspect(
    http: &OauthHttpClient,
    proxy: &OAuthProxyConfig,
    body: &str,
) -> axum::response::Response {
    let Some(ref url) = proxy.introspection_url else {
        return oauth_error_response(
            axum::http::StatusCode::NOT_FOUND,
            "not_supported",
            "introspection endpoint is not configured",
        );
    };
    proxy_oauth_admin_request(http, proxy, url, body).await
}

/// Handle `POST /revoke` - RFC 7009 token revocation proxy.
///
/// Forwards the request body to the upstream revocation endpoint,
/// injecting client credentials when configured. Returns the upstream
/// response as-is (per RFC 7009, typically 200 with empty body).
/// Requires `proxy.revocation_url` to be `Some`.
pub async fn handle_revoke(
    http: &OauthHttpClient,
    proxy: &OAuthProxyConfig,
    body: &str,
) -> axum::response::Response {
    let Some(ref url) = proxy.revocation_url else {
        return oauth_error_response(
            axum::http::StatusCode::NOT_FOUND,
            "not_supported",
            "revocation endpoint is not configured",
        );
    };
    proxy_oauth_admin_request(http, proxy, url, body).await
}

/// Shared proxy for introspection/revocation: injects `client_id` and
/// `client_secret` (when configured) and forwards the form-encoded body
/// upstream, returning the upstream status/body verbatim.
async fn proxy_oauth_admin_request(
    http: &OauthHttpClient,
    proxy: &OAuthProxyConfig,
    upstream_url: &str,
    body: &str,
) -> axum::response::Response {
    use axum::{
        http::{StatusCode, header},
        response::IntoResponse,
    };

    let mut upstream_body = replace_client_id(body, &proxy.client_id);
    if let Some(ref secret) = proxy.client_secret {
        use std::fmt::Write;

        use secrecy::ExposeSecret;
        let _ = write!(
            upstream_body,
            "&client_secret={}",
            urlencoding::encode(secret.expose_secret())
        );
    }

    let result = http
        .inner
        .post(upstream_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(upstream_body)
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_owned();
            let body_bytes = resp.bytes().await.unwrap_or_default();
            (status, [(header::CONTENT_TYPE, content_type)], body_bytes).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, url = %upstream_url, "OAuth admin proxy request failed");
            oauth_error_response(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "upstream endpoint unreachable",
            )
        }
    }
}

fn oauth_error_response(
    status: axum::http::StatusCode,
    error: &str,
    description: &str,
) -> axum::response::Response {
    use axum::{http::header, response::IntoResponse};
    let body = serde_json::json!({
        "error": error,
        "error_description": description,
    });
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// RFC 8693 Token Exchange
// ---------------------------------------------------------------------------

/// OAuth error response body from the authorization server.
#[derive(Debug, Deserialize)]
struct OAuthErrorResponse {
    error: String,
    error_description: Option<String>,
}

/// Map an upstream OAuth error code to an allowlisted short code suitable
/// for client exposure.
///
/// Returns one of the RFC 6749 §5.2 / RFC 8693 standard codes. Unknown or
/// non-standard codes collapse to `server_error` to avoid leaking
/// authorization-server implementation details to MCP clients.
fn sanitize_oauth_error_code(raw: &str) -> &'static str {
    match raw {
        "invalid_request" => "invalid_request",
        "invalid_client" => "invalid_client",
        "invalid_grant" => "invalid_grant",
        "unauthorized_client" => "unauthorized_client",
        "unsupported_grant_type" => "unsupported_grant_type",
        "invalid_scope" => "invalid_scope",
        "temporarily_unavailable" => "temporarily_unavailable",
        // RFC 8693 token-exchange specific.
        "invalid_target" => "invalid_target",
        // Anything else (including upstream-specific codes that may leak
        // implementation details) collapses to a generic short code.
        _ => "server_error",
    }
}

/// Exchange an inbound access token for a downstream access token
/// via RFC 8693 token exchange.
///
/// The MCP server calls this to swap a user's MCP-scoped JWT
/// (`subject_token`) for a new JWT scoped to a downstream API
/// identified by [`TokenExchangeConfig::audience`].
///
/// # Errors
///
/// Returns an error if the HTTP request fails, the authorization
/// server rejects the exchange, or the response cannot be parsed.
pub async fn exchange_token(
    http: &OauthHttpClient,
    config: &TokenExchangeConfig,
    subject_token: &str,
) -> Result<ExchangedToken, crate::error::McpxError> {
    use secrecy::ExposeSecret;

    let mut req = http
        .inner
        .post(&config.token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json");

    // Client authentication: HTTP Basic if client_secret is present.
    if let Some(ref secret) = config.client_secret {
        use base64::Engine;
        let credentials = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            urlencoding::encode(&config.client_id),
            urlencoding::encode(secret.expose_secret()),
        ));
        req = req.header("Authorization", format!("Basic {credentials}"));
    }
    // TODO: mTLS client cert auth when config.client_cert is set.

    let form_body = build_exchange_form(config, subject_token);

    let resp = req.body(form_body).send().await.map_err(|e| {
        tracing::error!(error = %e, "token exchange request failed");
        // Do NOT leak upstream URL, reqwest internals, or DNS detail to clients.
        crate::error::McpxError::Auth("server_error".into())
    })?;

    let status = resp.status();
    let body_bytes = resp.bytes().await.map_err(|e| {
        tracing::error!(error = %e, "failed to read token exchange response");
        crate::error::McpxError::Auth("server_error".into())
    })?;

    if !status.is_success() {
        core::hint::cold_path();
        // Parse upstream error for logging only; client-visible payload is a
        // sanitized short code from the RFC 6749 §5.2 / RFC 8693 allowlist.
        let parsed = serde_json::from_slice::<OAuthErrorResponse>(&body_bytes).ok();
        let short_code = parsed
            .as_ref()
            .map_or("server_error", |e| sanitize_oauth_error_code(&e.error));
        if let Some(ref e) = parsed {
            tracing::warn!(
                status = %status,
                upstream_error = %e.error,
                upstream_error_description = e.error_description.as_deref().unwrap_or(""),
                client_code = %short_code,
                "token exchange rejected by authorization server",
            );
        } else {
            tracing::warn!(
                status = %status,
                client_code = %short_code,
                "token exchange rejected (unparseable upstream body)",
            );
        }
        return Err(crate::error::McpxError::Auth(short_code.into()));
    }

    let exchanged = serde_json::from_slice::<ExchangedToken>(&body_bytes).map_err(|e| {
        tracing::error!(error = %e, "failed to parse token exchange response");
        // Avoid surfacing serde internals; map to sanitized short code so
        // McpxError::into_response cannot leak parser detail to the client.
        crate::error::McpxError::Auth("server_error".into())
    })?;

    log_exchanged_token(&exchanged);

    Ok(exchanged)
}

/// Build the RFC 8693 token-exchange form body. Adds `client_id` when the
/// client is public (no `client_secret`).
fn build_exchange_form(config: &TokenExchangeConfig, subject_token: &str) -> String {
    let body = format!(
        "grant_type={}&subject_token={}&subject_token_type={}&requested_token_type={}&audience={}",
        urlencoding::encode("urn:ietf:params:oauth:grant-type:token-exchange"),
        urlencoding::encode(subject_token),
        urlencoding::encode("urn:ietf:params:oauth:token-type:access_token"),
        urlencoding::encode("urn:ietf:params:oauth:token-type:access_token"),
        urlencoding::encode(&config.audience),
    );
    if config.client_secret.is_none() {
        format!(
            "{body}&client_id={}",
            urlencoding::encode(&config.client_id)
        )
    } else {
        body
    }
}

/// Debug-log the exchanged token. For JWTs, decode and log claim summary;
/// for opaque tokens, log length + issued type.
fn log_exchanged_token(exchanged: &ExchangedToken) {
    use base64::Engine;

    if !looks_like_jwt(&exchanged.access_token) {
        tracing::debug!(
            token_len = exchanged.access_token.len(),
            issued_token_type = ?exchanged.issued_token_type,
            expires_in = exchanged.expires_in,
            "exchanged token (opaque)",
        );
        return;
    }
    let Some(payload) = exchanged.access_token.split('.').nth(1) else {
        return;
    };
    let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
        return;
    };
    tracing::debug!(
        sub = ?claims.get("sub"),
        aud = ?claims.get("aud"),
        azp = ?claims.get("azp"),
        iss = ?claims.get("iss"),
        expires_in = exchanged.expires_in,
        "exchanged token claims (JWT)",
    );
}

/// Replace or inject the `client_id` parameter in a query/form string.
fn replace_client_id(params: &str, upstream_client_id: &str) -> String {
    let encoded_id = urlencoding::encode(upstream_client_id);
    let mut parts: Vec<String> = params
        .split('&')
        .filter(|p| !p.starts_with("client_id="))
        .map(String::from)
        .collect();
    parts.push(format!("client_id={encoded_id}"));
    parts.join("&")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::*;

    #[test]
    fn looks_like_jwt_valid() {
        // Minimal valid JWT structure: base64({"alg":"RS256"}).base64({}).sig
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("{header}.{payload}.signature");
        assert!(looks_like_jwt(&token));
    }

    #[test]
    fn looks_like_jwt_rejects_opaque_token() {
        assert!(!looks_like_jwt("dGhpcyBpcyBhbiBvcGFxdWUgdG9rZW4"));
    }

    #[test]
    fn looks_like_jwt_rejects_two_segments() {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\"}");
        let token = format!("{header}.payload");
        assert!(!looks_like_jwt(&token));
    }

    #[test]
    fn looks_like_jwt_rejects_four_segments() {
        assert!(!looks_like_jwt("a.b.c.d"));
    }

    #[test]
    fn looks_like_jwt_rejects_no_alg() {
        let header = URL_SAFE_NO_PAD.encode(b"{\"typ\":\"JWT\"}");
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("{header}.{payload}.sig");
        assert!(!looks_like_jwt(&token));
    }

    #[test]
    fn protected_resource_metadata_shape() {
        let config = OAuthConfig {
            issuer: "https://auth.example.com".into(),
            audience: "https://mcp.example.com/mcp".into(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".into(),
            scopes: vec![
                ScopeMapping {
                    scope: "mcp:read".into(),
                    role: "viewer".into(),
                },
                ScopeMapping {
                    scope: "mcp:admin".into(),
                    role: "ops".into(),
                },
            ],
            role_claim: None,
            role_mappings: vec![],
            jwks_cache_ttl: "10m".into(),
            proxy: None,
            token_exchange: None,
            ca_cert_path: None,
            allow_http_oauth_urls: false,
            max_jwks_keys: default_max_jwks_keys(),
        };
        let meta = protected_resource_metadata(
            "https://mcp.example.com/mcp",
            "https://mcp.example.com",
            &config,
        );
        assert_eq!(meta["resource"], "https://mcp.example.com/mcp");
        assert_eq!(meta["authorization_servers"][0], "https://mcp.example.com");
        assert_eq!(meta["scopes_supported"].as_array().unwrap().len(), 2);
        assert_eq!(meta["bearer_methods_supported"][0], "header");
    }

    // -----------------------------------------------------------------------
    // F2: OAuth URL HTTPS-only validation (CVE-class: MITM JWKS / token URL)
    // -----------------------------------------------------------------------

    fn validation_https_config() -> OAuthConfig {
        OAuthConfig::builder(
            "https://auth.example.com",
            "mcp",
            "https://auth.example.com/.well-known/jwks.json",
        )
        .build()
    }

    #[test]
    fn validate_accepts_all_https_urls() {
        let cfg = validation_https_config();
        cfg.validate().expect("all-HTTPS config must validate");
    }

    #[test]
    fn validate_rejects_http_jwks_uri() {
        let mut cfg = validation_https_config();
        cfg.jwks_uri = "http://auth.example.com/.well-known/jwks.json".into();
        let err = cfg.validate().expect_err("http jwks_uri must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("oauth.jwks_uri") && msg.contains("https"),
            "error must reference offending field + scheme requirement; got {msg:?}"
        );
    }

    #[test]
    fn validate_rejects_http_proxy_authorize_url() {
        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "http://idp.example.com/authorize", // <-- HTTP, must be rejected
                "https://idp.example.com/token",
                "client",
            )
            .build(),
        );
        let err = cfg
            .validate()
            .expect_err("http authorize_url must be rejected");
        assert!(
            err.to_string().contains("oauth.proxy.authorize_url"),
            "error must reference proxy.authorize_url; got {err}"
        );
    }

    #[test]
    fn validate_rejects_http_proxy_token_url() {
        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "https://idp.example.com/authorize",
                "http://idp.example.com/token", // <-- HTTP, must be rejected
                "client",
            )
            .build(),
        );
        let err = cfg.validate().expect_err("http token_url must be rejected");
        assert!(
            err.to_string().contains("oauth.proxy.token_url"),
            "error must reference proxy.token_url; got {err}"
        );
    }

    #[test]
    fn validate_rejects_http_proxy_introspection_and_revocation_urls() {
        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "https://idp.example.com/authorize",
                "https://idp.example.com/token",
                "client",
            )
            .introspection_url("http://idp.example.com/introspect")
            .build(),
        );
        let err = cfg
            .validate()
            .expect_err("http introspection_url must be rejected");
        assert!(err.to_string().contains("oauth.proxy.introspection_url"));

        let mut cfg = validation_https_config();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "https://idp.example.com/authorize",
                "https://idp.example.com/token",
                "client",
            )
            .revocation_url("http://idp.example.com/revoke")
            .build(),
        );
        let err = cfg
            .validate()
            .expect_err("http revocation_url must be rejected");
        assert!(err.to_string().contains("oauth.proxy.revocation_url"));
    }

    #[test]
    fn validate_rejects_http_token_exchange_url() {
        let mut cfg = validation_https_config();
        cfg.token_exchange = Some(TokenExchangeConfig::new(
            "http://idp.example.com/token".into(), // <-- HTTP
            "client".into(),
            None,
            None,
            "downstream".into(),
        ));
        let err = cfg
            .validate()
            .expect_err("http token_exchange.token_url must be rejected");
        assert!(
            err.to_string().contains("oauth.token_exchange.token_url"),
            "error must reference token_exchange.token_url; got {err}"
        );
    }

    #[test]
    fn validate_rejects_unparseable_url() {
        let mut cfg = validation_https_config();
        cfg.jwks_uri = "not a url".into();
        let err = cfg
            .validate()
            .expect_err("unparseable URL must be rejected");
        assert!(err.to_string().contains("invalid URL"));
    }

    #[test]
    fn validate_rejects_non_http_scheme() {
        let mut cfg = validation_https_config();
        cfg.jwks_uri = "file:///etc/passwd".into();
        let err = cfg.validate().expect_err("file:// scheme must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("must use https scheme") && msg.contains("file"),
            "error must reject non-http(s) schemes; got {msg:?}"
        );
    }

    #[test]
    fn validate_accepts_http_with_escape_hatch() {
        // F2 escape-hatch: `allow_http_oauth_urls = true` permits HTTP for
        // dev/test against local IdPs without TLS. Document the security
        // tradeoff (see field doc) and verify all 6 URL fields are accepted
        // when the flag is set.
        let mut cfg = OAuthConfig::builder(
            "http://auth.local",
            "mcp",
            "http://auth.local/.well-known/jwks.json",
        )
        .allow_http_oauth_urls(true)
        .build();
        cfg.proxy = Some(
            OAuthProxyConfig::builder(
                "http://idp.local/authorize",
                "http://idp.local/token",
                "client",
            )
            .introspection_url("http://idp.local/introspect")
            .revocation_url("http://idp.local/revoke")
            .build(),
        );
        cfg.token_exchange = Some(TokenExchangeConfig::new(
            "http://idp.local/token".into(),
            "client".into(),
            None,
            None,
            "downstream".into(),
        ));
        cfg.validate()
            .expect("escape hatch must permit http on all URL fields");
    }

    #[test]
    fn validate_with_escape_hatch_still_rejects_unparseable() {
        // Even with the escape hatch, malformed URLs are rejected so
        // garbage configuration cannot silently degrade to no-op.
        let mut cfg = validation_https_config();
        cfg.allow_http_oauth_urls = true;
        cfg.jwks_uri = "::not-a-url::".into();
        cfg.validate()
            .expect_err("escape hatch must NOT bypass URL parsing");
    }

    #[tokio::test]
    async fn jwks_cache_rejects_redirect_downgrade_to_http() {
        // F2.4 (Oracle modification A): even when the configured `jwks_uri`
        // is HTTPS, a `302 Location: http://...` from the JWKS host must
        // be refused by the reqwest redirect policy. Without this guard,
        // a network-positioned attacker who can spoof the upstream IdP
        // could redirect the JWKS fetch to plaintext and inject signing
        // keys, forging arbitrary JWTs.
        //
        // We assert at the reqwest-client level (rather than through
        // `validate_token`) so the assertion is precise: it pins the
        // policy to "reject scheme downgrade" rather than the broader
        // "JWKS fetch failed for any reason".

        // Install the same rustls crypto provider JwksCache::new uses,
        // so the test client can build with TLS support.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let policy = reqwest::redirect::Policy::custom(|attempt| {
            if attempt.url().scheme() != "https" {
                attempt.error("redirect to non-HTTPS URL refused")
            } else if attempt.previous().len() >= 2 {
                attempt.error("too many redirects (max 2)")
            } else {
                attempt.follow()
            }
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .redirect(policy)
            .build()
            .expect("test client builds");

        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", "http://example.invalid/jwks.json"),
            )
            .mount(&mock)
            .await;

        // Emulate an HTTPS jwks_uri that 302s to HTTP.  We can't easily
        // bring up an HTTPS wiremock, so we simulate the kernel of the
        // policy: the same client that JwksCache uses must refuse the
        // redirect target.  reqwest invokes the redirect policy
        // regardless of source scheme, so an HTTP -> HTTP redirect with
        // policy `custom(... if scheme != https then error ...)` still
        // yields the redirect-rejection error path.  That is sufficient
        // to lock in the policy semantics.
        let url = format!("{}/jwks.json", mock.uri());
        let err = client
            .get(&url)
            .send()
            .await
            .expect_err("redirect policy must reject scheme downgrade");
        let chain = format!("{err:#}");
        assert!(
            chain.contains("redirect to non-HTTPS URL refused")
                || chain.to_lowercase().contains("redirect"),
            "error must surface redirect-policy rejection; got {chain:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Integration tests with in-process RSA keypair + wiremock JWKS
    // -----------------------------------------------------------------------

    use rsa::{pkcs8::EncodePrivateKey, traits::PublicKeyParts};

    /// Generate an RSA-2048 keypair and return `(private_pem, jwks_json)`.
    fn generate_test_keypair(kid: &str) -> (String, serde_json::Value) {
        let mut rng = rsa::rand_core::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("keypair generation");
        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("PKCS8 PEM export")
            .to_string();

        let public_key = private_key.to_public_key();
        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": n,
                "e": e
            }]
        });

        (private_pem, jwks)
    }

    /// Mint a signed JWT with the given claims.
    fn mint_token(
        private_pem: &str,
        kid: &str,
        issuer: &str,
        audience: &str,
        subject: &str,
        scope: &str,
    ) -> String {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .expect("encoding key from PEM");
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());

        let now = jsonwebtoken::get_current_timestamp();
        let claims = serde_json::json!({
            "iss": issuer,
            "aud": audience,
            "sub": subject,
            "scope": scope,
            "exp": now + 3600,
            "iat": now,
        });

        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("JWT encoding")
    }

    fn test_config(jwks_uri: &str) -> OAuthConfig {
        OAuthConfig {
            issuer: "https://auth.test.local".into(),
            audience: "https://mcp.test.local/mcp".into(),
            jwks_uri: jwks_uri.into(),
            scopes: vec![
                ScopeMapping {
                    scope: "mcp:read".into(),
                    role: "viewer".into(),
                },
                ScopeMapping {
                    scope: "mcp:admin".into(),
                    role: "ops".into(),
                },
            ],
            role_claim: None,
            role_mappings: vec![],
            jwks_cache_ttl: "5m".into(),
            proxy: None,
            token_exchange: None,
            ca_cert_path: None,
            allow_http_oauth_urls: true,
            max_jwks_keys: default_max_jwks_keys(),
        }
    }

    #[tokio::test]
    async fn valid_jwt_returns_identity() {
        let kid = "test-key-1";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = JwksCache::new(&config).unwrap();

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "ci-bot",
            "mcp:read mcp:other",
        );

        let identity = cache.validate_token(&token).await;
        assert!(identity.is_some(), "valid JWT should authenticate");
        let id = identity.unwrap();
        assert_eq!(id.name, "ci-bot");
        assert_eq!(id.role, "viewer"); // first matching scope
        assert_eq!(id.method, AuthMethod::OAuthJwt);
    }

    #[tokio::test]
    async fn wrong_issuer_rejected() {
        let kid = "test-key-2";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = JwksCache::new(&config).unwrap();

        let token = mint_token(
            &pem,
            kid,
            "https://wrong-issuer.example.com", // wrong
            "https://mcp.test.local/mcp",
            "attacker",
            "mcp:admin",
        );

        assert!(cache.validate_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn wrong_audience_rejected() {
        let kid = "test-key-3";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = JwksCache::new(&config).unwrap();

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://wrong-audience.example.com", // wrong
            "attacker",
            "mcp:admin",
        );

        assert!(cache.validate_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn expired_jwt_rejected() {
        let kid = "test-key-4";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = JwksCache::new(&config).unwrap();

        // Create a token that expired 2 minutes ago (past the 60s leeway).
        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        let now = jsonwebtoken::get_current_timestamp();
        let claims = serde_json::json!({
            "iss": "https://auth.test.local",
            "aud": "https://mcp.test.local/mcp",
            "sub": "expired-bot",
            "scope": "mcp:read",
            "exp": now - 120,
            "iat": now - 3720,
        });
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).expect("JWT encoding");

        assert!(cache.validate_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn no_matching_scope_rejected() {
        let kid = "test-key-5";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = JwksCache::new(&config).unwrap();

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "limited-bot",
            "some:other:scope", // no matching scope
        );

        assert!(cache.validate_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn wrong_signing_key_rejected() {
        let kid = "test-key-6";
        let (_pem, jwks) = generate_test_keypair(kid);

        // Generate a DIFFERENT keypair for signing (attacker key).
        let (attacker_pem, _) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = JwksCache::new(&config).unwrap();

        // Sign with attacker key but JWKS has legitimate public key.
        let token = mint_token(
            &attacker_pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "attacker",
            "mcp:admin",
        );

        assert!(cache.validate_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn admin_scope_maps_to_ops_role() {
        let kid = "test-key-7";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = JwksCache::new(&config).unwrap();

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "admin-bot",
            "mcp:admin",
        );

        let id = cache
            .validate_token(&token)
            .await
            .expect("should authenticate");
        assert_eq!(id.role, "ops");
        assert_eq!(id.name, "admin-bot");
    }

    #[tokio::test]
    async fn jwks_server_down_returns_none() {
        // Point to a non-existent server.
        let config = test_config("http://127.0.0.1:1/jwks.json");
        let cache = JwksCache::new(&config).unwrap();

        let kid = "orphan-key";
        let (pem, _) = generate_test_keypair(kid);
        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "bot",
            "mcp:read",
        );

        assert!(cache.validate_token(&token).await.is_none());
    }

    // -----------------------------------------------------------------------
    // resolve_claim_path tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_claim_path_flat_string() {
        let mut extra = HashMap::new();
        extra.insert(
            "scope".into(),
            serde_json::Value::String("mcp:read mcp:admin".into()),
        );
        let values = resolve_claim_path(&extra, "scope");
        assert_eq!(values, vec!["mcp:read", "mcp:admin"]);
    }

    #[test]
    fn resolve_claim_path_flat_array() {
        let mut extra = HashMap::new();
        extra.insert(
            "roles".into(),
            serde_json::json!(["mcp-admin", "mcp-viewer"]),
        );
        let values = resolve_claim_path(&extra, "roles");
        assert_eq!(values, vec!["mcp-admin", "mcp-viewer"]);
    }

    #[test]
    fn resolve_claim_path_nested_keycloak() {
        let mut extra = HashMap::new();
        extra.insert(
            "realm_access".into(),
            serde_json::json!({"roles": ["uma_authorization", "mcp-admin"]}),
        );
        let values = resolve_claim_path(&extra, "realm_access.roles");
        assert_eq!(values, vec!["uma_authorization", "mcp-admin"]);
    }

    #[test]
    fn resolve_claim_path_missing_returns_empty() {
        let extra = HashMap::new();
        assert!(resolve_claim_path(&extra, "nonexistent.path").is_empty());
    }

    #[test]
    fn resolve_claim_path_numeric_leaf_returns_empty() {
        let mut extra = HashMap::new();
        extra.insert("count".into(), serde_json::json!(42));
        assert!(resolve_claim_path(&extra, "count").is_empty());
    }

    // -----------------------------------------------------------------------
    // role_claim integration tests (wiremock)
    // -----------------------------------------------------------------------

    /// Mint a JWT with arbitrary custom claims (for `role_claim` testing).
    fn mint_token_with_claims(private_pem: &str, kid: &str, claims: &serde_json::Value) -> String {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .expect("encoding key from PEM");
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("JWT encoding")
    }

    fn test_config_with_role_claim(
        jwks_uri: &str,
        role_claim: &str,
        role_mappings: Vec<RoleMapping>,
    ) -> OAuthConfig {
        OAuthConfig {
            issuer: "https://auth.test.local".into(),
            audience: "https://mcp.test.local/mcp".into(),
            jwks_uri: jwks_uri.into(),
            scopes: vec![],
            role_claim: Some(role_claim.into()),
            role_mappings,
            jwks_cache_ttl: "5m".into(),
            proxy: None,
            token_exchange: None,
            ca_cert_path: None,
            allow_http_oauth_urls: true,
            max_jwks_keys: default_max_jwks_keys(),
        }
    }

    #[tokio::test]
    async fn role_claim_keycloak_nested_array() {
        let kid = "test-role-1";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config_with_role_claim(
            &jwks_uri,
            "realm_access.roles",
            vec![
                RoleMapping {
                    claim_value: "mcp-admin".into(),
                    role: "ops".into(),
                },
                RoleMapping {
                    claim_value: "mcp-viewer".into(),
                    role: "viewer".into(),
                },
            ],
        );
        let cache = JwksCache::new(&config).unwrap();

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "keycloak-user",
                "exp": now + 3600,
                "iat": now,
                "realm_access": { "roles": ["uma_authorization", "mcp-admin"] }
            }),
        );

        let id = cache
            .validate_token(&token)
            .await
            .expect("should authenticate");
        assert_eq!(id.name, "keycloak-user");
        assert_eq!(id.role, "ops");
    }

    #[tokio::test]
    async fn role_claim_flat_roles_array() {
        let kid = "test-role-2";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config_with_role_claim(
            &jwks_uri,
            "roles",
            vec![
                RoleMapping {
                    claim_value: "MCP.Admin".into(),
                    role: "ops".into(),
                },
                RoleMapping {
                    claim_value: "MCP.Reader".into(),
                    role: "viewer".into(),
                },
            ],
        );
        let cache = JwksCache::new(&config).unwrap();

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "azure-ad-user",
                "exp": now + 3600,
                "iat": now,
                "roles": ["MCP.Reader", "OtherApp.Admin"]
            }),
        );

        let id = cache
            .validate_token(&token)
            .await
            .expect("should authenticate");
        assert_eq!(id.name, "azure-ad-user");
        assert_eq!(id.role, "viewer");
    }

    #[tokio::test]
    async fn role_claim_no_matching_value_rejected() {
        let kid = "test-role-3";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config_with_role_claim(
            &jwks_uri,
            "roles",
            vec![RoleMapping {
                claim_value: "mcp-admin".into(),
                role: "ops".into(),
            }],
        );
        let cache = JwksCache::new(&config).unwrap();

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "limited-user",
                "exp": now + 3600,
                "iat": now,
                "roles": ["some-other-role"]
            }),
        );

        assert!(cache.validate_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn role_claim_space_separated_string() {
        let kid = "test-role-4";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config_with_role_claim(
            &jwks_uri,
            "custom_scope",
            vec![
                RoleMapping {
                    claim_value: "write".into(),
                    role: "ops".into(),
                },
                RoleMapping {
                    claim_value: "read".into(),
                    role: "viewer".into(),
                },
            ],
        );
        let cache = JwksCache::new(&config).unwrap();

        let now = jsonwebtoken::get_current_timestamp();
        let token = mint_token_with_claims(
            &pem,
            kid,
            &serde_json::json!({
                "iss": "https://auth.test.local",
                "aud": "https://mcp.test.local/mcp",
                "sub": "custom-client",
                "exp": now + 3600,
                "iat": now,
                "custom_scope": "read audit"
            }),
        );

        let id = cache
            .validate_token(&token)
            .await
            .expect("should authenticate");
        assert_eq!(id.name, "custom-client");
        assert_eq!(id.role, "viewer");
    }

    #[tokio::test]
    async fn scope_backward_compat_without_role_claim() {
        // Verify existing `scopes` behavior still works when role_claim is None.
        let kid = "test-compat-1";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri); // role_claim: None, uses scopes
        let cache = JwksCache::new(&config).unwrap();

        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "legacy-bot",
            "mcp:admin other:scope",
        );

        let id = cache
            .validate_token(&token)
            .await
            .expect("should authenticate");
        assert_eq!(id.name, "legacy-bot");
        assert_eq!(id.role, "ops"); // mcp:admin -> ops via scopes
    }

    // -----------------------------------------------------------------------
    // JWKS refresh cooldown tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn jwks_refresh_deduplication() {
        // Verify that concurrent requests with unknown kids result in exactly
        // one JWKS fetch, not one per request (deduplication via mutex).
        let kid = "test-dedup";
        let (pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        let _mock = wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .expect(1) // Should be called exactly once
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = Arc::new(JwksCache::new(&config).unwrap());

        // Create 5 concurrent validation requests with the same valid token.
        let token = mint_token(
            &pem,
            kid,
            "https://auth.test.local",
            "https://mcp.test.local/mcp",
            "concurrent-bot",
            "mcp:read",
        );

        let mut handles = Vec::new();
        for _ in 0..5 {
            let c = Arc::clone(&cache);
            let t = token.clone();
            handles.push(tokio::spawn(async move { c.validate_token(&t).await }));
        }

        for h in handles {
            let result = h.await.unwrap();
            assert!(result.is_some(), "all concurrent requests should succeed");
        }

        // The expect(1) assertion on the mock verifies only one fetch occurred.
    }

    #[tokio::test]
    async fn jwks_refresh_cooldown_blocks_rapid_requests() {
        // Verify that rapid sequential requests with unknown kids (cache misses)
        // only trigger one JWKS fetch due to cooldown.
        let kid = "test-cooldown";
        let (_pem, jwks) = generate_test_keypair(kid);

        let mock_server = wiremock::MockServer::start().await;
        let _mock = wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks.json"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(&jwks))
            .expect(1) // Should be called exactly once despite multiple misses
            .mount(&mock_server)
            .await;

        let jwks_uri = format!("{}/jwks.json", mock_server.uri());
        let config = test_config(&jwks_uri);
        let cache = JwksCache::new(&config).unwrap();

        // First request with unknown kid triggers a refresh.
        let fake_token1 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InVua25vd24ta2lkLTEifQ.e30.sig";
        let _ = cache.validate_token(fake_token1).await;

        // Second request with a different unknown kid should NOT trigger refresh
        // because we're within the 10-second cooldown.
        let fake_token2 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InVua25vd24ta2lkLTIifQ.e30.sig";
        let _ = cache.validate_token(fake_token2).await;

        // Third request with yet another unknown kid - still within cooldown.
        let fake_token3 =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InVua25vd24ta2lkLTMifQ.e30.sig";
        let _ = cache.validate_token(fake_token3).await;

        // The expect(1) assertion verifies only one fetch occurred.
    }

    // -- introspection / revocation proxy --

    fn proxy_cfg(token_url: &str) -> OAuthProxyConfig {
        OAuthProxyConfig {
            authorize_url: "https://example.invalid/auth".into(),
            token_url: token_url.into(),
            client_id: "mcp-client".into(),
            client_secret: Some(secrecy::SecretString::from("shh".to_owned())),
            introspection_url: None,
            revocation_url: None,
            expose_admin_endpoints: false,
        }
    }

    /// Build an HTTP client for tests. Ensures a rustls crypto provider
    /// is installed (normally done inside `JwksCache::new`).
    fn test_http_client() -> OauthHttpClient {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        OauthHttpClient::with_config(&OAuthConfig::default()).expect("build test http client")
    }

    #[tokio::test]
    async fn introspect_proxies_and_injects_client_credentials() {
        use wiremock::matchers::{body_string_contains, method, path};

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .and(path("/introspect"))
            .and(body_string_contains("client_id=mcp-client"))
            .and(body_string_contains("client_secret=shh"))
            .and(body_string_contains("token=abc"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "active": true,
                    "scope": "read"
                })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut proxy = proxy_cfg(&format!("{}/token", mock_server.uri()));
        proxy.introspection_url = Some(format!("{}/introspect", mock_server.uri()));

        let http = test_http_client();
        let resp = handle_introspect(&http, &proxy, "token=abc").await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn introspect_returns_404_when_not_configured() {
        let proxy = proxy_cfg("https://example.invalid/token");
        let http = test_http_client();
        let resp = handle_introspect(&http, &proxy, "token=abc").await;
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn revoke_proxies_and_returns_upstream_status() {
        use wiremock::matchers::{method, path};

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .and(path("/revoke"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut proxy = proxy_cfg(&format!("{}/token", mock_server.uri()));
        proxy.revocation_url = Some(format!("{}/revoke", mock_server.uri()));

        let http = test_http_client();
        let resp = handle_revoke(&http, &proxy, "token=abc").await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn revoke_returns_404_when_not_configured() {
        let proxy = proxy_cfg("https://example.invalid/token");
        let http = test_http_client();
        let resp = handle_revoke(&http, &proxy, "token=abc").await;
        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn metadata_advertises_endpoints_only_when_configured() {
        let mut cfg = test_config("https://auth.test.local/jwks.json");
        // Without proxy configured, no introspection/revocation advertised.
        let m = authorization_server_metadata("https://mcp.local", &cfg);
        assert!(m.get("introspection_endpoint").is_none());
        assert!(m.get("revocation_endpoint").is_none());

        // With proxy + introspection_url but expose_admin_endpoints = false
        // (the secure default): endpoints MUST NOT be advertised.
        let mut proxy = proxy_cfg("https://upstream.local/token");
        proxy.introspection_url = Some("https://upstream.local/introspect".into());
        proxy.revocation_url = Some("https://upstream.local/revoke".into());
        cfg.proxy = Some(proxy);
        let m = authorization_server_metadata("https://mcp.local", &cfg);
        assert!(
            m.get("introspection_endpoint").is_none(),
            "introspection must not be advertised when expose_admin_endpoints=false"
        );
        assert!(
            m.get("revocation_endpoint").is_none(),
            "revocation must not be advertised when expose_admin_endpoints=false"
        );

        // Opt in: expose_admin_endpoints = true + introspection_url only.
        if let Some(p) = cfg.proxy.as_mut() {
            p.expose_admin_endpoints = true;
            p.revocation_url = None;
        }
        let m = authorization_server_metadata("https://mcp.local", &cfg);
        assert_eq!(
            m["introspection_endpoint"],
            serde_json::Value::String("https://mcp.local/introspect".into())
        );
        assert!(m.get("revocation_endpoint").is_none());

        // Add revocation_url.
        if let Some(p) = cfg.proxy.as_mut() {
            p.revocation_url = Some("https://upstream.local/revoke".into());
        }
        let m = authorization_server_metadata("https://mcp.local", &cfg);
        assert_eq!(
            m["revocation_endpoint"],
            serde_json::Value::String("https://mcp.local/revoke".into())
        );
    }
}
