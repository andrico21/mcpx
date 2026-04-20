use std::{
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use axum::{body::Body, extract::Request, middleware::Next, response::IntoResponse};
use rmcp::{
    ServerHandler,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{
        AuthConfig, AuthIdentity, AuthState, MtlsConfig, TlsConnInfo, auth_middleware,
        build_rate_limiter, extract_mtls_identity,
    },
    error::McpxError,
    rbac::{RbacPolicy, ToolRateLimiter, build_tool_rate_limiter, rbac_middleware},
};

/// Map an internal `anyhow::Error` chain into a public [`McpxError::Startup`]
/// at the public API boundary, flattening the chain via the alternate
/// formatter so callers see the full causal path.
#[allow(
    clippy::needless_pass_by_value,
    reason = "consumed at .map_err(anyhow_to_startup) call sites; by-value matches the closure shape"
)]
fn anyhow_to_startup(e: anyhow::Error) -> McpxError {
    McpxError::Startup(format!("{e:#}"))
}

/// Map a `std::io::Error` produced during server startup into a public
/// [`McpxError::Startup`]. We deliberately do not use the [`McpxError::Io`]
/// `From` impl here because startup-phase IO errors (bind, listener) are
/// semantically distinct from request-time IO errors and should surface
/// the originating operation in the message.
#[allow(
    clippy::needless_pass_by_value,
    reason = "consumed at .map_err(|e| io_to_startup(...)) call sites; by-value matches the closure shape"
)]
fn io_to_startup(op: &str, e: std::io::Error) -> McpxError {
    McpxError::Startup(format!("{op}: {e}"))
}

/// Async readiness check callback for the `/readyz` endpoint.
///
/// Returns a JSON object with at least a `"ready"` boolean.
/// When `ready` is false, the endpoint returns HTTP 503.
pub type ReadinessCheck =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = serde_json::Value> + Send>> + Send + Sync>;

/// Configuration for the MCP server.
#[allow(
    missing_debug_implementations,
    reason = "contains callback/trait objects that don't impl Debug"
)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "server configuration naturally has many boolean feature flags"
)]
#[non_exhaustive]
pub struct McpServerConfig {
    /// Socket address the MCP HTTP server binds to.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::new() / with_bind_addr(); direct field access will become pub(crate) in 1.0"
    )]
    pub bind_addr: String,
    /// Server name advertised via MCP `initialize`.
    #[deprecated(
        since = "0.13.0",
        note = "set via McpServerConfig::new(); direct field access will become pub(crate) in 1.0"
    )]
    pub name: String,
    /// Server version advertised via MCP `initialize`.
    #[deprecated(
        since = "0.13.0",
        note = "set via McpServerConfig::new(); direct field access will become pub(crate) in 1.0"
    )]
    pub version: String,
    /// Path to the TLS certificate (PEM). Required for TLS/mTLS.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_tls(); direct field access will become pub(crate) in 1.0"
    )]
    pub tls_cert_path: Option<PathBuf>,
    /// Path to the TLS private key (PEM). Required for TLS/mTLS.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_tls(); direct field access will become pub(crate) in 1.0"
    )]
    pub tls_key_path: Option<PathBuf>,
    /// Optional authentication config. When `Some` and `enabled`, auth
    /// is enforced on `/mcp`. `/healthz` is always open.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_auth(); direct field access will become pub(crate) in 1.0"
    )]
    pub auth: Option<AuthConfig>,
    /// Optional RBAC policy. When present and enabled, tool calls are
    /// checked against the policy after authentication.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_rbac(); direct field access will become pub(crate) in 1.0"
    )]
    pub rbac: Option<Arc<RbacPolicy>>,
    /// Allowed Origin values for DNS rebinding protection (MCP spec MUST).
    /// When empty and `public_url` is set, the origin is auto-derived from
    /// the public URL. When both are empty, only requests with no Origin
    /// header are accepted.
    /// Example entries: `"http://localhost:3000"`, `"https://myapp.example.com"`.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_allowed_origins(); direct field access will become pub(crate) in 1.0"
    )]
    pub allowed_origins: Vec<String>,
    /// Maximum tool invocations per source IP per minute.
    /// When set, enforced on every `tools/call` request.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_tool_rate_limit(); direct field access will become pub(crate) in 1.0"
    )]
    pub tool_rate_limit: Option<u32>,
    /// Optional readiness probe for `/readyz`.
    /// When `None`, `/readyz` mirrors `/healthz` (always OK).
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_readiness_check(); direct field access will become pub(crate) in 1.0"
    )]
    pub readiness_check: Option<ReadinessCheck>,
    /// Maximum request body size in bytes. Default: 1 MiB.
    /// Protects against oversized payloads causing OOM.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_max_request_body(); direct field access will become pub(crate) in 1.0"
    )]
    pub max_request_body: usize,
    /// Request processing timeout. Default: 120s.
    /// Requests exceeding this duration receive 408 Request Timeout.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_request_timeout(); direct field access will become pub(crate) in 1.0"
    )]
    pub request_timeout: Duration,
    /// Graceful shutdown timeout. Default: 30s.
    /// After the shutdown signal, in-flight requests have this long to finish.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_shutdown_timeout(); direct field access will become pub(crate) in 1.0"
    )]
    pub shutdown_timeout: Duration,
    /// Idle timeout for MCP sessions. Sessions with no activity for this
    /// duration are closed automatically. Default: 20 minutes.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_session_idle_timeout(); direct field access will become pub(crate) in 1.0"
    )]
    pub session_idle_timeout: Duration,
    /// Interval for SSE keep-alive pings. Prevents proxies and load
    /// balancers from killing idle connections. Default: 15 seconds.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_sse_keep_alive(); direct field access will become pub(crate) in 1.0"
    )]
    pub sse_keep_alive: Duration,
    /// Callback invoked once the server is built, delivering a
    /// [`ReloadHandle`] for hot-reloading auth keys and RBAC policy
    /// at runtime (e.g. on SIGHUP). Only useful when auth/RBAC is enabled.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_reload_callback(); direct field access will become pub(crate) in 1.0"
    )]
    pub on_reload_ready: Option<Box<dyn FnOnce(ReloadHandle) + Send>>,
    /// Additional application-specific routes merged into the top-level
    /// router.  These routes **bypass** the MCP auth and RBAC middleware,
    /// so the application is responsible for its own auth on them.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_extra_router(); direct field access will become pub(crate) in 1.0"
    )]
    pub extra_router: Option<axum::Router>,
    /// Externally reachable base URL (e.g. `https://mcp.example.com`).
    /// When set, OAuth metadata endpoints advertise this URL instead of
    /// the listen address. Required when binding `0.0.0.0` behind a
    /// reverse proxy or inside a container.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_public_url(); direct field access will become pub(crate) in 1.0"
    )]
    pub public_url: Option<String>,
    /// Log inbound HTTP request headers at DEBUG level.
    /// Sensitive values remain redacted.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::enable_request_header_logging(); direct field access will become pub(crate) in 1.0"
    )]
    pub log_request_headers: bool,
    /// Enable gzip/br response compression on MCP responses.
    /// Defaults to `false` to preserve existing behaviour.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::enable_compression(); direct field access will become pub(crate) in 1.0"
    )]
    pub compression_enabled: bool,
    /// Minimum response body size (in bytes) before compression kicks in.
    /// Only used when `compression_enabled` is true. Default: 1024.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::enable_compression(); direct field access will become pub(crate) in 1.0"
    )]
    pub compression_min_size: u16,
    /// Global cap on in-flight HTTP requests across the whole server.
    /// When `Some`, requests over the cap receive 503 Service Unavailable
    /// via `tower::load_shed`. Default: `None` (unlimited).
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_max_concurrent_requests(); direct field access will become pub(crate) in 1.0"
    )]
    pub max_concurrent_requests: Option<usize>,
    /// Enable `/admin/*` diagnostic endpoints. Requires `auth` to be
    /// configured and `enabled`. Default: `false`.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::enable_admin(); direct field access will become pub(crate) in 1.0"
    )]
    pub admin_enabled: bool,
    /// RBAC role required to access admin endpoints. Default: `"admin"`.
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::enable_admin(); direct field access will become pub(crate) in 1.0"
    )]
    pub admin_role: String,
    /// Enable Prometheus metrics endpoint on a separate listener.
    /// Requires the `metrics` crate feature.
    #[cfg(feature = "metrics")]
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_metrics(); direct field access will become pub(crate) in 1.0"
    )]
    pub metrics_enabled: bool,
    /// Bind address for the Prometheus metrics listener. Default: `127.0.0.1:9090`.
    #[cfg(feature = "metrics")]
    #[deprecated(
        since = "0.13.0",
        note = "use McpServerConfig::with_metrics(); direct field access will become pub(crate) in 1.0"
    )]
    pub metrics_bind: String,
}

/// Marker that wraps a value proven to satisfy its validation
/// contract.
///
/// The only way to obtain `Validated<McpServerConfig>` is by calling
/// [`McpServerConfig::validate`], which is the contract enforced at
/// the type level by [`serve`] and [`serve_with_listener`]. The
/// inner field is private, so downstream code cannot bypass
/// validation by hand-constructing the wrapper.
///
/// `Validated<T>` derefs to `&T` for read-only access. To mutate,
/// recover the raw value with [`Validated::into_inner`] and
/// re-validate.
///
/// # Example
///
/// ```no_run
/// use rmcp_server_kit::transport::{McpServerConfig, Validated, serve};
/// use rmcp::handler::server::ServerHandler;
/// use rmcp::model::{ServerCapabilities, ServerInfo};
///
/// #[derive(Clone)]
/// struct H;
/// impl ServerHandler for H {
///     fn get_info(&self) -> ServerInfo {
///         ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
///     }
/// }
///
/// # async fn example() -> rmcp_server_kit::Result<()> {
/// let config: Validated<McpServerConfig> =
///     McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0").validate()?;
/// serve(config, || H).await
/// # }
/// ```
///
/// Forgetting `.validate()?` is a compile error:
///
/// ```compile_fail
/// use rmcp_server_kit::transport::{McpServerConfig, serve};
/// use rmcp::handler::server::ServerHandler;
/// use rmcp::model::{ServerCapabilities, ServerInfo};
///
/// #[derive(Clone)]
/// struct H;
/// impl ServerHandler for H {
///     fn get_info(&self) -> ServerInfo {
///         ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
///     }
/// }
///
/// # async fn example() -> rmcp_server_kit::Result<()> {
/// let config = McpServerConfig::new("127.0.0.1:8080", "my-server", "0.1.0");
/// // Missing `.validate()?` -> mismatched types: expected
/// // `Validated<McpServerConfig>`, found `McpServerConfig`.
/// serve(config, || H).await
/// # }
/// ```
#[allow(
    missing_debug_implementations,
    reason = "wraps T which may not implement Debug; manual impl below avoids leaking inner contents into logs"
)]
pub struct Validated<T>(T);

impl<T> std::fmt::Debug for Validated<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Validated").finish_non_exhaustive()
    }
}

impl<T> Validated<T> {
    /// Borrow the inner value.
    #[must_use]
    pub fn as_inner(&self) -> &T {
        &self.0
    }

    /// Recover the raw value, discarding the validation proof.
    ///
    /// Re-validate before re-using the value with [`serve`] or
    /// [`serve_with_listener`].
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::ops::Deref for Validated<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

#[allow(
    deprecated,
    reason = "internal builders/validators legitimately read/write the deprecated `pub` fields they were designed to manage"
)]
impl McpServerConfig {
    /// Create a new server configuration with the given bind address,
    /// server name, and version. All other fields use safe defaults.
    ///
    /// Use the chainable `with_*` / `enable_*` builder methods to
    /// customize. Call [`McpServerConfig::validate`] to obtain a
    /// [`Validated<McpServerConfig>`] proof token, which is required by
    /// [`serve`] and [`serve_with_listener`].
    #[must_use]
    pub fn new(
        bind_addr: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            name: name.into(),
            version: version.into(),
            tls_cert_path: None,
            tls_key_path: None,
            auth: None,
            rbac: None,
            allowed_origins: Vec::new(),
            tool_rate_limit: None,
            readiness_check: None,
            max_request_body: 1024 * 1024,
            request_timeout: Duration::from_mins(2),
            shutdown_timeout: Duration::from_secs(30),
            session_idle_timeout: Duration::from_mins(20),
            sse_keep_alive: Duration::from_secs(15),
            on_reload_ready: None,
            extra_router: None,
            public_url: None,
            log_request_headers: false,
            compression_enabled: false,
            compression_min_size: 1024,
            max_concurrent_requests: None,
            admin_enabled: false,
            admin_role: "admin".to_owned(),
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            #[cfg(feature = "metrics")]
            metrics_bind: "127.0.0.1:9090".into(),
        }
    }

    // ---------------------------------------------------------------
    // Builder methods (fluent, consume + return self).
    //
    // Each method is `#[must_use]` because dropping the returned
    // `McpServerConfig` discards the configuration change.
    // ---------------------------------------------------------------

    /// Attach an authentication configuration. Required for
    /// [`enable_admin`](Self::enable_admin) and any non-public deployment.
    #[must_use]
    pub fn with_auth(mut self, auth: AuthConfig) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Override the bind address (e.g. `127.0.0.1:8080`). Useful when the
    /// final port is only known after pre-binding an ephemeral listener
    /// (tests, dynamic-port deployments).
    #[must_use]
    pub fn with_bind_addr(mut self, addr: impl Into<String>) -> Self {
        self.bind_addr = addr.into();
        self
    }

    /// Attach an RBAC policy. Tool calls are checked against the policy
    /// after authentication.
    #[must_use]
    pub fn with_rbac(mut self, rbac: Arc<RbacPolicy>) -> Self {
        self.rbac = Some(rbac);
        self
    }

    /// Configure TLS by providing the certificate and private key paths
    /// (PEM). Both must be readable at startup. Without this call, the
    /// server runs plain HTTP.
    #[must_use]
    pub fn with_tls(mut self, cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        self.tls_cert_path = Some(cert_path.into());
        self.tls_key_path = Some(key_path.into());
        self
    }

    /// Set the externally reachable base URL (e.g. `https://mcp.example.com`).
    /// Required when binding `0.0.0.0` behind a reverse proxy or inside
    /// a container so OAuth metadata and auto-derived origins resolve correctly.
    #[must_use]
    pub fn with_public_url(mut self, url: impl Into<String>) -> Self {
        self.public_url = Some(url.into());
        self
    }

    /// Replace the allowed Origin allow-list (DNS-rebinding protection).
    /// When empty and [`with_public_url`](Self::with_public_url) is set,
    /// the origin is auto-derived.
    #[must_use]
    pub fn with_allowed_origins<I, S>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_origins = origins.into_iter().map(Into::into).collect();
        self
    }

    /// Merge an additional axum router at the top level. Routes added
    /// here **bypass** rmcp-server-kit auth and RBAC; the application is responsible
    /// for its own protection.
    #[must_use]
    pub fn with_extra_router(mut self, router: axum::Router) -> Self {
        self.extra_router = Some(router);
        self
    }

    /// Install an async readiness probe for `/readyz`. Without this call,
    /// `/readyz` mirrors `/healthz` (always 200 OK).
    #[must_use]
    pub fn with_readiness_check(mut self, check: ReadinessCheck) -> Self {
        self.readiness_check = Some(check);
        self
    }

    /// Override the maximum request body (bytes). Must be `> 0`.
    /// Default: 1 MiB.
    #[must_use]
    pub fn with_max_request_body(mut self, bytes: usize) -> Self {
        self.max_request_body = bytes;
        self
    }

    /// Override the per-request processing timeout. Default: 2 minutes.
    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Override the graceful shutdown grace period. Default: 30 seconds.
    #[must_use]
    pub fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    /// Override the MCP session idle timeout. Default: 20 minutes.
    #[must_use]
    pub fn with_session_idle_timeout(mut self, timeout: Duration) -> Self {
        self.session_idle_timeout = timeout;
        self
    }

    /// Override the SSE keep-alive interval. Default: 15 seconds.
    #[must_use]
    pub fn with_sse_keep_alive(mut self, interval: Duration) -> Self {
        self.sse_keep_alive = interval;
        self
    }

    /// Cap the global number of in-flight HTTP requests via
    /// `tower::load_shed`. Excess requests receive 503 Service Unavailable.
    /// Default: unlimited.
    #[must_use]
    pub fn with_max_concurrent_requests(mut self, limit: usize) -> Self {
        self.max_concurrent_requests = Some(limit);
        self
    }

    /// Cap tool invocations per source IP per minute. Enforced on every
    /// `tools/call` request.
    #[must_use]
    pub fn with_tool_rate_limit(mut self, per_minute: u32) -> Self {
        self.tool_rate_limit = Some(per_minute);
        self
    }

    /// Register a callback that receives the [`ReloadHandle`] after the
    /// server is built. Use it to wire SIGHUP-style hot reloads of API
    /// keys and RBAC policy.
    #[must_use]
    pub fn with_reload_callback<F>(mut self, callback: F) -> Self
    where
        F: FnOnce(ReloadHandle) + Send + 'static,
    {
        self.on_reload_ready = Some(Box::new(callback));
        self
    }

    /// Enable gzip/brotli response compression on MCP responses.
    /// `min_size` is the smallest body size (bytes) eligible for
    /// compression. Default min size: 1024.
    #[must_use]
    pub fn enable_compression(mut self, min_size: u16) -> Self {
        self.compression_enabled = true;
        self.compression_min_size = min_size;
        self
    }

    /// Enable `/admin/*` diagnostic endpoints. Requires
    /// [`with_auth`](Self::with_auth) to be set and enabled; otherwise
    /// [`validate`](Self::validate) returns an error. `role` is the RBAC
    /// role gate (default: `"admin"`).
    #[must_use]
    pub fn enable_admin(mut self, role: impl Into<String>) -> Self {
        self.admin_enabled = true;
        self.admin_role = role.into();
        self
    }

    /// Log inbound HTTP request headers at DEBUG level. Sensitive
    /// values remain redacted by the logging layer.
    #[must_use]
    pub fn enable_request_header_logging(mut self) -> Self {
        self.log_request_headers = true;
        self
    }

    /// Enable the Prometheus metrics listener on `bind` (e.g.
    /// `127.0.0.1:9090`). Requires the `metrics` crate feature.
    #[cfg(feature = "metrics")]
    #[must_use]
    pub fn with_metrics(mut self, bind: impl Into<String>) -> Self {
        self.metrics_enabled = true;
        self.metrics_bind = bind.into();
        self
    }

    /// Validate the configuration and consume `self`, returning a
    /// [`Validated<McpServerConfig>`] proof token required by [`serve`]
    /// and [`serve_with_listener`]. This is the only way to construct
    /// `Validated<McpServerConfig>`, so the type system guarantees
    /// validation has run before the server starts.
    ///
    /// Checks:
    ///
    /// 1. `admin_enabled` requires `auth` to be configured and enabled.
    /// 2. `tls_cert_path` and `tls_key_path` must both be set or both
    ///    be unset.
    /// 3. `bind_addr` must parse as a [`SocketAddr`].
    /// 4. `public_url`, when set, must start with `http://` or `https://`.
    /// 5. Each entry in `allowed_origins` must start with `http://` or
    ///    `https://`.
    /// 6. `max_request_body` must be greater than zero.
    ///
    /// # Errors
    ///
    /// Returns [`McpxError::Config`] with a human-readable message on
    /// the first validation failure.
    pub fn validate(self) -> Result<Validated<Self>, McpxError> {
        self.check()?;
        Ok(Validated(self))
    }

    /// Run the validation checks without consuming `self`. Used by
    /// internal call sites (e.g. tests) that need to inspect a config
    /// without taking ownership.
    fn check(&self) -> Result<(), McpxError> {
        // 1. admin <-> auth dependency. Mirrors the runtime check in
        //    `build_app_router`: admin endpoints require an auth state,
        //    which is built only when `auth` is `Some` *and* `enabled`.
        if self.admin_enabled {
            let auth_enabled = self.auth.as_ref().is_some_and(|a| a.enabled);
            if !auth_enabled {
                return Err(McpxError::Config(
                    "admin_enabled=true requires auth to be configured and enabled".into(),
                ));
            }
        }

        // 2. TLS cert / key must be paired
        match (&self.tls_cert_path, &self.tls_key_path) {
            (Some(_), None) => {
                return Err(McpxError::Config(
                    "tls_cert_path is set but tls_key_path is missing".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(McpxError::Config(
                    "tls_key_path is set but tls_cert_path is missing".into(),
                ));
            }
            _ => {}
        }

        // 3. bind_addr parses
        if self.bind_addr.parse::<SocketAddr>().is_err() {
            return Err(McpxError::Config(format!(
                "bind_addr {:?} is not a valid socket address (expected e.g. 127.0.0.1:8080)",
                self.bind_addr
            )));
        }

        // 4. public_url scheme
        if let Some(ref url) = self.public_url
            && !(url.starts_with("http://") || url.starts_with("https://"))
        {
            return Err(McpxError::Config(format!(
                "public_url {url:?} must start with http:// or https://"
            )));
        }

        // 5. allowed_origins scheme
        for origin in &self.allowed_origins {
            if !(origin.starts_with("http://") || origin.starts_with("https://")) {
                return Err(McpxError::Config(format!(
                    "allowed_origins entry {origin:?} must start with http:// or https://"
                )));
            }
        }

        // 6. max_request_body > 0
        if self.max_request_body == 0 {
            return Err(McpxError::Config(
                "max_request_body must be greater than zero".into(),
            ));
        }

        Ok(())
    }
}

/// Handle for hot-reloading server configuration without restart.
///
/// Obtained via [`McpServerConfig::on_reload_ready`].
/// All swap operations are lock-free and wait-free -- in-flight requests
/// finish with the old values while new requests see the update immediately.
#[allow(
    missing_debug_implementations,
    reason = "contains Arc<AuthState> with non-Debug fields"
)]
pub struct ReloadHandle {
    auth: Option<Arc<AuthState>>,
    rbac: Option<Arc<ArcSwap<RbacPolicy>>>,
}

impl ReloadHandle {
    /// Atomically replace the API key list used by the auth middleware.
    pub fn reload_auth_keys(&self, keys: Vec<crate::auth::ApiKeyEntry>) {
        if let Some(ref auth) = self.auth {
            auth.reload_keys(keys);
        }
    }

    /// Atomically replace the RBAC policy used by the RBAC middleware.
    pub fn reload_rbac(&self, policy: RbacPolicy) {
        if let Some(ref rbac) = self.rbac {
            rbac.store(Arc::new(policy));
            tracing::info!("RBAC policy reloaded");
        }
    }
}

/// Generic MCP HTTP server.
///
/// Wraps an axum server with `/healthz` and `/mcp` endpoints.
/// When `tls_cert_path` and `tls_key_path` are both set, the server binds
/// with TLS (rustls). Optionally supports mTLS client certificate auth.
///
/// # Errors
///
/// Returns an error if the TCP listener cannot bind, TLS config is invalid,
/// or the server fails.
// TODO(refactor): cognitive complexity reduced from 111/25 to 83/25 by
// extracting `run_server` (serve-loop tail) and `install_oauth_proxy_routes`.
// Remaining flow is a linear router builder: middleware layering, feature-
// gated auth/RBAC wiring, and PRM/metrics installation. Further extraction
// would require threading many `&mut Router` helpers and hurt readability
// of the layer order (which is security-relevant and must stay visible).
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
/// Internal bundle of values produced by [`build_app_router`] and
/// consumed by [`serve`] / [`serve_with_listener`] when driving the
/// HTTP listener.
struct AppRunParams {
    /// TLS cert/key paths when TLS is configured.
    tls_paths: Option<(PathBuf, PathBuf)>,
    /// mTLS configuration when mutual-TLS auth is enabled.
    mtls_config: Option<MtlsConfig>,
    /// Graceful shutdown drain window.
    shutdown_timeout: Duration,
    /// Server-internal cancellation token. Cancelled by [`run_server`]
    /// once the shutdown trigger fires (so rmcp's child token also
    /// fires, terminating in-flight MCP sessions).
    ct: CancellationToken,
    /// `"http"` or `"https"` -- used only for boot-time logging.
    scheme: &'static str,
    /// Server name -- used only for boot-time logging.
    name: String,
}

/// Build the full application axum [`axum::Router`] (MCP route +
/// middleware stack + admin + OAuth + health endpoints + security
/// headers + CORS + compression + concurrency limit + origin check)
/// and the [`AppRunParams`] needed to drive it.
///
/// This is the shared core of [`serve`] and [`serve_with_listener`].
/// It performs *no* network I/O: callers are responsible for binding
/// (or accepting a pre-bound) [`TcpListener`] and invoking
/// [`run_server`].
#[allow(
    clippy::cognitive_complexity,
    reason = "router assembly is intrinsically sequential; splitting harms readability"
)]
#[allow(
    deprecated,
    reason = "internal router assembly reads deprecated `pub` config fields by design until 1.0 makes them pub(crate)"
)]
fn build_app_router<H, F>(
    mut config: McpServerConfig,
    handler_factory: F,
) -> anyhow::Result<(axum::Router, AppRunParams)>
where
    H: ServerHandler + 'static,
    F: Fn() -> H + Send + Sync + Clone + 'static,
{
    let ct = CancellationToken::new();

    let allowed_hosts = derive_allowed_hosts(&config.bind_addr, config.public_url.as_deref());
    tracing::info!(allowed_hosts = ?allowed_hosts, "configured Streamable HTTP allowed hosts");

    let mcp_service = StreamableHttpService::new(
        move || Ok(handler_factory()),
        {
            let mut mgr = LocalSessionManager::default();
            mgr.session_config.keep_alive = Some(config.session_idle_timeout);
            mgr.into()
        },
        StreamableHttpServerConfig::default()
            .with_allowed_hosts(allowed_hosts)
            .with_sse_keep_alive(Some(config.sse_keep_alive))
            .with_cancellation_token(ct.child_token()),
    );

    // Build the MCP route, optionally wrapped with auth and RBAC middleware.
    let mut mcp_router = axum::Router::new().nest_service("/mcp", mcp_service);

    // Build auth state eagerly when auth is configured so we can wire both
    // the auth middleware *and* the optional admin router against the same
    // state. The middleware itself is installed further down in layer order.
    let auth_state: Option<Arc<AuthState>> = match config.auth {
        Some(ref auth_config) if auth_config.enabled => {
            let rate_limiter = auth_config.rate_limit.as_ref().map(build_rate_limiter);
            let pre_auth_limiter = auth_config
                .rate_limit
                .as_ref()
                .map(crate::auth::build_pre_auth_limiter);

            #[cfg(feature = "oauth")]
            let jwks_cache = auth_config
                .oauth
                .as_ref()
                .map(|c| crate::oauth::JwksCache::new(c).map(Arc::new))
                .transpose()
                .map_err(|e| std::io::Error::other(format!("JWKS HTTP client: {e}")))?;

            Some(Arc::new(AuthState {
                api_keys: ArcSwap::new(Arc::new(auth_config.api_keys.clone())),
                rate_limiter,
                pre_auth_limiter,
                #[cfg(feature = "oauth")]
                jwks_cache,
                seen_identities: std::sync::Mutex::new(std::collections::HashSet::new()),
                counters: crate::auth::AuthCounters::default(),
            }))
        }
        _ => None,
    };

    // Build the RBAC policy swap early so the admin router and the later
    // RBAC middleware layer share the same hot-reloadable state.
    let rbac_swap = Arc::new(ArcSwap::new(
        config
            .rbac
            .clone()
            .unwrap_or_else(|| Arc::new(RbacPolicy::disabled())),
    ));

    // Optional /admin/* diagnostic routes. Merged BEFORE the
    // body-limit/timeout/RBAC/origin/auth layers so all of them apply.
    if config.admin_enabled {
        let Some(ref auth_state_ref) = auth_state else {
            return Err(anyhow::anyhow!(
                "admin_enabled=true requires auth to be configured and enabled"
            ));
        };
        let admin_state = crate::admin::AdminState {
            started_at: std::time::Instant::now(),
            name: config.name.clone(),
            version: config.version.clone(),
            auth: Some(Arc::clone(auth_state_ref)),
            rbac: Arc::clone(&rbac_swap),
        };
        let admin_cfg = crate::admin::AdminConfig {
            role: config.admin_role.clone(),
        };
        mcp_router = mcp_router.merge(crate::admin::admin_router(admin_state, &admin_cfg));
        tracing::info!(role = %config.admin_role, "/admin/* endpoints enabled");
    }

    // ----- Middleware order (CRITICAL: read carefully) ------------------
    //
    // axum/tower applies layers **bottom-up** at runtime: the LAST layer
    // added is the OUTERMOST (runs first on a request). To achieve a
    // request-time flow of:
    //
    //   body-limit -> timeout -> auth -> rbac -> handler
    //
    // we add layers in the REVERSE order:
    //
    //   1. RBAC               (innermost, runs last before handler)
    //   2. auth               (parses identity, sets extension for RBAC)
    //   3. timeout            (bounds total request time)
    //   4. body-limit         (outermost on /mcp; caps payload before
    //                          anything else reads/buffers it)
    //
    // Origin validation is installed on the OUTER router (after the
    // /mcp router is merged in), so it also protects /healthz, /readyz,
    // /version, and any OAuth proxy endpoints.
    //
    // Rationale:
    // - Body-limit must be outermost on /mcp so RBAC (which reads the
    //   JSON-RPC body) cannot be DoS'd by a 100MB payload.
    // - Auth must run before RBAC because RBAC consumes
    //   `req.extensions().get::<AuthIdentity>()` to enforce per-role
    //   policy.
    // - Origin runs before auth so we reject cross-origin requests
    //   without spending Argon2 cycles on unauthenticated callers.

    // [1] RBAC + tool rate-limit layer (innermost; closest to handler).
    // Always installed: even when RBAC is disabled, tool rate limiting may
    // be active (MCP spec: servers MUST rate limit tool invocations).
    {
        let tool_limiter: Option<Arc<ToolRateLimiter>> =
            config.tool_rate_limit.map(build_tool_rate_limiter);

        if rbac_swap.load().is_enabled() {
            tracing::info!("RBAC enforcement enabled on /mcp");
        }
        if let Some(limit) = config.tool_rate_limit {
            tracing::info!(limit, "tool rate limiting enabled (calls/min per IP)");
        }

        let rbac_for_mw = Arc::clone(&rbac_swap);
        mcp_router = mcp_router.layer(axum::middleware::from_fn(move |req, next| {
            let p = rbac_for_mw.load_full();
            let tl = tool_limiter.clone();
            rbac_middleware(p, tl, req, next)
        }));
    }

    // [2] Auth layer (runs before RBAC so AuthIdentity is in extensions).
    if let Some(ref auth_config) = config.auth
        && auth_config.enabled
    {
        let Some(ref state) = auth_state else {
            return Err(anyhow::anyhow!("auth state missing despite enabled config"));
        };

        let methods: Vec<&str> = [
            auth_config.mtls.is_some().then_some("mTLS"),
            (!auth_config.api_keys.is_empty()).then_some("bearer"),
            #[cfg(feature = "oauth")]
            auth_config.oauth.is_some().then_some("oauth-jwt"),
        ]
        .into_iter()
        .flatten()
        .collect();

        tracing::info!(
            methods = %methods.join(", "),
            api_keys = auth_config.api_keys.len(),
            "auth enabled on /mcp"
        );

        // Deliver reload handle to caller before capturing state in middleware.
        if let Some(cb) = config.on_reload_ready.take() {
            cb(ReloadHandle {
                auth: Some(Arc::clone(state)),
                rbac: Some(Arc::clone(&rbac_swap)),
            });
        }

        let state_for_mw = Arc::clone(state);
        mcp_router = mcp_router.layer(axum::middleware::from_fn(move |req, next| {
            let s = Arc::clone(&state_for_mw);
            auth_middleware(s, req, next)
        }));
    } else if let Some(cb) = config.on_reload_ready.take() {
        // Auth disabled but caller wants reload handle (RBAC-only reload).
        cb(ReloadHandle {
            auth: None,
            rbac: Some(Arc::clone(&rbac_swap)),
        });
    }

    // [3] Request timeout (returns 408 on expiry). Bounds total request
    // duration including auth + handler.
    mcp_router = mcp_router.layer(tower_http::timeout::TimeoutLayer::with_status_code(
        axum::http::StatusCode::REQUEST_TIMEOUT,
        config.request_timeout,
    ));

    // [4] Request body size limit (OUTERMOST on /mcp). Prevents OOM /
    // DoS from oversized payloads BEFORE any inner layer (auth, RBAC)
    // attempts to buffer or parse the body.
    mcp_router = mcp_router.layer(tower_http::limit::RequestBodyLimitLayer::new(
        config.max_request_body,
    ));

    // Compute the effective allowed-origins list for the outer
    // origin-check layer (installed on the merged router below). When
    // `allowed_origins` is empty but `public_url` is set, auto-derive
    // the origin from the public URL so MCP clients (e.g. Claude Code)
    // that send `Origin: <server-url>` are accepted without explicit
    // config.
    let mut effective_origins = config.allowed_origins.clone();
    if effective_origins.is_empty()
        && let Some(ref url) = config.public_url
    {
        // Origin = scheme + "://" + host (+ ":" + port if non-default).
        // Strip any path/query from the public URL.
        if let Some(scheme_end) = url.find("://") {
            let after_scheme = &url[scheme_end + 3..];
            let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
            let origin = format!("{}{}", &url[..scheme_end + 3], &after_scheme[..host_end]);
            tracing::info!(
                %origin,
                "auto-derived allowed origin from public_url"
            );
            effective_origins.push(origin);
        }
    }
    let allowed_origins: Arc<[String]> = Arc::from(effective_origins);
    let cors_origins = Arc::clone(&allowed_origins);
    let log_request_headers = config.log_request_headers;

    let readyz_route = if let Some(check) = config.readiness_check.take() {
        axum::routing::get(move || readyz(Arc::clone(&check)))
    } else {
        axum::routing::get(healthz)
    };

    #[allow(unused_mut)] // mut needed when oauth feature adds PRM route
    let mut router = axum::Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/readyz", readyz_route)
        .route(
            "/version",
            axum::routing::get({
                // Pre-serialize the version payload once at router-build
                // time. The handler then serves a cheap `Arc::clone` of the
                // immutable bytes per request, avoiding `serde_json::Value`
                // allocation + serialization on every `/version` hit.
                let payload_bytes: Arc<[u8]> =
                    serialize_version_payload(&config.name, &config.version);
                move || {
                    let p = Arc::clone(&payload_bytes);
                    async move {
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            p.to_vec(),
                        )
                    }
                }
            }),
        )
        .merge(mcp_router);

    // Merge application-specific routes (bypass MCP auth/RBAC middleware).
    if let Some(extra) = config.extra_router.take() {
        router = router.merge(extra);
    }

    // RFC 9728: Protected Resource Metadata endpoint.
    // When OAuth is configured, serve full metadata with authorization_servers.
    // Otherwise, serve a minimal document with just the resource URL and no
    // authorization_servers -- this tells MCP clients (e.g. Claude Code SDK)
    // that the server exists but does NOT require OAuth authentication,
    // preventing them from gating the connection behind a broken auth flow.
    let server_url = if let Some(ref url) = config.public_url {
        url.trim_end_matches('/').to_owned()
    } else {
        let prm_scheme = if config.tls_cert_path.is_some() {
            "https"
        } else {
            "http"
        };
        format!("{prm_scheme}://{}", config.bind_addr)
    };
    let resource_url = format!("{server_url}/mcp");

    #[cfg(feature = "oauth")]
    let prm_metadata = if let Some(ref auth_config) = config.auth
        && let Some(ref oauth_config) = auth_config.oauth
    {
        crate::oauth::protected_resource_metadata(&resource_url, &server_url, oauth_config)
    } else {
        serde_json::json!({ "resource": resource_url })
    };
    #[cfg(not(feature = "oauth"))]
    let prm_metadata = serde_json::json!({ "resource": resource_url });

    router = router.route(
        "/.well-known/oauth-protected-resource",
        axum::routing::get(move || {
            let m = prm_metadata.clone();
            async move { axum::Json(m) }
        }),
    );

    // OAuth 2.1 proxy endpoints: when an OAuth proxy is configured, expose
    // /authorize, /token, /register, and authorization server metadata so
    // MCP clients can perform Authorization Code + PKCE against the upstream
    // IdP (e.g. Keycloak) transparently.
    #[cfg(feature = "oauth")]
    if let Some(ref auth_config) = config.auth
        && let Some(ref oauth_config) = auth_config.oauth
        && oauth_config.proxy.is_some()
    {
        router = install_oauth_proxy_routes(router, &server_url, oauth_config)?;
    }

    // OWASP security response headers (applied to all responses).
    // HSTS is conditional on TLS being configured.
    let is_tls = config.tls_cert_path.is_some();
    router = router.layer(axum::middleware::from_fn(move |req, next| {
        security_headers_middleware(is_tls, req, next)
    }));

    // CORS preflight layer (required for browser-based MCP clients).
    // Uses the same effective origins as the origin check middleware
    // (including auto-derived origin from public_url).
    if !cors_origins.is_empty() {
        let cors = tower_http::cors::CorsLayer::new()
            .allow_origin(
                cors_origins
                    .iter()
                    .filter_map(|o| o.parse::<axum::http::HeaderValue>().ok())
                    .collect::<Vec<_>>(),
            )
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
            ]);
        router = router.layer(cors);
    }

    // Optional response compression (gzip + brotli). Skips small bodies
    // to avoid overhead. Applied after CORS so preflight responses remain
    // uncompressed.
    if config.compression_enabled {
        use tower_http::compression::Predicate as _;
        let predicate = tower_http::compression::DefaultPredicate::new().and(
            tower_http::compression::predicate::SizeAbove::new(config.compression_min_size),
        );
        router = router.layer(
            tower_http::compression::CompressionLayer::new()
                .gzip(true)
                .br(true)
                .compress_when(predicate),
        );
        tracing::info!(
            min_size = config.compression_min_size,
            "response compression enabled (gzip, br)"
        );
    }

    // Optional global concurrency cap. `load_shed` converts the
    // `ConcurrencyLimit` back-pressure error into 503 instead of hanging.
    if let Some(max) = config.max_concurrent_requests {
        let overload_handler = tower::ServiceBuilder::new()
            .layer(axum::error_handling::HandleErrorLayer::new(
                |_err: tower::BoxError| async {
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(serde_json::json!({
                            "error": "overloaded",
                            "error_description": "server is at capacity, retry later"
                        })),
                    )
                },
            ))
            .layer(tower::load_shed::LoadShedLayer::new())
            .layer(tower::limit::ConcurrencyLimitLayer::new(max));
        router = router.layer(overload_handler);
        tracing::info!(max, "global concurrency limit enabled");
    }

    // JSON fallback for unmatched routes. Without this, axum returns
    // an empty-body 404 that breaks MCP clients (e.g. Claude Code SDK)
    // when they probe OAuth endpoints like /authorize or /token.
    router = router.fallback(|| async {
        (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": "not_found",
                "error_description": "The requested endpoint does not exist"
            })),
        )
    });

    // Prometheus metrics: recording middleware + separate listener.
    #[cfg(feature = "metrics")]
    if config.metrics_enabled {
        let metrics = Arc::new(
            crate::metrics::McpMetrics::new().map_err(|e| anyhow::anyhow!("metrics init: {e}"))?,
        );
        let m = Arc::clone(&metrics);
        router = router.layer(axum::middleware::from_fn(
            move |req: Request<Body>, next: Next| {
                let m = Arc::clone(&m);
                metrics_middleware(m, req, next)
            },
        ));
        let metrics_bind = config.metrics_bind.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::metrics::serve_metrics(metrics_bind, metrics).await {
                tracing::error!("metrics listener failed: {e}");
            }
        });
    }

    // Origin validation layer (MCP spec: servers MUST validate the
    // Origin header to prevent DNS rebinding attacks). Installed as the
    // OUTERMOST layer on the OUTER router so it protects ALL routes
    // (`/mcp`, `/healthz`, `/readyz`, `/version`, OAuth proxy endpoints,
    // admin endpoints, extra_router, etc.) and runs BEFORE auth so we
    // reject cross-origin attackers without spending Argon2 cycles.
    //
    // Origin-less requests (e.g. server-to-server probes, curl, native
    // MCP clients) are permitted; only requests with an Origin header
    // that does not match `effective_origins` are rejected.
    router = router.layer(axum::middleware::from_fn(move |req, next| {
        let origins = Arc::clone(&allowed_origins);
        origin_check_middleware(origins, log_request_headers, req, next)
    }));

    let scheme = if config.tls_cert_path.is_some() {
        "https"
    } else {
        "http"
    };

    let tls_paths = match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
        _ => None,
    };
    let mtls_config = config.auth.as_ref().and_then(|a| a.mtls.as_ref()).cloned();

    Ok((
        router,
        AppRunParams {
            tls_paths,
            mtls_config,
            shutdown_timeout: config.shutdown_timeout,
            ct,
            scheme,
            name: config.name.clone(),
        },
    ))
}

/// Run the MCP HTTP server, binding to `config.bind_addr` and serving
/// until an OS shutdown signal (Ctrl-C / SIGTERM) is received.
///
/// This is the standard entry point for production deployments. For
/// deterministic shutdown control (e.g. integration tests), see
/// [`serve_with_listener`].
///
/// The configuration must be validated first via
/// [`McpServerConfig::validate`], which returns a [`Validated`] proof
/// token. This typestate guarantees, at compile time, that the server
/// never starts with an invalid configuration.
///
/// # Errors
///
/// Returns [`McpxError::Startup`] if binding to `config.bind_addr`
/// fails, or if the underlying axum server returns an error.
pub async fn serve<H, F>(
    config: Validated<McpServerConfig>,
    handler_factory: F,
) -> Result<(), McpxError>
where
    H: ServerHandler + 'static,
    F: Fn() -> H + Send + Sync + Clone + 'static,
{
    let config = config.into_inner();
    #[allow(
        deprecated,
        reason = "internal serve() reads `bind_addr` to construct the listener; field becomes pub(crate) in 1.0"
    )]
    let bind_addr = config.bind_addr.clone();
    let (router, params) = build_app_router(config, handler_factory).map_err(anyhow_to_startup)?;

    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| io_to_startup(&format!("bind {bind_addr}"), e))?;
    log_listening(&params.name, params.scheme, &bind_addr);

    run_server(
        router,
        listener,
        params.tls_paths,
        params.mtls_config,
        params.shutdown_timeout,
        params.ct,
    )
    .await
    .map_err(anyhow_to_startup)
}

/// Run the MCP HTTP server on a pre-bound [`TcpListener`], with optional
/// readiness signalling and external shutdown control.
///
/// This variant is intended for **deterministic integration tests** and
/// for embedders that need to bind the listening socket themselves
/// (e.g. systemd socket activation). Compared to [`serve`]:
///
/// * The caller passes a `TcpListener` that is already bound. This
///   eliminates the bind race in tests that previously required
///   poll-the-`/healthz`-loop start-up detection.
/// * `ready_tx`, when `Some`, receives the socket's
///   [`SocketAddr`] *after* the router is built and immediately before
///   the server starts accepting connections. Tests can `await` the
///   matching `oneshot::Receiver` to know exactly when it is safe to
///   issue requests.
/// * `shutdown`, when `Some`, gives the caller a
///   [`CancellationToken`] that triggers the same graceful-shutdown
///   path as a real OS signal. This avoids cross-platform issues with
///   sending real `SIGTERM` from tests on Windows.
///
/// All three optional parameters degrade gracefully: if `ready_tx` is
/// `None`, no signal is sent; if `shutdown` is `None`, the server only
/// stops on an OS signal (just like [`serve`]).
///
/// # Errors
///
/// Returns [`McpxError::Startup`] if router construction fails, if reading
/// the listener's `local_addr()` fails, or if the underlying axum
/// server returns an error.
pub async fn serve_with_listener<H, F>(
    listener: TcpListener,
    config: Validated<McpServerConfig>,
    handler_factory: F,
    ready_tx: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
    shutdown: Option<CancellationToken>,
) -> Result<(), McpxError>
where
    H: ServerHandler + 'static,
    F: Fn() -> H + Send + Sync + Clone + 'static,
{
    let config = config.into_inner();
    let local_addr = listener
        .local_addr()
        .map_err(|e| io_to_startup("listener.local_addr", e))?;
    let (router, params) = build_app_router(config, handler_factory).map_err(anyhow_to_startup)?;

    log_listening(&params.name, params.scheme, &local_addr.to_string());

    // Forward external shutdown into the server-internal cancellation
    // token so `run_server`'s shutdown trigger picks it up alongside
    // any real OS signal.
    if let Some(external) = shutdown {
        let internal = params.ct.clone();
        tokio::spawn(async move {
            external.cancelled().await;
            internal.cancel();
        });
    }

    // Signal readiness *after* the router is fully built and external
    // shutdown is wired, but *before* run_server takes ownership of
    // the listener. The receiver can immediately issue requests.
    if let Some(tx) = ready_tx {
        // Receiver may have been dropped (test gave up). That's fine.
        let _ = tx.send(local_addr);
    }

    run_server(
        router,
        listener,
        params.tls_paths,
        params.mtls_config,
        params.shutdown_timeout,
        params.ct,
    )
    .await
    .map_err(anyhow_to_startup)
}

/// Emit the standard "listening on …" log lines used by both
/// [`serve`] and [`serve_with_listener`].
#[allow(
    clippy::cognitive_complexity,
    reason = "tracing::info! macro expansions inflate the score; logic is trivial"
)]
fn log_listening(name: &str, scheme: &str, addr: &str) {
    tracing::info!("{name} listening on {addr}");
    tracing::info!("  MCP endpoint: {scheme}://{addr}/mcp");
    tracing::info!("  Health check: {scheme}://{addr}/healthz");
    tracing::info!("  Readiness:   {scheme}://{addr}/readyz");
}

/// Drive the chosen axum server variant (TLS or plain) with a graceful
/// shutdown window. Consumes the router and listener.
///
/// # Shutdown semantics
///
/// A single shutdown trigger (the FIRST of: OS signal via
/// `shutdown_signal()`, or external cancellation of `ct`) starts BOTH:
///
/// 1. axum's `.with_graceful_shutdown(...)` future, which stops
///    accepting new connections and waits for in-flight requests to
///    drain;
/// 2. a `tokio::time::sleep(shutdown_timeout)` race that forces exit if
///    drainage exceeds `shutdown_timeout`.
///
/// Previously this function awaited `shutdown_signal()` independently
/// in BOTH branches of a `tokio::select!`. Because `shutdown_signal`
/// resolves once per future and consumes one signal, the force-exit
/// timer was tied to a SECOND signal (a second SIGTERM the operator
/// would never send). Under a single SIGTERM the graceful drain could
/// hang indefinitely. The current implementation derives both branches
/// from a single shared trigger so the timeout race is anchored to the
/// FIRST (and only) signal.
async fn run_server(
    router: axum::Router,
    listener: TcpListener,
    tls_paths: Option<(PathBuf, PathBuf)>,
    mtls_config: Option<MtlsConfig>,
    shutdown_timeout: Duration,
    ct: CancellationToken,
) -> anyhow::Result<()> {
    // `shutdown_trigger` fires when the FIRST source resolves: either
    // an OS signal (Ctrl-C / SIGTERM) or external cancellation of `ct`
    // (which the test harness uses for deterministic shutdown).
    let shutdown_trigger = CancellationToken::new();
    {
        let trigger = shutdown_trigger.clone();
        let parent = ct.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = shutdown_signal() => {}
                () = parent.cancelled() => {}
            }
            trigger.cancel();
        });
    }

    let graceful = {
        let trigger = shutdown_trigger.clone();
        let ct = ct.clone();
        async move {
            trigger.cancelled().await;
            tracing::info!("shutting down (grace period: {shutdown_timeout:?})");
            ct.cancel();
        }
    };

    let force_exit_timer = {
        let trigger = shutdown_trigger.clone();
        async move {
            trigger.cancelled().await;
            tokio::time::sleep(shutdown_timeout).await;
        }
    };

    if let Some((cert_path, key_path)) = tls_paths {
        let tls_listener = TlsListener::new(listener, &cert_path, &key_path, mtls_config.as_ref())?;
        let make_svc = router.into_make_service_with_connect_info::<TlsConnInfo>();
        tokio::select! {
            result = axum::serve(tls_listener, make_svc)
                .with_graceful_shutdown(graceful) => { result?; }
            () = force_exit_timer => {
                tracing::warn!("shutdown timeout exceeded, forcing exit");
            }
        }
    } else {
        let make_svc = router.into_make_service_with_connect_info::<SocketAddr>();
        tokio::select! {
            result = axum::serve(listener, make_svc)
                .with_graceful_shutdown(graceful) => { result?; }
            () = force_exit_timer => {
                tracing::warn!("shutdown timeout exceeded, forcing exit");
            }
        }
    }

    Ok(())
}

/// Install the OAuth 2.1 proxy endpoints (`/authorize`, `/token`,
/// `/register`, and authorization server metadata) on `router`. The
/// caller must ensure `oauth_config.proxy` is `Some`.
///
/// # Errors
///
/// Returns [`McpxError::Startup`] if the shared
/// [`crate::oauth::OauthHttpClient`] cannot be initialized.
#[cfg(feature = "oauth")]
fn install_oauth_proxy_routes(
    router: axum::Router,
    server_url: &str,
    oauth_config: &crate::oauth::OAuthConfig,
) -> Result<axum::Router, McpxError> {
    let Some(ref proxy) = oauth_config.proxy else {
        return Ok(router);
    };

    // Single shared HTTP client for all proxy endpoints. Cloning is
    // cheap (refcounted) and shares the underlying connection pool.
    let http = crate::oauth::OauthHttpClient::new()?;

    let asm = crate::oauth::authorization_server_metadata(server_url, oauth_config);
    let router = router.route(
        "/.well-known/oauth-authorization-server",
        axum::routing::get(move || {
            let m = asm.clone();
            async move { axum::Json(m) }
        }),
    );

    let proxy_authorize = proxy.clone();
    let router = router.route(
        "/authorize",
        axum::routing::get(
            move |axum::extract::RawQuery(query): axum::extract::RawQuery| {
                let p = proxy_authorize.clone();
                async move { crate::oauth::handle_authorize(&p, &query.unwrap_or_default()) }
            },
        ),
    );

    let proxy_token = proxy.clone();
    let token_http = http.clone();
    let router = router.route(
        "/token",
        axum::routing::post(move |body: String| {
            let p = proxy_token.clone();
            let h = token_http.clone();
            async move { crate::oauth::handle_token(&h, &p, &body).await }
        }),
    );

    let proxy_register = proxy.clone();
    let router = router.route(
        "/register",
        axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
            let p = proxy_register;
            async move { axum::Json(crate::oauth::handle_register(&p, &body)) }
        }),
    );

    let router = if proxy.expose_admin_endpoints && proxy.introspection_url.is_some() {
        let proxy_introspect = proxy.clone();
        let introspect_http = http.clone();
        router.route(
            "/introspect",
            axum::routing::post(move |body: String| {
                let p = proxy_introspect.clone();
                let h = introspect_http.clone();
                async move { crate::oauth::handle_introspect(&h, &p, &body).await }
            }),
        )
    } else {
        router
    };

    let router = if proxy.expose_admin_endpoints && proxy.revocation_url.is_some() {
        let proxy_revoke = proxy.clone();
        let revoke_http = http;
        router.route(
            "/revoke",
            axum::routing::post(move |body: String| {
                let p = proxy_revoke.clone();
                let h = revoke_http.clone();
                async move { crate::oauth::handle_revoke(&h, &p, &body).await }
            }),
        )
    } else {
        router
    };

    tracing::info!(
        introspect = proxy.expose_admin_endpoints && proxy.introspection_url.is_some(),
        revoke = proxy.expose_admin_endpoints && proxy.revocation_url.is_some(),
        "OAuth 2.1 proxy endpoints enabled (/authorize, /token, /register)"
    );
    Ok(router)
}

/// Build the host allow-list for rmcp's DNS rebinding protection.
///
/// Includes loopback hosts by default, then augments with host/authority
/// derived from `public_url` and the server bind address.
fn derive_allowed_hosts(bind_addr: &str, public_url: Option<&str>) -> Vec<String> {
    let mut hosts = vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ];

    if let Some(url) = public_url
        && let Ok(uri) = url.parse::<axum::http::Uri>()
        && let Some(authority) = uri.authority()
    {
        let host = authority.host().to_owned();
        if !hosts.iter().any(|h| h == &host) {
            hosts.push(host);
        }

        let authority = authority.as_str().to_owned();
        if !hosts.iter().any(|h| h == &authority) {
            hosts.push(authority);
        }
    }

    if let Ok(uri) = format!("http://{bind_addr}").parse::<axum::http::Uri>()
        && let Some(authority) = uri.authority()
    {
        let host = authority.host().to_owned();
        if !hosts.iter().any(|h| h == &host) {
            hosts.push(host);
        }

        let authority = authority.as_str().to_owned();
        if !hosts.iter().any(|h| h == &authority) {
            hosts.push(authority);
        }
    }

    hosts
}

// - TLS support -

/// Implement axum's `Connected` trait for `TlsConnInfo` so that
/// `ConnectInfo<TlsConnInfo>` is available in middleware when serving
/// over our custom `TlsListener`.
///
/// The identity is read directly from the wrapping
/// [`AuthenticatedTlsStream`], which guarantees one-to-one correspondence
/// between the TLS connection and its mTLS identity. This eliminates the
/// previous shared-map approach which was vulnerable to ephemeral-port
/// reuse races (an unauthenticated reconnection from the same `(IP, port)`
/// pair could alias a stale entry).
impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TlsListener>>
    for TlsConnInfo
{
    fn connect_info(target: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        let addr = *target.remote_addr();
        let identity = target.io().identity().cloned();
        TlsConnInfo::new(addr, identity)
    }
}

/// A TLS-wrapping listener that implements axum's `Listener` trait.
///
/// When mTLS is configured, verifies client certificates against the
/// configured CA and extracts the client identity at handshake time.
/// The extracted identity is bound to the connection itself via the
/// returned [`AuthenticatedTlsStream`], so it is impossible for an
/// unrelated connection to observe it.
struct TlsListener {
    inner: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    mtls_default_role: String,
}

impl TlsListener {
    fn new(
        inner: TcpListener,
        cert_path: &Path,
        key_path: &Path,
        mtls_config: Option<&MtlsConfig>,
    ) -> anyhow::Result<Self> {
        // Install the ring crypto provider (ok to call multiple times).
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let certs = load_certs(cert_path)?;
        let key = load_key(key_path)?;

        let mtls_default_role;

        let tls_config = if let Some(mtls) = mtls_config {
            mtls_default_role = mtls.default_role.clone();
            let ca_certs = load_certs(&mtls.ca_cert_path)?;
            let mut root_store = rustls::RootCertStore::empty();
            for cert in &ca_certs {
                root_store
                    .add(cert.clone())
                    .map_err(|e| anyhow::anyhow!("invalid CA cert: {e}"))?;
            }
            let verifier = if mtls.required {
                rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                    .build()
                    .map_err(|e| anyhow::anyhow!("mTLS verifier error: {e}"))?
            } else {
                rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                    .allow_unauthenticated()
                    .build()
                    .map_err(|e| anyhow::anyhow!("mTLS verifier error: {e}"))?
            };

            tracing::info!(
                ca = %mtls.ca_cert_path.display(),
                required = mtls.required,
                "mTLS client auth configured"
            );

            rustls::ServerConfig::builder_with_protocol_versions(&[
                &rustls::version::TLS12,
                &rustls::version::TLS13,
            ])
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?
        } else {
            mtls_default_role = "viewer".to_owned();
            rustls::ServerConfig::builder_with_protocol_versions(&[
                &rustls::version::TLS12,
                &rustls::version::TLS13,
            ])
            .with_no_client_auth()
            .with_single_cert(certs, key)?
        };

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
        tracing::info!(
            "TLS enabled (cert: {}, key: {})",
            cert_path.display(),
            key_path.display()
        );
        Ok(Self {
            inner,
            acceptor,
            mtls_default_role,
        })
    }

    /// Extract the mTLS client cert identity from a completed TLS handshake.
    /// Returns `None` if no client certificate was presented or if the
    /// certificate could not be parsed into an [`AuthIdentity`].
    fn extract_handshake_identity(
        tls_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        default_role: &str,
        addr: SocketAddr,
    ) -> Option<AuthIdentity> {
        let (_, server_conn) = tls_stream.get_ref();
        let cert_der = server_conn.peer_certificates()?.first()?;
        let id = extract_mtls_identity(cert_der.as_ref(), default_role)?;
        tracing::debug!(name = %id.name, peer = %addr, "mTLS client cert accepted");
        Some(id)
    }
}

/// A TLS stream paired with the mTLS identity extracted at handshake time.
///
/// Wraps [`tokio_rustls::server::TlsStream`] so the verified client
/// identity travels with the connection itself. This replaces the previous
/// shared `MtlsIdentities` map, eliminating the
/// `(SocketAddr) -> AuthIdentity` aliasing risk caused by ephemeral-port
/// reuse and removing the need for an LRU eviction policy.
///
/// The wrapper is `Unpin` (its inner stream is `Unpin` because
/// [`tokio::net::TcpStream`] is `Unpin`), so `AsyncRead`/`AsyncWrite`
/// delegation uses safe pin projection via `Pin::new(&mut self.inner)`.
pub(crate) struct AuthenticatedTlsStream {
    inner: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    identity: Option<AuthIdentity>,
}

impl AuthenticatedTlsStream {
    /// Returns the verified mTLS client identity, if any.
    #[must_use]
    pub(crate) const fn identity(&self) -> Option<&AuthIdentity> {
        self.identity.as_ref()
    }
}

impl std::fmt::Debug for AuthenticatedTlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedTlsStream")
            .field("identity", &self.identity.as_ref().map(|id| &id.name))
            .finish_non_exhaustive()
    }
}

impl tokio::io::AsyncRead for AuthenticatedTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for AuthenticatedTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = AuthenticatedTlsStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.inner.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::debug!("TCP accept error: {e}");
                    continue;
                }
            };
            let tls_stream = match self.acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("TLS handshake failed from {addr}: {e}");
                    continue;
                }
            };
            let identity =
                Self::extract_handshake_identity(&tls_stream, &self.mtls_default_role, addr);
            let wrapped = AuthenticatedTlsStream {
                inner: tls_stream,
                identity,
            };
            return (wrapped, addr);
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_file_iter(path)
        .map_err(|e| anyhow::anyhow!("failed to read certs from {}: {e}", path.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("invalid cert in {}: {e}", path.display()))?;
    anyhow::ensure!(
        !certs.is_empty(),
        "no certificates found in {}",
        path.display()
    );
    Ok(certs)
}

fn load_key(path: &Path) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::PrivateKeyDer::from_pem_file(path)
        .map_err(|e| anyhow::anyhow!("failed to read key from {}: {e}", path.display()))
}

#[allow(clippy::unused_async)]
async fn healthz() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
    }))
}

/// Build the `/version` JSON payload for a given server name and version.
///
/// Build metadata (`build_git_sha`, `build_timestamp`, `rust_version`) is
/// read at compile time from the `MCPX_BUILD_SHA`, `MCPX_BUILD_TIME`, and
/// `MCPX_RUSTC_VERSION` env vars. Unset values resolve to `"unknown"`.
fn version_payload(name: &str, version: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "version": version,
        "build_git_sha": option_env!("MCPX_BUILD_SHA").unwrap_or("unknown"),
        "build_timestamp": option_env!("MCPX_BUILD_TIME").unwrap_or("unknown"),
        "rust_version": option_env!("MCPX_RUSTC_VERSION").unwrap_or("unknown"),
        "mcpx_version": env!("CARGO_PKG_VERSION"),
    })
}

/// Pre-serialize the `/version` payload to immutable bytes.
///
/// This is called once at router-build time so per-request handling can
/// reuse a cheap `Arc<[u8]>` clone instead of re-serializing a
/// [`serde_json::Value`] on every hit.
///
/// Serialization of a flat `serde_json::Value` of static-string fields
/// cannot fail in practice; the fallback to `b"{}"` exists only to
/// satisfy the crate-wide `unwrap_used` / `expect_used` lint policy.
fn serialize_version_payload(name: &str, version: &str) -> Arc<[u8]> {
    let value = version_payload(name, version);
    serde_json::to_vec(&value).map_or_else(|_| Arc::from(&b"{}"[..]), Arc::from)
}

async fn readyz(check: ReadinessCheck) -> impl IntoResponse {
    let status = check().await;
    let ready = status
        .get("ready")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let code = if ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (code, axum::Json(status))
}

/// Wait for SIGINT (ctrl-c) or SIGTERM (container stop).
///
/// On non-Unix platforms, only SIGINT is handled.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to register SIGTERM handler, using SIGINT only");
                ctrl_c.await.ok();
            }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}

// -- Origin validation (MCP 2025-11-25 spec, section 2.0.1) --

/// Middleware that validates the `Origin` header on incoming HTTP requests.
///
/// Record HTTP request metrics (method, path, status, duration).
#[cfg(feature = "metrics")]
async fn metrics_middleware(
    metrics: Arc<crate::metrics::McpMetrics>,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let start = std::time::Instant::now();

    let response = next.run(req).await;

    let status = response.status().as_u16().to_string();
    let duration = start.elapsed().as_secs_f64();

    metrics
        .http_requests_total
        .with_label_values(&[&method, &path, &status])
        .inc();
    metrics
        .http_request_duration_seconds
        .with_label_values(&[&method, &path])
        .observe(duration);

    response
}

/// OWASP security header hardening applied to every response.
///
/// Sets: `X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control`,
/// `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`,
/// `Cross-Origin-Embedder-Policy`, `Permissions-Policy`,
/// `X-Permitted-Cross-Domain-Policies`, `Content-Security-Policy`,
/// `X-DNS-Prefetch-Control`, and (when TLS is active) `Strict-Transport-Security`.
async fn security_headers_middleware(
    is_tls: bool,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    use axum::http::{HeaderName, HeaderValue, header};

    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();

    // Strip server identity headers to reduce information leakage.
    headers.remove(header::SERVER);
    headers.remove(HeaderName::from_static("x-powered-by"));

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("deny"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-embedder-policy"),
        HeaderValue::from_static("require-corp"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("accelerometer=(), camera=(), geolocation=(), microphone=()"),
    );
    headers.insert(
        HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert(
        HeaderName::from_static("x-dns-prefetch-control"),
        HeaderValue::from_static("off"),
    );

    if is_tls {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
    }

    resp
}

/// Per the MCP spec: if the Origin header is present and its value is not in
/// the allowed list, respond with 403 Forbidden. Requests without an Origin
/// header are allowed through (e.g. non-browser clients like curl, SDKs).
async fn origin_check_middleware(
    allowed: Arc<[String]>,
    log_request_headers: bool,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    log_incoming_request(&method, &path, req.headers(), log_request_headers);

    if let Some(origin) = req.headers().get(axum::http::header::ORIGIN) {
        let origin_str = origin.to_str().unwrap_or("");
        if !allowed.iter().any(|a| a == origin_str) {
            tracing::warn!(
                origin = origin_str,
                %method,
                %path,
                allowed = ?&*allowed,
                "rejected request: Origin not allowed"
            );
            return (
                axum::http::StatusCode::FORBIDDEN,
                "Forbidden: Origin not allowed",
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Emit a DEBUG log for an incoming request, optionally including the full
/// (redacted) header set.
fn log_incoming_request(
    method: &axum::http::Method,
    path: &str,
    headers: &axum::http::HeaderMap,
    log_request_headers: bool,
) {
    if log_request_headers {
        tracing::debug!(
            %method,
            %path,
            headers = %format_request_headers_for_log(headers),
            "incoming request"
        );
    } else {
        tracing::debug!(%method, %path, "incoming request");
    }
}

fn format_request_headers_for_log(headers: &axum::http::HeaderMap) -> String {
    headers
        .iter()
        .map(|(k, v)| {
            let name = k.as_str();
            if name == "authorization" || name == "cookie" || name == "proxy-authorization" {
                format!("{name}: [REDACTED]")
            } else {
                format!("{name}: {}", v.to_str().unwrap_or("<non-utf8>"))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// -- stdio transport --

/// Serve an MCP server over stdin/stdout (stdio transport).
///
/// # Security warnings
///
/// - **No authentication**: the parent process has full, unrestricted access.
/// - **No RBAC**: all tools are available regardless of policy.
/// - **No TLS**: messages travel over OS pipes in plaintext.
/// - **Single client**: only the parent process can connect.
/// - **No Origin validation**: not applicable to stdio.
///
/// Use this only when the MCP client spawns the server as a trusted subprocess
/// (e.g. Claude Desktop, VS Code Copilot). For network-accessible deployments,
/// use `serve()` (Streamable HTTP) instead.
///
/// # Errors
///
/// Returns [`McpxError::Startup`] if the handler fails to initialize or the
/// transport disconnects unexpectedly.
// NOTE: reported complexity 32/25 is driven entirely by `tracing::*!`
// macro expansion in this 18-line function (info/warn/info + two matches).
// There is nothing meaningful to extract; the allow stays.
#[allow(clippy::cognitive_complexity)]
pub async fn serve_stdio<H>(handler: H) -> Result<(), McpxError>
where
    H: ServerHandler + 'static,
{
    use rmcp::ServiceExt as _;

    tracing::info!("stdio transport: serving on stdin/stdout");
    tracing::warn!("stdio mode: auth, RBAC, TLS, and Origin checks are DISABLED");

    let transport = rmcp::transport::io::stdio();

    let service = handler
        .serve(transport)
        .await
        .map_err(|e| McpxError::Startup(format!("stdio initialize failed: {e}")))?;

    if let Err(e) = service.waiting().await {
        tracing::warn!(error = %e, "stdio session ended with error");
    }
    tracing::info!("stdio session ended");
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unwrap_in_result,
        clippy::print_stdout,
        clippy::print_stderr,
        deprecated,
        reason = "internal unit tests legitimately read/write the deprecated `pub` fields they were designed to verify"
    )]
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
        response::IntoResponse,
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt as _;

    use super::*;

    // -- McpServerConfig --

    #[test]
    fn server_config_new_defaults() {
        let cfg = McpServerConfig::new("0.0.0.0:8443", "test-server", "1.0.0");
        assert_eq!(cfg.bind_addr, "0.0.0.0:8443");
        assert_eq!(cfg.name, "test-server");
        assert_eq!(cfg.version, "1.0.0");
        assert!(cfg.tls_cert_path.is_none());
        assert!(cfg.tls_key_path.is_none());
        assert!(cfg.auth.is_none());
        assert!(cfg.rbac.is_none());
        assert!(cfg.allowed_origins.is_empty());
        assert!(cfg.tool_rate_limit.is_none());
        assert!(cfg.readiness_check.is_none());
        assert_eq!(cfg.max_request_body, 1024 * 1024);
        assert_eq!(cfg.request_timeout, Duration::from_mins(2));
        assert_eq!(cfg.shutdown_timeout, Duration::from_secs(30));
        assert!(!cfg.log_request_headers);
    }

    #[test]
    fn validate_consumes_and_proves() {
        // Valid config -> Validated wrapper, original is consumed.
        let cfg = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0");
        let validated = cfg.validate().expect("valid config");
        // Deref gives read-only access to inner fields.
        assert_eq!(validated.name, "test-server");
        // into_inner recovers the raw value.
        let raw = validated.into_inner();
        assert_eq!(raw.name, "test-server");

        // Invalid config (zero max_request_body) -> Err.
        let mut bad = McpServerConfig::new("127.0.0.1:8080", "test-server", "1.0.0");
        bad.max_request_body = 0;
        assert!(bad.validate().is_err(), "zero body cap must fail validate");
    }

    #[test]
    fn derive_allowed_hosts_includes_public_host() {
        let hosts = derive_allowed_hosts("0.0.0.0:8080", Some("https://mcp.example.com/mcp"));
        assert!(
            hosts.iter().any(|h| h == "mcp.example.com"),
            "public_url host must be allowed"
        );
    }

    #[test]
    fn derive_allowed_hosts_includes_bind_authority() {
        let hosts = derive_allowed_hosts("127.0.0.1:8080", None);
        assert!(
            hosts.iter().any(|h| h == "127.0.0.1"),
            "bind host must be allowed"
        );
        assert!(
            hosts.iter().any(|h| h == "127.0.0.1:8080"),
            "bind authority must be allowed"
        );
    }

    // -- healthz --

    #[tokio::test]
    async fn healthz_returns_ok_json() {
        let resp = healthz().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
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

    // -- readyz --

    #[tokio::test]
    async fn readyz_returns_ok_when_ready() {
        let check: ReadinessCheck =
            Arc::new(|| Box::pin(async { serde_json::json!({"ready": true, "db": "connected"}) }));
        let resp = readyz(check).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ready"], true);
        assert!(
            json.get("name").is_none(),
            "readyz must not expose server name"
        );
        assert!(
            json.get("version").is_none(),
            "readyz must not expose version"
        );
        assert_eq!(json["db"], "connected");
    }

    #[tokio::test]
    async fn readyz_returns_503_when_not_ready() {
        let check: ReadinessCheck =
            Arc::new(|| Box::pin(async { serde_json::json!({"ready": false}) }));
        let resp = readyz(check).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readyz_returns_503_when_ready_missing() {
        let check: ReadinessCheck =
            Arc::new(|| Box::pin(async { serde_json::json!({"status": "starting"}) }));
        let resp = readyz(check).await.into_response();
        // Missing "ready" field defaults to false -> 503
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // -- origin_check_middleware --

    /// Build a test router with origin check middleware and a simple handler.
    fn origin_router(origins: Vec<String>, log_request_headers: bool) -> axum::Router {
        let allowed: Arc<[String]> = Arc::from(origins);
        axum::Router::new()
            .route("/test", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let a = Arc::clone(&allowed);
                origin_check_middleware(a, log_request_headers, req, next)
            }))
    }

    #[tokio::test]
    async fn origin_allowed_passes() {
        let app = origin_router(vec!["http://localhost:3000".into()], false);
        let req = Request::builder()
            .uri("/test")
            .header(header::ORIGIN, "http://localhost:3000")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn origin_rejected_returns_403() {
        let app = origin_router(vec!["http://localhost:3000".into()], false);
        let req = Request::builder()
            .uri("/test")
            .header(header::ORIGIN, "http://evil.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn no_origin_header_passes() {
        let app = origin_router(vec!["http://localhost:3000".into()], false);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn empty_allowlist_rejects_any_origin() {
        let app = origin_router(vec![], false);
        let req = Request::builder()
            .uri("/test")
            .header(header::ORIGIN, "http://anything.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn empty_allowlist_passes_without_origin() {
        let app = origin_router(vec![], false);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn format_request_headers_redacts_sensitive_values() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer secret-token".parse().unwrap());
        headers.insert("cookie", "sid=abc".parse().unwrap());
        headers.insert("x-request-id", "req-123".parse().unwrap());

        let out = format_request_headers_for_log(&headers);
        assert!(out.contains("authorization: [REDACTED]"));
        assert!(out.contains("cookie: [REDACTED]"));
        assert!(out.contains("x-request-id: req-123"));
        assert!(!out.contains("secret-token"));
    }

    // -- security_headers_middleware --

    fn security_router(is_tls: bool) -> axum::Router {
        axum::Router::new()
            .route("/test", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                security_headers_middleware(is_tls, req, next)
            }))
    }

    #[tokio::test]
    async fn security_headers_set_on_response() {
        let app = security_router(false);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let h = resp.headers();
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(h.get("x-frame-options").unwrap(), "deny");
        assert_eq!(h.get("cache-control").unwrap(), "no-store, max-age=0");
        assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
        assert_eq!(h.get("cross-origin-opener-policy").unwrap(), "same-origin");
        assert_eq!(
            h.get("cross-origin-resource-policy").unwrap(),
            "same-origin"
        );
        assert_eq!(
            h.get("cross-origin-embedder-policy").unwrap(),
            "require-corp"
        );
        assert_eq!(h.get("x-permitted-cross-domain-policies").unwrap(), "none");
        assert!(
            h.get("permissions-policy")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("camera=()"),
            "permissions-policy must restrict browser features"
        );
        assert_eq!(
            h.get("content-security-policy").unwrap(),
            "default-src 'none'; frame-ancestors 'none'"
        );
        assert_eq!(h.get("x-dns-prefetch-control").unwrap(), "off");
        // No HSTS when TLS is off.
        assert!(h.get("strict-transport-security").is_none());
    }

    #[tokio::test]
    async fn hsts_set_when_tls_enabled() {
        let app = security_router(true);
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        let hsts = resp.headers().get("strict-transport-security").unwrap();
        assert!(
            hsts.to_str().unwrap().contains("max-age=63072000"),
            "HSTS must set 2-year max-age"
        );
    }

    // -- version endpoint --

    #[test]
    fn version_payload_contains_expected_fields() {
        let v = version_payload("my-server", "1.2.3");
        assert_eq!(v["name"], "my-server");
        assert_eq!(v["version"], "1.2.3");
        assert!(v["build_git_sha"].is_string());
        assert!(v["build_timestamp"].is_string());
        assert!(v["rust_version"].is_string());
        assert!(v["mcpx_version"].is_string());
    }

    // -- concurrency limit layer --

    #[tokio::test]
    async fn concurrency_limit_layer_composes_and_serves() {
        // We only assert the layer stack compiles and a single request
        // below the cap still succeeds. True back-pressure behaviour
        // requires a live HTTP server and is covered by integration tests.
        let app = axum::Router::new()
            .route("/ok", axum::routing::get(|| async { "ok" }))
            .layer(
                tower::ServiceBuilder::new()
                    .layer(axum::error_handling::HandleErrorLayer::new(
                        |_err: tower::BoxError| async { StatusCode::SERVICE_UNAVAILABLE },
                    ))
                    .layer(tower::load_shed::LoadShedLayer::new())
                    .layer(tower::limit::ConcurrencyLimitLayer::new(4)),
            );
        let resp = app
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // -- compression layer --

    #[tokio::test]
    async fn compression_layer_gzip_encodes_response() {
        use tower_http::compression::Predicate as _;

        let big_body = "a".repeat(4096);
        let app = axum::Router::new()
            .route(
                "/big",
                axum::routing::get(move || {
                    let body = big_body.clone();
                    async move { body }
                }),
            )
            .layer(
                tower_http::compression::CompressionLayer::new()
                    .gzip(true)
                    .br(true)
                    .compress_when(
                        tower_http::compression::DefaultPredicate::new()
                            .and(tower_http::compression::predicate::SizeAbove::new(1024)),
                    ),
            );

        let req = Request::builder()
            .uri("/big")
            .header(header::ACCEPT_ENCODING, "gzip")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
    }
}
