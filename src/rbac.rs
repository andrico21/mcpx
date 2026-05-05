//! Role-Based Access Control (RBAC) policy engine.
//!
//! Evaluates `(role, operation, host)` tuples against a set of role
//! definitions loaded from config.  Deny-overrides-allow semantics:
//! an explicit deny entry always wins over a wildcard allow.
//!
//! Includes an axum middleware that inspects MCP JSON-RPC tool calls
//! and enforces RBAC and per-IP tool rate limiting before the request
//! reaches the handler.

use std::{net::IpAddr, num::NonZeroU32, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::Sha256;

use crate::{
    auth::{AuthIdentity, TlsConnInfo},
    bounded_limiter::BoundedKeyedLimiter,
    error::McpxError,
};

/// Per-source-IP rate limiter for tool invocations. Memory-bounded against
/// IP-spray `DoS` via [`BoundedKeyedLimiter`].
pub(crate) type ToolRateLimiter = BoundedKeyedLimiter<IpAddr>;

/// Default tool rate limit: 120 invocations per minute per source IP.
// SAFETY: unwrap() is safe - literal 120 is provably non-zero (const-evaluated).
const DEFAULT_TOOL_RATE: NonZeroU32 = NonZeroU32::new(120).unwrap();

/// Default cap on the number of distinct source IPs tracked by the tool
/// rate limiter. Bounded to defend against IP-spray `DoS` exhausting memory.
const DEFAULT_TOOL_MAX_TRACKED_KEYS: usize = 10_000;

/// Default idle-eviction window for the tool rate limiter (15 minutes).
const DEFAULT_TOOL_IDLE_EVICTION: Duration = Duration::from_mins(15);

/// Build a per-IP tool rate limiter from a max-calls-per-minute value.
///
/// Memory-bounded with `DEFAULT_TOOL_MAX_TRACKED_KEYS` tracked keys and
/// `DEFAULT_TOOL_IDLE_EVICTION` idle eviction. Use
/// [`build_tool_rate_limiter_with_bounds`] to override.
#[must_use]
pub(crate) fn build_tool_rate_limiter(max_per_minute: u32) -> Arc<ToolRateLimiter> {
    build_tool_rate_limiter_with_bounds(
        max_per_minute,
        DEFAULT_TOOL_MAX_TRACKED_KEYS,
        DEFAULT_TOOL_IDLE_EVICTION,
    )
}

/// Build a per-IP tool rate limiter with explicit memory-bound parameters.
#[must_use]
pub(crate) fn build_tool_rate_limiter_with_bounds(
    max_per_minute: u32,
    max_tracked_keys: usize,
    idle_eviction: Duration,
) -> Arc<ToolRateLimiter> {
    let quota =
        governor::Quota::per_minute(NonZeroU32::new(max_per_minute).unwrap_or(DEFAULT_TOOL_RATE));
    Arc::new(BoundedKeyedLimiter::new(
        quota,
        max_tracked_keys,
        idle_eviction,
    ))
}

// Task-local storage for the current caller's RBAC role and identity name.
// Set by the RBAC middleware, read by tool handlers (e.g. list_hosts filtering, audit logging).
//
// `CURRENT_TOKEN` holds a [`SecretString`] so the raw bearer token is never
// printed via `Debug` (it formats as `"[REDACTED alloc::string::String]"`)
// and is zeroized on drop by the `secrecy` crate.
tokio::task_local! {
    static CURRENT_ROLE: String;
    static CURRENT_IDENTITY: String;
    static CURRENT_TOKEN: SecretString;
    static CURRENT_SUB: String;
}

/// Get the current caller's RBAC role (set by RBAC middleware).
/// Returns `None` outside an RBAC-scoped request context.
#[must_use]
pub fn current_role() -> Option<String> {
    CURRENT_ROLE.try_with(Clone::clone).ok()
}

/// Get the current caller's identity name (set by RBAC middleware).
/// Returns `None` outside an RBAC-scoped request context.
#[must_use]
pub fn current_identity() -> Option<String> {
    CURRENT_IDENTITY.try_with(Clone::clone).ok()
}

/// Get the raw bearer token for the current request as a [`SecretString`].
/// Returns `None` outside a request context or when auth used mTLS/API-key.
/// Tool handlers use this for downstream token passthrough.
///
/// The returned value is wrapped in [`SecretString`] so it does not leak
/// via `Debug`/`Display`/serde. Call `.expose_secret()` only when the
/// raw value is actually needed (e.g. as the `Authorization` header on
/// an outbound HTTP request).
///
/// An empty token is treated as absent (returns `None`); this preserves
/// backward compatibility with the prior `Option<String>` API where the
/// empty default sentinel meant "no token".
#[must_use]
pub fn current_token() -> Option<SecretString> {
    CURRENT_TOKEN
        .try_with(|t| {
            if t.expose_secret().is_empty() {
                None
            } else {
                Some(t.clone())
            }
        })
        .ok()
        .flatten()
}

/// Get the JWT `sub` claim (stable user ID, e.g. Keycloak UUID).
/// Returns `None` outside a request context or for non-JWT auth.
/// Use for stable per-user keying (token store, etc.).
#[must_use]
pub fn current_sub() -> Option<String> {
    CURRENT_SUB
        .try_with(Clone::clone)
        .ok()
        .filter(|s| !s.is_empty())
}

/// Run a future with `CURRENT_TOKEN` set so that [`current_token()`] returns
/// the given value inside the future. Useful when MCP tool handlers need the
/// raw bearer token but run in a spawned task where the RBAC middleware's
/// task-local scope is no longer active.
pub async fn with_token_scope<F: Future>(token: SecretString, f: F) -> F::Output {
    CURRENT_TOKEN.scope(token, f).await
}

/// Run a future with all task-locals (`CURRENT_ROLE`, `CURRENT_IDENTITY`,
/// `CURRENT_TOKEN`, `CURRENT_SUB`) set.  Use this when re-establishing the
/// full RBAC context in spawned tasks (e.g. rmcp session tasks) where the
/// middleware's scope is no longer active.
pub async fn with_rbac_scope<F: Future>(
    role: String,
    identity: String,
    token: SecretString,
    sub: String,
    f: F,
) -> F::Output {
    CURRENT_ROLE
        .scope(
            role,
            CURRENT_IDENTITY.scope(
                identity,
                CURRENT_TOKEN.scope(token, CURRENT_SUB.scope(sub, f)),
            ),
        )
        .await
}

/// A single role definition.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct RoleConfig {
    /// Role identifier referenced from identities (API keys, mTLS, JWT claims).
    pub name: String,
    /// Human-readable description, surfaced in diagnostics only.
    #[serde(default)]
    pub description: Option<String>,
    /// Allowed operations.  `["*"]` means all operations.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Explicitly denied operations (overrides allow).
    #[serde(default)]
    pub deny: Vec<String>,
    /// Host name glob patterns this role can access. `["*"]` means all hosts.
    #[serde(default = "default_hosts")]
    pub hosts: Vec<String>,
    /// Per-tool argument constraints. When a tool call matches, the
    /// specified argument's first whitespace-delimited token (or its
    /// `/`-basename) must appear in the allowlist.
    #[serde(default)]
    pub argument_allowlists: Vec<ArgumentAllowlist>,
}

impl RoleConfig {
    /// Create a role with the given name, allowed operations, and host patterns.
    #[must_use]
    pub fn new(name: impl Into<String>, allow: Vec<String>, hosts: Vec<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            allow,
            deny: vec![],
            hosts,
            argument_allowlists: vec![],
        }
    }

    /// Attach argument allowlists to this role.
    #[must_use]
    pub fn with_argument_allowlists(mut self, allowlists: Vec<ArgumentAllowlist>) -> Self {
        self.argument_allowlists = allowlists;
        self
    }
}

/// Per-tool argument allowlist entry.
///
/// When the middleware sees a `tools/call` for `tool`, it extracts the
/// string value at `argument` from the call's arguments object and checks
/// its first token against `allowed`. If the token is not in the list
/// the call is rejected with 403.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct ArgumentAllowlist {
    /// Tool name to match (exact or glob, e.g. `"run_query"`).
    pub tool: String,
    /// Argument key whose value is checked (e.g. `"cmd"`, `"query"`).
    pub argument: String,
    /// Permitted first-token values. Empty means unrestricted.
    #[serde(default)]
    pub allowed: Vec<String>,
}

impl ArgumentAllowlist {
    /// Create an argument allowlist for a tool.
    #[must_use]
    pub fn new(tool: impl Into<String>, argument: impl Into<String>, allowed: Vec<String>) -> Self {
        Self {
            tool: tool.into(),
            argument: argument.into(),
            allowed,
        }
    }
}

fn default_hosts() -> Vec<String> {
    vec!["*".into()]
}

/// Top-level RBAC configuration (deserializable from TOML).
#[derive(Debug, Clone, Default, Deserialize)]
#[non_exhaustive]
pub struct RbacConfig {
    /// Master switch -- when false, the RBAC middleware is not installed.
    #[serde(default)]
    pub enabled: bool,
    /// Role definitions available to identities.
    #[serde(default)]
    pub roles: Vec<RoleConfig>,
    /// Optional stable HMAC key (any length) used to redact argument
    /// values in deny logs. When set, redacted hashes are stable across
    /// process restarts (useful for log correlation across deploys).
    /// When `None`, a random 32-byte key is generated per process at
    /// first use; redacted hashes change every restart.
    ///
    /// The key is wrapped in [`SecretString`] so it never leaks via
    /// `Debug`/`Display`/serde and is zeroized on drop.
    #[serde(default)]
    pub redaction_salt: Option<SecretString>,
}

impl RbacConfig {
    /// Create an enabled RBAC config with the given roles.
    #[must_use]
    pub fn with_roles(roles: Vec<RoleConfig>) -> Self {
        Self {
            enabled: true,
            roles,
            redaction_salt: None,
        }
    }
}

/// Result of an RBAC policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RbacDecision {
    /// Caller is permitted to perform the requested operation.
    Allow,
    /// Caller is denied access.
    Deny,
}

/// Summary of a single role, produced by [`RbacPolicy::summary`].
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct RbacRoleSummary {
    /// Role name.
    pub name: String,
    /// Number of allow entries.
    pub allow: usize,
    /// Number of deny entries.
    pub deny: usize,
    /// Number of host patterns.
    pub hosts: usize,
    /// Number of argument allowlist entries.
    pub argument_allowlists: usize,
}

/// Summary of the whole RBAC policy, produced by [`RbacPolicy::summary`].
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct RbacPolicySummary {
    /// Whether RBAC enforcement is active.
    pub enabled: bool,
    /// Per-role summaries.
    pub roles: Vec<RbacRoleSummary>,
}

/// Compiled RBAC policy for fast lookup.
///
/// Built from [`RbacConfig`] at startup.  All lookups are O(n) over the
/// role's allow/deny/host lists, which is fine for the expected cardinality
/// (a handful of roles with tens of entries each).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RbacPolicy {
    roles: Vec<RoleConfig>,
    enabled: bool,
    /// HMAC key used to redact argument values in deny logs.
    /// Either a configured stable salt or a per-process random salt.
    redaction_salt: Arc<SecretString>,
}

impl RbacPolicy {
    /// Build a policy from config.  When `config.enabled` is false, all
    /// checks return [`RbacDecision::Allow`].
    #[must_use]
    pub fn new(config: &RbacConfig) -> Self {
        let salt = config
            .redaction_salt
            .clone()
            .unwrap_or_else(|| process_redaction_salt().clone());
        Self {
            roles: config.roles.clone(),
            enabled: config.enabled,
            redaction_salt: Arc::new(salt),
        }
    }

    /// Create a policy that always allows (RBAC disabled).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            roles: Vec::new(),
            enabled: false,
            redaction_salt: Arc::new(process_redaction_salt().clone()),
        }
    }

    /// Whether RBAC enforcement is active.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Summarize the policy for diagnostics (admin endpoint).
    ///
    /// Returns `(enabled, role_count, per_role_stats)` where each stat is
    /// `(name, allow_count, deny_count, host_count, argument_allowlist_count)`.
    #[must_use]
    pub fn summary(&self) -> RbacPolicySummary {
        let roles = self
            .roles
            .iter()
            .map(|r| RbacRoleSummary {
                name: r.name.clone(),
                allow: r.allow.len(),
                deny: r.deny.len(),
                hosts: r.hosts.len(),
                argument_allowlists: r.argument_allowlists.len(),
            })
            .collect();
        RbacPolicySummary {
            enabled: self.enabled,
            roles,
        }
    }

    /// Check whether `role` may perform `operation` (ignoring host).
    ///
    /// Use this for tools that don't target a specific host (e.g. `ping`,
    /// `list_hosts`).
    #[must_use]
    pub fn check_operation(&self, role: &str, operation: &str) -> RbacDecision {
        if !self.enabled {
            return RbacDecision::Allow;
        }
        let Some(role_cfg) = self.find_role(role) else {
            return RbacDecision::Deny;
        };
        if role_cfg.deny.iter().any(|d| d == operation) {
            return RbacDecision::Deny;
        }
        if role_cfg.allow.iter().any(|a| a == "*" || a == operation) {
            return RbacDecision::Allow;
        }
        RbacDecision::Deny
    }

    /// Check whether `role` may perform `operation` on `host`.
    ///
    /// Evaluation order:
    /// 1. If RBAC is disabled, allow.
    /// 2. Check operation permission (deny overrides allow).
    /// 3. Check host visibility via glob matching.
    #[must_use]
    pub fn check(&self, role: &str, operation: &str, host: &str) -> RbacDecision {
        if !self.enabled {
            return RbacDecision::Allow;
        }
        let Some(role_cfg) = self.find_role(role) else {
            return RbacDecision::Deny;
        };
        if role_cfg.deny.iter().any(|d| d == operation) {
            return RbacDecision::Deny;
        }
        if !role_cfg.allow.iter().any(|a| a == "*" || a == operation) {
            return RbacDecision::Deny;
        }
        if !Self::host_matches(&role_cfg.hosts, host) {
            return RbacDecision::Deny;
        }
        RbacDecision::Allow
    }

    /// Check whether `role` can see `host` at all (for `list_hosts` filtering).
    #[must_use]
    pub fn host_visible(&self, role: &str, host: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let Some(role_cfg) = self.find_role(role) else {
            return false;
        };
        Self::host_matches(&role_cfg.hosts, host)
    }

    /// Get the list of hosts patterns for a role.
    #[must_use]
    pub fn host_patterns(&self, role: &str) -> Option<&[String]> {
        self.find_role(role).map(|r| r.hosts.as_slice())
    }

    /// Check whether `value` passes the argument allowlists for `tool` under `role`.
    ///
    /// If the role has no matching `argument_allowlists` entry for the tool,
    /// all values are allowed. When a matching entry exists, `value` is
    /// tokenized using POSIX-shell-like lexical rules ([`shlex::split`])
    /// and its first argv element (or the `/`-basename of that element)
    /// must appear in the `allowed` list.
    ///
    /// **Scope of the contract.** This matcher targets consumers that
    /// interpret string arguments as POSIX-shell-like command lines on
    /// Unix-like systems (e.g. anything that subsequently feeds the value
    /// through `shlex` or an equivalent splitter before `execve`). It
    /// does **not** model real shell *execution* grammar (`FOO=1 cmd`,
    /// expansion, command substitution, redirection, operators) or
    /// Windows command-line tokenization (`CommandLineToArgvW`,
    /// `cmd.exe`, PowerShell). Consumers in those regimes remain subject
    /// to a parser differential and must validate at their own boundary.
    ///
    /// **Fail-closed cases (all return `false` when a matching allowlist
    /// entry exists):**
    ///
    /// - `value` fails to parse as a POSIX-shell-like command line
    ///   (e.g. unbalanced quotes, dangling escape).
    /// - `value` parses to zero tokens (empty input).
    /// - The first parsed token is the empty string (e.g.
    ///   `value = r#""""#` parses to `Some(vec![""])`). An empty argv
    ///   element is never a runnable executable, so we reject even when
    ///   `""` is in the allowlist.
    #[must_use]
    pub fn argument_allowed(&self, role: &str, tool: &str, argument: &str, value: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let Some(role_cfg) = self.find_role(role) else {
            return false;
        };
        for al in &role_cfg.argument_allowlists {
            if al.tool != tool && !glob_match(&al.tool, tool) {
                continue;
            }
            if al.argument != argument {
                continue;
            }
            if al.allowed.is_empty() {
                continue;
            }
            // Tokenize per POSIX-shell-like rules so quoted paths with
            // spaces match what an equivalently-tokenizing consumer
            // would actually run, and malformed shell syntax (unbalanced
            // quotes, dangling escapes) fails closed.
            let Some(tokens) = shlex::split(value) else {
                return false;
            };
            let Some(first_token) = tokens.first() else {
                return false;
            };
            // A well-formed but empty first argv element (e.g.
            // value = r#""""#) is never a runnable executable. Fail
            // closed even if "" appears in the allowlist.
            if first_token.is_empty() {
                return false;
            }
            // Also match against the basename if it's a path. POSIX
            // separator only; Windows-style backslash paths are out of
            // scope and will not basename-match (see crate-level docs).
            let basename = first_token
                .rsplit('/')
                .next()
                .unwrap_or(first_token.as_str());
            if !al.allowed.iter().any(|a| a == first_token || a == basename) {
                return false;
            }
        }
        true
    }

    /// Return the role config for a given role name.
    fn find_role(&self, name: &str) -> Option<&RoleConfig> {
        self.roles.iter().find(|r| r.name == name)
    }

    /// Check if a host name matches any of the given glob patterns.
    fn host_matches(patterns: &[String], host: &str) -> bool {
        patterns.iter().any(|p| glob_match(p, host))
    }

    /// HMAC-SHA256 the given argument value with this policy's redaction
    /// salt and return the first 8 hex characters (4 bytes / 32 bits).
    ///
    /// 32 bits is enough entropy for log correlation (1-in-4-billion
    /// collision per pair) while being far short of any preimage attack
    /// surface for an attacker reading logs. The HMAC construction
    /// guarantees that even short or low-entropy values cannot be
    /// recovered without the key.
    #[must_use]
    pub fn redact_arg(&self, value: &str) -> String {
        redact_with_salt(self.redaction_salt.expose_secret().as_bytes(), value)
    }
}

/// Process-wide random redaction salt, lazily generated on first use.
/// Used when [`RbacConfig::redaction_salt`] is `None`.
fn process_redaction_salt() -> &'static SecretString {
    use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
    static PROCESS_SALT: std::sync::OnceLock<SecretString> = std::sync::OnceLock::new();
    PROCESS_SALT.get_or_init(|| {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        // base64-encode so the SecretString is valid UTF-8; the HMAC
        // accepts arbitrary key bytes regardless.
        SecretString::from(STANDARD_NO_PAD.encode(bytes))
    })
}

/// HMAC-SHA256(`salt`, `value`) → first 8 hex chars.
///
/// Pulled out as a free function so it can be unit-tested and benchmarked
/// without constructing a full [`RbacPolicy`].
fn redact_with_salt(salt: &[u8], value: &str) -> String {
    use std::fmt::Write as _;

    use sha2::Digest as _;

    type HmacSha256 = Hmac<Sha256>;
    // HMAC-SHA256 accepts keys of any byte length: the spec pads short
    // keys with zeros and hashes long keys, so `new_from_slice` is
    // infallible here. We still defensively re-key with a SHA-256 of
    // the salt if construction ever fails (e.g. future hmac upstream
    // tightens the contract); both branches produce a valid keyed MAC.
    let mut mac = if let Ok(m) = HmacSha256::new_from_slice(salt) {
        m
    } else {
        let digest = Sha256::digest(salt);
        #[allow(clippy::expect_used)] // 32-byte digest always valid as HMAC key
        HmacSha256::new_from_slice(&digest).expect("32-byte SHA256 digest is valid HMAC key")
    };
    mac.update(value.as_bytes());
    let bytes = mac.finalize().into_bytes();
    // 4 bytes → 8 hex chars.
    let prefix = bytes.get(..4).unwrap_or(&[0; 4]);
    let mut out = String::with_capacity(8);
    for b in prefix {
        let _ = write!(out, "{b:02x}");
    }
    out
}

// -- RBAC middleware --

/// Axum middleware that enforces RBAC and per-IP tool rate limiting on
/// MCP tool calls.
///
/// Inspects POST request bodies for `tools/call` JSON-RPC messages,
/// extracts the tool name and `host` argument, and checks the
/// [`RbacPolicy`] against the [`AuthIdentity`] set by the auth middleware.
///
/// When a `tool_limiter` is provided, tool invocations are rate-limited
/// per source IP regardless of whether RBAC is enabled (MCP spec: servers
/// MUST rate limit tool invocations).
///
/// Non-POST requests and non-tool-call messages pass through unchanged.
/// The caller's role is stored in task-local storage for use by tool
/// handlers (e.g. `list_hosts` host filtering via [`current_role()`]).
// TODO(refactor): cognitive complexity reduced from 43/25 by extracting
// `enforce_tool_policy` and `enforce_rate_limit`. Remaining flow is a
// linear body-collect + JSON-RPC parse + dispatch, intentionally left
// inline to keep the request lifecycle visible at a glance.
#[allow(clippy::too_many_lines)]
pub(crate) async fn rbac_middleware(
    policy: Arc<RbacPolicy>,
    tool_limiter: Option<Arc<ToolRateLimiter>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Only inspect POST requests - tool calls are POSTs.
    if req.method() != Method::POST {
        return next.run(req).await;
    }

    // Extract peer IP for rate limiting.
    let peer_ip: Option<IpAddr> = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
        .or_else(|| {
            req.extensions()
                .get::<ConnectInfo<TlsConnInfo>>()
                .map(|ci| ci.0.addr.ip())
        });

    // Extract caller identity and role (may be absent when auth is off).
    let identity = req.extensions().get::<AuthIdentity>();
    let identity_name = identity.map(|id| id.name.clone()).unwrap_or_default();
    let role = identity.map(|id| id.role.clone()).unwrap_or_default();
    // Clone the SecretString end-to-end; an absent token becomes an empty
    // SecretString sentinel (current_token() filters this out as None).
    let raw_token: SecretString = identity
        .and_then(|id| id.raw_token.clone())
        .unwrap_or_else(|| SecretString::from(String::new()));
    let sub = identity.and_then(|id| id.sub.clone()).unwrap_or_default();

    // RBAC requires an authenticated identity.
    if policy.is_enabled() && identity.is_none() {
        return McpxError::Rbac("no authenticated identity".into()).into_response();
    }

    // Read the body for JSON-RPC inspection.
    let (parts, body) = req.into_parts();
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::error!(error = %e, "failed to read request body");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to read request body",
            )
                .into_response();
        }
    };

    // Try to parse as JSON and inspect JSON-RPC tool calls, including batch arrays.
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        let tool_calls = extract_tool_calls(&json);
        if !tool_calls.is_empty() {
            for params in tool_calls {
                if let Some(resp) = enforce_rate_limit(tool_limiter.as_deref(), peer_ip) {
                    return resp;
                }
                if policy.is_enabled()
                    && let Some(resp) = enforce_tool_policy(&policy, &identity_name, &role, params)
                {
                    return resp;
                }
            }
        }
    }
    // Non-parseable or non-tool-call requests pass through.

    // Reconstruct the request with the consumed body.
    let req = Request::from_parts(parts, Body::from(bytes));

    // Set the caller's role and identity in task-local storage for the handler.
    if role.is_empty() {
        next.run(req).await
    } else {
        CURRENT_ROLE
            .scope(
                role,
                CURRENT_IDENTITY.scope(
                    identity_name,
                    CURRENT_TOKEN.scope(raw_token, CURRENT_SUB.scope(sub, next.run(req))),
                ),
            )
            .await
    }
}

/// Extract the `params` object for every top-level `tools/call` message.
///
/// Supports either a single JSON-RPC object or a JSON-RPC batch array. Any
/// malformed elements are ignored so non-RPC payloads continue to pass through
/// unchanged.
fn extract_tool_calls(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    match value {
        serde_json::Value::Object(map) => map
            .get("method")
            .and_then(serde_json::Value::as_str)
            .filter(|method| *method == "tools/call")
            .and_then(|_| map.get("params"))
            .into_iter()
            .collect(),
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| match item {
                serde_json::Value::Object(map) => map
                    .get("method")
                    .and_then(serde_json::Value::as_str)
                    .filter(|method| *method == "tools/call")
                    .and_then(|_| map.get("params")),
                serde_json::Value::Null
                | serde_json::Value::Bool(_)
                | serde_json::Value::Number(_)
                | serde_json::Value::String(_)
                | serde_json::Value::Array(_) => None,
            })
            .collect(),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => Vec::new(),
    }
}

/// Per-IP rate limit check for tool invocations. Returns `Some(response)`
/// if the caller should be rejected.
fn enforce_rate_limit(
    tool_limiter: Option<&ToolRateLimiter>,
    peer_ip: Option<IpAddr>,
) -> Option<Response> {
    let limiter = tool_limiter?;
    let ip = peer_ip?;
    if limiter.check_key(&ip).is_err() {
        tracing::warn!(%ip, "tool invocation rate limited");
        return Some(McpxError::RateLimited("too many tool invocations".into()).into_response());
    }
    None
}

/// Apply RBAC tool/host + argument-allowlist checks. Returns `Some(response)`
/// when the caller must be rejected. Assumes `policy.is_enabled()`.
///
/// `identity_name` is passed explicitly (rather than read from
/// [`current_identity()`]) because this function runs *before* the
/// task-local context is installed by the middleware. Reading the
/// task-local here would always yield `None`, producing deny logs with
/// an empty `user` field.
fn enforce_tool_policy(
    policy: &RbacPolicy,
    identity_name: &str,
    role: &str,
    params: &serde_json::Value,
) -> Option<Response> {
    let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let host = params
        .get("arguments")
        .and_then(|a| a.get("host"))
        .and_then(|h| h.as_str());

    let decision = if let Some(host) = host {
        policy.check(role, tool_name, host)
    } else {
        policy.check_operation(role, tool_name)
    };
    if decision == RbacDecision::Deny {
        tracing::warn!(
            user = %identity_name,
            role = %role,
            tool = tool_name,
            host = host.unwrap_or("-"),
            "RBAC denied"
        );
        return Some(
            McpxError::Rbac(format!("{tool_name} denied for role '{role}'")).into_response(),
        );
    }

    let args = params.get("arguments").and_then(|a| a.as_object())?;
    for (arg_key, arg_val) in args {
        if let Some(val_str) = arg_val.as_str()
            && !policy.argument_allowed(role, tool_name, arg_key, val_str)
        {
            // Redact the raw value: log an HMAC-SHA256 prefix instead of
            // the literal string. Operators correlate hashes across log
            // lines without ever exposing potentially sensitive inputs
            // (paths, IDs, tokens accidentally passed as args, etc.).
            tracing::warn!(
                user = %identity_name,
                role = %role,
                tool = tool_name,
                argument = arg_key,
                arg_hmac = %policy.redact_arg(val_str),
                "argument not in allowlist"
            );
            return Some(
                McpxError::Rbac(format!(
                    "argument '{arg_key}' value not in allowlist for tool '{tool_name}'"
                ))
                .into_response(),
            );
        }
    }
    None
}

/// Simple glob matching: `*` matches any sequence of characters.
///
/// Supports multiple `*` wildcards anywhere in the pattern.
/// No `?`, `[...]`, or other advanced glob features.
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        // No wildcards - exact match.
        return pattern == text;
    }

    let mut pos = 0;

    // First part must match at the start (unless pattern starts with *).
    if let Some(&first) = parts.first()
        && !first.is_empty()
    {
        if !text.starts_with(first) {
            return false;
        }
        pos = first.len();
    }

    // Last part must match at the end (unless pattern ends with *).
    if let Some(&last) = parts.last()
        && !last.is_empty()
    {
        if !text[pos..].ends_with(last) {
            return false;
        }
        // Shrink the search area so middle parts don't overlap with the suffix.
        let end = text.len() - last.len();
        if pos > end {
            return false;
        }
        // Check middle parts in the remaining region.
        let middle = &text[pos..end];
        let middle_parts = parts.get(1..parts.len() - 1).unwrap_or_default();
        return match_middle(middle, middle_parts);
    }

    // Pattern ends with * - just check middle parts.
    let middle = &text[pos..];
    let middle_parts = parts.get(1..parts.len() - 1).unwrap_or_default();
    match_middle(middle, middle_parts)
}

/// Match middle glob segments sequentially in `text`.
fn match_middle(mut text: &str, parts: &[&str]) -> bool {
    for part in parts {
        if part.is_empty() {
            continue;
        }
        if let Some(idx) = text.find(part) {
            text = &text[idx + part.len()..];
        } else {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> RbacPolicy {
        RbacPolicy::new(&RbacConfig {
            enabled: true,
            roles: vec![
                RoleConfig {
                    name: "viewer".into(),
                    description: Some("Read-only".into()),
                    allow: vec![
                        "list_hosts".into(),
                        "resource_list".into(),
                        "resource_inspect".into(),
                        "resource_logs".into(),
                        "system_info".into(),
                    ],
                    deny: vec![],
                    hosts: vec!["*".into()],
                    argument_allowlists: vec![],
                },
                RoleConfig {
                    name: "deploy".into(),
                    description: Some("Lifecycle management".into()),
                    allow: vec![
                        "list_hosts".into(),
                        "resource_list".into(),
                        "resource_run".into(),
                        "resource_start".into(),
                        "resource_stop".into(),
                        "resource_restart".into(),
                        "resource_logs".into(),
                        "image_pull".into(),
                    ],
                    deny: vec!["resource_delete".into(), "resource_exec".into()],
                    hosts: vec!["web-*".into(), "api-*".into()],
                    argument_allowlists: vec![],
                },
                RoleConfig {
                    name: "ops".into(),
                    description: Some("Full access".into()),
                    allow: vec!["*".into()],
                    deny: vec![],
                    hosts: vec!["*".into()],
                    argument_allowlists: vec![],
                },
                RoleConfig {
                    name: "restricted-exec".into(),
                    description: Some("Exec with argument allowlist".into()),
                    allow: vec!["resource_exec".into()],
                    deny: vec![],
                    hosts: vec!["dev-*".into()],
                    argument_allowlists: vec![ArgumentAllowlist {
                        tool: "resource_exec".into(),
                        argument: "cmd".into(),
                        allowed: vec![
                            "sh".into(),
                            "bash".into(),
                            "cat".into(),
                            "ls".into(),
                            "ps".into(),
                        ],
                    }],
                },
            ],
            redaction_salt: None,
        })
    }

    // -- glob_match tests --

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("web-prod-1", "web-prod-1"));
        assert!(!glob_match("web-prod-1", "web-prod-2"));
    }

    #[test]
    fn glob_star_suffix() {
        assert!(glob_match("web-*", "web-prod-1"));
        assert!(glob_match("web-*", "web-staging"));
        assert!(!glob_match("web-*", "api-prod"));
    }

    #[test]
    fn glob_star_prefix() {
        assert!(glob_match("*-prod", "web-prod"));
        assert!(glob_match("*-prod", "api-prod"));
        assert!(!glob_match("*-prod", "web-staging"));
    }

    #[test]
    fn glob_star_middle() {
        assert!(glob_match("web-*-prod", "web-us-prod"));
        assert!(glob_match("web-*-prod", "web-eu-east-prod"));
        assert!(!glob_match("web-*-prod", "web-staging"));
    }

    #[test]
    fn glob_star_only() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn glob_multiple_stars() {
        assert!(glob_match("*web*prod*", "my-web-us-prod-1"));
        assert!(!glob_match("*web*prod*", "my-api-us-staging"));
    }

    // -- glob_match boundary / mutation-coverage tests --
    //
    // The cases below exist to kill specific mutants surfaced by
    // `cargo mutants` against `glob_match` / `match_middle` (see
    // CI run #84, May 2026). Each test is annotated with the mutation
    // it kills so the intent survives future refactors.

    /// Kill: `if pos > end` mutated to `pos == end` and `pos >= end`
    /// at `glob_match` line 863. The prefix and suffix exactly meet
    /// (no characters between them); the original code accepts this,
    /// both mutants reject it.
    #[test]
    fn glob_prefix_and_suffix_meet_exactly() {
        // parts = ["ab", "cd"]; first.len()=2, end=text.len()-last.len()=2.
        // pos == end → original passes the `pos > end` check, mutants fail.
        assert!(glob_match("ab*cd", "abcd"));
    }

    /// Kill: `parts.len() - 1` mutated to `parts.len() + 1` at line 868
    /// (middle-parts slice when pattern has a non-empty suffix). The
    /// mutant collapses the middle-parts slice to empty, which would
    /// incorrectly accept patterns whose middle segment isn't present.
    #[test]
    fn glob_middle_segment_required_with_suffix() {
        // Pattern requires "b" between "a" and "c"; text omits it.
        // Original: middle_parts=["b"], match_middle("xy", ["b"])=false → reject.
        // Mutant `+`: middle_parts=[] (slice out of bounds → unwrap_or_default),
        //             match_middle("xy", [])=true → wrongly accept.
        assert!(!glob_match("a*b*c", "axyc"));
    }

    /// Kill: `idx + part.len()` mutated to `idx - part.len()` at
    /// `match_middle` line 885. The mutant either underflows
    /// (panic in test) or fails to advance past the matched part,
    /// causing it to re-find the same prefix and accept patterns
    /// that should be rejected.
    #[test]
    fn glob_match_middle_advances_past_matched_part() {
        // Original: after finding "ab" at idx 2, advance to text[4..]="_yz",
        //           which contains no second "ab" → reject.
        // Mutant `-`: text[2-2..]="xxab_yz" → re-finds "ab" → wrongly accept
        //             (or panics for the smaller-idx variants).
        assert!(!glob_match("*ab*ab*", "xxab_yz"));
    }

    /// Kill: `idx + part.len()` mutated to `idx * part.len()` at
    /// `match_middle` line 885. The mutant computes a different
    /// (usually larger) advance offset that produces an out-of-bounds
    /// slice and panics, or skips over content that should match.
    #[test]
    fn glob_match_middle_uses_addition_not_multiplication() {
        // Original: find "abcde" at idx 8 in "yyyyyyyyabcde_X", advance
        //           to text[13..]="_X", find "X" → accept.
        // Mutant `*`: text[8*5..]=text[40..] → out-of-bounds → panic.
        assert!(glob_match("*abcde*X*", "yyyyyyyyabcde_X"));
    }

    // -- RbacPolicy::argument_allowed mutation-coverage tests --

    /// Kill: `&&` mutated to `||` at `argument_allowed` line 494.
    /// The original short-circuits the allowlist lookup only when both
    /// the literal name AND the glob fail to match. The mutant
    /// short-circuits when EITHER fails, which means a glob-matched
    /// allowlist (literal mismatch, glob match) is silently skipped
    /// and the call is wrongly allowed.
    #[test]
    fn argument_allowed_glob_pattern_with_literal_mismatch_still_enforced() {
        // Allowlist registered against pattern "run-*" with allowed=["ls"].
        // Calling tool="run-foo" — literal "run-*" != "run-foo" (true),
        // but glob_match("run-*", "run-foo") = true.
        //   Original `&&`: skip-condition = true && false = false → enforce
        //                  allowlist → "rm" not in ["ls"] → deny.
        //   Mutant `||`:   skip-condition = true || false = true → skip
        //                  allowlist → wrongly allow.
        let role = RoleConfig::new("viewer", vec!["run-foo".into()], vec!["*".into()])
            .with_argument_allowlists(vec![ArgumentAllowlist::new(
                "run-*",
                "cmd",
                vec!["ls".into()],
            )]);
        let mut config = RbacConfig::with_roles(vec![role]);
        config.enabled = true;
        let policy = RbacPolicy::new(&config);
        assert!(!policy.argument_allowed("viewer", "run-foo", "cmd", "rm"));
    }

    // -- RbacPolicy::check tests --

    #[test]
    fn disabled_policy_allows_everything() {
        let policy = RbacPolicy::new(&RbacConfig {
            enabled: false,
            roles: vec![],
            redaction_salt: None,
        });
        assert_eq!(
            policy.check("nonexistent", "resource_delete", "any-host"),
            RbacDecision::Allow
        );
    }

    #[test]
    fn unknown_role_denied() {
        let policy = test_policy();
        assert_eq!(
            policy.check("unknown", "resource_list", "web-prod-1"),
            RbacDecision::Deny
        );
    }

    #[test]
    fn viewer_allowed_read_ops() {
        let policy = test_policy();
        assert_eq!(
            policy.check("viewer", "resource_list", "web-prod-1"),
            RbacDecision::Allow
        );
        assert_eq!(
            policy.check("viewer", "system_info", "db-host"),
            RbacDecision::Allow
        );
    }

    #[test]
    fn viewer_denied_write_ops() {
        let policy = test_policy();
        assert_eq!(
            policy.check("viewer", "resource_run", "web-prod-1"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check("viewer", "resource_delete", "web-prod-1"),
            RbacDecision::Deny
        );
    }

    #[test]
    fn deploy_allowed_on_matching_hosts() {
        let policy = test_policy();
        assert_eq!(
            policy.check("deploy", "resource_run", "web-prod-1"),
            RbacDecision::Allow
        );
        assert_eq!(
            policy.check("deploy", "resource_start", "api-staging"),
            RbacDecision::Allow
        );
    }

    #[test]
    fn deploy_denied_on_non_matching_host() {
        let policy = test_policy();
        assert_eq!(
            policy.check("deploy", "resource_run", "db-prod-1"),
            RbacDecision::Deny
        );
    }

    #[test]
    fn deny_overrides_allow() {
        let policy = test_policy();
        assert_eq!(
            policy.check("deploy", "resource_delete", "web-prod-1"),
            RbacDecision::Deny
        );
        assert_eq!(
            policy.check("deploy", "resource_exec", "web-prod-1"),
            RbacDecision::Deny
        );
    }

    #[test]
    fn ops_wildcard_allows_everything() {
        let policy = test_policy();
        assert_eq!(
            policy.check("ops", "resource_delete", "any-host"),
            RbacDecision::Allow
        );
        assert_eq!(
            policy.check("ops", "secret_create", "db-host"),
            RbacDecision::Allow
        );
    }

    // -- host_visible tests --

    #[test]
    fn host_visible_respects_globs() {
        let policy = test_policy();
        assert!(policy.host_visible("deploy", "web-prod-1"));
        assert!(policy.host_visible("deploy", "api-staging"));
        assert!(!policy.host_visible("deploy", "db-prod-1"));
        assert!(policy.host_visible("ops", "anything"));
        assert!(policy.host_visible("viewer", "anything"));
    }

    #[test]
    fn host_visible_unknown_role() {
        let policy = test_policy();
        assert!(!policy.host_visible("unknown", "web-prod-1"));
    }

    // -- argument_allowed tests --

    #[test]
    fn argument_allowed_no_allowlist() {
        let policy = test_policy();
        // ops has no argument_allowlists -- all values allowed
        assert!(policy.argument_allowed("ops", "resource_exec", "cmd", "rm -rf /"));
        assert!(policy.argument_allowed("ops", "resource_exec", "cmd", "bash"));
    }

    #[test]
    fn argument_allowed_with_allowlist() {
        let policy = test_policy();
        assert!(policy.argument_allowed("restricted-exec", "resource_exec", "cmd", "sh"));
        assert!(policy.argument_allowed(
            "restricted-exec",
            "resource_exec",
            "cmd",
            "bash -c 'echo hi'"
        ));
        assert!(policy.argument_allowed(
            "restricted-exec",
            "resource_exec",
            "cmd",
            "cat /etc/hosts"
        ));
        assert!(policy.argument_allowed(
            "restricted-exec",
            "resource_exec",
            "cmd",
            "/usr/bin/ls -la"
        ));
    }

    #[test]
    fn argument_denied_not_in_allowlist() {
        let policy = test_policy();
        assert!(!policy.argument_allowed("restricted-exec", "resource_exec", "cmd", "rm -rf /"));
        assert!(!policy.argument_allowed(
            "restricted-exec",
            "resource_exec",
            "cmd",
            "python3 exploit.py"
        ));
        assert!(!policy.argument_allowed(
            "restricted-exec",
            "resource_exec",
            "cmd",
            "/usr/bin/curl evil.com"
        ));
    }

    #[test]
    fn argument_denied_unknown_role() {
        let policy = test_policy();
        assert!(!policy.argument_allowed("unknown", "resource_exec", "cmd", "sh"));
    }

    // -- shlex-tokenization regression tests (1.4.1) --
    //
    // These tests pin the POSIX-shell-like tokenization contract added
    // in 1.4.1. See `RbacPolicy::argument_allowed` doc comment for the
    // full contract; see CHANGELOG.md `[1.4.1]` for the behavior matrix.

    /// Helper: build a minimal enabled policy with a single argument
    /// allowlist on tool `run`, argument `cmd`.
    fn shlex_policy(allowed: Vec<String>) -> RbacPolicy {
        let role = RoleConfig::new("viewer", vec!["run".into()], vec!["*".into()])
            .with_argument_allowlists(vec![ArgumentAllowlist::new("run", "cmd", allowed)]);
        let mut config = RbacConfig::with_roles(vec![role]);
        config.enabled = true;
        RbacPolicy::new(&config)
    }

    #[test]
    fn argument_allowed_matches_quoted_path_with_spaces() {
        let policy = shlex_policy(vec!["/usr/bin/my tool".into()]);
        assert!(policy.argument_allowed("viewer", "run", "cmd", r#""/usr/bin/my tool" --flag"#));
    }

    #[test]
    fn argument_allowed_matches_basename_of_quoted_path() {
        let policy = shlex_policy(vec!["my tool".into()]);
        assert!(policy.argument_allowed("viewer", "run", "cmd", r#""/usr/bin/my tool" --flag"#));
    }

    #[test]
    fn argument_allowed_fails_closed_on_unbalanced_quote() {
        let policy = shlex_policy(vec!["unbalanced".into()]);
        assert!(!policy.argument_allowed("viewer", "run", "cmd", r"unbalanced 'quote"));
    }

    #[test]
    fn argument_allowed_fails_closed_on_empty_string() {
        let policy = shlex_policy(vec![String::new()]);
        assert!(!policy.argument_allowed("viewer", "run", "cmd", ""));
    }

    #[test]
    fn argument_allowed_handles_single_quoted_executable() {
        let policy = shlex_policy(vec!["/bin/sh".into()]);
        assert!(policy.argument_allowed("viewer", "run", "cmd", r"'/bin/sh' -c 'echo hi'"));
    }

    #[test]
    fn argument_allowed_handles_tab_separator() {
        let policy = shlex_policy(vec!["ls".into()]);
        assert!(policy.argument_allowed("viewer", "run", "cmd", "ls\t/etc/passwd"));
    }

    #[test]
    fn argument_allowed_plain_token_unchanged() {
        let policy = shlex_policy(vec!["ls".into()]);
        assert!(policy.argument_allowed("viewer", "run", "cmd", "ls"));
    }

    // Per Oracle review: the next four tests pin the cases the original
    // handoff missed. Each confirms the *new* (1.4.1) deny behavior so a
    // future regression to the old `split_whitespace` semantics would
    // surface as a test failure.

    #[test]
    fn argument_allowed_fails_closed_on_quoted_empty_first_token() {
        // value r#""""# parses to Some(vec![""]). An empty argv element
        // is never a runnable executable; deny even when "" is
        // explicitly allowlisted.
        let policy = shlex_policy(vec![String::new()]);
        assert!(!policy.argument_allowed("viewer", "run", "cmd", r#""""#));
    }

    #[test]
    fn argument_allowed_quoted_literal_token_no_longer_matches() {
        // 1.4.0 behavior: split_whitespace first token = "'bash'" --
        //                 matched literal allowlist entry "'bash'".
        // 1.4.1 behavior: shlex strips the surrounding quotes -> first
        //                 token = "bash" -- no match against allowlist
        //                 entry "'bash'". Deny.
        let policy = shlex_policy(vec!["'bash'".into()]);
        assert!(!policy.argument_allowed("viewer", "run", "cmd", "'bash' -c true"));
    }

    #[test]
    fn argument_allowed_backslash_literal_token_no_longer_matches() {
        // 1.4.0 behavior: literal first token "foo\\bar" matched.
        // 1.4.1 behavior: POSIX shlex treats backslash as escape ->
        //                 first token = "foobar". Allowlist entry with
        //                 a literal backslash no longer matches. Deny.
        let policy = shlex_policy(vec![r"foo\bar".into()]);
        assert!(!policy.argument_allowed("viewer", "run", "cmd", r"foo\bar --x"));
    }

    #[test]
    fn argument_allowed_windows_path_no_longer_matches() {
        // 1.4.0 behavior: literal Windows path matched.
        // 1.4.1 behavior: POSIX shlex eats backslashes -> path identity
        //                 changes; allowlist entry no longer matches.
        //                 Deny. Documented in CHANGELOG operator notes.
        let policy = shlex_policy(vec![r"C:\Windows\System32\cmd.exe".into()]);
        assert!(!policy.argument_allowed(
            "viewer",
            "run",
            "cmd",
            r"C:\Windows\System32\cmd.exe /c dir"
        ));
    }

    // -- host_patterns tests --

    #[test]
    fn host_patterns_returns_globs() {
        let policy = test_policy();
        assert_eq!(
            policy.host_patterns("deploy"),
            Some(vec!["web-*".to_owned(), "api-*".to_owned()].as_slice())
        );
        assert_eq!(
            policy.host_patterns("ops"),
            Some(vec!["*".to_owned()].as_slice())
        );
        assert!(policy.host_patterns("nonexistent").is_none());
    }

    // -- check_operation tests (no host check) --

    #[test]
    fn check_operation_allows_without_host() {
        let policy = test_policy();
        assert_eq!(
            policy.check_operation("deploy", "resource_run"),
            RbacDecision::Allow
        );
        // but check() with a non-matching host denies
        assert_eq!(
            policy.check("deploy", "resource_run", "db-prod-1"),
            RbacDecision::Deny
        );
    }

    #[test]
    fn check_operation_deny_overrides() {
        let policy = test_policy();
        assert_eq!(
            policy.check_operation("deploy", "resource_delete"),
            RbacDecision::Deny
        );
    }

    #[test]
    fn check_operation_unknown_role() {
        let policy = test_policy();
        assert_eq!(
            policy.check_operation("unknown", "resource_list"),
            RbacDecision::Deny
        );
    }

    #[test]
    fn check_operation_disabled() {
        let policy = RbacPolicy::new(&RbacConfig {
            enabled: false,
            roles: vec![],
            redaction_salt: None,
        });
        assert_eq!(
            policy.check_operation("nonexistent", "anything"),
            RbacDecision::Allow
        );
    }

    // -- current_role / current_identity tests --

    #[test]
    fn current_role_returns_none_outside_scope() {
        assert!(current_role().is_none());
    }

    #[test]
    fn current_identity_returns_none_outside_scope() {
        assert!(current_identity().is_none());
    }

    // -- rbac_middleware integration tests --

    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use tower::ServiceExt as _;

    fn tool_call_body(tool: &str, args: &serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": args
            }
        })
        .to_string()
    }

    fn rbac_router(policy: Arc<RbacPolicy>) -> axum::Router {
        axum::Router::new()
            .route("/mcp", axum::routing::post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                let p = Arc::clone(&policy);
                rbac_middleware(p, None, req, next)
            }))
    }

    fn rbac_router_with_identity(policy: Arc<RbacPolicy>, identity: AuthIdentity) -> axum::Router {
        axum::Router::new()
            .route("/mcp", axum::routing::post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(
                move |mut req: Request<Body>, next: Next| {
                    let p = Arc::clone(&policy);
                    let id = identity.clone();
                    async move {
                        req.extensions_mut().insert(id);
                        rbac_middleware(p, None, req, next).await
                    }
                },
            ))
    }

    #[tokio::test]
    async fn middleware_passes_non_post() {
        let policy = Arc::new(test_policy());
        let app = rbac_router(policy);
        // GET passes through even without identity.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/mcp")
            .body(Body::empty())
            .unwrap();
        // GET on a POST-only route returns 405, but the middleware itself
        // doesn't block it -- it returns next.run(req).
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn middleware_denies_without_identity() {
        let policy = Arc::new(test_policy());
        let app = rbac_router(policy);
        let body = tool_call_body("resource_list", &serde_json::json!({}));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn middleware_allows_permitted_tool() {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: crate::auth::AuthMethod::BearerToken,
            name: "alice".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        let body = tool_call_body("resource_list", &serde_json::json!({}));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn middleware_denies_unpermitted_tool() {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: crate::auth::AuthMethod::BearerToken,
            name: "alice".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        let body = tool_call_body("resource_delete", &serde_json::json!({}));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn middleware_passes_non_tool_call_post() {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: crate::auth::AuthMethod::BearerToken,
            name: "alice".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        // A non-tools/call JSON-RPC (e.g. resources/list) passes through.
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list"
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn middleware_enforces_argument_allowlist() {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: crate::auth::AuthMethod::BearerToken,
            name: "dev".into(),
            role: "restricted-exec".into(),
            raw_token: None,
            sub: None,
        };
        // Allowed command
        let app = rbac_router_with_identity(Arc::clone(&policy), id.clone());
        let body = tool_call_body(
            "resource_exec",
            &serde_json::json!({"cmd": "ls -la", "host": "dev-1"}),
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Denied command
        let app = rbac_router_with_identity(policy, id);
        let body = tool_call_body(
            "resource_exec",
            &serde_json::json!({"cmd": "rm -rf /", "host": "dev-1"}),
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn middleware_disabled_policy_passes_everything() {
        let policy = Arc::new(RbacPolicy::disabled());
        let app = rbac_router(policy);
        // No identity, disabled policy -- should pass.
        let body = tool_call_body("anything", &serde_json::json!({}));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn middleware_batch_all_allowed_passes() {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: crate::auth::AuthMethod::BearerToken,
            name: "alice".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "resource_list", "arguments": {} }
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "system_info", "arguments": {} }
            }
        ])
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn middleware_batch_with_denied_call_rejects_entire_batch() {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: crate::auth::AuthMethod::BearerToken,
            name: "alice".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "resource_list", "arguments": {} }
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "resource_delete", "arguments": {} }
            }
        ])
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn middleware_batch_mixed_allowed_and_denied_rejects() {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: crate::auth::AuthMethod::BearerToken,
            name: "dev".into(),
            role: "restricted-exec".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "resource_exec",
                    "arguments": { "cmd": "ls -la", "host": "dev-1" }
                }
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "resource_exec",
                    "arguments": { "cmd": "rm -rf /", "host": "dev-1" }
                }
            }
        ])
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // -- redact_arg / redaction_salt tests --

    #[test]
    fn redact_with_salt_is_deterministic_per_salt() {
        let salt = b"unit-test-salt";
        let a = redact_with_salt(salt, "rm -rf /");
        let b = redact_with_salt(salt, "rm -rf /");
        assert_eq!(a, b, "same input + salt must yield identical hash");
        assert_eq!(a.len(), 8, "redacted hash is 8 hex chars (4 bytes)");
        assert!(
            a.chars().all(|c| c.is_ascii_hexdigit()),
            "redacted hash must be lowercase hex: {a}"
        );
    }

    #[test]
    fn redact_with_salt_differs_across_salts() {
        let v = "the-same-value";
        let h1 = redact_with_salt(b"salt-one", v);
        let h2 = redact_with_salt(b"salt-two", v);
        assert_ne!(
            h1, h2,
            "different salts must produce different hashes for the same value"
        );
    }

    #[test]
    fn redact_with_salt_distinguishes_values() {
        let salt = b"k";
        let h1 = redact_with_salt(salt, "alpha");
        let h2 = redact_with_salt(salt, "beta");
        // Hash collisions on 32 bits are 1-in-4-billion; safe to assert.
        assert_ne!(h1, h2, "different values must produce different hashes");
    }

    #[test]
    fn policy_with_configured_salt_redacts_consistently() {
        let cfg = RbacConfig {
            enabled: true,
            roles: vec![],
            redaction_salt: Some(SecretString::from("my-stable-salt")),
        };
        let p1 = RbacPolicy::new(&cfg);
        let p2 = RbacPolicy::new(&cfg);
        assert_eq!(
            p1.redact_arg("payload"),
            p2.redact_arg("payload"),
            "policies built from the same configured salt must agree"
        );
    }

    #[test]
    fn policy_without_configured_salt_uses_process_salt() {
        let cfg = RbacConfig {
            enabled: true,
            roles: vec![],
            redaction_salt: None,
        };
        let p1 = RbacPolicy::new(&cfg);
        let p2 = RbacPolicy::new(&cfg);
        // Within one process, the lazy OnceLock salt is shared.
        assert_eq!(
            p1.redact_arg("payload"),
            p2.redact_arg("payload"),
            "process-wide salt must be consistent within one process"
        );
    }

    #[test]
    fn redact_arg_is_fast_enough() {
        // Sanity floor: a single redaction should take well under 100 µs
        // even in unoptimized debug builds. Production criterion bench
        // (see H-T4 plan) will assert a stricter <10 µs threshold.
        let salt = b"perf-sanity-salt-32-bytes-padded";
        let value = "x".repeat(256);
        let start = std::time::Instant::now();
        let _ = redact_with_salt(salt, &value);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(5),
            "single redact_with_salt took {elapsed:?}, expected <5 ms even in debug"
        );
    }

    // -- enforce_tool_policy identity propagation regression test (BUG H-S3) --

    /// Regression: when `enforce_tool_policy` denied a request, the deny
    /// log used to read `current_identity()`, which was always `None` at
    /// that point because the task-local context is installed *after*
    /// policy enforcement. The fix passes `identity_name` explicitly.
    ///
    /// We assert the deny path returns 403 (the visible behaviour).
    /// The log-content assertion lives behind tracing-test which we have
    /// not yet added as a dev-dep; the explicit-parameter signature alone
    /// makes the previous bug structurally impossible.
    #[tokio::test]
    async fn deny_path_uses_explicit_identity_not_task_local() {
        let policy = Arc::new(test_policy());
        let id = AuthIdentity {
            method: crate::auth::AuthMethod::BearerToken,
            name: "alice-the-auditor".into(),
            role: "viewer".into(),
            raw_token: None,
            sub: None,
        };
        let app = rbac_router_with_identity(policy, id);
        // viewer is not allowed to call resource_delete -> 403.
        let body = tool_call_body("resource_delete", &serde_json::json!({}));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
