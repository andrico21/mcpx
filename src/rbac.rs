//! Role-Based Access Control (RBAC) policy engine.
//!
//! Evaluates `(role, operation, host)` tuples against a set of role
//! definitions loaded from config.  Deny-overrides-allow semantics:
//! an explicit deny entry always wins over a wildcard allow.
//!
//! Includes an axum middleware that inspects MCP JSON-RPC tool calls
//! and enforces RBAC and per-IP tool rate limiting before the request
//! reaches the handler.

use std::{net::IpAddr, num::NonZeroU32, sync::Arc};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use http_body_util::BodyExt;
use serde::Deserialize;

use crate::{
    auth::{AuthIdentity, TlsConnInfo},
    error::McpxError,
};

/// Per-source-IP rate limiter for tool invocations.
pub type ToolRateLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// Default tool rate limit: 120 invocations per minute per source IP.
// SAFETY: unwrap() is safe - literal 120 is provably non-zero (const-evaluated).
const DEFAULT_TOOL_RATE: NonZeroU32 = NonZeroU32::new(120).unwrap();

/// Build a per-IP tool rate limiter from a max-calls-per-minute value.
#[must_use]
pub fn build_tool_rate_limiter(max_per_minute: u32) -> Arc<ToolRateLimiter> {
    let quota =
        governor::Quota::per_minute(NonZeroU32::new(max_per_minute).unwrap_or(DEFAULT_TOOL_RATE));
    Arc::new(RateLimiter::keyed(quota))
}

// Task-local storage for the current caller's RBAC role and identity name.
// Set by the RBAC middleware, read by tool handlers (e.g. list_hosts filtering, audit logging).
tokio::task_local! {
    static CURRENT_ROLE: String;
    static CURRENT_IDENTITY: String;
    static CURRENT_TOKEN: String;
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

/// Get the raw bearer token for the current request (set by RBAC middleware).
/// Returns `None` outside a request context or when auth used mTLS/API-key.
/// Tool handlers use this for downstream token passthrough.
#[must_use]
pub fn current_token() -> Option<String> {
    CURRENT_TOKEN
        .try_with(Clone::clone)
        .ok()
        .filter(|t| !t.is_empty())
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
pub async fn with_token_scope<F: Future>(token: String, f: F) -> F::Output {
    CURRENT_TOKEN.scope(token, f).await
}

/// Run a future with all task-locals (`CURRENT_ROLE`, `CURRENT_IDENTITY`,
/// `CURRENT_TOKEN`, `CURRENT_SUB`) set.  Use this when re-establishing the
/// full RBAC context in spawned tasks (e.g. rmcp session tasks) where the
/// middleware's scope is no longer active.
pub async fn with_rbac_scope<F: Future>(
    role: String,
    identity: String,
    token: String,
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
}

impl RbacConfig {
    /// Create an enabled RBAC config with the given roles.
    #[must_use]
    pub fn with_roles(roles: Vec<RoleConfig>) -> Self {
        Self {
            enabled: true,
            roles,
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
}

impl RbacPolicy {
    /// Build a policy from config.  When `config.enabled` is false, all
    /// checks return [`RbacDecision::Allow`].
    #[must_use]
    pub fn new(config: &RbacConfig) -> Self {
        Self {
            roles: config.roles.clone(),
            enabled: config.enabled,
        }
    }

    /// Create a policy that always allows (RBAC disabled).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            roles: Vec::new(),
            enabled: false,
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
    /// all values are allowed. When a matching entry exists, the first
    /// whitespace-delimited token of `value` (or its `/`-basename) must
    /// appear in the `allowed` list.
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
            // Match the first token (the executable / keyword).
            let first_token = value.split_whitespace().next().unwrap_or(value);
            // Also match against the basename if it's a path.
            let basename = first_token.rsplit('/').next().unwrap_or(first_token);
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
pub async fn rbac_middleware(
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
                .map(|ci| ci.0.0.ip())
        });

    // Extract caller identity and role (may be absent when auth is off).
    let identity = req.extensions().get::<AuthIdentity>();
    let identity_name = identity.map(|id| id.name.clone()).unwrap_or_default();
    let role = identity.map(|id| id.role.clone()).unwrap_or_default();
    let raw_token = identity
        .and_then(|id| id.raw_token.clone())
        .unwrap_or_default();
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

    // Try to parse as a JSON-RPC tool call.
    if let Ok(msg) = serde_json::from_slice::<JsonRpcEnvelope>(&bytes)
        && msg.method.as_deref() == Some("tools/call")
    {
        if let Some(resp) = enforce_rate_limit(tool_limiter.as_deref(), peer_ip) {
            return resp;
        }
        if let Some(ref params) = msg.params
            && policy.is_enabled()
            && let Some(resp) = enforce_tool_policy(&policy, &role, params)
        {
            return resp;
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

/// Minimal JSON-RPC envelope for extracting tool call info.
#[derive(Deserialize)]
struct JsonRpcEnvelope {
    method: Option<String>,
    params: Option<serde_json::Value>,
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
fn enforce_tool_policy(
    policy: &RbacPolicy,
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
        let identity = current_identity().unwrap_or_default();
        tracing::warn!(
            user = %identity,
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
            tracing::warn!(
                role = %role,
                tool = tool_name,
                argument = arg_key,
                value = val_str,
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

    // -- RbacPolicy::check tests --

    #[test]
    fn disabled_policy_allows_everything() {
        let policy = RbacPolicy::new(&RbacConfig {
            enabled: false,
            roles: vec![],
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
}
