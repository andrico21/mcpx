//! Admin diagnostic endpoints.
//!
//! When enabled, the server exposes a small `/admin/*` surface that returns
//! read-only diagnostic JSON: uptime, active auth configuration (no
//! secrets), auth counters, and an RBAC policy summary.
//!
//! The admin router is always wrapped in the existing auth + RBAC stack
//! and additionally requires the caller's role to match the `role` field
//! on [`crate::admin::AdminConfig`]. Configuration validation refuses to
//! enable admin without auth.

use std::{
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;

use crate::{auth::AuthState, rbac::RbacPolicy};

/// Admin endpoint configuration.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AdminConfig {
    /// RBAC role required to access the admin endpoints.
    pub role: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            role: "admin".to_owned(),
        }
    }
}

/// Shared state used by admin endpoint handlers.
#[allow(
    missing_debug_implementations,
    reason = "contains Arc<AuthState> and ArcSwap<RbacPolicy> without Debug impls"
)]
#[derive(Clone)]
#[non_exhaustive]
pub struct AdminState {
    /// Server start instant, used for uptime.
    pub started_at: Instant,
    /// Server name for /admin/status.
    pub name: String,
    /// Server version for /admin/status.
    pub version: String,
    /// Shared auth state (optional for test constructions).
    pub auth: Option<Arc<AuthState>>,
    /// Shared RBAC policy for diagnostics.
    pub rbac: Arc<ArcSwap<RbacPolicy>>,
}

/// `/admin/status` response body.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct AdminStatus {
    /// Server name.
    pub name: String,
    /// Server version string.
    pub version: String,
    /// Seconds since the server process started.
    pub uptime_seconds: u64,
    /// Wall-clock UNIX epoch at startup.
    pub started_at_epoch: u64,
}

fn admin_status(state: &AdminState) -> AdminStatus {
    let started_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
        .saturating_sub(state.started_at.elapsed().as_secs());
    AdminStatus {
        name: state.name.clone(),
        version: state.version.clone(),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        started_at_epoch: started_epoch,
    }
}

async fn status_handler(State(state): State<AdminState>) -> Json<AdminStatus> {
    Json(admin_status(&state))
}

async fn auth_keys_handler(State(state): State<AdminState>) -> Response {
    state.auth.as_ref().map_or_else(
        || not_available("auth is not configured"),
        |auth| Json(auth.api_key_summaries()).into_response(),
    )
}

async fn auth_counters_handler(State(state): State<AdminState>) -> Response {
    state.auth.as_ref().map_or_else(
        || not_available("auth is not configured"),
        |auth| Json(auth.counters_snapshot()).into_response(),
    )
}

async fn rbac_handler(State(state): State<AdminState>) -> Response {
    Json(state.rbac.load().summary()).into_response()
}

fn not_available(reason: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "unavailable",
            "error_description": reason,
        })),
    )
        .into_response()
}

/// Role-check middleware for admin routes.
///
/// Reads the caller's role from the `AuthIdentity` request extension
/// (populated by the outer auth middleware) and rejects requests whose
/// role does not match `expected_role`.
pub async fn require_admin_role(
    expected_role: Arc<str>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let role = req
        .extensions()
        .get::<crate::auth::AuthIdentity>()
        .map_or("", |id| id.role.as_str());
    if role != expected_role.as_ref() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "error_description": "admin role required",
            })),
        )
            .into_response();
    }
    next.run(req).await
}

/// Build the `/admin` router layered with the admin role check.
///
/// The caller is expected to merge this router on top of their top-level
/// router *after* the auth + RBAC middleware has been installed, so that
/// by the time a request reaches this router the task-local role is set.
pub fn admin_router(state: AdminState, config: &AdminConfig) -> Router {
    let role: Arc<str> = Arc::from(config.role.as_str());
    Router::new()
        .route("/admin/status", get(status_handler))
        .route("/admin/auth/keys", get(auth_keys_handler))
        .route("/admin/auth/counters", get(auth_counters_handler))
        .route("/admin/rbac", get(rbac_handler))
        .with_state(state)
        .layer(axum::middleware::from_fn(move |req, next| {
            let r = Arc::clone(&role);
            require_admin_role(r, req, next)
        }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::sync::Mutex;

    use axum::http::Request;
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        auth::{ApiKeyEntry, AuthCounters, AuthIdentity, AuthMethod, AuthState},
        rbac::{RbacConfig, RbacPolicy, RoleConfig},
    };

    fn make_auth_state() -> Arc<AuthState> {
        Arc::new(AuthState {
            api_keys: ArcSwap::from_pointee(vec![ApiKeyEntry::new(
                "test-key",
                "argon2id-hash",
                "admin",
            )]),
            rate_limiter: None,
            #[cfg(feature = "oauth")]
            jwks_cache: None,
            seen_identities: Mutex::new(std::collections::HashSet::default()),
            counters: AuthCounters::default(),
        })
    }

    fn make_state() -> AdminState {
        AdminState {
            started_at: Instant::now(),
            name: "test".into(),
            version: "0.0.0".into(),
            auth: Some(make_auth_state()),
            rbac: Arc::new(ArcSwap::from_pointee(RbacPolicy::new(
                &RbacConfig::with_roles(vec![RoleConfig::new(
                    "admin",
                    vec!["*".into()],
                    vec!["*".into()],
                )]),
            ))),
        }
    }

    fn admin_req(uri: &str, role: Option<&str>) -> Request<Body> {
        let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        if let Some(r) = role {
            req.extensions_mut().insert(AuthIdentity {
                name: "tester".into(),
                role: r.to_owned(),
                method: AuthMethod::BearerToken,
                raw_token: None,
                sub: None,
            });
        }
        req
    }

    #[tokio::test]
    async fn keys_endpoint_omits_hash() {
        let app = admin_router(make_state(), &AdminConfig::default());
        let resp = app
            .oneshot(admin_req("/admin/auth/keys", Some("admin")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], "test-key");
        assert!(arr[0].get("hash").is_none());
    }

    #[tokio::test]
    async fn wrong_role_gets_403() {
        let app = admin_router(make_state(), &AdminConfig::default());
        let resp = app
            .oneshot(admin_req("/admin/status", Some("viewer")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn no_identity_gets_403() {
        let app = admin_router(make_state(), &AdminConfig::default());
        let resp = app.oneshot(admin_req("/admin/status", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn status_returns_uptime() {
        let app = admin_router(make_state(), &AdminConfig::default());
        let resp = app
            .oneshot(admin_req("/admin/status", Some("admin")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rbac_summary_includes_role_list() {
        let app = admin_router(make_state(), &AdminConfig::default());
        let resp = app
            .oneshot(admin_req("/admin/rbac", Some("admin")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["roles"][0]["name"], "admin");
    }
}
