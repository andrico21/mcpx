use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

/// Generic MCP server error type.
///
/// Application crates should define their own error types and convert
/// from/into `McpxError` where needed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum McpxError {
    /// Configuration parsing or validation failed.
    #[error("configuration error: {0}")]
    Config(String),

    /// Authentication failed (bad/missing credential).
    #[error("authentication failed: {0}")]
    Auth(String),

    /// Authorization (RBAC) denied the request.
    #[error("authorization denied: {0}")]
    Rbac(String),

    /// Request was rejected by a rate limiter.
    #[error("rate limited: {0}")]
    RateLimited(String),

    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// TOML parse error (configuration loading).
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    /// TLS configuration failure (certificate load, key parse, rustls config).
    #[error("TLS error: {0}")]
    Tls(String),

    /// Server startup failure (binding, listener, runtime initialization).
    #[error("server startup error: {0}")]
    Startup(String),

    /// Metrics registration failure (e.g. Prometheus duplicate or invalid metric).
    #[cfg(feature = "metrics")]
    #[error("metrics error: {0}")]
    Metrics(String),
}

impl IntoResponse for McpxError {
    fn into_response(self) -> Response {
        let (status, client_msg) = match self {
            Self::Auth(msg) => (StatusCode::UNAUTHORIZED, msg),
            Self::Rbac(msg) => (StatusCode::FORBIDDEN, msg),
            Self::RateLimited(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
            // All remaining variants are internal - return a generic 500
            // to avoid leaking implementation details.
            other @ (Self::Config(_)
            | Self::Io(_)
            | Self::Json(_)
            | Self::Toml(_)
            | Self::Tls(_)
            | Self::Startup(_)) => {
                tracing::error!(error = %other, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
            #[cfg(feature = "metrics")]
            other @ Self::Metrics(_) => {
                tracing::error!(error = %other, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
        };
        (status, client_msg).into_response()
    }
}

/// Convenience `Result` alias bound to [`McpxError`].
pub type Result<T> = std::result::Result<T, McpxError>;

#[cfg(test)]
mod tests {
    use axum::{http::StatusCode, response::IntoResponse};
    use http_body_util::BodyExt;

    use super::*;

    async fn status_of(err: McpxError) -> (StatusCode, String) {
        let resp = err.into_response();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn auth_error_returns_401() {
        let (status, body) = status_of(McpxError::Auth("bad token".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("bad token"));
    }

    #[tokio::test]
    async fn rbac_error_returns_403() {
        let (status, body) = status_of(McpxError::Rbac("denied".into())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("denied"));
    }

    #[tokio::test]
    async fn rate_limited_error_returns_429() {
        let (status, body) = status_of(McpxError::RateLimited("slow down".into())).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(body.contains("slow down"));
    }

    #[tokio::test]
    async fn config_error_returns_500() {
        let (status, body) = status_of(McpxError::Config("bad".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body, "internal server error",
            "must not leak internal detail"
        );
    }

    #[tokio::test]
    async fn io_error_returns_500() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let (status, body) = status_of(McpxError::from(io_err)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body, "internal server error",
            "must not leak internal detail"
        );
    }

    #[tokio::test]
    async fn tls_error_returns_500() {
        let (status, body) = status_of(McpxError::Tls("bad cert".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body, "internal server error",
            "must not leak internal detail"
        );
    }

    #[tokio::test]
    async fn startup_error_returns_500() {
        let (status, body) = status_of(McpxError::Startup("bind failed".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body, "internal server error",
            "must not leak internal detail"
        );
    }

    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn metrics_error_returns_500() {
        let (status, body) = status_of(McpxError::Metrics("dup metric".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body, "internal server error",
            "must not leak internal detail"
        );
    }

    #[test]
    fn display_preserves_message() {
        let err = McpxError::Auth("unauthorized".into());
        assert_eq!(err.to_string(), "authentication failed: unauthorized");

        let err = McpxError::Rbac("forbidden".into());
        assert_eq!(err.to_string(), "authorization denied: forbidden");

        let err = McpxError::RateLimited("throttled".into());
        assert_eq!(err.to_string(), "rate limited: throttled");
    }
}
