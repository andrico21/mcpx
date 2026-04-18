#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unwrap_in_result,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

//! `mcpx` - reusable MCP server framework.
//!
//! Provides Streamable-HTTP transport with TLS/mTLS, health endpoints,
//! structured observability (tracing + JSON logs + audit file),
//! authentication (Bearer/mTLS/OAuth 2.1 JWT), RBAC, and rate limiting.
//! Application crates depend on `mcpx` and supply their own `ServerHandler`
//! implementation.

/// Reusable server and observability configuration primitives.
pub mod config;
/// Generic error type and `Result` alias for server-side code.
pub mod error;
/// Tracing / JSON logs / audit file initialization.
pub mod observability;
/// Streamable HTTP transport and server entry points.
pub mod transport;

/// Authentication state (API keys, mTLS, OAuth JWT) and middleware.
pub mod auth;
/// Role-based access control policy engine and middleware.
pub mod rbac;

/// Memory-bounded keyed rate limiter (LRU + idle eviction).
pub mod bounded_limiter;

/// Admin diagnostic endpoints (status, auth keys metadata, counters, RBAC).
pub mod admin;

/// Re-exports for the [`secrecy`] crate's secret-wrapper types.
pub mod secret;

/// Opt-in tool-call hooks (before/after) and result-size cap.
pub mod tool_hooks;

#[cfg(feature = "oauth")]
/// OAuth 2.1 JWKS cache, token validation, and token exchange helpers.
pub mod oauth;

#[cfg(feature = "metrics")]
/// Prometheus metrics registry shared across server components.
pub mod metrics;
