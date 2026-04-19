//! Prometheus metrics for MCP servers.
//!
//! Provides a shared [`crate::metrics::McpMetrics`] registry with standard HTTP counters.
//! The transport layer exposes these via a `/metrics` endpoint on a
//! dedicated listener when `metrics_enabled` is true.
//!
//! # Public surface and the `prometheus` crate
//!
//! [`crate::metrics::McpMetrics::registry`] and the `IntCounterVec` / `HistogramVec` fields are
//! intentionally exposed so downstream crates can register additional custom
//! collectors against the same registry. This re-exports the [`prometheus`]
//! crate types as part of `rmcp-server-kit`'s public API; pin the same major version to
//! avoid type-identity mismatches when registering custom metrics.

use std::sync::Arc;

use prometheus::{
    Encoder, HistogramVec, IntCounterVec, Registry, TextEncoder, histogram_opts, opts,
};

use crate::error::McpxError;

/// Collected Prometheus metrics for an MCP server.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct McpMetrics {
    /// Prometheus registry holding all counters and histograms.
    pub registry: Registry,
    /// Total HTTP requests by method, path, and status code.
    pub http_requests_total: IntCounterVec,
    /// HTTP request duration in seconds by method and path.
    pub http_request_duration_seconds: HistogramVec,
}

impl McpMetrics {
    /// Create a new metrics registry with default MCP counters.
    ///
    /// # Errors
    ///
    /// Returns [`McpxError::Metrics`] if counter registration fails (should
    /// not happen unless duplicate registrations occur).
    pub fn new() -> Result<Self, McpxError> {
        let registry = Registry::new();

        let http_requests_total = IntCounterVec::new(
            opts!("rmcp_server_kit_http_requests_total", "Total HTTP requests"),
            &["method", "path", "status"],
        )
        .map_err(|e| McpxError::Metrics(e.to_string()))?;
        registry
            .register(Box::new(http_requests_total.clone()))
            .map_err(|e| McpxError::Metrics(e.to_string()))?;

        let http_request_duration_seconds = HistogramVec::new(
            histogram_opts!(
                "rmcp_server_kit_http_request_duration_seconds",
                "HTTP request duration in seconds"
            ),
            &["method", "path"],
        )
        .map_err(|e| McpxError::Metrics(e.to_string()))?;
        registry
            .register(Box::new(http_request_duration_seconds.clone()))
            .map_err(|e| McpxError::Metrics(e.to_string()))?;

        Ok(Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
        })
    }

    /// Encode all collected metrics as Prometheus text format.
    #[must_use]
    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buf = Vec::new();
        if let Err(e) = encoder.encode(&metric_families, &mut buf) {
            tracing::warn!(error = %e, "prometheus encode failed");
            return String::new();
        }
        // TextEncoder always produces valid UTF-8; fall back to empty on
        // the near-impossible chance it doesn't.
        String::from_utf8(buf).unwrap_or_default()
    }
}

/// Spawn a dedicated HTTP listener that serves Prometheus metrics on `/metrics`.
///
/// # Errors
///
/// Returns [`McpxError::Startup`] if the TCP listener cannot bind or the
/// underlying axum server fails.
pub async fn serve_metrics(bind: String, metrics: Arc<McpMetrics>) -> Result<(), McpxError> {
    let app = axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let m = Arc::clone(&metrics);
            async move { m.encode() }
        }),
    );

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| McpxError::Startup(format!("metrics bind {bind}: {e}")))?;
    tracing::info!("metrics endpoint listening on http://{bind}/metrics");
    axum::serve(listener, app)
        .await
        .map_err(|e| McpxError::Startup(format!("metrics serve: {e}")))?;
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
        clippy::print_stderr
    )]
    use super::*;

    #[test]
    fn new_creates_registry_with_counters() {
        let m = McpMetrics::new().unwrap();
        // Incrementing a counter should make it appear in gather output.
        m.http_requests_total
            .with_label_values(&["GET", "/test", "200"])
            .inc();
        m.http_request_duration_seconds
            .with_label_values(&["GET", "/test"])
            .observe(0.1);
        assert_eq!(m.registry.gather().len(), 2);
    }

    #[test]
    fn encode_empty_registry() {
        let m = McpMetrics::new().unwrap();
        let output = m.encode();
        // Empty counters/histograms produce no samples but the output is valid.
        assert!(output.is_empty() || output.contains("rmcp_server_kit_"));
    }

    #[test]
    fn counter_increment_shows_in_encode() {
        let m = McpMetrics::new().unwrap();
        m.http_requests_total
            .with_label_values(&["GET", "/healthz", "200"])
            .inc();
        let output = m.encode();
        assert!(output.contains("rmcp_server_kit_http_requests_total"));
        assert!(output.contains("method=\"GET\""));
        assert!(output.contains("path=\"/healthz\""));
        assert!(output.contains("status=\"200\""));
        assert!(output.contains(" 1")); // count = 1
    }

    #[test]
    fn histogram_observe_shows_in_encode() {
        let m = McpMetrics::new().unwrap();
        m.http_request_duration_seconds
            .with_label_values(&["POST", "/mcp"])
            .observe(0.042);
        let output = m.encode();
        assert!(output.contains("rmcp_server_kit_http_request_duration_seconds"));
        assert!(output.contains("method=\"POST\""));
        assert!(output.contains("path=\"/mcp\""));
    }

    #[test]
    fn multiple_increments_accumulate() {
        let m = McpMetrics::new().unwrap();
        let counter = m
            .http_requests_total
            .with_label_values(&["POST", "/mcp", "200"]);
        counter.inc();
        counter.inc();
        counter.inc();
        let output = m.encode();
        assert!(output.contains(" 3")); // count = 3
    }

    #[test]
    fn clone_shares_registry() {
        let m = McpMetrics::new().unwrap();
        let m2 = m.clone();
        m.http_requests_total
            .with_label_values(&["GET", "/test", "200"])
            .inc();
        // The clone should see the same counter value.
        let output = m2.encode();
        assert!(output.contains(" 1"));
    }
}
