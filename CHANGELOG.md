# Changelog

All notable changes to `mcpx` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0: breaking changes bump the **minor** version.

## [Unreleased]

## [0.9.30] - 2026-04-17

### Added
- Initial public release as a standalone crate, extracted from the
  `atlassian-mcp-rs` monorepo.
- Streamable HTTP transport with TLS/mTLS, `/mcp`, `/healthz`, `/readyz`,
  and admin diagnostic endpoints.
- API-key, mTLS, and OAuth 2.1 JWT (feature `oauth`) authentication
  middleware.
- Role-based access control engine with per-tool allow-lists and
  per-role argument constraints.
- Per-IP rate limiting, request-body caps, OWASP security headers,
  configurable CORS and Host allow-lists.
- Optional Prometheus metrics (feature `metrics`).
- Opt-in tool-call hooks with a configurable result-size cap.
- OAuth 2.1 JWKS cache, token validation, and RFC 8693 token-exchange
  helpers (feature `oauth`).
