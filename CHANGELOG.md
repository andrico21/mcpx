# Changelog

All notable changes to `rmcp-server-kit` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Breaking changes bump the **major** version.

## [Unreleased]

### Added

- **Mutation-coverage tests** for `glob_match` / `match_middle` boundary
  cases in `src/rbac.rs` and for `RbacPolicy::argument_allowed` glob-tool
  matching, killing five surviving mutants surfaced by the nightly
  `cargo mutants` job. Each test is annotated with the specific mutation
  it kills so the intent survives future refactors.
- **Exact-string contract tests** for `AuthFailureClass::as_str`,
  `response_body`, and `bearer_error` in `src/auth.rs`. These literals
  are part of the observable wire/log surface (metric labels, audit-log
  fields, OAuth `WWW-Authenticate` reasons); the tests pin them so a
  silent change becomes a test failure.
- **Boolean-flag contract tests** for `AuthConfig::summary` in
  `src/auth.rs`, asserting `bearer` is `true` iff `api_keys` is
  non-empty (kills the surviving `!`-deletion mutant at line 615) and
  pinning `enabled` / `mtls` / `oauth` propagation.

## [1.5.0] - 2026-04-29

### Added

- **Configurable security headers** (`src/transport.rs`) -- new
  `SecurityHeadersConfig` struct and `McpServerConfig::with_security_headers`
  builder method allow operators to override or omit any of the twelve
  OWASP security headers emitted by `security_headers_middleware`. Each
  field is `Option<String>` with a three-state semantic: `None` keeps the
  default, `Some("")` omits the header entirely, and `Some(value)` overrides.
  Non-empty values are validated via `HeaderValue::from_str` inside
  `McpServerConfig::validate()`; invalid values fail server startup. The
  `Strict-Transport-Security` field additionally rejects any value containing
  `preload` (case-insensitive) -- HSTS preload-list opt-in must be made via
  a dedicated future builder, not smuggled through this knob. Existing
  defaults are unchanged; this is a purely additive API surface change.

### Fixed

- **OAuth proxy** (`src/transport.rs`) -- `/token`, `/register`, `/introspect`,
  and `/revoke` responses now include `Pragma: no-cache` and
  `Vary: Authorization`, completing RFC 6749 §5.1 / RFC 6750 §5.4 compliance
  for OAuth proxy deployments. `Cache-Control: no-store` was already set
  globally by `security_headers_middleware`; this patch fills the remaining
  legacy-cache and `Vary` gaps. The new `oauth_token_cache_headers_middleware`
  is feature-gated (`oauth`) and only active when `OAuthConfig.proxy` is
  configured -- resource-server-only deployments are unaffected. `Vary` is
  appended (not replaced), preserving any pre-existing `Vary` value (e.g.
  `Accept-Encoding` from the compression layer).

## [1.4.1] - 2026-04-24

Patch release fixing a tokenization bug in `RbacPolicy::argument_allowed`
that prevented allowlist entries containing spaces from ever matching,
and tightening fail-closed handling of malformed shell input.

### Security

- **`Cargo.lock`** -- bump transitive `rustls-webpki` `0.103.12 -> 0.103.13`
  to pick up the fix for [RUSTSEC-2026-0104](https://rustsec.org/advisories/RUSTSEC-2026-0104).
  The advisory describes a reachable panic in
  `BorrowedCertRevocationList::from_der` /
  `OwnedCertRevocationList::from_der` when parsing a syntactically valid
  empty `BIT STRING` in the `onlySomeReasons` element of an
  `IssuingDistributionPoint` CRL extension. The panic is reachable
  before the CRL signature is verified, so any consumer that fetches
  CRLs via `mtls_revocation` would be exposed; consumers that do not
  use CRLs are unaffected. No code or API changes in this crate -- the
  fix is entirely a transitive dependency bump.

### Fixed

- **`src/rbac.rs`** -- `RbacPolicy::argument_allowed` now tokenizes
  argument values with POSIX-shell-like lexical rules (`shlex::split`)
  instead of `str::split_whitespace`. Allowlist entries containing
  spaces (e.g. `/usr/bin/my tool`) now match correctly when the value
  quotes the path per shell rules; previously they were unmatchable.
  Malformed shell syntax (unbalanced quotes, dangling escapes), empty
  `value`, and well-formed but empty first argv elements (e.g.
  `value = r#""""#`) now fail closed.

### Behavior change matrix

POSIX-shell-like tokenization is now the contract. The new behavior
diverges from `str::split_whitespace` in the cases below. We ship as a
patch because (a) the function signature is unchanged, (b) the
"now-allow" change unbreaks legitimately-quoted spaced paths, and
(c) every "now-deny" change is either malformed input or a
configuration that worked only by accident under whitespace splitting
and almost certainly diverged from the consumer's actual exec
tokenization downstream.

| Input class | 1.4.0 | 1.4.1 | Direction |
|---|---|---|---|
| Plain unquoted token (`ls`) | allow if listed | allow if listed | identical |
| Quoted path with embedded space (e.g. `"/usr/bin/my tool" --x`) | deny (broken) | allow if listed | stricter-correct |
| Unbalanced quote / dangling escape | accepts truncation | **deny** | stricter (security-positive) |
| Empty input string `""` | accepts `""` if listed | **deny** | stricter |
| Quoted empty token `r#""""#` | accepts `""` if listed | **deny** | stricter |
| Tab/newline separator | works incidentally | works per POSIX | identical in practice |
| Quoted-literal allowlist entry (e.g. `["'bash'"]` matching `'bash' -c true`) | allow | **deny** (shlex strips the surrounding quotes -> first token `bash`, not `'bash'`) | observable regression -- see operator notes |
| Backslash-literal allowlist entry (e.g. `[r"foo\bar"]`) | allow | **deny** (POSIX shlex treats `\` as escape -> first token becomes `foobar`) | observable regression -- see operator notes |
| Windows-style path allowlist entry (e.g. `[r"C:\Windows\System32\cmd.exe"]`) | allow | **deny** (POSIX shlex eats backslashes) | observable regression -- see operator notes |

### Notes for operators

- **POSIX-shell-like semantics only.** The matcher now models POSIX
  word-splitting + quote removal as performed by `shlex::split`. It
  does **not** model real shell *execution* (`FOO=1 cmd`, expansions,
  command substitution, redirections, operators) or Windows
  command-line tokenization (`CommandLineToArgvW`, `cmd.exe`,
  PowerShell). Consumers in those regimes still need their own
  validation at the boundary.
- **Backslash is an escape character** under POSIX rules. Allowlist
  entries that embed `\` (e.g. Windows-style paths) must be quoted at
  the policy boundary, expressed with forward slashes, or migrated to
  a typed pre-tokenized argument matcher in a future release.
- **Quoted literals in the allowlist** (e.g. `"'bash'"`) no longer
  match. These configurations were never sound -- they only worked
  because the old `split_whitespace` first token also retained the
  quote characters as literals, which any execve-aware consumer would
  immediately strip. Update such entries to the bare command name
  (`"bash"`) or its full path.
- **Performance:** `shlex::split` allocates a `Vec<String>` for the
  full input on every matched allowlist entry, where the previous
  implementation only walked to the first whitespace. Acceptable under
  existing request-body caps; observable on adversarial input.

### API surface

API surface unchanged: signature of `RbacPolicy::argument_allowed`
(`fn(&self, role: &str, tool: &str, argument: &str, value: &str) -> bool`)
is preserved. `cargo semver-checks` confirms patch-level compatibility.

### Dependencies

- Added `shlex = "1.3"` (MIT/Apache-2.0, zero transitive deps). Pinned
  to `>=1.3` to stay on the post-RUSTSEC-2024-0006 line; that advisory
  affects `shlex::quote` / `shlex::join` (CVE-2024-58266), neither of
  which is consumed here.

## [1.4.0] - 2026-04-24

Minor release adding an opt-in operator allowlist for the OAuth/JWKS
post-DNS SSRF guard, so in-cluster IdPs (e.g. Keycloak resolving to
RFC1918 addresses) can be reached without disabling SSRF protection.
Defaults are unchanged (fail-closed), and cloud-metadata addresses
remain blocked regardless of allowlist contents.

### Added

- **`src/oauth.rs`** — New `OAuthSsrfAllowlist { hosts, cidrs }` type and
  `OAuthConfigBuilder::ssrf_allowlist(...)` setter. Lets operators name
  the hostnames or CIDR blocks (IPv4 and IPv6) whose otherwise-blocked
  addresses (private/loopback/link-local/CGNAT/unique-local) the
  OAuth/JWKS fetcher is allowed to reach. Hosts are case-insensitive
  exact match; CIDRs are family-strict (no IPv4-mapped-IPv6, no `/0`,
  no zone IDs, host bits must be zero). Misconfiguration is rejected at
  `OAuthConfig::validate()` and `JwksCache::new()` so deploy-time
  feedback is immediate. When non-empty, validation logs a
  `tracing::warn!` naming the host and CIDR counts.
- **`src/ssrf.rs`** — New `CompiledSsrfAllowlist` + `CidrEntry` types
  (crate-private) and `redirect_target_reason_with_allowlist` that
  consults the allowlist on per-redirect-hop literal-IP screening while
  keeping cloud-metadata unbypassable.
- **`src/ssrf.rs`** — Cloud-metadata classifier now also covers AWS
  IPv6 (`fd00:ec2::254`), GCP IPv6 (`fd20:ce::254`), and the
  Alibaba/Tencent IPv4 metadata address (`100.100.100.200`). These
  addresses are classified as `cloud_metadata` *before* the generic
  `unique_local` / `cgnat` buckets so an operator allowlist for
  `fd00::/8` or `100.64.0.0/10` cannot silently re-allow them.

### Security

- **`src/oauth.rs`** — Cloud-metadata IPv4 (`169.254.169.254`,
  `100.100.100.200`) and IPv6 (`fd00:ec2::254`, `fd20:ce::254`) are
  now explicitly carved out of the operator allowlist path: even when
  an operator allowlists a containing CIDR, addresses classified as
  `cloud_metadata` continue to use the strict legacy error message and
  are never permitted. New unit tests pin this invariant
  (`redirect_with_fd00_8_allowlist_still_blocks_aws_v6_metadata`,
  `redirect_with_cgnat_allowlist_still_blocks_alibaba_metadata`).
- **`src/oauth.rs`** — Empty (default) allowlist preserves the
  pre-1.4.0 error message verbatim so existing operator runbooks and
  alerting on "OAuth target resolved to blocked IP" keep working.
  Configured allowlists that still block emit a more verbose error
  naming the hostname, the resolved IP, the block reason, and the two
  config fields the operator can edit.

### Changed

- **`src/oauth.rs`** — `evaluate_oauth_redirect`,
  `screen_oauth_target`, and `screen_oauth_target_with_test_override`
  now take a `&CompiledSsrfAllowlist` parameter. These are private
  helpers; no downstream impact.

### Documentation

- **`docs/GUIDE.md`** — New "Allowing in-cluster IdPs" subsection in the
  OAuth chapter showing the recommended TOML and builder snippets.
- **`SECURITY.md`** — New "Operator allowlist" subsection under OAuth
  SSRF hardening documenting the trust model, the cloud-metadata
  carve-out, and the auditing expectations.

## [1.3.2] - 2026-04-21

Security and quality patch release rolling up the post-1.3.1 multi-agent
review findings. No breaking changes; drop-in replacement for `1.3.1`.

### Security

- **`src/auth.rs`** — Bearer-scheme parsing in the auth middleware is now case-insensitive per RFC 7235 §2.1 (e.g. `bearer …` and `BEARER …` are accepted alongside `Bearer …`). Previously these were silently rejected as `invalid_credential` and counted toward the auth-failure rate limit, which could cause spurious lockouts for spec-conformant clients.
- **`src/auth.rs`** — `AuthIdentity` and `ApiKeyEntry` now have manual `Debug` implementations that redact the raw bearer token, the JWT `sub` claim, and the Argon2id hash. This prevents secret material from leaking via `format!("{:?}", …)` or `tracing::debug!(?identity, …)` calls, and is enforced by new unit tests.
- **`src/oauth.rs`** — Added post-DNS SSRF screening for the initial OAuth/JWKS request target so hostnames resolving to blocked IP ranges are rejected before connect, mirroring CRL fetch hardening.
- **`src/oauth.rs`** — Added opt-in `strict_audience_validation` so operators can disable the legacy `azp` fallback and enforce `aud`-only audience checks for new deployments.
- **`src/transport.rs` / `src/oauth.rs`** — Added opt-in `require_auth_on_admin_endpoints` so OAuth `/introspect` and `/revoke` can be mounted behind the normal auth middleware while preserving legacy behavior by default.
- **`src/rbac.rs`** — RBAC and tool rate limiting now inspect JSON-RPC batch arrays and reject the full batch if any `tools/call` entry is denied.
- **`src/oauth.rs`** — Added `jwks_max_response_bytes` (default 1 MiB) and streaming JWKS reads so oversized responses are refused without unbounded allocation.

### Changed

- **`src/metrics.rs`** — `http_request_duration_seconds` now uses an explicit, latency-tuned bucket set (`[1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s]`) instead of the Prometheus default buckets, which were skewed toward web-page rather than RPC latency. The histogram name and labels are unchanged; existing dashboards keep working but will gain finer sub-100 ms resolution.
- **`src/tool_hooks.rs`** — `with_hooks` now documents that dropping the returned wrapper silently loses the configured hooks. The natural `#[must_use]` enforcement is deferred to the next minor-version bump (adding `#[must_use]` to a public function is a SemVer-minor change per cargo-semver-checks).
- **`README.md`** — Quick-start dependency line dropped the gratuitous `features = ["oauth"]` so a copy-paste install no longer pulls in OAuth, `jsonwebtoken`, and `reqwest` for users who only need the default transport. Optional features are now described in a separate note pointing at the Cargo features table.

### Documentation

- **`docs/ARCHITECTURE.md` / `docs/MINDMAP.md`** — Refreshed mTLS sections to match the current per-connection `TlsConnInfo` design (the previous text described the long-removed `RwLock<HashMap<SocketAddr, AuthIdentity>>` map).
- **`docs/ARCHITECTURE.md`** — Metrics section now lists only the metrics actually exported by `src/metrics.rs` (`http_requests_total`, `http_request_duration_seconds`) and points operators at `McpMetrics::registry` for custom collectors. The previous list named gauges and counters that were never implemented.

## [1.3.1] - 2026-04-21

First usable release of `rmcp-server-kit`. A reusable, production-grade
framework for building [Model Context Protocol](https://modelcontextprotocol.io/)
servers in Rust on top of the official `rmcp` SDK.

Consumers supply an `rmcp::handler::server::ServerHandler` implementation;
this crate provides Streamable HTTP transport, TLS / mTLS, structured
authentication (API key, mTLS, OAuth 2.1 JWT), RBAC with per-tool
argument allowlists, per-IP rate limiting, OWASP security headers,
structured observability, optional Prometheus metrics, admin
diagnostics, and graceful shutdown.

### Highlights

- **Transport** — Streamable HTTP (`/mcp`), `/healthz`, `/readyz`,
  `/version`, admin diagnostics, graceful shutdown, configurable TLS
  and mTLS. Optional `serve_stdio()` for local subprocess MCP.
- **Authentication** — API-key (Argon2id-hashed, constant-time verify),
  mTLS client certificates with subject→role mapping, OAuth 2.1 JWT
  validation against JWKS (feature `oauth`). Pre-auth rate limiting
  defends Argon2id against CPU-spray attacks.
- **mTLS revocation** — CDP-driven CRL fetching with bounded memory,
  bounded concurrency, and bounded discovery rate. Auto-discovers CRL
  URLs from the CA chain at startup and from connecting client certs
  during handshakes. Hot-reloadable via `ReloadHandle::refresh_crls()`.
- **RBAC** — `RbacPolicy` with default-deny, per-role allow/deny tool
  lists (glob-supported), per-tool argument allowlists, HMAC-SHA256
  argument-value redaction in deny logs, task-local accessors
  (`current_role`, `current_identity`, `current_token`, `current_sub`).
- **OAuth 2.1** — JWKS cache with refresh cooldown, configurable allowed
  algorithms (RS256/ES256 default; symmetric keys rejected), HTTPS-only
  redirect policy, custom CA support, optional OAuth proxy endpoints
  (`/authorize`, `/token`, `/register`, `/introspect`, `/revoke`).
- **SSRF hardening** — Validate-time literal-IP / userinfo rejection on
  every operator-supplied URL plus a runtime per-hop IP-range guard on
  every redirect closure (CRL, JWKS, OAuth admin traffic). Blocks
  private, loopback, link-local, multicast, broadcast, and cloud-
  metadata ranges.
- **Hardening defaults** — Per-IP token-bucket rate limiting (governor)
  with memory-bounded LRU eviction, request-body cap (default 1 MiB),
  request-timeout cap, OWASP security headers (HSTS, CSP, X-Frame-
  Options, etc.), configurable CORS and Host allow-lists, JWKS key cap
  (default 256), CRL response-body cap (default 5 MiB).
- **Hot reload** — Lock-free `arc-swap`-backed reload of API keys,
  RBAC policy, and CRL set without dropping in-flight requests.
- **Tool hooks** — Opt-in `HookedHandler` wrapping `ServerHandler` with
  async `before_call` / `after_call` hooks. After-hooks run on a
  spawned task with the parent span and RBAC task-locals re-installed.
  Configurable `max_result_bytes` cap.
- **Observability** — `tracing-subscriber` initialization with
  `EnvFilter`, JSON or pretty console output, optional audit-file
  sink. Sensitive values wrapped in `secrecy::SecretString` end-to-end.
- **Metrics** (feature `metrics`) — Prometheus registry served on a
  separate listener (request count, duration histogram, in-flight
  gauge, auth failures, RBAC denies).
- **Configuration** — Programmatic builder API on `McpServerConfig`
  with compile-time `Validated<T>` typestate, plus matching TOML
  schema in `src/config.rs`.

### Cargo features

- `oauth` (default off) — OAuth 2.1 JWT validation via JWKS plus
  optional OAuth proxy endpoints.
- `metrics` (default off) — Prometheus registry and `/metrics` endpoint.
- `test-helpers` (default off) — opt-in test-only constructors used by
  downstream integration suites; not part of the stable API surface.

### Minimum supported Rust

`rmcp-server-kit` targets stable Rust **1.95** or newer (`edition = "2024"`).

### Documentation

- [`README.md`](README.md) — quick start.
- [`docs/GUIDE.md`](docs/GUIDE.md) — end-to-end consumer guide and TOML schema.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — file-cited deep architecture map.
- [`docs/MINDMAP.md`](docs/MINDMAP.md) — visual project mindmap.
- [`AGENTS.md`](AGENTS.md) — repository navigation hub for AI agents.
- [`SECURITY.md`](SECURITY.md) — coordinated disclosure policy and
  hardening posture.
