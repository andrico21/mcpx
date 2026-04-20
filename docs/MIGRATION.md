# Migrating to the standalone `rmcp-server-kit` crate

This guide covers two migrations:

1. Moving from an in-repo `path` dependency to the standalone crate.
2. Upgrading from any `0.x` release to `1.0`.

## 1. Update your `Cargo.toml`

### Git dependency (development / pre-release)

Pin to a tagged release:

```toml
[dependencies]
rmcp-server-kit = { git = "https://github.com/andrico21/rmcp-server-kit", tag = "1.0.0", features = ["oauth"] }
```

### crates.io dependency (stable / production)

Use a caret range so patch and minor releases flow in automatically:

```toml
[dependencies]
rmcp-server-kit = { version = "1", features = ["oauth"] }
```

Avoid the exact-version pin (`version = "=1.0.0"`); it prevents security
patches from reaching your build.

## 2. Remove the workspace member

If `mcpx` was a member of your `[workspace]`, delete the `mcpx/`
directory and the `"mcpx"` entry in `Cargo.toml`:

```diff
 [workspace]
-members = ["mcpx", "my-app"]
+members = ["my-app"]
 resolver = "3"
```

If `my-app` was the only other member, consider flattening the workspace
to a single crate — see the host project's `docs/EXPORT.md` for the full
procedure.

## 3. Keep workspace-level lints in sync

`rmcp-server-kit` previously inherited `[workspace.lints.*]` from your root
`Cargo.toml`. After extraction, `rmcp-server-kit` owns its own lint table; the
downstream crate keeps (or promotes) its workspace lints independently.

## 4. Public-API changes

The extraction itself introduces **no breaking changes** in the public
API. Only stray doc comments and a hardcoded test hostname were scrubbed
(see `CHANGELOG.md` 0.9.30).

## 5. Build & verify

```bash
cargo update -p rmcp-server-kit
cargo build --all-features
cargo test --all-features
```

Expected: identical behavior to the pre-split build. If you observe
different `rmcp` version resolution, pin `rmcp` in your own `Cargo.toml`
to match the version declared in `rmcp-server-kit`'s `[dependencies]`.

## 6. Feature-flag parity

| Feature   | Meaning                                                  |
|-----------|----------------------------------------------------------|
| `oauth`   | Enables OAuth 2.1 JWT validation and token exchange.     |
| `metrics` | Exposes a Prometheus registry and `/metrics` endpoint.   |

Both remain opt-in to keep the default dependency footprint small.

---

## Migrating from 1.2.1 to 1.3.0

`1.3.0` is a **security-hardening release** focused on OAuth and mTLS
resilience. While there are no breaking public-API changes, several new
resource caps and an SSRF guard are now active by default.

### OAuth URL hardening and per-hop redirect SSRF guard

OAuth URL hardening operates in two layers:

- **At config-construction time**, `OAuthConfig::validate` rejects any of
  the six configured URL fields (`issuer`, `jwks_uri`,
  `authorization_endpoint`, `token_endpoint`, `revocation_endpoint`,
  `introspection_endpoint`) that contain HTTP userinfo (`user:pass@host`)
  or that use a literal IP host (IPv4 or IPv6). Operators must use DNS
  hostnames.
- **At runtime, on every HTTP redirect hop**, both the shared
  `OauthHttpClient` and the `JwksCache` redirect closures run a sync
  per-hop SSRF guard that rejects targets resolving to private, loopback,
  link-local, multicast, broadcast, unspecified, or cloud-metadata IP
  ranges. `https -> http` downgrades are always rejected; `http -> http`
  is permitted only when `allow_http_oauth_urls = true`.

A redirect that violates either the scheme policy or the per-hop range
guard fails the underlying `reqwest` call; on the OAuth path this surfaces
as an HTTP 500 with `"failed to fetch ..."` and the rejection reason is
emitted as a `WARN` log line.

This release does **not** add an async DNS-resolution guard on the
initial (non-redirect) OAuth request itself — the validate-time blanket
literal-IP rejection is the trust anchor for operator-supplied URLs.

### OAuth hardening: URL validation and JWKS caps

`check_oauth_url` (applied at config-construction and redirect time) now
rejects URLs containing userinfo or IP literals. Additionally, a new
fail-closed cap on the number of JWKS keys is enforced:

```toml
[oauth]
max_jwks_keys = 256  # default; fail-closed on overflow
```

If your IdP publishes an unusually large number of keys (exceeding 256), raise
`max_jwks_keys` to match your deployment requirements.

### Bounded growth for mTLS revocation (mTLS deployments only)

Three new knobs were added to `MtlsConfig` to cap memory usage in the face
of high-cardinality CRL discovery:

```toml
[mtls]
crl_max_host_semaphores = 1024  # default
crl_max_seen_urls       = 4096  # default
crl_max_cache_entries   = 1024  # default
```

These defaults are sized for enterprise deployments; operators with
thousands of distinct issuing CAs or CDP hosts should scale these caps
upward.

### Action items

1. `cargo update -p rmcp-server-kit` (or bump the pin to `"1.3.0"`).
2. If you use mTLS with a very high number of distinct CRL sources, review
   the new `crl_max_*` caps.
3. If you use OAuth, verify your `issuer` and `jwks_uri` (and any of
   `authorization_endpoint`, `token_endpoint`, `revocation_endpoint`,
   `introspection_endpoint` you set) do not use IP literals or contain
   userinfo (use DNS names instead).
4. No action required if you do not use mTLS or OAuth.

---

## Migrating from 1.2.0 to 1.2.1

`1.2.1` is a **security-hardening patch release**. There are no breaking
public-API changes; every existing `1.2.0` consumer keeps compiling and
linking. The notable behavioural changes are:

### Hardened CRL fetcher (mTLS deployments only)

The CRL Distribution Point fetcher now applies an SSRF guard before each
fetch (scheme allowlist, userinfo reject, private/loopback/link-local/
cloud-metadata IP block) and disables HTTP redirects for CRL traffic.
Three new TOML knobs were added with safe defaults (see
[`docs/GUIDE.md`](GUIDE.md#crl-configuration-toml-all-defaults-shown)
and [`SECURITY.md`](../SECURITY.md#crl-fetch-ssrf-hardening-since-121)):

```toml
[mtls]
crl_max_concurrent_fetches = 4         # default
crl_max_response_bytes     = 5242880   # 5 MiB default
crl_discovery_rate_per_min = 60        # default
```

If you previously relied on a CDP URL that resolved to a private IP
(uncommon — typically a misconfiguration), the fetch will now fail with
a structured deny log. Move the CRL host to a public address or behind
a reverse proxy that the server can reach without leaving its trust zone.

### `OauthHttpClient::new()` deprecated

`OauthHttpClient::new()` is now `#[deprecated(since = "1.2.1")]` in
favour of `OauthHttpClient::with_config(&OAuthConfig)`. The new
constructor wires the configured CA bundle, the HTTPS-downgrade-rejecting
redirect policy, and the `allow_http_oauth_urls` toggle in one call.
The old constructor still works for one more minor release.

```diff
- let http = OauthHttpClient::new()?;
+ let http = OauthHttpClient::with_config(&oauth_config)?;
```

If you build an `OAuthConfig` via the builder, no source change is
required — `JwksCache` and the OAuth proxy paths now construct
`OauthHttpClient` via `with_config` internally. The deprecation only
affects code that constructed `OauthHttpClient` directly.

### Trust-boundary clarification for OAuth endpoint URLs

`oauth.issuer` / `oauth.jwks_uri` / discovery URLs are treated as
**operator-trusted configuration** in 1.2.x. Per-hop DNS/private-IP
SSRF guarding for OAuth-bound traffic is deferred to **1.3.0**; in the
meantime, do not let tenants or end-users influence those URLs at
runtime. See
[`SECURITY.md` — Trust boundary on OAuth endpoint URLs](../SECURITY.md#trust-boundary-on-oauth-endpoint-urls).

### Action items

1. `cargo update -p rmcp-server-kit` (or bump the pin to `"1.2.1"`).
2. If you construct `OauthHttpClient` directly, switch to
   `with_config(&oauth_config)`.
3. If you run mTLS, scan your operator dashboard for CDP fetch denies
   after upgrade and reclassify any URLs that resolved to private IPs.
4. No action required if you do not use mTLS or OAuth.

---

## Migrating from 0.x to 1.0

`1.0.0` is the first stable release of `rmcp-server-kit`. From this point on the crate
follows strict [SemVer 2.0.0](https://semver.org/): no breaking changes
within the `1.x` series.

The `1.0.0` release bundles every breaking change accumulated during the
`0.x` series. If you are already on `0.13.x`, the upgrade is a no-op other
than bumping your `Cargo.toml`. If you are on an older `0.x`, review the
intermediate sections of [`CHANGELOG.md`](../CHANGELOG.md) for the full
list of behavioural changes.

### Action items

1. **Rename the crate dependency and imports.** The crate was renamed from
   `mcpx` to `rmcp-server-kit` for the `1.0.0` release. Update both
   `Cargo.toml` and Rust import paths:

    ```diff
     [dependencies]
    -mcpx = { version = "1", features = ["oauth"] }
    +rmcp-server-kit = { version = "1", features = ["oauth"] }

    -use mcpx::transport::serve;
    +use rmcp_server_kit::transport::serve;
    ```

2. **Bump the dependency.** Switch to caret-`1` to receive future
    `1.x.y` patches and minor releases automatically:

    ```toml
    rmcp-server-kit = { version = "1", features = ["oauth"] }
    ```

3. **Re-run your build & tests.** Most downstream crates need no source
   changes:

    ```bash
    cargo update -p rmcp-server-kit
    cargo build --all-features
    cargo test --all-features
    ```

4. **Audit deny / warn lint suppressions.** `rmcp-server-kit` 1.0 enforces a stricter
   lint set internally; if you copied any `#[allow(...)]` attributes from
    pre-1.0 rmcp-server-kit source they may now be redundant.

5. **Review your TOML config files** against the schema in
   [`docs/GUIDE.md`](GUIDE.md#configuration-via-toml). Any field that was
   removed during the `0.x` series will produce a deserialization error at
   startup; add or rename as appropriate.

6. **Re-pin compatible versions of `rmcp`, `tokio`, `axum`, `rustls`** to
   match the versions declared in `rmcp-server-kit 1.0.0`'s `Cargo.toml` if you saw
   resolver mismatches on `0.x`.

### What does *not* change

- Public module layout (`rmcp_server_kit::transport`, `rmcp_server_kit::auth`, `rmcp_server_kit::rbac`,
  `rmcp_server_kit::oauth`, `rmcp_server_kit::metrics`, `rmcp_server_kit::tool_hooks`, ...).
- Crate-root re-exports (`rmcp_server_kit::McpxError`, `rmcp_server_kit::Result`).
- The `serve()` / `serve_stdio()` entry-point signatures.
- Cargo feature names (`oauth`, `metrics`).
- The MCP wire protocol — `rmcp-server-kit 1.x` continues to track the latest
  stable Streamable HTTP transport from `rmcp`.

### Forward compatibility

Within `1.x`:

- New methods may be added to `#[non_exhaustive]` structs and enums.
- New variants may be added to `#[non_exhaustive]` enums.
- New optional Cargo features may be introduced.

These are explicitly **not** breaking under our SemVer policy. If you
match exhaustively on a non-exhaustive type or rely on a struct's exact
field set, expect to add a wildcard arm or use one of the constructor
helpers documented in the GUIDE.
