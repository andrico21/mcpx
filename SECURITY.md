# Security Policy

## Supported versions

| Version  | Supported |
|----------|-----------|
| 1.3.x    | ✅        |
| 1.2.x    | ✅        |
| < 1.2    | ❌        |

We support the latest minor release and the previous one for security
fixes. Patch releases (`x.y.Z`) are issued for the supported lines only.

## Reporting a vulnerability

**Please do not report security issues through public GitHub/GitLab
issues.**

Instead, use **GitHub Security Advisories** (private vulnerability
reporting) on the public repository:

<https://github.com/andrico21/rmcp-server-kit/security/advisories/new>

Include:

- A description of the vulnerability and its impact.
- Reproduction steps (a minimal code sample if possible).
- The commit hash or release version affected.
- Any proof-of-concept exploit code.

We aim to acknowledge reports within **3 business days**, provide an
initial assessment within **7 days**, and issue a fix or mitigation plan
within **30 days** for confirmed high-severity issues.

## What counts as a vulnerability

- Authentication or authorization bypass in `auth` / `rbac` / `oauth`.
- Remote crash / denial of service triggered by a well-formed request.
- Information disclosure through error messages, logs, or admin
  endpoints.
- TLS / mTLS misconfiguration that weakens transport security below
  the documented baseline.
- Any issue in the OWASP Top 10 categories applicable to a server
  library.

## Certificate revocation

> ✅ **Since 1.2.0, rmcp-server-kit performs CDP-driven CRL revocation
> checking for client certificates by default whenever `[mtls]` is
> configured.** OCSP is **not** implemented.

### How CRL checking works

When mTLS is enabled, rmcp-server-kit:

1. At startup, scans the configured CA chain for the X.509 **CRL Distribution
   Points** (CDP) extension and fetches each referenced CRL via HTTP(S),
   bounded by a 10-second total bootstrap deadline.
2. On each new client certificate observed during a TLS handshake, lazily
   discovers any additional CDP URLs the leaf or intermediates point at and
   schedules them for fetch.
3. Caches every CRL in memory keyed by URL and refreshes it before
   `nextUpdate` (clamped to `[10 min, 24 h]`) on a background task.
4. Hot-swaps the underlying `rustls::ClientCertVerifier` via `ArcSwap` once
   new CRLs land, so handshakes always check the freshest revocation data
   without dropping in-flight connections.
5. **Fails open by default**: if a CRL cannot be fetched or has expired
   beyond the configured grace period, the handshake is still allowed and
   a `WARN` log is emitted. Operators who require fail-closed semantics can
   set `crl_deny_on_unavailable = true`.

`ReloadHandle::refresh_crls()` forces an immediate refresh of every cached
CRL — useful from an admin endpoint or a cron-driven probe.

### Configuration (TOML)

```toml
[mtls]
ca_cert_path = "/etc/certs/clients-ca.pem"

# CRL fields (all defaults shown)
crl_enabled              = true     # set false to disable revocation entirely
crl_deny_on_unavailable  = false    # fail-open by default; set true for fail-closed
crl_allow_http           = true     # allow http:// CDP URLs (CRLs are signed by the CA, so plain HTTP is acceptable)
crl_end_entity_only      = false    # check the full chain, not just the leaf
crl_enforce_expiration   = true     # reject CRLs whose nextUpdate is in the past (subject to crl_stale_grace)
crl_fetch_timeout        = "30s"    # per-fetch HTTP timeout
crl_stale_grace          = "24h"    # how long an expired CRL can still be trusted while we keep retrying
# crl_refresh_interval   = "1h"     # override the auto interval derived from nextUpdate
```

### Limitations

- **OCSP is not implemented.** If your PKI distributes revocation only via
  OCSP (no CDP), CRL checking will not protect you. Mitigations below
  still apply.
- **Caches are per-process and in-memory.** Restarting the process drops
  the cache; bootstrap re-fetches everything within the 10 s deadline.
- **CDP URLs are honoured after SSRF normalisation, not rewritten.**
  rmcp-server-kit does not proxy or pin CDP URLs, but it does enforce a
  scheme allowlist, reject userinfo, and refuse private/loopback/link-local/
  cloud-metadata IP literals before issuing the fetch (see
  [CRL fetch SSRF hardening](#crl-fetch-ssrf-hardening-since-121) below).
  Operators must still ensure their issuing CA's CDP host is reachable
  from the server's network.
- **Default is fail-open.** This protects availability over confidentiality;
  set `crl_deny_on_unavailable = true` if your threat model inverts that
  trade-off.

### CRL fetch SSRF hardening (since 1.2.1)

CRL Distribution Point URLs are extracted from X.509 extensions on
attacker-influenceable client certificates, so the CRL fetcher is treated
as a hostile-input network call. Before any HTTP request is issued,
`src/mtls_revocation.rs::ssrf_guard` rejects URLs that:

- Use a scheme other than `http://` or `https://` (`ftp://`, `file://`,
  `gopher://`, `data:`, `dict://`, etc. are all denied).
- Carry RFC 3986 userinfo (`user:pass@host`).
- Resolve (after DNS) to a private/loopback/link-local/multicast/
  unspecified/broadcast IPv4 or IPv6 address, including the cloud
  metadata endpoints `169.254.169.254` and `fd00:ec2::254`, IPv4-mapped
  IPv6 `::ffff:0:0/96`, IPv4-compatible IPv6, IPv6 unique-local
  `fc00::/7`, IPv6 link-local `fe80::/10`, and the IPv6 loopback `::1`.

In addition the fetcher applies four bounded-resource caps to limit
SSRF/DoS amplification even if a CRL host is reachable:

| Knob                            | Default       | Purpose                                                                                       |
|---------------------------------|---------------|-----------------------------------------------------------------------------------------------|
| `crl_max_concurrent_fetches`    | `4`           | Global cap on parallel CRL fetches across all hosts (per-host concurrency is hard-capped at 1). |
| `crl_max_response_bytes`        | `5 MiB`       | Body size cap; streams aborted mid-response when exceeded.                                    |
| `crl_discovery_rate_per_min`    | `60`          | Process-global rate limit on *new* CDP URLs admitted into the fetch pipeline.                  |
| `crl_fetch_timeout`             | `30 s`        | Per-fetch HTTP timeout.                                                                        |
| `crl_max_host_semaphores`      | `1024`        | Caps the number of unique CDP hosts tracked for per-host concurrency gating (since 1.3.0).    |
| `crl_max_seen_urls`            | `4096`        | Caps the URL-deduplication map to prevent unbounded memory growth from discovery (since 1.3.0). |
| `crl_max_cache_entries`        | `1024`        | Caps the number of parsed CRLs held in memory (since 1.3.0).                                  |

The fetcher also disables HTTP redirects entirely for CRL traffic — a
CRL is signed by the issuing CA, so blindly following a redirect to an
operator-unintended host has no security benefit.

As of **1.3.0**, discovery URLs containing IP literals are normalized
(rejecting octal/hex/percent-encoded obfuscation) before the SSRF check,
eliminating the bypass window identified in 1.2.1.

### OAuth SSRF hardening (since 1.3.0)

When the optional `oauth` feature is enabled, the JWKS fetcher and the
shared `OauthHttpClient` (used for token exchange, introspection, and
revocation) now enforce the same per-hop SSRF guard as the CRL fetcher.
This closes the internal-HTTPS-GET exposure identified in 1.2.1.

In addition to the per-hop DNS/private-IP guard, the OAuth subsystem
applies three resource-exhaustion caps:

| Knob                            | Default       | Purpose                                                                                       |
|---------------------------------|---------------|-----------------------------------------------------------------------------------------------|
| `max_jwks_keys`                 | `256`         | Caps the number of public keys parsed from a single JWKS document; fail-closed on overflow.   |
| `reqwest` default              | `10`          | Hard limit on the number of HTTP redirects followed during a fetch (not user-tunable).       |
| `OauthHttpClient` timeout      | `30 s`        | Total timeout for an OAuth-bound HTTP request (default).                                     |

Furthermore, `check_oauth_url` (applied at config-construction time
and redirect time) now rejects URLs that:
- Carry RFC 3986 userinfo (`https://user:pass@host/`).
- Use an IP literal in the host position (`https://127.0.0.1/`).

These hardening measures ensure that the operator-trusted configuration
model remains robust against hostile or compromised Identity Providers.

### OAuth HTTPS enforcement (since 1.2.1)

When the optional `oauth` feature is enabled, `OauthHttpClient`
(`src/oauth.rs`) installs a redirect policy that:

- Rejects HTTPS → HTTP downgrades unconditionally.
- Allows HTTP → HTTP only when the operator has set
  `oauth.allow_http_oauth_urls = true` (off by default; intended for
  local development against a non-TLS IdP).
- Caps redirect hops to a small constant.

Prefer `OauthHttpClient::with_config(&OAuthConfig)` over the deprecated
`OauthHttpClient::new()` so that this policy and the configured CA bundle
are wired consistently for every OAuth-bound HTTPS call (JWKS, discovery,
token exchange, the optional `/authorize`/`/token`/`/register`/
`/introspect`/`/revoke` proxy upstreams).

#### Trust boundary on OAuth endpoint URLs

The `oauth.issuer`, `oauth.jwks_uri`, and other OAuth/OIDC endpoint
URLs are treated as **operator-trusted configuration**, not as
attacker-supplied input. As of **1.3.0**, OAuth URL hardening operates
in two layers: `OAuthConfig::validate` rejects userinfo and ALL literal
IP hosts across the six configured URL fields (operators must use DNS
hostnames), and a sync per-hop SSRF range guard runs inside both the
`OauthHttpClient` and `JwksCache` redirect closures, rejecting targets
that resolve to private, loopback, link-local, multicast, broadcast,
unspecified, or cloud-metadata IP ranges. `https -> http` redirect
downgrades are always rejected; `http -> http` is permitted only when
`allow_http_oauth_urls = true`. This release does not add an async
DNS-resolution guard on the initial (non-redirect) OAuth request.

Implications:

- Do **not** allow tenants or end-users to influence
  `oauth.issuer` / `oauth.jwks_uri` / discovery URLs at runtime.
- A compromised IdP cannot reach internal hosts behind the SSRF guard,
  but can still trigger HTTPS GETs to any public host reachable from
  the deployment. Combine with strict egress firewalling for
  high-assurance environments.
- "Key stuffing" attacks where a hostile IdP returns thousands of JWKS
  keys to slow down validation are blocked by the `max_jwks_keys` cap
  (default 256).

### Defence-in-depth (still recommended)

Even with CRL enabled, the original mitigations remain best practice:

1. **Short-lived certificates (≤24h)** — bounds exposure regardless of CRL
   propagation latency.
   - [cert-manager](https://cert-manager.io/) `Certificate.spec.duration: 24h`, `renewBefore: 8h`.
   - [HashiCorp Vault PKI](https://developer.hashicorp.com/vault/docs/secrets/pki) `max_ttl=24h` with agent-driven renewal.
   - [Smallstep `step-ca`](https://smallstep.com/docs/step-ca/) with the autorenewal daemon.
2. **CA rotation on compromise** — for longer-lived certs you can still
   rotate the issuing CA and reload via `ReloadHandle::reload_*` for a
   zero-downtime swap of trust roots.
3. **Network-layer revocation** — block compromised peers at the service
   mesh / load balancer / firewall for sub-second propagation.

### What "point-in-time mTLS" still means

CRL checking happens at handshake time. After a connection is established,
the session remains trusted for its lifetime regardless of any subsequent
revocation event. **A long-lived mTLS session with a certificate that is
revoked *after* the handshake will continue to be honoured until the
connection is closed by either side.** Combine short-lived sessions with
short-lived certs for the strongest guarantees.

### Threat model addendum

- A stolen private key is valid until either (a) the next CRL publication
  marks it revoked **and** rmcp-server-kit's cache refreshes, or (b) the
  certificate's `notAfter` passes — whichever comes first. ≤24 h cert
  lifetimes still bound this exposure even when CRL fetching fails.
- An evicted operator's certificate becomes invalid as soon as the
  issuing CA publishes the updated CRL and rmcp-server-kit refreshes it
  (≤ `nextUpdate` clamped to 24 h, or immediately via
  `ReloadHandle::refresh_crls()`).
- OCSP is not implemented; if your PKI publishes only OCSP, treat
  revocation as unsupported and apply the defence-in-depth mitigations
  above.

## Coordinated disclosure

Once a fix is released, we will:

1. Publish a `RUSTSEC` advisory if `rustsec/advisory-db` accepts it.
2. Tag the release `X.Y.Z` (no `v` prefix) with a `[SECURITY]`
   changelog entry.
3. Credit the reporter (unless they request anonymity).

