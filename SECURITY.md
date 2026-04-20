# Security Policy

## Supported versions

| Version  | Supported |
|----------|-----------|
| 0.11.x   | ✅        |
| 0.10.x   | ✅        |
| < 0.10   | ❌        |

Once `rmcp-server-kit` reaches 1.0, we will support the latest minor release and the
previous one for security fixes.

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
- **CDP URLs are honoured as-is.** rmcp-server-kit does not rewrite,
  proxy, or pin them. Operators must ensure their issuing CA's CDP host
  is reachable from the server's network.
- **Default is fail-open.** This protects availability over confidentiality;
  set `crl_deny_on_unavailable = true` if your threat model inverts that
  trade-off.

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

