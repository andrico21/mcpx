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

Users of the internal mirror at
`[REDACTED]` may alternatively open a
**confidential issue** in that project.

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

> ⚠️ **rmcp-server-kit does NOT validate CRL or OCSP for client certificates.**
> mTLS authentication is verified **point-in-time at the TLS handshake**
> against the configured trust roots. There is **no online revocation
> check**, no CRL fetcher, and no OCSP stapling validator.

This is a deliberate trade-off: CRL/OCSP machinery adds significant
operational complexity (network dependencies, soft-fail vs hard-fail
semantics, clock skew, stapling negotiation) that is rarely tuned
correctly and is itself a frequent source of outages and
vulnerabilities. Operators are expected to manage revocation **out of
band** using one of the following workflows.

### Required mitigations (pick at least one)

1. **Short-lived certificates (≤24h)** — strongly recommended.
   - The cert lifetime IS the revocation window.
   - Issue with [cert-manager](https://cert-manager.io/) using
     `Certificate.spec.duration: 24h` (or shorter) and
     `renewBefore: 8h`.
   - Issue with [HashiCorp Vault PKI](https://developer.hashicorp.com/vault/docs/secrets/pki)
     dynamic secrets (`max_ttl=24h`, agent-driven renewal).
   - Issue with [Smallstep `step-ca`](https://smallstep.com/docs/step-ca/)
     and the autorenewal daemon.
2. **CA rotation on compromise** — for longer-lived certs, you MUST
   rotate the issuing CA and reload rmcp-server-kit (use the `ReloadHandle` from
   `transport::serve()` to swap trust roots without restart).
3. **Network-layer revocation** — block compromised peers at your
   service mesh / load balancer / firewall.

### What "point-in-time mTLS" means

When a client presents a certificate, rmcp-server-kit (via `rustls`) verifies:

- The chain validates against the configured CA roots.
- The leaf certificate's `notBefore` / `notAfter` window covers
  *now*.
- Signatures are cryptographically valid.

After the handshake completes, the connection is trusted for its
lifetime regardless of any subsequent revocation event. **A long-lived
mTLS session with a revoked certificate will continue to be honoured
until the connection is closed by either side.**

### Threat model addendum

- A stolen private key is valid for the full remaining lifetime of the
  associated certificate. ≤24h cert lifetimes bound this exposure.
- An evicted operator's certificate remains valid until expiry. Use
  short-lived certs and/or rotate the issuing CA.
- rmcp-server-kit does **not** participate in any revocation protocol. Adding CRL
  or OCSP validation is **deferred** and tracked as a future
  enhancement (no committed timeline).

## Coordinated disclosure

Once a fix is released, we will:

1. Publish a `RUSTSEC` advisory if `rustsec/advisory-db` accepts it.
2. Tag the release `X.Y.Z` (no `v` prefix) with a `[SECURITY]`
   changelog entry.
3. Credit the reporter (unless they request anonymity).

