# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.9.x   | ✅        |
| < 0.9   | ❌        |

Once `mcpx` reaches 1.0, we will support the latest minor release and the
previous one for security fixes.

## Reporting a vulnerability

**Please do not report security issues through public GitHub/GitLab
issues.**

Instead, use **GitHub Security Advisories** (private vulnerability
reporting) on the public repository:

<https://github.com/andrico21/mcp-mcpx/security/advisories/new>

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

## Coordinated disclosure

Once a fix is released, we will:

1. Publish a `RUSTSEC` advisory if `rustsec/advisory-db` accepts it.
2. Tag the release `vX.Y.Z` with a `[SECURITY]` changelog entry.
3. Credit the reporter (unless they request anonymity).
