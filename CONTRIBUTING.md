# Contributing to rmcp-server-kit

Thanks for your interest in contributing!

## Coding standards

All Rust code in this repository must follow
[RUST_GUIDELINES.md](RUST_GUIDELINES.md). Before opening a PR, review the
Quick Reference Checklist at the end of that document; reviewers will
enforce it. For Rust / Cargo / Clippy 1.95 specifics (new lints, new
APIs, MSRV policy), see
[docs/RUST_1_95_NOTES.md](docs/RUST_1_95_NOTES.md).

## Development prerequisites

- Rust **1.95 or newer** (stable toolchain) — `edition = "2024"`.
- `cargo-deny` (for the `ci deny` step): `cargo install cargo-deny`.
- `cargo-audit` (for the `ci audit` step): `cargo install cargo-audit`.
- A nightly toolchain is only required for `cargo fmt` (the `rustfmt.toml`
  uses a couple of unstable options).

## Verification steps

Run locally before opening a PR:

```bash
cargo +nightly fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
cargo audit
```

All five must pass.

## Pull request checklist

- [ ] Commit follows the [Conventional Commits](#commit-convention) format.
- [ ] `fmt`, `clippy`, and `test` all clean.
- [ ] New public items are documented (rustdoc, `#[must_use]` where
      appropriate).
- [ ] CHANGELOG updated under `## [Unreleased]` if user-visible.
- [ ] No `unwrap()` / `expect()` / `panic!` in library code paths.
- [ ] No internal error details leaked in HTTP responses.

## Commit convention

```
<type>(<scope>): <subject>

<body>
```

**Types**: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `ci`.
**Scopes** (one of the top-level modules): `transport`, `auth`, `rbac`,
`config`, `error`, `observability`, `oauth`, `metrics`, `admin`,
`tool-hooks`, `secret`.

Examples:

- `feat(oauth): support RFC 8693 token-exchange with mTLS`
- `fix(transport): accept `Host: host:port` with non-default port`
- `docs(rbac): document task-local accessors`

## Coding rules (non-negotiable)

- `unsafe_code` is forbidden at the crate level.
- No `unwrap()` / `expect()` / `panic!` / `todo!` in library code.
- Accept `&str` not `&String`; `&[T]` not `&Vec<T>`.
- No `.clone()` to satisfy the borrow checker.
- No blocking I/O inside `async fn`.
- All HTTP responses must carry OWASP security headers set by the
  middleware stack.
- Secrets go through `secrecy::SecretString` / `secrecy::SecretBox`.

## Adding a cargo feature

1. Gate the new optional dependency with `optional = true`.
2. Add a `[features]` entry that activates it via `dep:<crate>`.
3. Document the feature in `README.md` and `docs/GUIDE.md`.
4. Add a `[package.metadata.docs.rs]` exercise if the feature introduces
   new public items (docs.rs already builds with `all-features = true`).
5. Extend CI: `cargo test --features <new-feature>` matrix entry.

## Licensing

Contributions are dual-licensed under MIT OR Apache-2.0, matching the
crate. By opening a PR you agree to this licensing.
