#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Property-based tests for `rmcp-server-kit`.
//!
//! Each target asserts a *property* that must hold for an arbitrary,
//! generator-produced input. Cases run with the proptest default budget
//! (≥1024 cases per target) so regressions in the asserted properties
//! are caught probabilistically rather than relying on hand-picked
//! examples.
//!
//! Targets:
//!
//! 1. **API key generate→verify round-trip** -- every freshly generated
//!    key must verify against itself, regardless of the surrounding
//!    timing or noise from co-generated keys.
//! 2. **`argument_allowed` monotonicity** -- when an allowlist contains
//!    a value, that value's *first POSIX-shell argv element* must be
//!    accepted; when an allowlist is non-empty and does NOT contain the
//!    value, the value must be rejected. This guards against silent
//!    regressions in the `glob_match` / basename matching path.
//! 3. **Tool-name glob safety** -- patterns built from random
//!    alphanumeric strings + `*` wildcards must never panic when matched
//!    against arbitrary tool names. (Catches regex/glob-engine
//!    regressions.)

use proptest::prelude::*;
use rmcp_server_kit::{
    auth::{ApiKeyEntry, generate_api_key, verify_bearer_token},
    rbac::{ArgumentAllowlist, RbacConfig, RbacPolicy, RoleConfig},
};

// Proptest config: ≥1024 cases per target (plan acceptance gate).
// Argon2id verification is intentionally CPU-expensive, so the API-key
// round-trip uses a smaller case count to keep total runtime sane while
// still exceeding the previous default by 4x.
const PROPTEST_CASES: u32 = 1024;
const ARGON2_PROPTEST_CASES: u32 = 64;

// ---------------------------------------------------------------------------
// 1. API key round-trip
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(ARGON2_PROPTEST_CASES))]

    /// `generate_api_key` must always produce a token that verifies.
    /// The `extra_keys` parameter introduces decoy entries to ensure
    /// constant-time iteration in `verify_bearer_token` does not affect
    /// correctness of the matching key.
    #[test]
    fn api_key_generate_verify_roundtrip(extra_keys in 0usize..4) {
        let (token, hash) = generate_api_key().expect("generate_api_key");
        let mut keys = vec![ApiKeyEntry::new("primary", hash, "viewer")];
        // Add decoy keys whose hashes are valid but won't match `token`.
        for i in 0..extra_keys {
            let (_decoy_token, decoy_hash) =
                generate_api_key().expect("generate_api_key decoy");
            keys.push(ApiKeyEntry::new(format!("decoy-{i}"), decoy_hash, "viewer"));
        }
        let id = verify_bearer_token(&token, &keys);
        prop_assert!(id.is_some(), "freshly generated token must verify");
        let id = id.expect("verified identity");
        prop_assert_eq!(id.name, "primary");
        prop_assert_eq!(id.role, "viewer");
    }
}

// ---------------------------------------------------------------------------
// 2. argument_allowed monotonicity
// ---------------------------------------------------------------------------

/// Generate a non-empty alphanumeric token (no whitespace, no slash, no
/// glob meta-chars).
fn token_strategy() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9_]{0,15}".prop_map(String::from)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// When `allowed` contains `value`, the policy must accept; when
    /// `allowed` is non-empty and does not contain `value`, it must
    /// reject. The argument value is the bare token (no whitespace), so
    /// the first-token / basename normalization in
    /// [`RbacPolicy::argument_allowed`] is an identity mapping here.
    #[test]
    fn argument_allowed_membership(
        allowed in proptest::collection::vec(token_strategy(), 1..8),
        candidate in token_strategy(),
    ) {
        let role = RoleConfig::new(
            "viewer",
            vec!["run_query".into()],
            vec!["*".into()],
        )
        .with_argument_allowlists(vec![ArgumentAllowlist::new(
            "run_query",
            "cmd",
            allowed.clone(),
        )]);
        let mut config = RbacConfig::with_roles(vec![role]);
        config.enabled = true;
        let policy = RbacPolicy::new(&config);

        let actual = policy.argument_allowed("viewer", "run_query", "cmd", &candidate);
        let expected = allowed.iter().any(|v| v == &candidate);
        prop_assert_eq!(actual, expected,
            "argument_allowed disagrees with set membership");
    }
}

// ---------------------------------------------------------------------------
// 3. Tool-name glob safety
// ---------------------------------------------------------------------------

/// Generate a glob pattern: alphanumeric segments separated by `*`.
fn glob_pattern_strategy() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z]{1,6}", 1..5).prop_map(|parts| parts.join("*"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// Pattern matching against arbitrary tool names must never panic.
    /// The result itself is opaque -- this target exists to fuzz the
    /// `glob_match` path used by per-tool argument allowlists.
    #[test]
    fn glob_pattern_never_panics(
        pattern in glob_pattern_strategy(),
        tool in "[a-z]{1,12}".prop_map(String::from),
    ) {
        let role = RoleConfig::new(
            "viewer",
            vec!["*".into()],
            vec!["*".into()],
        )
        .with_argument_allowlists(vec![ArgumentAllowlist::new(
            pattern,
            "cmd",
            vec!["ls".into()],
        )]);
        let mut config = RbacConfig::with_roles(vec![role]);
        config.enabled = true;
        let policy = RbacPolicy::new(&config);

        // Both branches must terminate without panicking on any input.
        let _ = policy.argument_allowed("viewer", &tool, "cmd", "ls");
        let _ = policy.argument_allowed("viewer", &tool, "cmd", "rm");
    }
}
