//! Memory-bound regression test for [`mcpx::bounded_limiter::BoundedKeyedLimiter`].
//!
//! This test pushes one million distinct source IPs through a 10 000-key
//! bounded limiter and asserts that the resident set does not grow by more
//! than 50 MiB. It is `#[ignore]`-gated because it is slow and noisy on
//! shared CI runners; run it explicitly with:
//!
//! ```sh
//! cargo test --release --test limiter_memory -- --ignored --nocapture
//! ```
//!
//! A dedicated `memory-bounds` CI job runs this on Linux as a release-gate.

#![allow(clippy::expect_used, clippy::print_stderr, clippy::cast_precision_loss)]

use std::{net::IpAddr, time::Duration};

use mcpx::bounded_limiter::BoundedKeyedLimiter;

/// Maximum permissible RSS growth (in MiB) over the test body.
///
/// Empirically, 1 M unique IPv4 addresses through a 10 000-key bounded
/// limiter holds well under 10 MiB of growth on Linux. We assert a 50 MiB
/// ceiling to give room for allocator slack and CI variance while still
/// catching genuine unbounded growth (which would be hundreds of MiB).
const MAX_RSS_GROWTH_MIB: f64 = 50.0;

/// Number of distinct keys to send through the limiter.
const TOTAL_KEYS: u32 = 1_000_000;

/// Hard cap on simultaneously tracked keys.
const MAX_TRACKED: usize = 10_000;

#[test]
#[ignore = "memory benchmark; run explicitly via --ignored"]
fn one_million_ips_holds_under_50mib() {
    let baseline = memory_stats::memory_stats()
        .expect("memory_stats unavailable on this platform")
        .physical_mem;

    let limiter: BoundedKeyedLimiter<IpAddr> =
        BoundedKeyedLimiter::with_per_minute(10, MAX_TRACKED, Duration::from_mins(15));

    for i in 0..TOTAL_KEYS {
        let _ = limiter.check_key(&IpAddr::from(i.to_be_bytes()));
    }

    assert_eq!(
        limiter.len(),
        MAX_TRACKED,
        "tracked-key cap must hold exactly at MAX_TRACKED after 1 M inserts"
    );

    let after = memory_stats::memory_stats()
        .expect("memory_stats unavailable on this platform")
        .physical_mem;

    let growth_mib = (after.saturating_sub(baseline)) as f64 / (1024.0 * 1024.0);
    eprintln!("RSS growth: {growth_mib:.2} MiB (cap {MAX_RSS_GROWTH_MIB:.0} MiB)");
    assert!(
        growth_mib < MAX_RSS_GROWTH_MIB,
        "RSS grew by {growth_mib:.2} MiB; expected under {MAX_RSS_GROWTH_MIB:.0} MiB. \
         Memory bound likely regressed."
    );
}
