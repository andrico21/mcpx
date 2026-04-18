//! Memory-bounded keyed rate limiter.
//!
//! [`BoundedKeyedLimiter`] wraps a map of per-key
//! [`governor::DefaultDirectRateLimiter`] instances behind a hard cap on the
//! number of tracked keys, with an idle-eviction policy and an LRU fallback
//! when the cap is reached.
//!
//! # Why
//!
//! The `governor` crate ships a [`governor::RateLimiter::keyed`] state store
//! whose memory grows monotonically with the number of distinct keys
//! observed. For server use cases keyed by source IP this is a
//! denial-of-service vector: an attacker spraying packets from spoofed or
//! distinct source addresses can exhaust process memory regardless of the
//! per-key quota.
//!
//! [`BoundedKeyedLimiter`] addresses this by:
//!
//! 1. Holding a [`std::collections::HashMap`] of `K -> Entry` where each
//!    `Entry` carries its own direct (per-key) limiter and a `last_seen`
//!    timestamp.
//! 2. Capping the map at `max_tracked_keys` entries.
//! 3. On insert when the map is full, first pruning entries whose
//!    `last_seen` is older than `idle_eviction`, then -- if still full --
//!    evicting the entry with the oldest `last_seen` ("LRU eviction").
//!    The new key is **always** inserted; honest new clients are never
//!    rejected because the table is full.
//! 4. Updating `last_seen` on **every** check (including rate-limit
//!    rejections) so an actively-firing attacker cannot dodge eviction by
//!    appearing idle.
//! 5. Optionally spawning a best-effort background prune task. Cap
//!    enforcement does **not** depend on this task running -- it is
//!    purely an optimization that reclaims memory between admission
//!    events.
//!
//! # Trade-offs
//!
//! - When a previously-evicted key reappears it gets a **fresh** quota.
//!   This is documented behaviour: a key under sustained load keeps its
//!   `last_seen` updated and therefore is never evicted; eviction only
//!   targets idle keys.
//! - The map uses [`std::sync::Mutex`] (not [`tokio::sync::Mutex`]) since
//!   admission checks must be synchronous and never `.await`.
//! - We do not log inside the critical section.

use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, Mutex, PoisonError, Weak},
    time::{Duration, Instant},
};

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};

/// Reason a [`BoundedKeyedLimiter::check_key`] call rejected a request.
///
/// Currently only carries a single variant; modelled as an enum (rather
/// than a unit struct) so callers can `match` exhaustively and to leave
/// room for future reasons (e.g. burst-debt or distinct quota classes).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BoundedLimiterError {
    /// The key has exceeded its per-key quota for the current window.
    #[error("rate limit exceeded for key")]
    RateLimited,
}

/// Per-key limiter entry: the underlying direct limiter plus the wall-clock
/// timestamp of the most recent admission attempt for this key.
struct Entry {
    limiter: DefaultDirectRateLimiter,
    last_seen: Instant,
}

/// Inner shared state. Held behind an [`Arc`] in [`BoundedKeyedLimiter`]
/// and a [`Weak`] inside the optional background prune task so the task
/// self-terminates once the limiter is dropped.
struct Inner<K: Eq + Hash + Clone> {
    map: Mutex<HashMap<K, Entry>>,
    quota: Quota,
    max_tracked_keys: usize,
    idle_eviction: Duration,
}

/// Memory-bounded keyed rate limiter.
///
/// Cheaply cloneable; clones share state.
#[allow(
    missing_debug_implementations,
    reason = "wraps governor RateLimiter which has no Debug impl"
)]
pub struct BoundedKeyedLimiter<K: Eq + Hash + Clone> {
    inner: Arc<Inner<K>>,
}

impl<K: Eq + Hash + Clone> Clone for BoundedKeyedLimiter<K> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<K: Eq + Hash + Clone + Send + Sync + 'static> BoundedKeyedLimiter<K> {
    /// Create a new bounded keyed limiter.
    ///
    /// * `quota` -- the per-key rate-limit quota applied to every entry.
    /// * `max_tracked_keys` -- hard cap on the number of simultaneously
    ///   tracked keys. When reached, an insert first prunes idle entries
    ///   then falls back to LRU eviction.
    /// * `idle_eviction` -- entries whose `last_seen` is older than this
    ///   are eligible for opportunistic pruning.
    ///
    /// # Background prune task
    ///
    /// If a Tokio runtime is available at construction time, a best-effort
    /// background task is spawned that periodically prunes idle entries.
    /// Cap enforcement does **not** depend on this task; it is purely an
    /// optimisation that reclaims memory between admission events. The
    /// task self-terminates when the last [`BoundedKeyedLimiter`] clone is
    /// dropped (it holds only a [`Weak`] reference to the inner state).
    ///
    /// If no Tokio runtime is available (e.g. unit tests using
    /// `#[test]` rather than `#[tokio::test]`), no task is spawned and
    /// pruning happens lazily on every full-table insert. Both behaviours
    /// are correct.
    #[must_use]
    pub fn new(quota: Quota, max_tracked_keys: usize, idle_eviction: Duration) -> Self {
        let inner = Arc::new(Inner {
            map: Mutex::new(HashMap::new()),
            quota,
            max_tracked_keys,
            idle_eviction,
        });
        Self::spawn_prune_task(&inner);
        Self { inner }
    }

    /// Spawn the optional background prune task. No-op if there is no
    /// current Tokio runtime.
    fn spawn_prune_task(inner: &Arc<Inner<K>>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let weak: Weak<Inner<K>> = Arc::downgrade(inner);
        // Prune at most once every quarter of `idle_eviction`, but never
        // less than once per minute (to avoid waking up too often when
        // operators configure a very long eviction window).
        let interval = (inner.idle_eviction / 4).max(Duration::from_mins(1));
        handle.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // We just woke up from `Handle::spawn`; don't burn the first tick.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                Self::prune_idle(&inner);
            }
        });
    }

    /// Drop entries whose `last_seen` is older than `idle_eviction`.
    fn prune_idle(inner: &Inner<K>) {
        let mut guard = inner.map.lock().unwrap_or_else(PoisonError::into_inner);
        let cutoff = Instant::now()
            .checked_sub(inner.idle_eviction)
            .unwrap_or_else(Instant::now);
        guard.retain(|_, entry| entry.last_seen >= cutoff);
    }

    /// Evict the single entry with the oldest `last_seen`. Caller must hold
    /// the map lock. Used only when the table is full *after* idle pruning.
    fn evict_lru(map: &mut HashMap<K, Entry>) {
        let oldest_key = map
            .iter()
            .min_by_key(|(_, entry)| entry.last_seen)
            .map(|(k, _)| k.clone());
        if let Some(key) = oldest_key {
            map.remove(&key);
        }
    }

    /// Test the per-key quota for `key`.
    ///
    /// Returns `Ok(())` if the request is allowed. The `last_seen`
    /// timestamp is updated on **every** call -- including rate-limit
    /// rejections -- so an actively firing attacker cannot age out into
    /// a fresh quota by appearing idle.
    ///
    /// When inserting a new key into a full table, idle entries are pruned
    /// first; if the table is still full, the entry with the oldest
    /// `last_seen` is evicted (LRU). The new key is always inserted --
    /// honest new clients are never rejected because the table is full.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedLimiterError::RateLimited`] when `key` has
    /// exceeded its per-key quota for the current window.
    pub fn check_key(&self, key: &K) -> Result<(), BoundedLimiterError> {
        let mut guard = self
            .inner
            .map
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        if let Some(entry) = guard.get_mut(key) {
            entry.last_seen = now;
            return entry
                .limiter
                .check()
                .map_err(|_| BoundedLimiterError::RateLimited);
        }
        // New key: make room if necessary, then insert.
        if guard.len() >= self.inner.max_tracked_keys {
            // Prune idle first.
            let cutoff = now
                .checked_sub(self.inner.idle_eviction)
                .unwrap_or_else(Instant::now);
            guard.retain(|_, entry| entry.last_seen >= cutoff);
            // If still full, evict LRU.
            if guard.len() >= self.inner.max_tracked_keys {
                Self::evict_lru(&mut guard);
            }
        }
        let limiter = RateLimiter::direct(self.inner.quota);
        let result = limiter
            .check()
            .map_err(|_| BoundedLimiterError::RateLimited);
        guard.insert(
            key.clone(),
            Entry {
                limiter,
                last_seen: now,
            },
        );
        result
    }

    /// Number of currently tracked keys. Used by tests and admin endpoints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// `true` when no keys are currently tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, num::NonZeroU32, time::Duration};

    use governor::Quota;

    use super::BoundedKeyedLimiter;

    fn ip(n: u32) -> IpAddr {
        IpAddr::from(n.to_be_bytes())
    }

    /// The hard cap on tracked keys must never be exceeded, even under a
    /// stream of distinct keys far larger than the cap.
    #[test]
    fn never_exceeds_max_tracked_keys() {
        let quota = Quota::per_minute(NonZeroU32::new(10).unwrap());
        let limiter: BoundedKeyedLimiter<IpAddr> =
            BoundedKeyedLimiter::new(quota, 100, Duration::from_hours(1));
        for i in 0..10_000_u32 {
            let _ = limiter.check_key(&ip(i));
            assert!(
                limiter.len() <= 100,
                "tracked keys exceeded cap at iteration {i}: {} > 100",
                limiter.len()
            );
        }
        assert_eq!(limiter.len(), 100, "table should be full at the cap");
    }

    /// When a previously-evicted key reappears, it must get a fresh quota.
    /// This is *documented* behaviour, not a bug: keys under sustained
    /// load keep their `last_seen` updated and therefore are not evicted.
    #[test]
    fn evicted_keys_get_fresh_quota() {
        let quota = Quota::per_minute(NonZeroU32::new(2).unwrap());
        let limiter: BoundedKeyedLimiter<IpAddr> =
            BoundedKeyedLimiter::new(quota, 2, Duration::from_hours(1));

        let target = ip(1);
        // Burn the quota for `target`.
        assert!(limiter.check_key(&target).is_ok(), "first ok");
        assert!(limiter.check_key(&target).is_ok(), "second ok");
        assert!(limiter.check_key(&target).is_err(), "third blocked");

        // Force eviction by inserting two unrelated keys (cap = 2). The
        // attacker (`target`) is rate-limited -- it has a *recent*
        // `last_seen` because of the failed check above. So inserting
        // two new keys must NOT evict the attacker; instead one of the
        // *other* unrelated keys gets evicted via LRU. We therefore
        // need three unrelated keys to push `target` out by LRU.
        //
        // Sleep a tiny amount so unrelated keys have strictly newer
        // last_seen than `target`'s last write.
        std::thread::sleep(Duration::from_millis(5));
        let _ = limiter.check_key(&ip(2));
        std::thread::sleep(Duration::from_millis(5));
        let _ = limiter.check_key(&ip(3));
        // `target` is now the oldest entry; cap is 2. ip(3) eviction LRU'd
        // either ip(2) or `target`. Inserting ip(4) again forces another
        // eviction. After enough fresh inserts, `target` is gone.
        std::thread::sleep(Duration::from_millis(5));
        let _ = limiter.check_key(&ip(4));
        std::thread::sleep(Duration::from_millis(5));
        let _ = limiter.check_key(&ip(5));

        // `target` should have been evicted by now -- a fresh check_key
        // re-inserts with a fresh quota.
        assert!(
            limiter.check_key(&target).is_ok(),
            "evicted key gets a fresh quota on reappearance"
        );
    }

    /// An actively over-quota key must NOT be evicted just because new
    /// keys are knocking. `last_seen` is updated on every check including
    /// rate-limit rejections, so the attacker stays at the front of the
    /// LRU queue. Other (older) entries are evicted instead.
    #[test]
    fn active_over_quota_key_not_evicted() {
        let quota = Quota::per_minute(NonZeroU32::new(2).unwrap());
        let limiter: BoundedKeyedLimiter<IpAddr> =
            BoundedKeyedLimiter::new(quota, 3, Duration::from_hours(1));

        // Seed the table with three idle entries so cap is reached.
        for i in 100..103_u32 {
            let _ = limiter.check_key(&ip(i));
        }
        assert_eq!(limiter.len(), 3);

        // The attacker now starts firing. First two are allowed
        // (fills quota), then we expect refusals -- but each refusal
        // updates last_seen so the attacker stays "current".
        std::thread::sleep(Duration::from_millis(5));
        let attacker = ip(200);
        // Inserting attacker evicts one of the older keys (cap=3).
        let _ = limiter.check_key(&attacker);
        let _ = limiter.check_key(&attacker);

        // Interleave attacker hits with new-key knocks. The attacker
        // keeps firing (last_seen always current), so when new keys
        // arrive and force eviction, the LRU victim must be one of the
        // *other* (older) entries, not the attacker.
        for new_key in 300..310_u32 {
            std::thread::sleep(Duration::from_millis(2));
            let _ = limiter.check_key(&attacker); // attacker stays current
            std::thread::sleep(Duration::from_millis(2));
            let _ = limiter.check_key(&ip(new_key)); // forces eviction
        }

        // One final attacker hit immediately before the assertion to
        // ensure no other key has been touched more recently.
        let _ = limiter.check_key(&attacker);

        // Attacker must STILL be rate-limited (quota exhausted, not a
        // freshly-allocated entry). The check returns Err because the
        // existing entry with exhausted quota is still there.
        assert!(
            limiter.check_key(&attacker).is_err(),
            "actively over-quota attacker must not be evicted into a fresh quota"
        );
    }
}
