//! In-process replay cache, for single-replica deployments only.

use ans_verify::{MemoryReplayCache, PopErrorKind, ReplayCache as _};

use crate::backend::ReplayBackend;
use crate::error::ReplayError;

/// A bounded, in-process replay cache.
///
/// This wraps the SDK's own [`MemoryReplayCache`] rather than reimplementing it.
/// Its generation-bucketed eviction and capacity handling are already written and
/// tested there, and a second implementation of a security-critical structure is
/// a second thing to get wrong.
///
/// # Not conformant behind a load balancer
///
/// §7.6 is explicit: "An in-process cache blocks reuse within one replica only; a
/// proof replays cleanly against any other replica. Multi-replica deployments
/// MUST share the replay cache across replicas serving the same `htu`
/// authority." [`ReplayBackend::is_shared`] returns `false` here so configuration
/// validation can refuse the combination.
#[derive(Debug)]
pub struct MemoryBackend {
    inner: MemoryReplayCache,
}

impl MemoryBackend {
    /// Build a cache holding at most `max_entries` live entries.
    ///
    /// Size it for the in-flight window, per §7.6:
    /// `max_entries >= peak_rps * (pop_skew + grace)`. Passing `0` takes the
    /// SDK's default.
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: MemoryReplayCache::new(max_entries),
        }
    }

    /// Live entries currently held.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when nothing is held.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// The configured entry ceiling.
    ///
    /// §7.6 and §9.6 want an alarm on occupancy *before* saturation, because a
    /// saturated cache is an authentication outage for every caller rather than a
    /// degradation.
    pub fn capacity(&self) -> usize {
        self.inner.cap()
    }
}

#[async_trait::async_trait]
impl ReplayBackend for MemoryBackend {
    async fn check_and_store(&self, key: &str, exp_unix: i64) -> Result<bool, ReplayError> {
        // The SDK reports capacity exhaustion as an error, which it can do from
        // inside its own crate. Translate rather than swallow the cause.
        self.inner
            .check_and_store(key, exp_unix)
            .await
            .map_err(|err| match err.kind {
                PopErrorKind::ReplayCacheFull => ReplayError::AtCapacity { live: self.len() },
                _ => ReplayError::Unavailable(err.to_string()),
            })
    }

    fn kind(&self) -> &'static str {
        "memory"
    }

    fn is_shared(&self) -> bool {
        false
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_fresh_key_stores_and_a_repeat_is_a_replay() {
        let b = MemoryBackend::new(16);
        let exp = far_future();
        assert!(!b.check_and_store("a", exp).await.unwrap());
        assert!(b.check_and_store("a", exp).await.unwrap());
    }

    #[tokio::test]
    async fn distinct_keys_do_not_collide() {
        let b = MemoryBackend::new(16);
        let exp = far_future();
        assert!(!b.check_and_store("a", exp).await.unwrap());
        assert!(!b.check_and_store("b", exp).await.unwrap());
    }

    #[tokio::test]
    async fn capacity_exhaustion_is_an_error_not_a_silent_admit() {
        // §7.6: over-retention is the safe direction; silently making room is
        // not. A full cache must refuse, and the refusal must be distinguishable
        // from "fresh".
        let b = MemoryBackend::new(1);
        let exp = far_future();
        assert!(!b.check_and_store("first", exp).await.unwrap());
        let err = b.check_and_store("second", exp).await.unwrap_err();
        assert!(matches!(err, ReplayError::AtCapacity { .. }), "got {err:?}");
    }

    #[test]
    fn reports_itself_as_unshared() {
        // This is what stops a multi-replica deployment silently violating §7.6.
        let b = MemoryBackend::new(1);
        assert!(!b.is_shared());
        assert_eq!(b.kind(), "memory");
    }

    #[test]
    fn capacity_is_visible_for_occupancy_alarms() {
        let b = MemoryBackend::new(64);
        assert_eq!(b.capacity(), 64);
        assert!(b.is_empty());
    }

    fn far_future() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
        .unwrap_or(0)
            + 3600
    }
}
