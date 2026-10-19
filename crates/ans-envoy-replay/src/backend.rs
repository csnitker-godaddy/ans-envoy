//! The replay-backend trait and the fail-closed bridge to the SDK.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ans_verify::{PopError, PopErrorKind, ReplayCache};

use crate::error::ReplayError;

/// A store that can atomically record a single-use proof identifier.
///
/// Backends retain infrastructure error details; [`FailClosedCache`] maps them
/// to the SDK's public error categories while counting and logging failures.
///
/// Implementations MUST make check-and-store a single atomic operation (§7.6).
/// Read-then-write across two round trips is not sufficient: two replicas
/// handling the same replayed proof would both read "absent" and both admit it.
#[async_trait::async_trait]
pub trait ReplayBackend: Send + Sync + std::fmt::Debug {
    /// Record `key`, reporting whether it was already present and live.
    ///
    /// `Ok(true)` means the key was already there — a replay. `Ok(false)` means
    /// it was stored. `Err` means the backend could not decide, which is a
    /// rejection.
    async fn check_and_store(&self, key: &str, exp_unix: i64) -> Result<bool, ReplayError>;

    /// Short name for logs and metrics, e.g. `redis` or `memory`.
    fn kind(&self) -> &'static str;

    /// Whether this backend is shared across replicas.
    ///
    /// §7.6: "Multi-replica deployments MUST share the replay cache across
    /// replicas serving the same `htu` authority." Configuration validation uses
    /// this to refuse a multi-replica deployment on an in-process cache.
    fn is_shared(&self) -> bool;
}

/// Counters for what the replay layer actually did.
///
/// Infrastructure failures remain distinct from actual replay attempts.
#[derive(Debug, Default)]
pub struct ReplayMetrics {
    fresh: AtomicU64,
    replayed: AtomicU64,
    backend_errors: AtomicU64,
}

impl ReplayMetrics {
    /// Proofs recorded for the first time.
    pub fn fresh(&self) -> u64 {
        self.fresh.load(Ordering::Relaxed)
    }

    /// Proofs rejected because their `jti` was already recorded.
    pub fn replayed(&self) -> u64 {
        self.replayed.load(Ordering::Relaxed)
    }

    /// Requests rejected because the backend could not answer.
    ///
    /// **Alert on this.** A non-zero rate means requests are being refused for
    /// an infrastructure reason.
    pub fn backend_errors(&self) -> u64 {
        self.backend_errors.load(Ordering::Relaxed)
    }
}

/// Bridges a [`ReplayBackend`] to the SDK's [`ans_verify::ReplayCache`].
///
/// Backend failures return `REPLAY_CACHE_FULL` or `REPLAY_CACHE_UNAVAILABLE`.
/// The SDK rejects these before returning an authenticated identity.
#[derive(Debug)]
pub struct FailClosedCache {
    backend: Arc<dyn ReplayBackend>,
    metrics: Arc<ReplayMetrics>,
}

impl FailClosedCache {
    /// Wrap a backend.
    pub fn new(backend: Arc<dyn ReplayBackend>) -> Self {
        Self {
            backend,
            metrics: Arc::new(ReplayMetrics::default()),
        }
    }

    /// The counters, shareable with an admin/metrics surface.
    pub fn metrics(&self) -> Arc<ReplayMetrics> {
        Arc::clone(&self.metrics)
    }

    /// The wrapped backend's kind.
    pub fn kind(&self) -> &'static str {
        self.backend.kind()
    }

    /// Whether the wrapped backend is shared across replicas.
    pub fn is_shared(&self) -> bool {
        self.backend.is_shared()
    }
}

#[async_trait::async_trait]
impl ReplayCache for FailClosedCache {
    async fn check_and_store(&self, key: &str, exp_unix: i64) -> Result<bool, PopError> {
        match self.backend.check_and_store(key, exp_unix).await {
            Ok(false) => {
                self.metrics.fresh.fetch_add(1, Ordering::Relaxed);
                Ok(false)
            }
            Ok(true) => {
                self.metrics.replayed.fetch_add(1, Ordering::Relaxed);
                Ok(true)
            }
            Err(err) => {
                self.metrics.backend_errors.fetch_add(1, Ordering::Relaxed);
                tracing::error!(
                    backend = self.backend.kind(),
                    cause = err.label(),
                    error = %err,
                    "replay backend could not answer; failing closed"
                );
                let kind = match err {
                    ReplayError::AtCapacity { .. } => PopErrorKind::ReplayCacheFull,
                    _ => PopErrorKind::ReplayCacheUnavailable,
                };
                Err(PopError::with_source(
                    kind,
                    "replay backend rejected the request",
                    err,
                ))
            }
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Scripted(std::sync::Mutex<Vec<Result<bool, ReplayError>>>);

    #[async_trait::async_trait]
    impl ReplayBackend for Scripted {
        async fn check_and_store(&self, _key: &str, _exp: i64) -> Result<bool, ReplayError> {
            let mut q = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match q.pop() {
                Some(Ok(v)) => Ok(v),
                Some(Err(e)) => Err(e),
                None => Ok(false),
            }
        }
        fn kind(&self) -> &'static str {
            "scripted"
        }
        fn is_shared(&self) -> bool {
            true
        }
    }

    fn cache(script: Vec<Result<bool, ReplayError>>) -> FailClosedCache {
        FailClosedCache::new(Arc::new(Scripted(std::sync::Mutex::new(script))))
    }

    #[tokio::test]
    async fn a_fresh_key_is_stored() {
        let c = cache(vec![Ok(false)]);
        assert!(!c.check_and_store("k", 0).await.unwrap());
        assert_eq!(c.metrics().fresh(), 1);
        assert_eq!(c.metrics().backend_errors(), 0);
    }

    #[tokio::test]
    async fn a_seen_key_is_reported_as_a_replay() {
        let c = cache(vec![Ok(true)]);
        assert!(c.check_and_store("k", 0).await.unwrap());
        assert_eq!(c.metrics().replayed(), 1);
    }

    #[tokio::test]
    async fn a_backend_error_fails_closed_with_an_infrastructure_label() {
        let c = cache(vec![Err(ReplayError::Unavailable("down".into()))]);
        assert_eq!(
            c.check_and_store("k", 0).await.unwrap_err().kind,
            PopErrorKind::ReplayCacheUnavailable
        );
        assert_eq!(c.metrics().backend_errors(), 1);
        assert_eq!(c.metrics().replayed(), 0);
    }

    #[tokio::test]
    async fn a_timeout_fails_closed_too() {
        let c = cache(vec![Err(ReplayError::Timeout { deadline_ms: 50 })]);
        assert_eq!(
            c.check_and_store("k", 0).await.unwrap_err().kind,
            PopErrorKind::ReplayCacheUnavailable
        );
        assert_eq!(c.metrics().backend_errors(), 1);
    }

    #[tokio::test]
    async fn capacity_exhaustion_fails_closed() {
        let c = cache(vec![Err(ReplayError::AtCapacity { live: 100 })]);
        assert_eq!(
            c.check_and_store("k", 0).await.unwrap_err().kind,
            PopErrorKind::ReplayCacheFull
        );
        assert_eq!(c.metrics().backend_errors(), 1);
    }

    #[tokio::test]
    async fn backend_properties_are_visible_through_the_wrapper() {
        let c = cache(vec![]);
        assert_eq!(c.kind(), "scripted");
        assert!(c.is_shared());
    }
}
