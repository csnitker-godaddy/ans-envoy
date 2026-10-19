//! Redis-backed replay cache — the ANS-6 §7.6 shared store.

use std::time::Duration;

use redis::AsyncCommands as _;
use redis::aio::ConnectionManager;

use crate::backend::ReplayBackend;
use crate::error::{ReplayError, ReplayStartupError};

/// Minimum TTL written for an entry.
///
/// §7.6 wants retention of at least `iat + skew + grace`. A proof whose window
/// has already closed still gets a floor rather than a zero or negative TTL,
/// because `SET ... PX 0` is an error and a vanishing entry would reopen the
/// boundary the grace exists to close.
const MIN_TTL: Duration = Duration::from_secs(1);

/// Eviction policy the store must be running.
const REQUIRED_EVICTION_POLICY: &str = "noeviction";

/// A replay cache shared across every replica that serves one `htu` authority.
///
/// # Why this exists
///
/// §7.6: "Multi-replica deployments MUST share the replay cache across replicas
/// serving the same `htu` authority." An in-process cache blocks reuse within one
/// replica only, so behind a load balancer a proof replays cleanly against any
/// replica that has not seen it. A shared backend enforces that requirement
/// independently of which proxy integration hosts the verifier.
///
/// # Atomicity
///
/// Check-and-store is one `SET key value NX PX ttl` round trip. `NX` makes the
/// set conditional on absence, so the decision is Redis's and is atomic across
/// replicas. A `GET` followed by a `SET` would not do: two replicas racing the
/// same replayed proof would both read absent and both admit it.
#[derive(Clone)]
pub struct RedisBackend {
    conn: ConnectionManager,
    deadline: Duration,
    key_prefix: String,
}

impl std::fmt::Debug for RedisBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisBackend")
            .field("deadline", &self.deadline)
            .field("key_prefix", &self.key_prefix)
            .finish_non_exhaustive()
    }
}

impl RedisBackend {
    /// How long startup will wait to reach the store before giving up.
    ///
    /// `ConnectionManager` retries with backoff by default, which is right for a
    /// blip mid-flight and wrong at startup: an unreachable store made `connect`
    /// hang for about eight minutes before this bound existed. A service that
    /// hangs during startup is worse than one that exits with a reason — the
    /// former looks like a slow rollout, and nothing in the logs says why.
    pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    /// Connect, then refuse to proceed unless the store can never evict.
    ///
    /// The eviction check is not a nicety. Under `allkeys-lru` (or any policy
    /// that drops live keys to make room) Redis silently deletes a recorded
    /// `jti`, and the next presentation of that proof looks fresh — the precise
    /// behaviour §7.6 forbids when it says a cache "never silently admits a
    /// possibly-replayed proof". A store that can evict is not a conformant
    /// replay cache, so this returns an error and the caller must not start.
    pub async fn connect(
        url: &str,
        deadline: Duration,
        key_prefix: impl Into<String>,
    ) -> Result<Self, ReplayStartupError> {
        Self::connect_with_timeout(url, deadline, key_prefix, Self::CONNECT_TIMEOUT).await
    }

    /// [`Self::connect`] with an explicit startup bound.
    pub async fn connect_with_timeout(
        url: &str,
        deadline: Duration,
        key_prefix: impl Into<String>,
        connect_timeout: Duration,
    ) -> Result<Self, ReplayStartupError> {
        let client =
            redis::Client::open(url).map_err(|e| ReplayStartupError::Unreachable(e.to_string()))?;

        let conn = tokio::time::timeout(connect_timeout, client.get_connection_manager())
            .await
            .map_err(|_| {
                ReplayStartupError::Unreachable(format!(
                    "no connection within {}ms",
                    connect_timeout.as_millis()
                ))
            })?
            .map_err(|e| ReplayStartupError::Unreachable(e.to_string()))?;

        let backend = Self {
            conn,
            deadline,
            key_prefix: key_prefix.into(),
        };

        // Bounded too: a store that accepts a connection and then never answers
        // would otherwise stall startup just as effectively.
        tokio::time::timeout(connect_timeout, backend.assert_no_eviction())
            .await
            .map_err(|_| {
                ReplayStartupError::Unreachable(format!(
                    "connected, but no reply to CONFIG GET within {}ms",
                    connect_timeout.as_millis()
                ))
            })??;

        Ok(backend)
    }

    /// Read `maxmemory-policy` and require `noeviction`.
    ///
    /// Some managed Redis offerings disable `CONFIG GET`. There the policy cannot
    /// be established, and the honest outcome is a loud warning rather than a
    /// false assurance: refusing to start would make the service unusable on
    /// those platforms, and claiming the check passed would be a lie. The
    /// operator is told to verify it out of band.
    async fn assert_no_eviction(&self) -> Result<(), ReplayStartupError> {
        let mut conn = self.conn.clone();
        let reply: Result<Vec<String>, _> = redis::cmd("CONFIG")
            .arg("GET")
            .arg("maxmemory-policy")
            .query_async(&mut conn)
            .await;

        match reply {
            Ok(kv) => {
                // Reply shape is [name, value].
                let Some(policy) = kv.get(1) else {
                    tracing::warn!(
                        "replay store did not report maxmemory-policy; verify out of band that \
                         it is {REQUIRED_EVICTION_POLICY} (ANS-6 §7.6)"
                    );
                    return Ok(());
                };
                if policy.eq_ignore_ascii_case(REQUIRED_EVICTION_POLICY) {
                    tracing::info!(policy = %policy, "replay store eviction policy verified");
                    return Ok(());
                }
                Err(ReplayStartupError::EvictionEnabled {
                    found: policy.clone(),
                })
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not read maxmemory-policy (CONFIG GET may be disabled on managed \
                     Redis); verify out of band that it is {REQUIRED_EVICTION_POLICY} — under an \
                     eviction policy a live jti can be dropped and a replayed proof admitted \
                     (ANS-6 §7.6)"
                );
                Ok(())
            }
        }
    }

    /// Namespaced key, so a shared Redis can serve more than one purpose.
    fn key(&self, digest: &str) -> String {
        format!("{}{}", self.key_prefix, digest)
    }

    /// TTL for an entry whose retention floor is `exp_unix`.
    fn ttl_for(exp_unix: i64, now_unix: i64) -> Duration {
        let remaining = exp_unix.saturating_sub(now_unix);
        if remaining <= 0 {
            MIN_TTL
        } else {
            Duration::from_secs(u64::try_from(remaining).unwrap_or(1)).max(MIN_TTL)
        }
    }
}

#[async_trait::async_trait]
impl ReplayBackend for RedisBackend {
    async fn check_and_store(&self, key: &str, exp_unix: i64) -> Result<bool, ReplayError> {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
        .unwrap_or(i64::MAX);
        let ttl = Self::ttl_for(exp_unix, now);
        let full_key = self.key(key);
        let mut conn = self.conn.clone();

        // §9.6: "A shared cache MUST be consulted with a deadline; a timeout is
        // a rejection, never a skip."
        let fut = async move {
            conn.set_options::<_, _, Option<String>>(
                &full_key,
                1_u8,
                redis::SetOptions::default()
                    .conditional_set(redis::ExistenceCheck::NX)
                    .with_expiration(redis::SetExpiry::PX(
                        u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX),
                    )),
            )
            .await
        };

        match tokio::time::timeout(self.deadline, fut).await {
            // `SET NX` returns the status on success and nil when the key
            // already existed, which is exactly the replay signal.
            Ok(Ok(Some(_))) => Ok(false),
            Ok(Ok(None)) => Ok(true),
            Ok(Err(e)) => Err(ReplayError::Unavailable(e.to_string())),
            Err(_elapsed) => Err(ReplayError::Timeout {
                deadline_ms: u64::try_from(self.deadline.as_millis()).unwrap_or(u64::MAX),
            }),
        }
    }

    fn kind(&self) -> &'static str {
        "redis"
    }

    fn is_shared(&self) -> bool {
        true
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_tracks_the_remaining_retention_window() {
        let ttl = RedisBackend::ttl_for(1_000_100, 1_000_000);
        assert_eq!(ttl, Duration::from_secs(100));
    }

    #[test]
    fn an_already_closed_window_still_gets_a_floor() {
        // A zero or negative PX is a Redis error, and an entry that vanishes
        // immediately reopens the boundary gap the §7.6 grace exists to close.
        assert_eq!(RedisBackend::ttl_for(1_000_000, 1_000_000), MIN_TTL);
        assert_eq!(RedisBackend::ttl_for(999_000, 1_000_000), MIN_TTL);
    }

    #[test]
    fn ttl_is_never_below_the_floor() {
        assert!(RedisBackend::ttl_for(1_000_001, 1_000_000) >= MIN_TTL);
    }

    #[test]
    fn required_policy_is_noeviction() {
        // Guards the constant against a well-meaning edit: any other policy
        // makes silent replay admission possible.
        assert_eq!(REQUIRED_EVICTION_POLICY, "noeviction");
    }
}
