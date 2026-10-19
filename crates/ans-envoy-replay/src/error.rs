//! Replay-backend errors.
//!
//! Infrastructure errors are preserved when mapped into the SDK error type.

/// Why a replay backend could not answer.
///
/// Every variant is a **rejection**. ANS-6 §7.6 requires a cache that is "at
/// capacity or erroring" to reject rather than "silently admit a
/// possibly-replayed proof", and §9.6 adds that a timeout "is a rejection, never
/// a skip". Nothing here is recoverable into an allow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReplayError {
    /// The store holds as many live entries as it is allowed to.
    ///
    /// §11.6: an attacker without a TL-vouched certificate cannot occupy a slot,
    /// because §7.6's record-after-trust rule commits the `jti` only after the
    /// status-token binding. So saturation means legitimate traffic outgrew the
    /// sizing, and the answer is to shrink the `iat` window before growing the
    /// cache (§9.6).
    #[error("replay cache is at capacity ({live} live entries); requests are being rejected")]
    AtCapacity {
        /// Live entries at the time of rejection.
        live: usize,
    },

    /// The shared store did not answer inside its deadline.
    #[error("replay store did not answer within {deadline_ms}ms")]
    Timeout {
        /// The deadline that elapsed, in milliseconds.
        deadline_ms: u64,
    },

    /// The shared store returned an error, or could not be reached.
    #[error("replay store unavailable: {0}")]
    Unavailable(String),

    /// The store answered in a shape this backend does not understand.
    #[error("replay store returned an unexpected reply: {0}")]
    UnexpectedReply(String),
}

impl ReplayError {
    /// Stable label for metrics and alerting.
    pub fn label(&self) -> &'static str {
        match self {
            Self::AtCapacity { .. } => "at_capacity",
            Self::Timeout { .. } => "timeout",
            Self::Unavailable(_) => "unavailable",
            Self::UnexpectedReply(_) => "unexpected_reply",
        }
    }
}

/// Failures that stop the process from starting.
///
/// Kept separate from [`ReplayError`] because these are not request-time
/// outcomes: they are reasons the service must refuse to serve at all.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReplayStartupError {
    /// The store could not be reached during startup checks.
    #[error("cannot reach the replay store at startup: {0}")]
    Unreachable(String),

    /// The store is configured to evict, which would silently admit replays.
    ///
    /// This is the sharpest failure mode in the whole design. Under an eviction
    /// policy such as `allkeys-lru`, Redis drops a live `jti` to make room and
    /// the next presentation of that proof looks fresh. §7.6 forbids exactly
    /// that: a cache "never silently admits a possibly-replayed proof". A store
    /// that can evict cannot be a conformant replay cache, so the service
    /// refuses to start rather than run in a state that looks healthy and is not.
    #[error(
        "replay store eviction policy is {found:?}, but ANS-6 §7.6 requires a store that never \
         evicts live entries — set maxmemory-policy to noeviction"
    )]
    EvictionEnabled {
        /// The policy the store reported.
        found: String,
    },
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_stable_and_distinct() {
        let all = [
            ReplayError::AtCapacity { live: 1 }.label(),
            ReplayError::Timeout { deadline_ms: 50 }.label(),
            ReplayError::Unavailable("x".into()).label(),
            ReplayError::UnexpectedReply("x".into()).label(),
        ];
        let mut sorted = all.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "labels must be distinct");
    }

    #[test]
    fn eviction_error_names_the_offending_policy_and_the_fix() {
        let e = ReplayStartupError::EvictionEnabled {
            found: "allkeys-lru".to_string(),
        };
        let msg = e.to_string();
        assert!(msg.contains("allkeys-lru"));
        assert!(msg.contains("noeviction"));
    }
}
