#![warn(missing_docs)]

//! # ANS-6 §7.6 replay caches
//!
//! Single-use `DPoP` proof identifiers, stored so a proof cannot be presented
//! twice.
//!
//! ## What §7.6 actually demands
//!
//! Five things, and all of them shape this crate:
//!
//! 1. **Atomic check-and-store.** One operation that reports whether the key was
//!    present and, only if not, records it. [`RedisBackend`] uses a single
//!    `SET NX PX`, so the decision is the server's.
//! 2. **Shared across replicas.** "Multi-replica deployments MUST share the
//!    replay cache across replicas serving the same `htu` authority." This is the
//!    requirement applies regardless of the proxy integration model.
//!    [`ReplayBackend::is_shared`] exists so
//!    configuration validation can refuse an unshared cache behind a load
//!    balancer.
//! 3. **Retention of at least `iat + skew + grace`.** Redis per-key expiry gives
//!    this exactly, rather than the coarse generation buckets an in-process cache
//!    uses.
//! 4. **Bounded storage.** The key is already a fixed-width digest of the `jti`
//!    when it reaches this crate — the SDK hashes it — so a bound on entries is
//!    also a bound on bytes.
//! 5. **Fail closed.** "A cache at capacity or erroring rejects the request; it
//!    never silently admits a possibly-replayed proof."
//!
//! ## Two things worth knowing before deploying
//!
//! **The store must not evict.** [`RedisBackend::connect`] reads
//! `maxmemory-policy` and rejects a reported evicting policy. If the policy
//! cannot be read, startup warns and requires out-of-band operator verification.
//! Under
//! `allkeys-lru` Redis drops a live `jti` to make room and the next presentation
//! of that proof looks fresh — silent replay admission, which is exactly what
//! §7.6 forbids. This is the sharpest failure mode in the design.
//!
//! **Backend failures have distinct labels.** [`FailClosedCache`] maps capacity
//! exhaustion to `REPLAY_CACHE_FULL` and other failures to
//! `REPLAY_CACHE_UNAVAILABLE`. Both reject. Alert on [`ReplayMetrics::backend_errors`].

mod backend;
mod error;
mod memory;
mod redis_store;

pub use backend::{FailClosedCache, ReplayBackend, ReplayMetrics};
pub use error::{ReplayError, ReplayStartupError};
pub use memory::MemoryBackend;
pub use redis_store::RedisBackend;
