#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for the ANS-6 §7.6 shared replay cache.
//!
//! These need a real Redis, because the properties under test are the server's
//! rather than ours: `SET NX` atomicity, per-key expiry, and — the one that
//! decides this project's architecture — that two independent processes reach the
//! same verdict about the same proof.
//!
//! Set `ANS_ENVOY_TEST_REDIS_URL` to run them. Without it they skip rather than
//! fail, so `cargo test` stays green on a machine with no Redis. CI supplies one.
//!
//! Every key is namespaced with a per-run prefix and given a short TTL, so these
//! cannot collide with anything else in the database they run against.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ans_envoy_replay::{FailClosedCache, RedisBackend, ReplayBackend, ReplayStartupError};
use ans_verify::ReplayCache as _;

/// The Redis under test, or `None` to skip.
fn redis_url() -> Option<String> {
    std::env::var("ANS_ENVOY_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.is_empty())
}

/// A prefix unique to this run, so nothing here can touch other data.
fn unique_prefix(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("ans6-test:{}:{tag}:{nanos}:", std::process::id())
}

fn soon() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0)
        + 30
}

async fn backend(tag: &str) -> Option<RedisBackend> {
    let url = redis_url()?;
    match RedisBackend::connect(&url, Duration::from_millis(500), unique_prefix(tag)).await {
        Ok(b) => Some(b),
        Err(ReplayStartupError::EvictionEnabled { found }) => {
            panic!(
                "the test Redis has maxmemory-policy={found}, but ANS-6 §7.6 requires \
                 noeviction — an evicting store can drop a live jti and admit a replay"
            )
        }
        Err(e) => panic!("cannot reach the test Redis: {e}"),
    }
}

#[tokio::test]
async fn connects_to_a_noeviction_store() {
    let Some(b) = backend("connect").await else {
        return;
    };
    assert_eq!(b.kind(), "redis");
    // The property that makes Redis a conformant choice above one replica.
    assert!(b.is_shared());
}

#[tokio::test]
async fn a_fresh_proof_id_is_stored_and_a_repeat_is_a_replay() {
    let Some(b) = backend("repeat").await else {
        return;
    };
    let exp = soon();
    assert!(
        !b.check_and_store("abc", exp).await.unwrap(),
        "first presentation must be recorded, not reported as seen"
    );
    assert!(
        b.check_and_store("abc", exp).await.unwrap(),
        "second presentation of the same jti must be a replay"
    );
}

#[tokio::test]
async fn distinct_proof_ids_do_not_collide() {
    let Some(b) = backend("distinct").await else {
        return;
    };
    let exp = soon();
    assert!(!b.check_and_store("one", exp).await.unwrap());
    assert!(!b.check_and_store("two", exp).await.unwrap());
    assert!(!b.check_and_store("three", exp).await.unwrap());
}

#[tokio::test]
async fn two_backends_sharing_one_store_see_each_others_records() {
    // This is the ANS-6 §7.6 requirement in its load-bearing form:
    // "Multi-replica deployments MUST share the replay cache across replicas
    // serving the same `htu` authority."
    //
    // Two independently-connected backends on the same prefix stand in for two
    // replicas. A proof spent through one must be refused through the other —
    // the property required of any deployment with multiple replicas.
    let Some(url) = redis_url() else {
        return;
    };
    let prefix = unique_prefix("cross-replica");

    let replica_a = RedisBackend::connect(&url, Duration::from_millis(500), prefix.clone())
        .await
        .expect("replica A should connect");
    let replica_b = RedisBackend::connect(&url, Duration::from_millis(500), prefix)
        .await
        .expect("replica B should connect");

    let exp = soon();
    assert!(
        !replica_a.check_and_store("shared-jti", exp).await.unwrap(),
        "replica A should record the proof"
    );
    assert!(
        replica_b.check_and_store("shared-jti", exp).await.unwrap(),
        "replica B must refuse a proof already spent on replica A"
    );
}

#[tokio::test]
async fn different_prefixes_are_isolated() {
    // So a shared Redis can serve more than one purpose without one deployment's
    // proof ids shadowing another's.
    let Some(url) = redis_url() else {
        return;
    };
    let a = RedisBackend::connect(&url, Duration::from_millis(500), unique_prefix("iso-a"))
        .await
        .unwrap();
    let b = RedisBackend::connect(&url, Duration::from_millis(500), unique_prefix("iso-b"))
        .await
        .unwrap();

    let exp = soon();
    assert!(!a.check_and_store("same-key", exp).await.unwrap());
    assert!(
        !b.check_and_store("same-key", exp).await.unwrap(),
        "a different prefix must not see the other's record"
    );
}

#[tokio::test]
async fn an_entry_expires_so_the_cache_stays_bounded() {
    // §7.6 wants retention of at least `iat + skew + grace`, not forever. Redis
    // per-key expiry gives exactly that; an entry that never expired would grow
    // the store without bound.
    let Some(b) = backend("expiry").await else {
        return;
    };
    // An already-closed window takes the 1s floor rather than a zero or negative
    // TTL, which Redis would reject.
    let past = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0)
        - 10;

    assert!(!b.check_and_store("short-lived", past).await.unwrap());
    assert!(
        b.check_and_store("short-lived", past).await.unwrap(),
        "still live immediately after storing"
    );

    tokio::time::sleep(Duration::from_millis(1400)).await;
    assert!(
        !b.check_and_store("short-lived", past).await.unwrap(),
        "the entry should have expired, so the id is fresh again"
    );
}

#[tokio::test]
async fn the_fail_closed_wrapper_reports_a_replay_through_the_sdk_trait() {
    // End of the chain: what `verify_caller` actually sees.
    let Some(b) = backend("wrapper").await else {
        return;
    };
    let cache = FailClosedCache::new(Arc::new(b));
    let exp = soon();

    assert!(!cache.check_and_store("wrapped", exp).await.unwrap());
    assert!(cache.check_and_store("wrapped", exp).await.unwrap());

    let metrics = cache.metrics();
    assert_eq!(metrics.fresh(), 1);
    assert_eq!(metrics.replayed(), 1);
    // No backend error occurred, so the counter that distinguishes an outage from
    // a genuine replay must stay at zero.
    assert_eq!(metrics.backend_errors(), 0);
}

#[tokio::test]
async fn an_unreachable_store_fails_startup_quickly() {
    // Port 1 is reserved and nothing listens there.
    //
    // The bound matters as much as the outcome. `ConnectionManager` retries with
    // backoff by default, and before `CONNECT_TIMEOUT` existed this call hung for
    // about eight minutes — a service that hangs during startup looks like a slow
    // rollout, and nothing says why. Refusing to start *is* the strongest form of
    // failing closed, but it has to be prompt to be useful.
    //
    // No test Redis needed, so this always runs.
    let started = std::time::Instant::now();
    let result = RedisBackend::connect_with_timeout(
        "redis://127.0.0.1:1",
        Duration::from_millis(150),
        unique_prefix("unreachable"),
        Duration::from_millis(400),
    )
    .await;

    assert!(
        result.is_err(),
        "an unreachable store must not yield a usable backend"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "startup should fail fast, took {:?}",
        started.elapsed()
    );
}

// Deliberately NOT tested here: "a store that cannot answer in time fails
// closed". A tiny per-request deadline races a real round trip, and a warm
// connection often wins — so the test passes or fails on scheduler luck. A flaky
// test is worse than none; it teaches people to re-run CI.
//
// The property is covered deterministically in the unit tests, where a scripted
// backend returns `ReplayError::Timeout` and `FailClosedCache` is asserted to
// return REPLAY_CACHE_UNAVAILABLE (see `backend.rs::a_timeout_fails_closed_too`).
