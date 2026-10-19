//! Counters, and the Prometheus text rendering for them.
//!
//! Hand-rolled rather than pulled from a metrics crate. The exposition format is
//! a dozen lines of text, and this service already carries `envoy-types`, which
//! compiles 312 generated proto modules — the dependency budget is better spent
//! elsewhere.
//!
//! One counter matters more than the rest. `ans_replay_backend_errors_total` is
//! how an operator distinguishes a genuine replayed proof from a replay store
//! that could not answer: both surface to the caller as a `REPLAY` denial, because
//! the SDK's `ReplayCache` trait cannot carry an error out of an external
//! implementation. See `ans_envoy_replay::FailClosedCache`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ans_envoy_replay::ReplayMetrics;

/// Decision and health counters.
#[derive(Debug, Default)]
pub struct Telemetry {
    checks_total: AtomicU64,
    allowed_total: AtomicU64,
    denied_total: AtomicU64,
    adapt_errors_total: AtomicU64,
    /// Denials by stable label, so alerts can target a specific failure.
    by_label: Mutex<BTreeMap<&'static str, u64>>,
}

impl Telemetry {
    /// A fresh registry.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record an allow.
    pub fn allowed(&self) {
        self.checks_total.fetch_add(1, Ordering::Relaxed);
        self.allowed_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a denial under its stable label.
    pub fn denied(&self, label: &'static str) {
        self.checks_total.fetch_add(1, Ordering::Relaxed);
        self.denied_total.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut map) = self.by_label.lock() {
            *map.entry(label).or_insert(0) += 1;
        }
    }

    /// Record a `CheckRequest` this service could not read at all.
    pub fn adapt_error(&self) {
        self.adapt_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Total checks served.
    pub fn checks(&self) -> u64 {
        self.checks_total.load(Ordering::Relaxed)
    }

    /// Render the Prometheus exposition format.
    pub fn render(&self, replay: &ReplayMetrics, replay_backend: &str, shared: bool) -> String {
        let mut out = String::new();

        // Writing to a String cannot fail, so the Result is deliberately
        // discarded rather than unwrapped — this crate denies `unwrap`.
        let _ = writeln!(
            out,
            "# HELP ans_authz_checks_total Authorization checks served.\n\
             # TYPE ans_authz_checks_total counter\n\
             ans_authz_checks_total {}",
            self.checks_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP ans_authz_allowed_total Requests authenticated.\n\
             # TYPE ans_authz_allowed_total counter\n\
             ans_authz_allowed_total {}",
            self.allowed_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP ans_authz_denied_total Requests refused.\n\
             # TYPE ans_authz_denied_total counter\n\
             ans_authz_denied_total {}",
            self.denied_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP ans_authz_denied_by_label_total Refusals by ANS-6 denial label.\n\
             # TYPE ans_authz_denied_by_label_total counter"
        );
        if let Ok(map) = self.by_label.lock() {
            for (label, count) in map.iter() {
                let _ = writeln!(
                    out,
                    "ans_authz_denied_by_label_total{{label=\"{label}\"}} {count}"
                );
            }
        }

        let _ = writeln!(
            out,
            "# HELP ans_authz_adapt_errors_total CheckRequests this service could not read.\n\
             # TYPE ans_authz_adapt_errors_total counter\n\
             ans_authz_adapt_errors_total {}",
            self.adapt_errors_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP ans_replay_fresh_total Proof ids recorded for the first time.\n\
             # TYPE ans_replay_fresh_total counter\n\
             ans_replay_fresh_total{{backend=\"{replay_backend}\"}} {}",
            replay.fresh()
        );

        let _ = writeln!(
            out,
            "# HELP ans_replay_replayed_total Proofs refused as already seen.\n\
             # TYPE ans_replay_replayed_total counter\n\
             ans_replay_replayed_total{{backend=\"{replay_backend}\"}} {}",
            replay.replayed()
        );

        // Infrastructure failures have their own denial labels and counter.
        let _ = writeln!(
            out,
            "# HELP ans_replay_backend_errors_total Requests refused because the replay store \
             could not answer. ALERT ON THIS separately from genuine replay attempts.\n\
             # TYPE ans_replay_backend_errors_total counter\n\
             ans_replay_backend_errors_total{{backend=\"{replay_backend}\"}} {}",
            replay.backend_errors()
        );

        let _ = writeln!(
            out,
            "# HELP ans_replay_cache_shared Whether the replay cache is shared across replicas \
             (ANS-6 §7.6 requires 1 above one replica).\n\
             # TYPE ans_replay_cache_shared gauge\n\
             ans_replay_cache_shared{{backend=\"{replay_backend}\"}} {}",
            u8::from(shared)
        );

        out
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_allows_and_denials_separately() {
        let t = Telemetry::new();
        t.allowed();
        t.denied("REPLAY");
        t.denied("REPLAY");
        t.denied("DUPLICATE_HEADER");
        assert_eq!(t.checks(), 4);
        let rendered = t.render(&ReplayMetrics::default(), "redis", true);
        assert!(rendered.contains("ans_authz_allowed_total 1"));
        assert!(rendered.contains("ans_authz_denied_total 3"));
        assert!(rendered.contains(r#"ans_authz_denied_by_label_total{label="REPLAY"} 2"#));
        assert!(
            rendered.contains(r#"ans_authz_denied_by_label_total{label="DUPLICATE_HEADER"} 1"#)
        );
    }

    #[test]
    fn the_shared_cache_gauge_reflects_the_backend() {
        let t = Telemetry::new();
        assert!(
            t.render(&ReplayMetrics::default(), "memory", false)
                .contains(r#"ans_replay_cache_shared{backend="memory"} 0"#)
        );
        assert!(
            t.render(&ReplayMetrics::default(), "redis", true)
                .contains(r#"ans_replay_cache_shared{backend="redis"} 1"#)
        );
    }

    #[test]
    fn the_backend_error_counter_carries_an_alerting_hint() {
        // Infrastructure failures need a separate alert from replay attempts.
        let t = Telemetry::new();
        let rendered = t.render(&ReplayMetrics::default(), "redis", true);
        assert!(rendered.contains("ans_replay_backend_errors_total"));
        assert!(rendered.contains("ALERT ON THIS"));
    }

    #[test]
    fn adapt_errors_are_counted_outside_the_decision_totals() {
        // A CheckRequest we cannot read is a protocol mismatch with the proxy,
        // not a caller behaviour, so it must not inflate the denial rate.
        let t = Telemetry::new();
        t.adapt_error();
        assert_eq!(t.checks(), 0);
        assert!(
            t.render(&ReplayMetrics::default(), "redis", true)
                .contains("ans_authz_adapt_errors_total 1")
        );
    }

    #[test]
    fn rendering_is_valid_exposition_shape() {
        let t = Telemetry::new();
        t.allowed();
        let rendered = t.render(&ReplayMetrics::default(), "redis", true);
        for line in rendered.lines() {
            assert!(
                line.starts_with("# HELP ") || line.starts_with("# TYPE ") || line.contains(' '),
                "unexpected line: {line}"
            );
        }
    }
}
