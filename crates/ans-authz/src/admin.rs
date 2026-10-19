//! Admin surface: liveness, readiness, metrics, and observed conformance.
//!
//! `/readyz` is the interesting one. Two of the Envoy settings ANS-6 depends on
//! cannot be checked from inside this process at startup — they are properties of
//! the proxy's configuration, and the only evidence is a request. So readiness
//! reports what has actually been *observed*, letting a rollout gate on it:
//! a deployment where `encode_raw_headers` was forgotten denies every request,
//! and this endpoint says why.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};

use crate::telemetry::Telemetry;

/// What this process has observed about its proxy's configuration.
///
/// Populated from real requests, because there is no other source.
#[derive(Debug, Default)]
pub struct Observed {
    /// Whether any request has arrived with an uncoalesced header map, i.e.
    /// whether `encode_raw_headers: true` is actually in effect (§4.6).
    raw_headers_seen: AtomicBool,
    /// Whether any request has arrived with an asserted authority (§7.7).
    authority_seen: AtomicBool,
    /// Whether any request at all has been served.
    any_request: AtomicBool,
}

impl Observed {
    /// A fresh observation record.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record what one request revealed about the proxy's configuration.
    pub fn record(&self, raw_headers: bool, authority: bool) {
        self.any_request.store(true, Ordering::Relaxed);
        if raw_headers {
            self.raw_headers_seen.store(true, Ordering::Relaxed);
        }
        if authority {
            self.authority_seen.store(true, Ordering::Relaxed);
        }
    }

    /// Whether uncoalesced headers have been seen.
    pub fn raw_headers(&self) -> bool {
        self.raw_headers_seen.load(Ordering::Relaxed)
    }

    /// Whether an asserted authority has been seen.
    pub fn authority(&self) -> bool {
        self.authority_seen.load(Ordering::Relaxed)
    }

    /// Whether anything has been served yet.
    pub fn served_anything(&self) -> bool {
        self.any_request.load(Ordering::Relaxed)
    }
}

/// Shared state for the admin router.
#[derive(Clone)]
pub struct AdminState {
    /// Decision counters.
    pub telemetry: Arc<Telemetry>,
    /// Replay counters.
    pub replay: Arc<ans_envoy_replay::ReplayMetrics>,
    /// Replay backend name.
    pub replay_backend: &'static str,
    /// Whether the replay cache is shared across replicas.
    pub replay_shared: bool,
    /// Observed proxy configuration.
    pub observed: Arc<Observed>,
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState")
            .field("replay_backend", &self.replay_backend)
            .finish_non_exhaustive()
    }
}

/// Build the admin router.
pub fn router(state: AdminState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
}

/// Liveness: the process is up. Deliberately says nothing about conformance —
/// restarting a correctly-running process because its proxy is misconfigured
/// would not fix anything.
async fn healthz() -> &'static str {
    "ok\n"
}

/// Readiness, including observed proxy conformance.
///
/// Returns 503 once a request has been served without an uncoalesced header map:
/// that means §4.6 duplicate detection is impossible, this service is denying
/// everything, and a rollout should stop rather than proceed.
async fn readyz(State(state): State<AdminState>) -> (StatusCode, Json<serde_json::Value>) {
    let served = state.observed.served_anything();
    let raw_headers = state.observed.raw_headers();
    let conformant = !served || raw_headers;

    let body = serde_json::json!({
        "ready": conformant,
        "checksServed": state.telemetry.checks(),
        "observed": {
            "servedAnyRequest": served,
            "encodeRawHeaders": raw_headers,
            "authorityAsserted": state.observed.authority(),
        },
        "replay": {
            "backend": state.replay_backend,
            "sharedAcrossReplicas": state.replay_shared,
            "backendErrors": state.replay.backend_errors(),
        },
        "notes": if conformant {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(
                "requests are arriving without an uncoalesced header map, so ANS-6 §4.6 \
                 duplicate detection is impossible and every request is being denied. Set \
                 encode_raw_headers: true on the Envoy ext_authz filter."
                    .to_string(),
            )
        },
    });

    let code = if conformant {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body))
}

/// Prometheus exposition.
async fn metrics(State(state): State<AdminState>) -> (StatusCode, String) {
    (
        StatusCode::OK,
        state
            .telemetry
            .render(&state.replay, state.replay_backend, state.replay_shared),
    )
}

/// Serve the admin surface until `shutdown` resolves.
pub async fn serve(
    addr: SocketAddr,
    state: AdminState,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "admin surface listening");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown)
        .await
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AdminState {
        AdminState {
            telemetry: Telemetry::new(),
            replay: Arc::new(ans_envoy_replay::ReplayMetrics::default()),
            replay_backend: "memory",
            replay_shared: false,
            observed: Observed::new(),
        }
    }

    #[test]
    fn a_fresh_process_has_observed_nothing() {
        let o = Observed::new();
        assert!(!o.served_anything());
        assert!(!o.raw_headers());
        assert!(!o.authority());
    }

    #[test]
    fn observations_latch_on() {
        // One good request is enough to establish that the proxy is configured
        // correctly; a later request without an authority (a route that forgot
        // its context_extensions) must not un-observe it.
        let o = Observed::new();
        o.record(true, true);
        o.record(false, false);
        assert!(o.raw_headers());
        assert!(o.authority());
    }

    #[tokio::test]
    async fn readiness_is_ok_before_any_request() {
        // Nothing observed yet is not evidence of misconfiguration.
        let (code, body) = readyz(State(state())).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body.0["ready"], serde_json::Value::Bool(true));
    }

    #[tokio::test]
    async fn readiness_fails_once_a_request_arrives_without_raw_headers() {
        // The rollout gate: encode_raw_headers was forgotten, every request is
        // being denied, and this is how a deploy finds out.
        let s = state();
        s.observed.record(false, true);
        let (code, body) = readyz(State(s)).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["ready"], serde_json::Value::Bool(false));
        assert!(
            body.0["notes"]
                .as_str()
                .unwrap_or_default()
                .contains("encode_raw_headers")
        );
    }

    #[tokio::test]
    async fn readiness_recovers_when_a_good_request_arrives() {
        let s = state();
        s.observed.record(true, true);
        let (code, _) = readyz(State(s)).await;
        assert_eq!(code, StatusCode::OK);
    }

    #[tokio::test]
    async fn readiness_reports_the_replay_topology() {
        // §7.6: an operator should be able to see whether the cache is shared.
        let (_, body) = readyz(State(state())).await;
        assert_eq!(body.0["replay"]["backend"], "memory");
        assert_eq!(
            body.0["replay"]["sharedAcrossReplicas"],
            serde_json::Value::Bool(false)
        );
    }

    #[tokio::test]
    async fn liveness_does_not_depend_on_proxy_conformance() {
        // Restarting would not fix a misconfigured proxy, so liveness must not
        // report it.
        assert_eq!(healthz().await, "ok\n");
    }

    #[tokio::test]
    async fn readiness_reports_how_many_checks_were_served() {
        let s = state();
        s.telemetry.allowed();
        s.telemetry.denied("REPLAY");
        let (_, body) = readyz(State(s)).await;
        assert_eq!(body.0["checksServed"], 2);
    }

    #[tokio::test]
    async fn metrics_render() {
        let s = state();
        s.telemetry.allowed();
        let (code, body) = metrics(State(s)).await;
        assert_eq!(code, StatusCode::OK);
        assert!(body.contains("ans_authz_allowed_total 1"));
    }
}
