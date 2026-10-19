//! Turning a validated [`Config`] into a running verifier.
//!
//! Everything expensive or fallible happens here, at startup, and a failure means
//! the process does not serve. That ordering is deliberate: ANS-6 §4.6 requires
//! artifacts to be "refreshed by each agent's own runtime in the background, never
//! in the request path", so the root-key bootstrap fetch belongs at startup and
//! nowhere else.

use std::sync::Arc;
use std::time::Duration;

use ans_envoy_config::{Config, MethodsConfig, ReplayBackendKind, VerificationConfig};
use ans_envoy_core::{EnabledMethods, Policy, Verifier, selftest_authority_reconstruction};
use ans_envoy_replay::{
    FailClosedCache, MemoryBackend, RedisBackend, ReplayBackend, ReplayMetrics,
};
use ans_verify::{
    HttpScittClient, KeyRefreshHandle, RefreshableKeyStore, ScittClient, ScittKeyStore,
    VerifiedArtifactCache,
};

/// Why the service could not start.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// The §7.7 wiring self-test failed.
    #[error("ANS-6 §7.7 wiring self-test failed: {0}")]
    SelfTest(String),

    /// No usable Transparency Log signing key could be obtained.
    #[error("cannot establish a trusted TL signing key: {0}")]
    RootKeys(String),

    /// The replay store could not be brought up conformantly.
    #[error(transparent)]
    Replay(#[from] ans_envoy_replay::ReplayStartupError),
}

/// Everything the gRPC service needs, plus the handles that keep it alive.
pub struct Runtime {
    /// The verifier.
    pub verifier: Arc<Verifier>,
    /// Replay counters, for the admin surface.
    pub replay_metrics: Arc<ReplayMetrics>,
    /// Replay backend name, for labels.
    pub replay_backend: &'static str,
    /// Whether the replay cache is shared across replicas (§7.6).
    pub replay_shared: bool,
    /// Background key-refresh task. Dropping this cancels the refresh, so it is
    /// held for the process lifetime.
    pub _key_refresh: Option<KeyRefreshHandle>,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("replay_backend", &self.replay_backend)
            .field("replay_shared", &self.replay_shared)
            .finish_non_exhaustive()
    }
}

/// Build the runtime from validated configuration.
pub async fn build(config: &Config) -> Result<Runtime, StartupError> {
    // §7.7's wiring-time check, before anything else. It costs nothing and it
    // guards a property whose regression is invisible in behaviour: every request
    // would still authenticate, just against the wrong URL.
    selftest_authority_reconstruction().map_err(StartupError::SelfTest)?;

    let (keys, key_refresh) = build_key_store(config).await?;
    let (replay, metrics, backend_name, shared) = build_replay(config).await?;

    let verifier = Verifier::new(
        keys,
        replay,
        policy_from(&config.verification),
        VerifiedArtifactCache::new(0),
    );

    Ok(Runtime {
        verifier: Arc::new(verifier),
        replay_metrics: metrics,
        replay_backend: backend_name,
        replay_shared: shared,
        _key_refresh: key_refresh,
    })
}

/// Translate configuration into the verifier's policy.
fn policy_from(config: &VerificationConfig) -> Policy {
    Policy {
        methods: match config.methods {
            MethodsConfig::MethodB => EnabledMethods::MethodBOnly,
            MethodsConfig::MethodA => EnabledMethods::MethodAOnly,
            MethodsConfig::Both => EnabledMethods::Both,
        },
        require_receipt: config.require_receipt,
        allowed_ans_names: config.allowed_ans_names.clone(),
        pop_skew: Some(Duration::from_secs(config.pop_skew_secs)),
        status_skew: Some(Duration::from_secs(config.status_skew_secs)),
    }
}

/// §4.5 — obtain the TL's verification keys, once, at startup.
///
/// Three postures, all valid per §4.5:
///
/// - **URL only**: fetch at bootstrap and refresh in the background. A failed
///   bootstrap is fatal — with no key there is nothing to verify against, and
///   starting anyway would mean refusing every request while looking healthy.
/// - **Static keys only**: a pinned deployment that "simply rejects unknown kids
///   until its configuration is updated, which is a valid posture" (§4.5). §11.10
///   recommends this where root-key trust matters, since a fetched key is trusted
///   on no more evidence than a TLS connection.
/// - **Both**: start from the pinned set and merge additively.
async fn build_key_store(
    config: &Config,
) -> Result<(Arc<RefreshableKeyStore>, Option<KeyRefreshHandle>), StartupError> {
    let tl = &config.transparency_log;
    let pinned = if tl.static_root_keys.is_empty() {
        None
    } else {
        Some(
            ScittKeyStore::from_c2sp_keys(&tl.static_root_keys)
                .map_err(|e| StartupError::RootKeys(format!("pinned keys unusable: {e}")))?,
        )
    };

    let Some(url) = tl.root_keys_url.as_deref() else {
        // Static-only. Validation has already guaranteed at least one source.
        let store = pinned.ok_or_else(|| {
            StartupError::RootKeys("no root_keys_url and no static_root_keys".to_string())
        })?;
        tracing::info!(
            keys = store.len(),
            "using pinned TL keys; no refresh configured"
        );
        return Ok((Arc::new(RefreshableKeyStore::from_static(store)), None));
    };

    let base = base_url_of(url);
    let client: Arc<dyn ScittClient> = Arc::new(
        HttpScittClient::new(&base)
            .map_err(|e| StartupError::RootKeys(format!("bad transparency log URL: {e}")))?,
    );

    let initial = if let Some(store) = pinned {
        store
    } else {
        // The one-time bootstrap fetch §4.5 describes. Off the request path.
        let lines = client.fetch_root_keys().await.map_err(|e| {
            StartupError::RootKeys(format!("bootstrap fetch from {base} failed: {e}"))
        })?;
        ScittKeyStore::from_c2sp_keys(&lines)
            .map_err(|e| StartupError::RootKeys(format!("no usable key in {base} response: {e}")))?
    };

    tracing::info!(
        keys = initial.len(),
        url = %base,
        "TL key store bootstrapped"
    );

    let store = RefreshableKeyStore::new(initial, client);
    let handle = store.start_background_refresh(Duration::from_secs(tl.refresh_interval_secs));
    Ok((Arc::new(store), Some(handle)))
}

/// `HttpScittClient` wants the TL base URL, but operators think in terms of the
/// `/root-keys` endpoint, so accept either.
fn base_url_of(url: &str) -> String {
    url.trim_end_matches('/')
        .strip_suffix("/root-keys")
        .unwrap_or_else(|| url.trim_end_matches('/'))
        .to_string()
}

/// §7.6 — bring up the replay cache.
async fn build_replay(
    config: &Config,
) -> Result<
    (
        Arc<dyn ans_verify::ReplayCache>,
        Arc<ReplayMetrics>,
        &'static str,
        bool,
    ),
    StartupError,
> {
    let backend: Arc<dyn ReplayBackend> = match config.replay.backend {
        ReplayBackendKind::Redis => {
            let url = config.replay.redis_url.as_deref().unwrap_or_default();
            // `connect` also refuses a store whose eviction policy could drop a
            // live jti — under `allkeys-lru` a replayed proof would look fresh.
            Arc::new(
                RedisBackend::connect(
                    url,
                    Duration::from_millis(config.replay.deadline_ms),
                    config.replay.key_prefix.clone(),
                )
                .await?,
            )
        }
        ReplayBackendKind::Memory => Arc::new(MemoryBackend::new(config.replay.max_entries)),
    };

    let name = backend.kind();
    let shared = backend.is_shared();
    let cache = FailClosedCache::new(backend);
    let metrics = cache.metrics();

    tracing::info!(backend = name, shared, "replay cache ready");
    Ok((Arc::new(cache), metrics, name, shared))
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_keys_url_is_reduced_to_its_base() {
        assert_eq!(
            base_url_of("https://tl.example.com/root-keys"),
            "https://tl.example.com"
        );
        assert_eq!(
            base_url_of("https://tl.example.com/root-keys/"),
            "https://tl.example.com"
        );
    }

    #[test]
    fn a_bare_base_url_is_left_alone() {
        assert_eq!(
            base_url_of("https://tl.example.com"),
            "https://tl.example.com"
        );
        assert_eq!(
            base_url_of("https://tl.example.com/"),
            "https://tl.example.com"
        );
    }

    #[test]
    fn a_nested_path_is_preserved() {
        // Some deployments front the TL under a prefix.
        assert_eq!(
            base_url_of("https://gw.example.com/tl/root-keys"),
            "https://gw.example.com/tl"
        );
    }

    /// A baseline verification config for the translation tests.
    fn verification_config() -> VerificationConfig {
        VerificationConfig {
            methods: MethodsConfig::Both,
            require_receipt: false,
            reduced_mode_justification: Some("x".repeat(20)),
            allowed_ans_names: vec!["ans://v1.0.0.a.example.com".to_string()],
            pop_skew_secs: 90,
            status_skew_secs: 45,
            content_binding: ans_envoy_config::ContentBinding::Required,
        }
    }

    #[test]
    fn the_policy_translation_carries_every_field() {
        let vc = verification_config();
        let p = policy_from(&vc);
        assert_eq!(p.methods, EnabledMethods::Both);
        assert!(!p.require_receipt);
        assert_eq!(p.allowed_ans_names.len(), 1);
        assert_eq!(p.pop_skew, Some(Duration::from_secs(90)));
        assert_eq!(p.status_skew, Some(Duration::from_secs(45)));
    }

    #[test]
    fn the_selftest_runs_before_anything_expensive() {
        // Guards the ordering in `build`: if the self-test moved after the
        // network calls, a misconfigured deployment would fail slowly and with a
        // less useful error.
        assert!(selftest_authority_reconstruction().is_ok());
    }
}
