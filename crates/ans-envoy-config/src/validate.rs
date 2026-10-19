//! Startup validation — the checks that decide whether this service may serve.
//!
//! ANS-6 §7.7 is unusually direct about this: "Implementations MUST fail startup
//! when neither is configured, and MUST NOT fall back to deriving the comparison
//! authority from the request's own `Host` header." The SDK cannot discharge that
//! obligation — its own documentation says so: "this library cannot see your
//! startup, so enforce that in the embedding service." This module is that
//! enforcement.
//!
//! Every problem is collected rather than reported one at a time. An operator
//! fixing a config should see all of it, not discover the next fault on the next
//! restart.

use crate::schema::{AuthorityMode, Config, ContentBinding, MethodsConfig, ReplayBackendKind};

/// The spec cap on status-token clock-skew tolerance (§4.4 step 7: "≤ 10 minutes").
const MAX_STATUS_SKEW_SECS: u64 = 600;

/// One reason the service must not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// Dotted path to the offending setting.
    pub field: String,
    /// The ANS-6 section that requires this.
    pub spec: &'static str,
    /// What is wrong, and what to do about it.
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}]: {}", self.field, self.spec, self.message)
    }
}

/// A concern that does not block startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    /// Dotted path to the setting.
    pub field: String,
    /// Relevant ANS-6 section.
    pub spec: &'static str,
    /// What to look at.
    pub message: String,
}

impl std::fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}]: {}", self.field, self.spec, self.message)
    }
}

fn err(field: &str, spec: &'static str, message: impl Into<String>) -> ConfigError {
    ConfigError {
        field: field.to_string(),
        spec,
        message: message.into(),
    }
}

fn warn(field: &str, spec: &'static str, message: impl Into<String>) -> ConfigWarning {
    ConfigWarning {
        field: field.to_string(),
        spec,
        message: message.into(),
    }
}

/// Validate a configuration. `Err` means the process must not serve.
pub fn validate(cfg: &Config) -> Result<(), Vec<ConfigError>> {
    let mut errors = Vec::new();

    validate_server(cfg, &mut errors);
    validate_authority(cfg, &mut errors);
    validate_verification(cfg, &mut errors);
    validate_replay(cfg, &mut errors);
    validate_transparency_log(cfg, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Concerns worth logging at startup that do not justify refusing to serve.
pub fn warnings(cfg: &Config) -> Vec<ConfigWarning> {
    let mut out = Vec::new();

    if cfg.replay.backend == ReplayBackendKind::Memory {
        out.push(warn(
            "replay.backend",
            "§7.6",
            "the in-process replay cache blocks reuse within this replica only. \
             `replicas = 1` is asserted in configuration, but nothing stops this \
             deployment being scaled up afterwards — at which point a proof \
             replays cleanly against any replica that has not seen it, with no \
             signal. Prefer the redis backend for anything that might scale.",
        ));
    }

    if cfg.verification.methods != MethodsConfig::MethodA {
        out.push(warn(
            "verification.content_binding",
            "§7.13",
            "Method B requires with_request_body, allow_partial_message: false, and pack_as_bytes: true. Run ans-authz validate-envoy against the deployed listener.",
        ));
    }

    if cfg.authority.mode == AuthorityMode::SoleConfigured {
        out.push(warn(
            "authority.mode",
            "§7.7",
            "sole_configured is the weaker half of §7.7: it is only correct while \
             this callee answers as exactly one authority. context_extension \
             scales to more than one and is sourced from xDS rather than \
             configuration.",
        ));
    }

    if cfg.verification.pop_skew_secs > 300 {
        out.push(warn(
            "verification.pop_skew_secs",
            "§7.6",
            format!(
                "a {}s freshness window is wide. §7.6: each halving of the window \
                 halves both replay exposure and replay-cache pressure.",
                cfg.verification.pop_skew_secs
            ),
        ));
    }

    out
}

fn validate_server(cfg: &Config, errors: &mut Vec<ConfigError>) {
    match (&cfg.server.listen, &cfg.server.uds_path) {
        (None, None) => errors.push(err(
            "server.listen",
            "—",
            "set exactly one of `listen` or `uds_path`",
        )),
        (Some(_), Some(_)) => errors.push(err(
            "server.listen",
            "—",
            "`listen` and `uds_path` are mutually exclusive; set exactly one",
        )),
        _ => {}
    }
}

fn validate_authority(cfg: &Config, errors: &mut Vec<ConfigError>) {
    // §7.7, the load-bearing check. Neither mechanism configured is the
    // misconfigured callee of the spec's worked example A.6.
    match cfg.authority.mode {
        AuthorityMode::ContextExtension => {
            if cfg.authority.context_extension_key.trim().is_empty() {
                errors.push(err(
                    "authority.context_extension_key",
                    "§7.7",
                    "must name the per-route key the proxy asserts (for Envoy, a \
                     key under ExtAuthzPerRoute.check_settings.context_extensions)",
                ));
            }
        }
        AuthorityMode::SoleConfigured => match cfg.authority.authorities.len() {
            0 => errors.push(err(
                "authority.authorities",
                "§7.7",
                "sole_configured requires exactly one authority; with none, the \
                 comparison URL could only come from the request's own Host \
                 header, which §7.7 forbids",
            )),
            1 => {}
            n => errors.push(err(
                "authority.authorities",
                "§7.7",
                format!(
                    "sole_configured requires exactly one authority, found {n}. With \
                     several and no per-route assertion, a proof minted for one \
                     would pass on a request that arrived at another. Use \
                     mode = \"context_extension\" instead."
                ),
            )),
        },
    }

    for (i, authority) in cfg.authority.authorities.iter().enumerate() {
        let field = format!("authority.authorities[{i}]");
        let a = authority.trim();
        if a.is_empty() {
            errors.push(err(&field, "§7.7", "must not be empty"));
        } else if a.contains("://") {
            errors.push(err(
                &field,
                "§7.7",
                "must be a bare authority (`host` or `host:port`), not a URL",
            ));
        } else if a.contains('/') {
            errors.push(err(
                &field,
                "§7.7",
                "must be a bare authority with no path component",
            ));
        }
    }
}

fn validate_verification(cfg: &Config, errors: &mut Vec<ConfigError>) {
    if cfg.verification.methods != MethodsConfig::MethodA
        && cfg.verification.content_binding != ContentBinding::Required
    {
        errors.push(err(
            "verification.content_binding",
            "§7.13",
            "the merged ANS-6 standard requires a digest on every Method B proof, including empty requests; set content_binding = \"required\"",
        ));
    }

    // §7.1: the reduced mode is permitted but must be a documented decision.
    if !cfg.verification.require_receipt {
        let justified = cfg
            .verification
            .reduced_mode_justification
            .as_deref()
            .map(str::trim)
            .is_some_and(|j| j.len() >= 16);
        if !justified {
            errors.push(err(
                "verification.reduced_mode_justification",
                "§7.1",
                "running without receipts trades away the request-time inclusion \
                 proof. §7.1 permits it and requires the deployment to document \
                 the choice, so set a justification of at least 16 characters.",
            ));
        }
    }

    if cfg.verification.pop_skew_secs == 0 {
        errors.push(err(
            "verification.pop_skew_secs",
            "§7.4",
            "must be greater than zero; a zero window rejects every proof",
        ));
    }

    if cfg.verification.status_skew_secs > MAX_STATUS_SKEW_SECS {
        errors.push(err(
            "verification.status_skew_secs",
            "§4.4",
            format!(
                "must not exceed {MAX_STATUS_SKEW_SECS}s; §4.4 caps clock-skew \
                 tolerance at 10 minutes, and a wider value extends the \
                 revocation-latency bound (§11.1)"
            ),
        ));
    }

    for (i, name) in cfg.verification.allowed_ans_names.iter().enumerate() {
        if name.trim().is_empty() {
            errors.push(err(
                &format!("verification.allowed_ans_names[{i}]"),
                "§7.5",
                "must not be empty",
            ));
        }
    }

    // Method A needs the proxy to hand over a client certificate, which is a
    // deployment property this service cannot check. Flagged in envoy_lint
    // instead; nothing to validate here beyond the enum itself.
    let _ = matches!(
        cfg.verification.methods,
        MethodsConfig::MethodA | MethodsConfig::Both | MethodsConfig::MethodB
    );
}

fn validate_replay(cfg: &Config, errors: &mut Vec<ConfigError>) {
    if cfg.replay.deadline_ms == 0 {
        errors.push(err(
            "replay.deadline_ms",
            "§9.6",
            "must be greater than zero; a shared cache MUST be consulted with a \
             deadline and a timeout is a rejection",
        ));
    }

    match cfg.replay.backend {
        ReplayBackendKind::Redis => {
            if cfg
                .replay
                .redis_url
                .as_deref()
                .map(str::trim)
                .is_none_or(str::is_empty)
            {
                errors.push(err(
                    "replay.redis_url",
                    "§7.6",
                    "required when backend = \"redis\"",
                ));
            }
        }
        ReplayBackendKind::Memory => {
            // §7.6: "Multi-replica deployments MUST share the replay cache across
            // replicas serving the same `htu` authority."
            if cfg.replay.replicas > 1 {
                errors.push(err(
                    "replay.backend",
                    "§7.6",
                    format!(
                        "the in-process cache blocks reuse within one replica only, but \
                         replicas = {}. A proof would replay cleanly against any other \
                         replica. Use backend = \"redis\".",
                        cfg.replay.replicas
                    ),
                ));
            }
        }
    }

    if cfg.replay.replicas == 0 {
        errors.push(err("replay.replicas", "§7.6", "must be at least 1"));
    }
}

fn validate_transparency_log(cfg: &Config, errors: &mut Vec<ConfigError>) {
    let has_url = cfg
        .transparency_log
        .root_keys_url
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());
    let has_static = !cfg.transparency_log.static_root_keys.is_empty();

    if !has_url && !has_static {
        errors.push(err(
            "transparency_log",
            "§4.5",
            "set `root_keys_url`, `static_root_keys`, or both. The one-time \
             root-key fetch is the only trust bootstrapping the SCITT tier \
             requires, and without a key there is nothing to verify against.",
        ));
    }

    if has_url && cfg.transparency_log.refresh_interval_secs == 0 {
        errors.push(err(
            "transparency_log.refresh_interval_secs",
            "§4.6",
            "must be greater than zero; artifacts are refreshed in the background, \
             never in the request path",
        ));
    }

    if let Some(url) = cfg.transparency_log.root_keys_url.as_deref()
        && !url.starts_with("https://")
        && !url.starts_with("http://")
    {
        errors.push(err(
            "transparency_log.root_keys_url",
            "§4.5",
            "must be an absolute http(s) URL",
        ));
    }

    // §11.10 is explicit that a new root key is trusted on no more evidence than
    // a TLS fetch from a trusted TL domain. Plain HTTP removes even that.
    if let Some(url) = cfg.transparency_log.root_keys_url.as_deref()
        && url.starts_with("http://")
    {
        errors.push(err(
            "transparency_log.root_keys_url",
            "§11.10",
            "must be https. Root-key trust is fetch-channel trust: over plain HTTP \
             anyone on the path can introduce a key this verifier will then trust.",
        ));
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Config;

    fn base() -> Config {
        toml::from_str(
            r#"
[server]
listen = "127.0.0.1:10003"
admin_listen = "127.0.0.1:9901"

[authority]
mode = "context_extension"

[verification]
methods = "method_b"
require_receipt = true
pop_skew_secs = 120
status_skew_secs = 60
content_binding = "required"

[replay]
backend = "memory"
deadline_ms = 50
max_entries = 100000
replicas = 1

[transparency_log]
root_keys_url = "https://tl.example.com/root-keys"
"#,
        )
        .unwrap()
    }

    fn fields(errors: &[ConfigError]) -> Vec<&str> {
        errors.iter().map(|e| e.field.as_str()).collect()
    }

    #[test]
    fn the_baseline_configuration_is_valid() {
        assert!(validate(&base()).is_ok());
    }

    // ── §7.7 ─────────────────────────────────────────────────────

    #[test]
    fn sole_configured_with_no_authority_fails_startup() {
        // The headline §7.7 requirement: with neither mechanism wired, the only
        // remaining source would be the client-controlled Host header.
        let mut cfg = base();
        cfg.authority.mode = AuthorityMode::SoleConfigured;
        cfg.authority.authorities.clear();
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"authority.authorities"));
        assert!(errs.iter().any(|e| e.spec == "§7.7"));
    }

    #[test]
    fn sole_configured_with_two_authorities_fails_startup() {
        // A proof minted for one would pass on a request that arrived at the other.
        let mut cfg = base();
        cfg.authority.mode = AuthorityMode::SoleConfigured;
        cfg.authority.authorities = vec!["a.example".into(), "b.example".into()];
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"authority.authorities"));
    }

    #[test]
    fn sole_configured_with_exactly_one_authority_is_valid() {
        let mut cfg = base();
        cfg.authority.mode = AuthorityMode::SoleConfigured;
        cfg.authority.authorities = vec!["api.example.com".into()];
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn an_empty_context_extension_key_fails_startup() {
        let mut cfg = base();
        cfg.authority.context_extension_key = "  ".into();
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"authority.context_extension_key"));
    }

    #[test]
    fn an_authority_given_as_a_url_is_rejected() {
        let mut cfg = base();
        cfg.authority.authorities = vec!["https://api.example.com".into()];
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"authority.authorities[0]"));
    }

    #[test]
    fn an_authority_with_a_path_is_rejected() {
        let mut cfg = base();
        cfg.authority.authorities = vec!["api.example.com/v1".into()];
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"authority.authorities[0]"));
    }

    // ── §7.6 ─────────────────────────────────────────────────────

    #[test]
    fn memory_backend_with_multiple_replicas_fails_startup() {
        // Enforce the §7.6 shared-cache requirement for multiple replicas.
        let mut cfg = base();
        cfg.replay.replicas = 3;
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"replay.backend"));
        assert!(errs.iter().any(|e| e.spec == "§7.6"));
    }

    #[test]
    fn redis_backend_with_multiple_replicas_is_valid() {
        let mut cfg = base();
        cfg.replay.backend = ReplayBackendKind::Redis;
        cfg.replay.redis_url = Some("redis://127.0.0.1:6379".into());
        cfg.replay.replicas = 3;
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn redis_backend_without_a_url_fails_startup() {
        let mut cfg = base();
        cfg.replay.backend = ReplayBackendKind::Redis;
        cfg.replay.redis_url = None;
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"replay.redis_url"));
    }

    #[test]
    fn a_zero_replay_deadline_fails_startup() {
        let mut cfg = base();
        cfg.replay.deadline_ms = 0;
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"replay.deadline_ms"));
    }

    // ── §7.13 ────────────────────────────────────────────────────

    #[test]
    fn requiring_content_binding_is_valid_and_warns_about_its_prerequisite() {
        // `required` became enforceable once the SDK exposed content_sha256. It
        // still depends on the proxy supplying bodies, which this process cannot
        // check — hence a warning naming the Envoy setting rather than an error.
        let mut cfg = base();
        cfg.verification.content_binding = ContentBinding::Required;
        assert!(validate(&cfg).is_ok());
        let w = warnings(&cfg);
        assert!(
            w.iter()
                .any(|w| w.spec == "§7.13" && w.message.contains("with_request_body")),
            "expected a with_request_body warning, got {w:?}"
        );
    }

    #[test]
    fn optional_content_binding_fails_startup_for_method_b_and_both() {
        for methods in [MethodsConfig::MethodB, MethodsConfig::Both] {
            let mut cfg = base();
            cfg.verification.methods = methods;
            cfg.verification.content_binding = ContentBinding::Optional;
            let errors = validate(&cfg).unwrap_err();
            assert!(fields(&errors).contains(&"verification.content_binding"));
        }
    }

    // ── §7.1 ─────────────────────────────────────────────────────

    #[test]
    fn dropping_receipts_without_a_justification_fails_startup() {
        let mut cfg = base();
        cfg.verification.require_receipt = false;
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"verification.reduced_mode_justification"));
    }

    #[test]
    fn a_token_justification_is_not_enough() {
        let mut cfg = base();
        cfg.verification.require_receipt = false;
        cfg.verification.reduced_mode_justification = Some("n/a".into());
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn dropping_receipts_with_a_real_justification_is_allowed() {
        let mut cfg = base();
        cfg.verification.require_receipt = false;
        cfg.verification.reduced_mode_justification = Some(
            "TL receipt endpoint unavailable in this enclave; accepted by SecEng 2026-09".into(),
        );
        assert!(validate(&cfg).is_ok());
    }

    // ── §4.4 / §4.5 ──────────────────────────────────────────────

    #[test]
    fn status_skew_beyond_the_spec_cap_fails_startup() {
        let mut cfg = base();
        cfg.verification.status_skew_secs = 601;
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"verification.status_skew_secs"));
    }

    #[test]
    fn status_skew_at_the_cap_is_allowed() {
        let mut cfg = base();
        cfg.verification.status_skew_secs = 600;
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn a_zero_pop_skew_fails_startup() {
        let mut cfg = base();
        cfg.verification.pop_skew_secs = 0;
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"verification.pop_skew_secs"));
    }

    #[test]
    fn no_root_key_source_at_all_fails_startup() {
        let mut cfg = base();
        cfg.transparency_log.root_keys_url = None;
        cfg.transparency_log.static_root_keys.clear();
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"transparency_log"));
    }

    #[test]
    fn pinned_static_keys_with_no_url_is_a_valid_posture() {
        // §4.5: a pinned, static deployment that simply rejects unknown kids.
        let mut cfg = base();
        cfg.transparency_log.root_keys_url = None;
        cfg.transparency_log.static_root_keys = vec!["tl.example.com+c9e2f584+AjBZ".into()];
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn a_plaintext_root_keys_url_fails_startup() {
        // §11.10: root-key trust is fetch-channel trust.
        let mut cfg = base();
        cfg.transparency_log.root_keys_url = Some("http://tl.example.com/root-keys".into());
        let errs = validate(&cfg).unwrap_err();
        assert!(errs.iter().any(|e| e.spec == "§11.10"));
    }

    // ── server ───────────────────────────────────────────────────

    #[test]
    fn neither_listener_fails_startup() {
        let mut cfg = base();
        cfg.server.listen = None;
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"server.listen"));
    }

    #[test]
    fn both_listeners_fail_startup() {
        let mut cfg = base();
        cfg.server.uds_path = Some("/run/ans-authz.sock".into());
        let errs = validate(&cfg).unwrap_err();
        assert!(fields(&errs).contains(&"server.listen"));
    }

    // ── aggregation ──────────────────────────────────────────────

    #[test]
    fn every_problem_is_reported_at_once() {
        // An operator should fix a config in one pass, not discover the next
        // fault on the next restart.
        let mut cfg = base();
        cfg.server.listen = None;
        cfg.verification.pop_skew_secs = 0;
        cfg.verification.status_skew_secs = 900;
        cfg.replay.deadline_ms = 0;
        let errs = validate(&cfg).unwrap_err();
        assert!(errs.len() >= 4, "expected several errors, got {errs:?}");
    }

    // ── warnings ─────────────────────────────────────────────────

    #[test]
    fn the_memory_backend_warns_about_later_scaling() {
        let cfg = base();
        let w = warnings(&cfg);
        assert!(w.iter().any(|w| w.field == "replay.backend"));
    }

    #[test]
    fn a_wide_freshness_window_is_warned_about() {
        let mut cfg = base();
        cfg.verification.pop_skew_secs = 600;
        let w = warnings(&cfg);
        assert!(w.iter().any(|w| w.field == "verification.pop_skew_secs"));
    }

    #[test]
    fn warnings_never_block_a_valid_configuration() {
        let cfg = base();
        assert!(validate(&cfg).is_ok());
        assert_ne!(warnings(&cfg), Vec::<ConfigWarning>::new());
    }
}
