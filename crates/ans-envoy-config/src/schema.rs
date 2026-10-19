//! The configuration file, as a type.
//!
//! Two rules shape this module.
//!
//! **Security-relevant settings are not defaulted.** ANS-6 §9 requires a
//! deployment to *choose* its failure behaviour and §11.1 requires it to document
//! the values it runs. A field with a permissive default lets a deployment make
//! that choice by omission, so the fields that matter have no `serde(default)`
//! and configuration parsing fails without them.
//!
//! **Nothing here is validated by construction.** Parsing produces a
//! [`Config`]; [`crate::validate`] decides whether it is allowed to run. Keeping
//! those apart means every rejection can be reported together, rather than one
//! per restart.

use std::collections::BTreeMap;

use serde::Deserialize;

/// A complete `ans-authz` configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where to listen, and how.
    pub server: ServerConfig,
    /// ANS-6 §7.7 authority resolution.
    pub authority: AuthorityConfig,
    /// What to verify and how strictly.
    pub verification: VerificationConfig,
    /// ANS-6 §7.6 replay cache.
    pub replay: ReplayConfig,
    /// Where the Transparency Log's signing keys come from.
    pub transparency_log: TransparencyLogConfig,
}

/// Listener configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// gRPC listen address, e.g. `127.0.0.1:10003`.
    ///
    /// Mutually exclusive with `uds_path`. A loopback or Unix socket keeps the
    /// authorizer unreachable from anywhere but its own proxy — this service
    /// answers "is this caller authentic", so anything that can reach it and be
    /// believed is a bypass.
    #[serde(default)]
    pub listen: Option<String>,
    /// Unix domain socket path to listen on instead of TCP.
    #[serde(default)]
    pub uds_path: Option<String>,
    /// Admin/metrics HTTP listen address.
    pub admin_listen: String,
}

/// How the externally-visible authority is established (§7.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityMode {
    /// Read it from a per-route value the proxy asserts.
    ///
    /// For Envoy: `ExtAuthzPerRoute.check_settings.context_extensions`. This is
    /// the strong form — xDS-sourced, per virtual host, and not forwarded
    /// upstream, so a client cannot reach it.
    ContextExtension,
    /// Use the single authority named in configuration.
    ///
    /// Valid only for a one-authority deployment. Two configured authorities with
    /// no per-route assertion would let a proof minted for A pass on a request
    /// that arrived at B, so validation refuses that combination.
    SoleConfigured,
}

/// §7.7 authority configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    /// Which mechanism supplies the authority.
    pub mode: AuthorityMode,
    /// The `context_extensions` key to read, for [`AuthorityMode::ContextExtension`].
    #[serde(default = "default_context_extension_key")]
    pub context_extension_key: String,
    /// Externally-visible authorities this callee answers as.
    ///
    /// Under [`AuthorityMode::SoleConfigured`] this must hold exactly one entry.
    /// Under [`AuthorityMode::ContextExtension`] it is an optional allowlist that
    /// the proxy-asserted value must belong to — belt and braces, so a
    /// mis-scoped xDS push cannot introduce an authority nobody intended.
    #[serde(default)]
    pub authorities: Vec<String>,
}

fn default_context_extension_key() -> String {
    "ans_trusted_authority".to_string()
}

/// Which caller-authentication methods are accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodsConfig {
    /// ANS-6 §7 only.
    MethodB,
    /// ANS-6 §6 only.
    MethodA,
    /// Both.
    Both,
}

/// Request-content binding posture (§7.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentBinding {
    /// Legacy draft value. Startup rejects it for Method B and Both.
    Optional,
    /// Every Method B proof must bind its content, including empty content.
    /// Requires complete raw body buffering in Envoy.
    Required,
}

/// Verification policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationConfig {
    /// Accepted methods (§10.1 requires documenting which).
    pub methods: MethodsConfig,
    /// Require a SCITT receipt for Method B (§7.1). Method A always requires one.
    pub require_receipt: bool,
    /// Why this deployment runs without receipts.
    ///
    /// §7.1 permits the reduced mode but requires documenting the choice.
    /// Requiring prose here is how that obligation is enforced rather than
    /// merely stated: a deployment cannot drop the inclusion proof by flipping a
    /// boolean.
    #[serde(default)]
    pub reduced_mode_justification: Option<String>,
    /// Accepted-peer set as `ans://` names (§7.5.4). Empty accepts any proven agent.
    #[serde(default)]
    pub allowed_ans_names: Vec<String>,
    /// `DPoP` `iat` freshness window in seconds (§7.4 step 9).
    pub pop_skew_secs: u64,
    /// Status-token clock-skew tolerance in seconds (§4.4, spec caps at 600).
    pub status_skew_secs: u64,
    /// Request-content binding posture (§7.13).
    pub content_binding: ContentBinding,
}

/// Replay-cache backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayBackendKind {
    /// Shared across replicas. The only §7.6-conformant choice above one replica.
    Redis,
    /// In-process. Single replica only.
    Memory,
}

/// §7.6 replay-cache configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayConfig {
    /// Which backend to use.
    pub backend: ReplayBackendKind,
    /// Redis connection URL, for [`ReplayBackendKind::Redis`].
    #[serde(default)]
    pub redis_url: Option<String>,
    /// Key prefix, so a shared Redis can serve more than one purpose.
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,
    /// Deadline for a shared-store round trip, in milliseconds (§9.6).
    ///
    /// A timeout is a rejection, so this is an availability/latency knob with
    /// teeth: too low and legitimate callers are refused under load.
    pub deadline_ms: u64,
    /// Entry ceiling for the in-process backend.
    #[serde(default)]
    pub max_entries: usize,
    /// How many replicas of this service will run.
    ///
    /// Declared rather than detected. §7.6 requires a shared cache above one
    /// replica, and this is the only signal available at startup — see the
    /// caveat in [`crate::validate`].
    pub replicas: u32,
}

fn default_key_prefix() -> String {
    "ans6:jti:".to_string()
}

/// Where the TL's verification keys come from (§4.5).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparencyLogConfig {
    /// `/root-keys` URL to bootstrap and refresh from.
    #[serde(default)]
    pub root_keys_url: Option<String>,
    /// C2SP signed-note verifier lines, pinned in configuration.
    ///
    /// §11.10: "Deployments needing more SHOULD pin keys explicitly and treat any
    /// addition as an operator-approval event rather than an automatic merge."
    /// Supplying keys here and no URL is that posture — a static store that
    /// simply rejects unknown `kid`s, which §4.5 calls a valid stance.
    #[serde(default)]
    pub static_root_keys: Vec<String>,
    /// Background refresh interval in seconds (§4.6).
    ///
    /// Refresh happens off the request path; §4.6 forbids fetching during
    /// verification.
    #[serde(default = "default_refresh_secs")]
    pub refresh_interval_secs: u64,
    /// Extra labels to attach to logs and metrics.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

fn default_refresh_secs() -> u64 {
    1800
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
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
static_root_keys = ["tl.example.com+c9e2f584+AjBZ"]
"#;

    #[test]
    fn parses_a_minimal_configuration() {
        let cfg: Config = toml::from_str(MINIMAL).unwrap();
        assert_eq!(cfg.authority.mode, AuthorityMode::ContextExtension);
        assert_eq!(cfg.authority.context_extension_key, "ans_trusted_authority");
        assert_eq!(cfg.verification.methods, MethodsConfig::MethodB);
        assert_eq!(cfg.replay.backend, ReplayBackendKind::Memory);
        assert_eq!(cfg.replay.key_prefix, "ans6:jti:");
        assert_eq!(cfg.transparency_log.refresh_interval_secs, 1800);
    }

    #[test]
    fn an_unknown_key_is_rejected_rather_than_ignored() {
        // A typo in a security setting must not be silently discarded — the
        // deployment would then be running a policy nobody chose.
        let bad = format!("{MINIMAL}\n[extra]\nnope = 1\n");
        assert!(toml::from_str::<Config>(&bad).is_err());
    }

    #[test]
    fn a_misspelled_field_inside_verification_is_rejected() {
        let bad = MINIMAL.replace("require_receipt = true", "require_reciept = true");
        assert!(toml::from_str::<Config>(&bad).is_err());
    }

    #[test]
    fn security_relevant_fields_have_no_defaults() {
        // Dropping each must fail the parse, so a deployment cannot choose a
        // policy by omission (§9, §11.1).
        for field in [
            "require_receipt = true",
            "pop_skew_secs = 120",
            "status_skew_secs = 60",
            "content_binding = \"required\"",
            "replicas = 1",
            "deadline_ms = 50",
            "mode = \"context_extension\"",
            "methods = \"method_b\"",
            "backend = \"memory\"",
        ] {
            let without = MINIMAL.replace(field, "");
            assert!(
                toml::from_str::<Config>(&without).is_err(),
                "{field} must be required"
            );
        }
    }

    #[test]
    fn legacy_optional_parses_so_startup_can_explain_the_required_migration() {
        let cfg: Config = toml::from_str(&MINIMAL.replace(
            "content_binding = \"required\"",
            "content_binding = \"optional\"",
        ))
        .unwrap();
        assert_eq!(cfg.verification.content_binding, ContentBinding::Optional);
    }
}
