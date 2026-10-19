#![warn(missing_docs)]

//! # Configuration and startup validation for `ans-authz`
//!
//! Two jobs, both of which ANS-6 assigns to "the embedding service" rather than
//! to a verification library.
//!
//! ## 1. Fail startup, not requests (§7.7)
//!
//! > Implementations MUST fail startup when neither is configured, and MUST NOT
//! > fall back to deriving the comparison authority from the request's own `Host`
//! > header.
//!
//! The SDK is explicit that it cannot do this: *"this library cannot see your
//! startup, so enforce that in the embedding service."* [`validate`] is that
//! enforcement, and it refuses several other ways a deployment can look healthy
//! while being unconformant — an in-process replay cache behind more than one
//! replica (§7.6), receipts disabled without a documented reason (§7.1),
//! content binding declared `required` when this build cannot enforce it (§7.13).
//!
//! There is one honest gap. This process can fail its own startup, but Envoy
//! cannot: an xDS push that removes a route's `context_extensions` is a live
//! config change, not a restart. So the request-time behaviour is fail-closed too
//! — a request arriving with no asserted authority is denied rather than falling
//! back to anything.
//!
//! ## 2. Lint the half we ship but do not run
//!
//! [`envoy_lint::lint`] checks the Envoy settings ANS-6 conformance depends on.
//! They are outside this binary, and three of the five are not expressible in the
//! Istio or Envoy Gateway CRDs at all — so the linter is advisory for anything
//! delivered by a control plane. It runs in CI over every shipped artifact and is
//! documented as a pre-deploy gate.

pub mod envoy_lint;
mod schema;
mod validate;

pub use envoy_lint::{LintError, LintFinding, Severity};
pub use schema::{
    AuthorityConfig, AuthorityMode, Config, ContentBinding, MethodsConfig, ReplayBackendKind,
    ReplayConfig, ServerConfig, TransparencyLogConfig, VerificationConfig,
};
pub use validate::{ConfigError, ConfigWarning, validate, warnings};

/// Errors from loading a configuration file.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The path attempted.
        path: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The file was not valid TOML, or did not match the schema.
    #[error("cannot parse {path}: {source}")]
    Parse {
        /// The path attempted.
        path: String,
        /// The underlying error.
        #[source]
        source: toml::de::Error,
    },

    /// The configuration parsed but must not be served.
    #[error("configuration is not conformant:\n{}", format_errors(.0))]
    Invalid(Vec<ConfigError>),
}

fn format_errors(errors: &[ConfigError]) -> String {
    errors
        .iter()
        .map(|e| format!("  - {e}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Read, parse, and validate a configuration file.
///
/// The validation step is not optional and not separable. A caller that could
/// load without validating would be one refactor away from serving a config
/// §7.7 forbids.
pub fn load(path: &str) -> Result<Config, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_string(),
        source,
    })?;
    let config: Config = toml::from_str(&text).map_err(|source| LoadError::Parse {
        path: path.to_string(),
        source,
    })?;
    validate(&config).map_err(LoadError::Invalid)?;
    Ok(config)
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_reports_its_path() {
        let err = load("/nonexistent/ans-authz.toml").unwrap_err();
        assert!(matches!(err, LoadError::Io { .. }));
        assert!(err.to_string().contains("/nonexistent/ans-authz.toml"));
    }

    #[test]
    fn invalid_errors_render_every_problem() {
        let err = LoadError::Invalid(vec![
            ConfigError {
                field: "authority.authorities".into(),
                spec: "§7.7",
                message: "first".into(),
            },
            ConfigError {
                field: "replay.backend".into(),
                spec: "§7.6",
                message: "second".into(),
            },
        ]);
        let rendered = err.to_string();
        assert!(rendered.contains("§7.7"));
        assert!(rendered.contains("§7.6"));
        assert!(rendered.contains("first"));
        assert!(rendered.contains("second"));
    }
}
