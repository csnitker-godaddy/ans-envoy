//! Resolving the externally-visible authority from an Envoy `CheckRequest` (§7.7).
//!
//! This is the module the spec's worked example A.6 is about. In that example a
//! callee derives its `htu` comparison URL from the request's own `Host` header,
//! and an attacker replays a proof captured from a call to a *different* origin
//! with a spoofed `Host`. Every check passes and "a request the caller never made
//! to this service authenticates as that caller".
//!
//! So `attributes.request.http.host` is never read here. The authority comes from
//! `context_extensions` — which per the proto is set by configuration and "will
//! not be sent to the upstream server", making it unreachable by a client — or
//! from this service's own configuration.

use ans_envoy_config::{AuthorityConfig, AuthorityMode};
use ans_envoy_core::{AuthoritySource, normalize_authority};
use envoy_types::pb::envoy::service::auth::v3::AttributeContext;

/// Resolves the §7.7 authority for each request.
#[derive(Debug, Clone)]
pub struct AuthorityResolver {
    mode: AuthorityMode,
    context_extension_key: String,
    /// Normalized allowlist. Empty means "no allowlist".
    allowed: Vec<String>,
}

impl AuthorityResolver {
    /// Build from validated configuration.
    ///
    /// Configuration validation has already refused the combinations §7.7
    /// forbids — notably `sole_configured` with zero or several authorities — so
    /// this does not re-check them.
    pub fn from_config(config: &AuthorityConfig) -> Self {
        Self {
            mode: config.mode,
            context_extension_key: config.context_extension_key.clone(),
            allowed: config
                .authorities
                .iter()
                .map(|a| normalize_authority(a))
                .collect(),
        }
    }

    /// The authority for this request, or `None` if none can be established.
    ///
    /// `None` is a denial. There is deliberately no fallback: the only other
    /// value available would be the client-controlled `Host`, and §7.7 calls
    /// using it "the vulnerability, not the defense".
    pub fn resolve(&self, attributes: &AttributeContext) -> Option<AuthoritySource> {
        match self.mode {
            AuthorityMode::ContextExtension => {
                let raw = attributes
                    .context_extensions
                    .get(&self.context_extension_key)?;
                let normalized = normalize_authority(raw);
                if normalized.is_empty() {
                    return None;
                }
                // Belt and braces: when an allowlist is also configured, a
                // proxy-asserted authority outside it is refused. A mis-scoped
                // xDS push should not be able to introduce an authority nobody
                // intended.
                if !self.allowed.is_empty() && !self.allowed.contains(&normalized) {
                    tracing::warn!(
                        asserted = %normalized,
                        "proxy asserted an authority outside the configured allowlist"
                    );
                    return None;
                }
                Some(AuthoritySource::ProxyAsserted(normalized))
            }
            AuthorityMode::SoleConfigured => self
                .allowed
                .first()
                .cloned()
                .map(AuthoritySource::SoleConfigured),
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(mode: AuthorityMode, authorities: &[&str]) -> AuthorityConfig {
        AuthorityConfig {
            mode,
            context_extension_key: "ans_trusted_authority".to_string(),
            authorities: authorities.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn attributes(extensions: &[(&str, &str)], host: &str) -> AttributeContext {
        let mut ctx = AttributeContext {
            context_extensions: extensions
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<HashMap<_, _>>(),
            ..Default::default()
        };
        ctx.request = Some(
            envoy_types::pb::envoy::service::auth::v3::attribute_context::Request {
                http: Some(
                    envoy_types::pb::envoy::service::auth::v3::attribute_context::HttpRequest {
                        host: host.to_string(),
                        ..Default::default()
                    },
                ),
                ..Default::default()
            },
        );
        ctx
    }

    #[test]
    fn reads_the_proxy_asserted_authority() {
        let r = AuthorityResolver::from_config(&config(AuthorityMode::ContextExtension, &[]));
        let attrs = attributes(&[("ans_trusted_authority", "api.example.com")], "whatever");
        assert_eq!(
            r.resolve(&attrs),
            Some(AuthoritySource::ProxyAsserted(
                "api.example.com".to_string()
            ))
        );
    }

    #[test]
    fn normalizes_case_and_the_default_port() {
        // §7.7: compared case-insensitively with default ports dropped.
        let r = AuthorityResolver::from_config(&config(AuthorityMode::ContextExtension, &[]));
        let attrs = attributes(&[("ans_trusted_authority", "API.Example.COM:443")], "x");
        assert_eq!(
            r.resolve(&attrs).map(|a| a.authority().to_string()),
            Some("api.example.com".to_string())
        );
    }

    #[test]
    fn a_missing_context_extension_resolves_to_nothing() {
        // Which the verifier turns into a denial — never a fallback to Host.
        let r = AuthorityResolver::from_config(&config(AuthorityMode::ContextExtension, &[]));
        let attrs = attributes(&[], "api.example.com");
        assert_eq!(r.resolve(&attrs), None);
    }

    #[test]
    fn the_host_header_is_never_used_as_the_authority() {
        // This is the example A.6 defence, asserted directly: a request whose
        // Host claims payments.example.com resolves to nothing when the proxy
        // asserted no authority.
        let r = AuthorityResolver::from_config(&config(AuthorityMode::ContextExtension, &[]));
        let attrs = attributes(&[], "payments.example.com");
        assert!(r.resolve(&attrs).is_none());
    }

    #[test]
    fn a_spoofed_host_cannot_override_the_asserted_authority() {
        let r = AuthorityResolver::from_config(&config(AuthorityMode::ContextExtension, &[]));
        let attrs = attributes(
            &[("ans_trusted_authority", "api.other.example")],
            "payments.example.com",
        );
        assert_eq!(
            r.resolve(&attrs).map(|a| a.authority().to_string()),
            Some("api.other.example".to_string())
        );
    }

    #[test]
    fn an_asserted_authority_outside_the_allowlist_is_refused() {
        let r = AuthorityResolver::from_config(&config(
            AuthorityMode::ContextExtension,
            &["api.example.com"],
        ));
        let attrs = attributes(&[("ans_trusted_authority", "evil.example")], "x");
        assert!(r.resolve(&attrs).is_none());
    }

    #[test]
    fn an_asserted_authority_inside_the_allowlist_is_accepted() {
        let r = AuthorityResolver::from_config(&config(
            AuthorityMode::ContextExtension,
            &["api.example.com"],
        ));
        let attrs = attributes(&[("ans_trusted_authority", "api.example.com")], "x");
        assert!(r.resolve(&attrs).is_some());
    }

    #[test]
    fn an_empty_asserted_value_resolves_to_nothing() {
        let r = AuthorityResolver::from_config(&config(AuthorityMode::ContextExtension, &[]));
        let attrs = attributes(&[("ans_trusted_authority", "   ")], "x");
        assert!(r.resolve(&attrs).is_none());
    }

    #[test]
    fn sole_configured_ignores_the_request_entirely() {
        let r = AuthorityResolver::from_config(&config(
            AuthorityMode::SoleConfigured,
            &["api.example.com"],
        ));
        let attrs = attributes(&[("ans_trusted_authority", "evil.example")], "evil.example");
        assert_eq!(
            r.resolve(&attrs),
            Some(AuthoritySource::SoleConfigured(
                "api.example.com".to_string()
            ))
        );
    }

    #[test]
    fn sole_configured_with_no_authority_resolves_to_nothing() {
        // Validation refuses this configuration; the runtime still fails closed
        // rather than inventing an authority.
        let r = AuthorityResolver::from_config(&config(AuthorityMode::SoleConfigured, &[]));
        let attrs = attributes(&[], "x");
        assert!(r.resolve(&attrs).is_none());
    }
}
