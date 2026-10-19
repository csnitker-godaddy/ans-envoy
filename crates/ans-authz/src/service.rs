//! The `envoy.service.auth.v3.Authorization` implementation.

use std::sync::Arc;

use ans_envoy_adapter::{AuthorityResolver, adapt, to_check_response};
use ans_envoy_core::{Decision, DenyReason, Verifier};
use envoy_types::pb::envoy::service::auth::v3::authorization_server::Authorization;
use envoy_types::pb::envoy::service::auth::v3::{CheckRequest, CheckResponse};
use tonic::{Request, Response, Status};

use crate::admin::Observed;
use crate::telemetry::Telemetry;

/// Denial label for a `CheckRequest` this service could not read.
const LABEL_MALFORMED_CHECK_REQUEST: &str = "MALFORMED_CHECK_REQUEST";

/// The authorization server.
pub struct AnsAuthz {
    verifier: Arc<Verifier>,
    resolver: AuthorityResolver,
    telemetry: Arc<Telemetry>,
    observed: Arc<Observed>,
}

impl std::fmt::Debug for AnsAuthz {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnsAuthz").finish_non_exhaustive()
    }
}

impl AnsAuthz {
    /// Assemble the service.
    pub fn new(
        verifier: Arc<Verifier>,
        resolver: AuthorityResolver,
        telemetry: Arc<Telemetry>,
        observed: Arc<Observed>,
    ) -> Self {
        Self {
            verifier,
            resolver,
            telemetry,
            observed,
        }
    }

    /// Decide one request. Always produces a decision, never an error.
    async fn decide(&self, request: &CheckRequest) -> Decision {
        match adapt(request, &self.resolver) {
            Ok(facts) => {
                // Two of the Envoy settings ANS-6 depends on can only be
                // observed from a real request. Recording them is what lets
                // /readyz tell a rollout that the proxy is misconfigured.
                self.observed.record(
                    facts.headers.raw_values_available,
                    facts.authority.is_some(),
                );
                self.verifier.authenticate(&facts).await
            }
            Err(e) => {
                // The proxy and this service disagree about the protocol. That is
                // a wiring fault rather than caller behaviour, so it is counted
                // separately — but the request is still refused.
                self.telemetry.adapt_error();
                tracing::error!(error = %e, "could not read CheckRequest");
                Decision::Deny(DenyReason::deployment(
                    LABEL_MALFORMED_CHECK_REQUEST,
                    e.to_string(),
                ))
            }
        }
    }
}

#[tonic::async_trait]
impl Authorization for AnsAuthz {
    /// # This function must never return `Err`
    ///
    /// Envoy treats a failed `Check` call — a transport error, or a gRPC status
    /// that is not a considered decision — as a **communication failure**, and
    /// applies the operator's `failure_mode_allow` to it. With
    /// `failure_mode_allow: true` that admits the request.
    ///
    /// So returning `Err(Status::internal(..))` on an unexpected condition would
    /// hand the decision to a config setting, which is exactly the fail-open lever
    /// §7.6 ("a cache at capacity or erroring rejects the request") and §9.6 ("a
    /// timeout is a rejection, never a skip") exist to close.
    ///
    /// Every path below returns `Ok`, carrying either `OK` or
    /// `PERMISSION_DENIED`. A denial expressed that way is a decision Envoy must
    /// honour, not an error it may override.
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let decision = self.decide(&request.into_inner()).await;

        match &decision {
            Decision::Allow(caller) => {
                self.telemetry.allowed();
                tracing::debug!(
                    ans_name = %caller.ans_name,
                    agent_id = %caller.agent_id,
                    method = caller.method.label(),
                    "authenticated caller"
                );
            }
            Decision::Deny(reason) => {
                self.telemetry.denied(reason.label);
                // The label goes to the caller; the detail stays here. It names
                // which check failed, which is the feedback an attacker tuning a
                // forged proof is looking for.
                tracing::info!(
                    label = reason.label,
                    fault = reason.fault.label(),
                    status = reason.status(),
                    detail = %reason.detail,
                    "refused request"
                );
            }
        }

        Ok(Response::new(to_check_response(&decision)))
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use ans_envoy_config::{AuthorityConfig, AuthorityMode};
    use envoy_types::pb::envoy::service::auth::v3::check_response::HttpResponse;

    fn resolver() -> AuthorityResolver {
        AuthorityResolver::from_config(&AuthorityConfig {
            mode: AuthorityMode::ContextExtension,
            context_extension_key: "ans_trusted_authority".to_string(),
            authorities: Vec::new(),
        })
    }

    /// A service whose verifier is never reached, for exercising the adapt-error
    /// path without standing up a key store.
    fn adapt_error_only() -> (AuthorityResolver, Arc<Telemetry>) {
        (resolver(), Telemetry::new())
    }

    #[tokio::test]
    async fn a_malformed_check_request_is_refused_not_errored() {
        // The critical property: even a request we cannot parse produces a
        // decision. An Err here would be a communication failure that
        // failure_mode_allow could turn into an allow.
        let (resolver, telemetry) = adapt_error_only();

        // Build the deny path directly: `decide` short-circuits before touching
        // the verifier when adaptation fails, so no key store is needed.
        let decision = match adapt(&CheckRequest { attributes: None }, &resolver) {
            Ok(_) => panic!("expected adapt to fail"),
            Err(e) => {
                telemetry.adapt_error();
                Decision::Deny(DenyReason::deployment(
                    LABEL_MALFORMED_CHECK_REQUEST,
                    e.to_string(),
                ))
            }
        };

        let response = to_check_response(&decision);
        // PERMISSION_DENIED, not a gRPC error.
        assert_eq!(response.status.as_ref().map(|s| s.code), Some(7));
        assert!(matches!(
            response.http_response,
            Some(HttpResponse::DeniedResponse(_))
        ));
        assert_eq!(telemetry.checks(), 0, "adapt errors are counted separately");
    }

    #[test]
    fn the_malformed_label_is_distinct_from_the_sdk_vocabulary() {
        // Reusing an SDK label here would make an alert on it ambiguous.
        assert!(!ans_envoy_core::labels::RAW_HEADERS_UNAVAILABLE.eq(LABEL_MALFORMED_CHECK_REQUEST));
        assert_eq!(LABEL_MALFORMED_CHECK_REQUEST, "MALFORMED_CHECK_REQUEST");
    }
}
