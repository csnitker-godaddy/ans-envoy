//! [`Decision`] → `CheckResponse`.
//!
//! ## The one rule that matters here
//!
//! **Never return a gRPC error.** Envoy treats a failed `Check` call — a
//! transport error, or a non-`OK` gRPC status that is not a considered decision —
//! as a *communication failure*, and applies the operator's `failure_mode_allow`
//! to it. With `failure_mode_allow: true` that admits the request. So a handler
//! that answers an unexpected condition with `Err(Status::internal(..))` has
//! handed the decision to a config setting, which is precisely the fail-open lever
//! §7.6 and §9.6 exist to close.
//!
//! Every outcome this module produces is therefore `Ok(CheckResponse)` carrying
//! either `OK` or `PERMISSION_DENIED`. A denial expressed that way is a decision
//! Envoy must honour, not an error it may override.
//!
//! ## What reaches the upstream, and what does not
//!
//! An allow injects the authenticated identity as `x-ans-caller-*` request
//! headers. Each of the five controlled headers that this service does not set
//! is explicitly *removed*, so a client cannot supply `x-ans-caller-ans-name` and
//! have an upstream believe it. That removal is the load-bearing half: adding a
//! header only helps if the absence of one cannot be forged.
//!
//! A denial returns the stable label and nothing else. The human-readable detail
//! stays in the logs — it narrates which check failed, which is the feedback an
//! attacker probing a proof is looking for.

use ans_envoy_core::{AuthenticatedCaller, Decision, DenyReason};
use envoy_types::pb::envoy::config::core::v3::{
    HeaderValue, HeaderValueOption, header_value_option::HeaderAppendAction,
};
use envoy_types::pb::envoy::service::auth::v3::{
    CheckResponse, DeniedHttpResponse, OkHttpResponse, check_response::HttpResponse,
};
use envoy_types::pb::envoy::r#type::v3::HttpStatus;
use envoy_types::pb::google::rpc;

/// gRPC status codes, from `google.rpc.Code`.
const GRPC_OK: i32 = 0;
const GRPC_PERMISSION_DENIED: i32 = 7;

/// Header carrying the caller's full `ans://` name.
pub const HEADER_ANS_NAME: &str = "x-ans-caller-ans-name";
/// Header carrying the caller's agent id.
pub const HEADER_AGENT_ID: &str = "x-ans-caller-agent-id";
/// Header carrying the identity certificate fingerprint that proved possession.
pub const HEADER_CERT_FP: &str = "x-ans-caller-cert-fp";
/// Header carrying the RFC 7638 thumbprint of the proof key (`cnf.jkt`).
pub const HEADER_JKT: &str = "x-ans-caller-jkt";
/// Header carrying which ANS-6 method authenticated the caller.
pub const HEADER_METHOD: &str = "x-ans-caller-method";
/// Header carrying the denial label, for upstream logging on a rejected request.
pub const HEADER_DENY_LABEL: &str = "x-ans-deny-label";

/// Every header this service controls.
///
/// Used to remove the ones not set on a given request. A client-supplied
/// `x-ans-caller-jkt` surviving into a Method-A request would let an upstream
/// believe a proof key existed when possession came from the TLS handshake.
const CONTROLLED_HEADERS: [&str; 5] = [
    HEADER_ANS_NAME,
    HEADER_AGENT_ID,
    HEADER_CERT_FP,
    HEADER_JKT,
    HEADER_METHOD,
];

/// Turn a decision into a `CheckResponse`.
pub fn to_check_response(decision: &Decision) -> CheckResponse {
    match decision {
        Decision::Allow(caller) => allow(caller),
        Decision::Deny(reason) => deny(reason),
    }
}

/// An allow, with the authenticated identity injected for the upstream.
fn allow(caller: &AuthenticatedCaller) -> CheckResponse {
    let mut set: Vec<(&str, String)> = vec![
        (HEADER_ANS_NAME, caller.ans_name.clone()),
        (HEADER_AGENT_ID, caller.agent_id.clone()),
        (HEADER_CERT_FP, caller.fingerprint.clone()),
        (HEADER_METHOD, caller.method.label().to_string()),
    ];
    if let Some(jkt) = caller.jkt.as_ref() {
        set.push((HEADER_JKT, jkt.clone()));
    }

    let set_names: Vec<&str> = set.iter().map(|(name, _)| *name).collect();
    let to_remove: Vec<String> = CONTROLLED_HEADERS
        .iter()
        .filter(|name| !set_names.contains(name))
        .map(|name| (*name).to_string())
        .collect();

    CheckResponse {
        status: Some(rpc::Status {
            code: GRPC_OK,
            message: "authenticated".to_string(),
            details: Vec::new(),
        }),
        dynamic_metadata: None,
        http_response: Some(HttpResponse::OkResponse(OkHttpResponse {
            headers: set.into_iter().map(|(n, v)| overwrite(n, &v)).collect(),
            headers_to_remove: to_remove,
            ..Default::default()
        })),
    }
}

/// A denial. `PERMISSION_DENIED` is a decision Envoy honours regardless of
/// `failure_mode_allow`.
fn deny(reason: &DenyReason) -> CheckResponse {
    let mut headers = vec![overwrite(HEADER_DENY_LABEL, reason.label)];
    if let Some(challenge) = reason.www_authenticate() {
        headers.push(overwrite("www-authenticate", challenge));
    }

    CheckResponse {
        status: Some(rpc::Status {
            code: GRPC_PERMISSION_DENIED,
            message: reason.label.to_string(),
            details: Vec::new(),
        }),
        dynamic_metadata: None,
        http_response: Some(HttpResponse::DeniedResponse(DeniedHttpResponse {
            status: Some(HttpStatus {
                code: i32::from(reason.status()),
            }),
            headers,
            // The label only. `reason.detail` names the failed check, which is
            // exactly what an attacker tuning a forged proof wants to read.
            body: reason.label.to_string(),
        })),
    }
}

/// A header that replaces any client-supplied value of the same name.
fn overwrite(name: &str, value: &str) -> HeaderValueOption {
    HeaderValueOption {
        header: Some(HeaderValue {
            key: name.to_string(),
            value: value.to_string(),
            raw_value: Vec::new(),
        }),
        append_action: HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
        keep_empty_value: false,
        ..Default::default()
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use ans_envoy_core::{MethodSelector, labels};

    fn caller(method: MethodSelector, jkt: Option<&str>) -> AuthenticatedCaller {
        AuthenticatedCaller {
            ans_name: "ans://v1.0.0.caller.example.com".to_string(),
            agent_id: "7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07".to_string(),
            fingerprint: "SHA256:aabb".to_string(),
            jkt: jkt.map(str::to_string),
            method,
        }
    }

    fn ok_response(r: &CheckResponse) -> &OkHttpResponse {
        match r.http_response.as_ref() {
            Some(HttpResponse::OkResponse(ok)) => ok,
            other => panic!("expected OkResponse, got {other:?}"),
        }
    }

    fn denied_response(r: &CheckResponse) -> &DeniedHttpResponse {
        match r.http_response.as_ref() {
            Some(HttpResponse::DeniedResponse(d)) => d,
            other => panic!("expected DeniedResponse, got {other:?}"),
        }
    }

    fn header(ok: &OkHttpResponse, name: &str) -> Option<String> {
        ok.headers
            .iter()
            .filter_map(|h| h.header.as_ref())
            .find(|h| h.key == name)
            .map(|h| h.value.clone())
    }

    // ── allow ────────────────────────────────────────────────────

    #[test]
    fn an_allow_carries_grpc_ok() {
        let r = to_check_response(&Decision::Allow(Box::new(caller(
            MethodSelector::MethodB,
            Some("thumb"),
        ))));
        assert_eq!(r.status.as_ref().map(|s| s.code), Some(GRPC_OK));
    }

    #[test]
    fn an_allow_injects_the_authenticated_identity() {
        let r = to_check_response(&Decision::Allow(Box::new(caller(
            MethodSelector::MethodB,
            Some("thumb"),
        ))));
        let ok = ok_response(&r);
        assert_eq!(
            header(ok, HEADER_ANS_NAME).as_deref(),
            Some("ans://v1.0.0.caller.example.com")
        );
        assert_eq!(header(ok, HEADER_CERT_FP).as_deref(), Some("SHA256:aabb"));
        assert_eq!(header(ok, HEADER_JKT).as_deref(), Some("thumb"));
        assert_eq!(header(ok, HEADER_METHOD).as_deref(), Some("method_b"));
    }

    #[test]
    fn identity_headers_overwrite_rather_than_append() {
        // Appending would let a client-supplied value ride alongside ours and an
        // upstream read either.
        let r = to_check_response(&Decision::Allow(Box::new(caller(
            MethodSelector::MethodB,
            Some("thumb"),
        ))));
        for h in &ok_response(&r).headers {
            assert_eq!(
                h.append_action,
                HeaderAppendAction::OverwriteIfExistsOrAdd as i32
            );
        }
    }

    #[test]
    fn method_a_removes_the_thumbprint_header_it_cannot_set() {
        // The load-bearing case. Method A has no proof key, so a client-supplied
        // x-ans-caller-jkt must not survive into the upstream request.
        let r = to_check_response(&Decision::Allow(Box::new(caller(
            MethodSelector::MethodA,
            None,
        ))));
        let ok = ok_response(&r);
        assert!(header(ok, HEADER_JKT).is_none());
        assert!(
            ok.headers_to_remove.contains(&HEADER_JKT.to_string()),
            "jkt must be removed, got {:?}",
            ok.headers_to_remove
        );
    }

    #[test]
    fn every_controlled_header_is_either_set_or_removed() {
        // No gap: a header in this family is never left to the client.
        for (method, jkt) in [
            (MethodSelector::MethodB, Some("thumb")),
            (MethodSelector::MethodA, None),
        ] {
            let r = to_check_response(&Decision::Allow(Box::new(caller(method, jkt))));
            let ok = ok_response(&r);
            for name in CONTROLLED_HEADERS {
                let is_set = header(ok, name).is_some();
                let is_removed = ok.headers_to_remove.contains(&name.to_string());
                assert!(
                    is_set ^ is_removed,
                    "{name} must be exactly one of set/removed (set={is_set}, removed={is_removed})"
                );
            }
        }
    }

    // ── deny ─────────────────────────────────────────────────────

    #[test]
    fn a_denial_uses_permission_denied_not_an_error_status() {
        // PERMISSION_DENIED is a decision Envoy honours. A transport-level error
        // would be a communication failure, subject to failure_mode_allow.
        let r = to_check_response(&Decision::Deny(DenyReason::caller(
            labels::DUPLICATE_HEADER,
            "two DPoP headers",
        )));
        assert_eq!(
            r.status.as_ref().map(|s| s.code),
            Some(GRPC_PERMISSION_DENIED)
        );
    }

    #[test]
    fn a_caller_denial_returns_401_and_the_rfc9449_challenge() {
        let r = to_check_response(&Decision::Deny(DenyReason::caller(
            labels::DUPLICATE_HEADER,
            "d",
        )));
        let d = denied_response(&r);
        assert_eq!(d.status.as_ref().map(|s| s.code), Some(401));
        assert!(
            d.headers
                .iter()
                .filter_map(|h| h.header.as_ref())
                .any(|h| h.key == "www-authenticate")
        );
    }

    #[test]
    fn a_deployment_denial_returns_500_without_a_challenge() {
        let r = to_check_response(&Decision::Deny(DenyReason::deployment(
            labels::RAW_HEADERS_UNAVAILABLE,
            "encode_raw_headers off",
        )));
        let d = denied_response(&r);
        assert_eq!(d.status.as_ref().map(|s| s.code), Some(500));
        assert!(
            !d.headers
                .iter()
                .filter_map(|h| h.header.as_ref())
                .any(|h| h.key == "www-authenticate")
        );
    }

    #[test]
    fn a_denial_body_carries_the_label_and_not_the_detail() {
        // The detail names which check failed; that belongs in our logs, not in
        // a response to whoever is probing.
        let r = to_check_response(&Decision::Deny(DenyReason::caller(
            labels::DUPLICATE_HEADER,
            "the DPoP header appeared 2 times",
        )));
        let d = denied_response(&r);
        assert_eq!(d.body, labels::DUPLICATE_HEADER);
        assert!(!d.body.contains("appeared 2 times"));
    }

    #[test]
    fn a_denial_exposes_the_label_as_a_header_for_upstream_logs() {
        let r = to_check_response(&Decision::Deny(DenyReason::caller(
            labels::NO_CREDENTIAL,
            "x",
        )));
        let d = denied_response(&r);
        assert!(
            d.headers
                .iter()
                .filter_map(|h| h.header.as_ref())
                .any(|h| h.key == HEADER_DENY_LABEL && h.value == labels::NO_CREDENTIAL)
        );
    }
}
