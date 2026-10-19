//! `CheckRequest` → [`RequestFacts`].
//!
//! This is the only place in the codebase that reads Envoy's wire types. Keeping
//! it here is what lets the §7.4/§7.5 orchestration be hosted by something other
//! than `ext_authz` later — `ext_proc`, for the §7.13 content binding that
//! `ext_authz` cannot support without a byte cap.

use ans_envoy_core::{ContentUnavailable, RequestContent, RequestFacts};
use envoy_types::pb::envoy::service::auth::v3::CheckRequest;
use envoy_types::pb::envoy::service::auth::v3::attribute_context::HttpRequest;

use crate::authority::AuthorityResolver;
use crate::headers;

/// Why a `CheckRequest` could not be read at all.
#[derive(Debug, thiserror::Error)]
pub enum AdaptError {
    /// Envoy sent no attribute context.
    #[error("CheckRequest carried no attributes")]
    NoAttributes,
    /// Envoy sent no HTTP request attributes.
    #[error("CheckRequest carried no request.http attributes")]
    NoHttpRequest,
}

/// Reduce a `CheckRequest` to the facts ANS-6 verification needs.
///
/// A malformed `CheckRequest` is an error rather than a denial: it means the
/// proxy and this service disagree about the protocol, which is a wiring problem
/// and not something a caller did. The caller still gets refused — see
/// [`crate::response`] — but the distinction is worth keeping in the logs.
pub fn adapt(
    request: &CheckRequest,
    resolver: &AuthorityResolver,
) -> Result<RequestFacts, AdaptError> {
    let attributes = request
        .attributes
        .as_ref()
        .ok_or(AdaptError::NoAttributes)?;
    let http = attributes
        .request
        .as_ref()
        .and_then(|r| r.http.as_ref())
        .ok_or(AdaptError::NoHttpRequest)?;

    Ok(RequestFacts {
        method: http.method.clone(),
        // `path` is documented as "the request target, as it appears in the first
        // line of the HTTP request… No decoding is performed" — which is exactly
        // what §7.3 wants. It is passed through untouched; any normalization
        // Envoy already applied is invisible here, which is why the shipped
        // listener config pins `normalize_path`, `merge_slashes`, and
        // `path_with_escaped_slashes_action` off.
        target: http.path.clone(),
        authority: resolver.resolve(attributes),
        headers: headers::extract(http),
        peer_certificate_pem: peer_certificate(request),
        content: request_content(http),
    })
}

/// Envoy sets this to `true` when it truncated the body at `max_request_bytes`.
const PARTIAL_BODY_HEADER: &str = "x-envoy-auth-partial-body";

/// What the proxy could tell us about the request body (§7.13).
///
/// Keep bytes intact; the core hashes them only after identity verification.
/// The shipped Envoy configuration bounds buffering and requires raw bytes.
fn request_content(http: &HttpRequest) -> RequestContent {
    // Truncation first: a prefix is worse than nothing, because hashing it
    // produces a mismatch indistinguishable from tampering.
    if headers::first(http, PARTIAL_BODY_HEADER).as_deref() == Some("true") {
        return RequestContent::Unavailable(ContentUnavailable::Truncated);
    }

    if !http.raw_body.is_empty() {
        return RequestContent::Bytes(http.raw_body.clone());
    }
    // Envoy's string body may replace non-UTF-8 octets. It is never a safe
    // fallback for the raw content required by §7.13.
    if !http.body.is_empty() {
        return RequestContent::Unavailable(ContentUnavailable::NotBuffered);
    }

    // No bytes. Either there is genuinely no body, or the proxy is not buffering.
    if declares_content(http) {
        RequestContent::Unavailable(ContentUnavailable::NotBuffered)
    } else {
        RequestContent::Absent
    }
}

/// Whether the request claims to carry a body.
///
/// Best-effort, and the imprecision is bounded in the safe direction. On HTTP/2 a
/// streamed body may arrive with no `content-length`, in which case this reports
/// `false` and the content is treated as absent — a caller that bound its content
/// is then refused. That is fail-closed and visible, not a silent accept.
fn declares_content(http: &HttpRequest) -> bool {
    if let Some(len) = headers::first(http, "content-length")
        && let Ok(n) = len.trim().parse::<u64>()
        && n > 0
    {
        return true;
    }
    // HTTP/1.1 chunked has no content-length.
    headers::first(http, "transfer-encoding")
        .is_some_and(|te| te.to_ascii_lowercase().contains("chunked"))
}

/// The downstream client certificate, for Method A (§6.1).
///
/// Envoy populates `source.certificate` only when `include_peer_certificate: true`
/// is set on the filter, and the value is a URL-encoded PEM. `source.principal` is
/// deliberately not used: it holds only the first URI SAN, so it cannot supply the
/// DNS SAN or the fingerprint §6.3 compares, and trusting a pre-extracted identity
/// where the certificate itself is available adds a second parser for no gain.
fn peer_certificate(request: &CheckRequest) -> Option<String> {
    let raw = request
        .attributes
        .as_ref()?
        .source
        .as_ref()
        .map(|s| s.certificate.as_str())
        .filter(|c| !c.is_empty())?;

    match percent_encoding::percent_decode_str(raw).decode_utf8() {
        Ok(pem) => Some(pem.into_owned()),
        Err(e) => {
            // Do not fall back to the raw value: a certificate we cannot decode
            // must not become a certificate we half-parse.
            tracing::warn!(error = %e, "peer certificate is not percent-decodable UTF-8");
            None
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use ans_envoy_config::{AuthorityConfig, AuthorityMode};
    use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue};
    use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
    use envoy_types::pb::envoy::service::auth::v3::attribute_context::{
        HttpRequest, Peer, Request,
    };
    use std::collections::HashMap;

    fn resolver() -> AuthorityResolver {
        AuthorityResolver::from_config(&AuthorityConfig {
            mode: AuthorityMode::ContextExtension,
            context_extension_key: "ans_trusted_authority".to_string(),
            authorities: Vec::new(),
        })
    }

    fn check_request(certificate: &str) -> CheckRequest {
        CheckRequest {
            attributes: Some(AttributeContext {
                source: Some(Peer {
                    certificate: certificate.to_string(),
                    ..Default::default()
                }),
                context_extensions: [(
                    "ans_trusted_authority".to_string(),
                    "api.example.com".to_string(),
                )]
                .into_iter()
                .collect::<HashMap<_, _>>(),
                request: Some(Request {
                    http: Some(HttpRequest {
                        method: "POST".to_string(),
                        path: "/api/task?x=1".to_string(),
                        host: "spoofed.example".to_string(),
                        header_map: Some(HeaderMap {
                            headers: vec![HeaderValue {
                                key: "DPoP".to_string(),
                                value: String::new(),
                                raw_value: b"proof".to_vec(),
                            }],
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn adapts_method_target_authority_and_headers() {
        let facts = adapt(&check_request(""), &resolver()).unwrap();
        assert_eq!(facts.method, "POST");
        assert_eq!(facts.target, "/api/task?x=1");
        assert_eq!(
            facts.authority.as_ref().map(|a| a.authority().to_string()),
            Some("api.example.com".to_string())
        );
        assert_eq!(facts.headers.dpop.single(), Some("proof"));
    }

    #[test]
    fn the_target_keeps_its_query_string_untouched() {
        // §7.3: the path is preserved byte-for-byte; the query is dropped later,
        // by the one normalizer that also produced the signer's `htu`.
        let facts = adapt(&check_request(""), &resolver()).unwrap();
        assert!(facts.target.contains('?'));
    }

    #[test]
    fn the_spoofed_host_never_becomes_the_authority() {
        let facts = adapt(&check_request(""), &resolver()).unwrap();
        assert_eq!(
            facts.authority.map(|a| a.authority().to_string()),
            Some("api.example.com".to_string())
        );
    }

    #[test]
    fn an_absent_certificate_is_none_not_empty_string() {
        let facts = adapt(&check_request(""), &resolver()).unwrap();
        assert!(facts.peer_certificate_pem.is_none());
    }

    #[test]
    fn a_percent_encoded_certificate_is_decoded() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let encoded = "-----BEGIN%20CERTIFICATE-----%0AAAAA%0A-----END%20CERTIFICATE-----%0A";
        let facts = adapt(&check_request(encoded), &resolver()).unwrap();
        assert_eq!(facts.peer_certificate_pem.as_deref(), Some(pem));
    }

    #[test]
    fn missing_attributes_is_an_adapt_error() {
        let err = adapt(&CheckRequest { attributes: None }, &resolver()).unwrap_err();
        assert!(matches!(err, AdaptError::NoAttributes));
    }

    #[test]
    fn missing_http_attributes_is_an_adapt_error() {
        let req = CheckRequest {
            attributes: Some(AttributeContext::default()),
        };
        let err = adapt(&req, &resolver()).unwrap_err();
        assert!(matches!(err, AdaptError::NoHttpRequest));
    }

    #[test]
    fn a_request_without_a_header_map_reports_headers_as_uncountable() {
        // Which the verifier turns into a deny-everything MISCONFIGURED outcome,
        // rather than silently skipping §4.6.
        let mut req = check_request("");
        if let Some(attrs) = req.attributes.as_mut()
            && let Some(request) = attrs.request.as_mut()
            && let Some(http) = request.http.as_mut()
        {
            http.header_map = None;
        }
        let facts = adapt(&req, &resolver()).unwrap();
        assert!(!facts.headers.raw_values_available);
    }
    #[test]
    fn binary_body_is_preserved_without_hashing_or_decoding() {
        let http = HttpRequest {
            raw_body: vec![0xff, 0x00, 0x80],
            ..Default::default()
        };
        assert_eq!(
            request_content(&http),
            RequestContent::Bytes(vec![0xff, 0x00, 0x80])
        );
    }

    #[test]
    fn a_string_body_is_not_a_safe_substitute_for_raw_octets() {
        let http = HttpRequest {
            body: "lossy body".into(),
            ..Default::default()
        };
        assert_eq!(
            request_content(&http),
            RequestContent::Unavailable(ContentUnavailable::NotBuffered)
        );
    }
}
