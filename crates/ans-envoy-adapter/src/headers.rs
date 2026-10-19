//! Extracting the four §4.6 decision headers from a `CheckRequest`.
//!
//! ANS-6 §4.6 requires rejecting a request in which `DPoP`, `Authorization`,
//! `X-SCITT-Receipt`, or `X-ANS-Status-Token` appears more than once, because
//! "two hops reading different values of the same header reach different
//! conclusions about the same request".
//!
//! Envoy can only satisfy that with `encode_raw_headers: true`. With it unset,
//! `attributes.request.http.headers` is a map whose duplicate keys have been
//! comma-joined, so two `DPoP` headers are indistinguishable from one containing
//! a comma — the check becomes unenforceable at this hop. With it set, Envoy
//! populates `header_map`, whose docs say plainly: "headers with the same key are
//! not combined into a single comma separated header."
//!
//! Envoy's inline `Authorization` header is an exception: HTTP decoding can
//! combine occurrences before `ext_authz` builds the raw map. A comma-bearing
//! Authorization value is therefore ambiguous and must fail closed. OAuth `DPoP`
//! and Bearer token credentials do not permit commas; parameter-list schemes
//! such as Digest are outside this adapter's Authorization contract.
//!
//! So the absence of `header_map` is itself a finding, and it is reported as
//! [`SecurityHeaders::raw_values_available`] `== false` rather than papered over.

use ans_envoy_core::{HeaderCount, SecurityHeaders};
use envoy_types::pb::envoy::service::auth::v3::attribute_context::HttpRequest;

/// Canonical lowercase names of the headers §4.6 governs.
const DPOP: &str = "dpop";
const AUTHORIZATION: &str = "authorization";
const RECEIPT: &str = "x-scitt-receipt";
const STATUS_TOKEN: &str = "x-ans-status-token";

/// Read the four decision headers, counting occurrences.
pub fn extract(http: &HttpRequest) -> SecurityHeaders {
    let Some(map) = http.header_map.as_ref() else {
        // `encode_raw_headers` is off. Every count is unknowable, and the
        // verifier denies the request rather than guessing.
        return SecurityHeaders {
            dpop: HeaderCount::Uncountable,
            authorization: HeaderCount::Uncountable,
            receipt: HeaderCount::Uncountable,
            status_token: HeaderCount::Uncountable,
            raw_values_available: false,
        };
    };

    let mut dpop = Vec::new();
    let mut authorization = Vec::new();
    let mut receipt = Vec::new();
    let mut status_token = Vec::new();

    for header in &map.headers {
        let key = header.key.to_ascii_lowercase();
        let target = match key.as_str() {
            DPOP => &mut dpop,
            AUTHORIZATION => &mut authorization,
            RECEIPT => &mut receipt,
            STATUS_TOKEN => &mut status_token,
            _ => continue,
        };
        if let Some(value) = header_value(header) {
            target.push(value);
        } else {
            // A value that is not UTF-8 cannot be a compact JWS or standard
            // base64, so it is not usable — but it *is* an occurrence, and
            // dropping it would turn a duplicate into a single. Record a
            // placeholder so the count stays honest.
            target.push(String::new());
        }
    }

    SecurityHeaders {
        dpop: HeaderCount::from_values(&dpop),
        authorization: authorization_count(&authorization),
        receipt: HeaderCount::from_values(&receipt),
        status_token: HeaderCount::from_values(&status_token),
        raw_values_available: true,
    }
}

/// Preserve fail-closed duplicate detection across Envoy's inline-header merge.
/// A single comma-bearing field cannot be distinguished from combined fields.
fn authorization_count(values: &[String]) -> HeaderCount {
    if let [value] = values
        && value.contains(',')
    {
        return HeaderCount::Repeated(value.bytes().filter(|b| *b == b',').count() + 1);
    }
    HeaderCount::from_values(values)
}

/// The first value of an arbitrary header, matched case-insensitively.
///
/// For headers outside the four §4.6 governs, where duplication is not a
/// rejection and the first value is the operative one. Reads `header_map` when
/// available and falls back to the coalesced `headers` map, so it still works on
/// a deployment without `encode_raw_headers` — such a deployment is denied for
/// other reasons, but this must not be the thing that panics or misreports.
pub fn first(http: &HttpRequest, name: &str) -> Option<String> {
    let wanted = name.to_ascii_lowercase();

    if let Some(map) = http.header_map.as_ref() {
        for header in &map.headers {
            if header.key.to_ascii_lowercase() == wanted {
                return header_value(header);
            }
        }
        return None;
    }

    http.headers
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase() == wanted)
        .map(|(_, v)| v.clone())
}

/// The header's value as text.
///
/// Under `encode_raw_headers` Envoy populates `raw_value` rather than `value`, so
/// `raw_value` is preferred and `value` is the fallback for a config that does
/// not set the flag but somehow still produced a `header_map`.
fn header_value(header: &envoy_types::pb::envoy::config::core::v3::HeaderValue) -> Option<String> {
    if !header.raw_value.is_empty() {
        return String::from_utf8(header.raw_value.clone()).ok();
    }
    if header.value.is_empty() {
        // An empty header is present but carries nothing. Treat it as an
        // occurrence with an empty value; the verifier will reject it on
        // content, not on count.
        return Some(String::new());
    }
    Some(header.value.clone())
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue};

    fn raw(pairs: &[(&str, &str)]) -> HttpRequest {
        HttpRequest {
            header_map: Some(HeaderMap {
                headers: pairs
                    .iter()
                    .map(|(k, v)| HeaderValue {
                        key: (*k).to_string(),
                        value: String::new(),
                        raw_value: (*v).as_bytes().to_vec(),
                    })
                    .collect(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn without_a_header_map_nothing_is_countable() {
        let h = extract(&HttpRequest::default());
        assert!(!h.raw_values_available);
        assert_eq!(h.dpop, HeaderCount::Uncountable);
        assert_eq!(h.authorization, HeaderCount::Uncountable);
        assert_eq!(h.receipt, HeaderCount::Uncountable);
        assert_eq!(h.status_token, HeaderCount::Uncountable);
    }

    #[test]
    fn a_single_occurrence_of_each_is_read() {
        let h = extract(&raw(&[
            ("DPoP", "proof"),
            ("Authorization", "DPoP tok"),
            ("X-SCITT-Receipt", "rcpt"),
            ("X-ANS-Status-Token", "tok"),
        ]));
        assert!(h.raw_values_available);
        assert_eq!(h.dpop.single(), Some("proof"));
        assert_eq!(h.authorization.single(), Some("DPoP tok"));
        assert_eq!(h.receipt.single(), Some("rcpt"));
        assert_eq!(h.status_token.single(), Some("tok"));
        assert_eq!(h.first_repeated(), None);
    }

    #[test]
    fn header_names_are_matched_case_insensitively() {
        // HTTP header names are case-insensitive, and Envoy lowercases in HTTP/2
        // but not necessarily elsewhere.
        let h = extract(&raw(&[("dpop", "p"), ("X-Ans-Status-Token", "t")]));
        assert_eq!(h.dpop.single(), Some("p"));
        assert_eq!(h.status_token.single(), Some("t"));
    }

    #[test]
    fn a_duplicated_dpop_is_counted_as_repeated() {
        // The §4.6 case that only works because of encode_raw_headers.
        let h = extract(&raw(&[("DPoP", "one"), ("DPoP", "two")]));
        assert_eq!(h.dpop, HeaderCount::Repeated(2));
        assert_eq!(h.first_repeated(), Some("DPoP"));
    }

    #[test]
    fn a_comma_in_one_value_is_not_mistaken_for_a_duplicate() {
        // The whole point of reading the raw map: a single value containing a
        // comma must stay a single value.
        let h = extract(&raw(&[("DPoP", "one,two")]));
        assert_eq!(h.dpop, HeaderCount::Once("one,two".to_string()));
        assert_eq!(h.first_repeated(), None);
    }

    #[test]
    fn each_governed_header_is_counted_independently() {
        let h = extract(&raw(&[
            ("X-SCITT-Receipt", "a"),
            ("X-SCITT-Receipt", "b"),
            ("DPoP", "p"),
        ]));
        assert_eq!(h.receipt, HeaderCount::Repeated(2));
        assert_eq!(h.dpop.single(), Some("p"));
    }

    #[test]
    fn unrelated_headers_are_ignored() {
        let h = extract(&raw(&[("User-Agent", "curl"), ("DPoP", "p")]));
        assert_eq!(h.dpop.single(), Some("p"));
        assert_eq!(h.authorization, HeaderCount::Absent);
    }

    #[test]
    fn a_non_utf8_value_still_counts_as_an_occurrence() {
        // Otherwise two headers, one of them binary, would be reported as one —
        // turning a §4.6 rejection into an accepted request.
        let http = HttpRequest {
            header_map: Some(HeaderMap {
                headers: vec![
                    HeaderValue {
                        key: "DPoP".to_string(),
                        value: String::new(),
                        raw_value: vec![0xff, 0xfe],
                    },
                    HeaderValue {
                        key: "DPoP".to_string(),
                        value: String::new(),
                        raw_value: b"proof".to_vec(),
                    },
                ],
            }),
            ..Default::default()
        };
        assert_eq!(extract(&http).dpop, HeaderCount::Repeated(2));
    }

    #[test]
    fn the_value_field_is_used_when_raw_value_is_absent() {
        let http = HttpRequest {
            header_map: Some(HeaderMap {
                headers: vec![HeaderValue {
                    key: "DPoP".to_string(),
                    value: "from-value".to_string(),
                    raw_value: Vec::new(),
                }],
            }),
            ..Default::default()
        };
        assert_eq!(extract(&http).dpop.single(), Some("from-value"));
    }

    #[test]
    fn an_empty_header_map_means_nothing_present_but_countable() {
        let h = extract(&raw(&[]));
        assert!(h.raw_values_available);
        assert_eq!(h.dpop, HeaderCount::Absent);
    }
    #[test]
    fn envoy_coalesced_authorization_is_rejected_before_token_binding() {
        for value in [
            "DPoP token,DPoP token",
            "Bearer one,Bearer two",
            "DPoP token, DPoP other",
        ] {
            let h = extract(&raw(&[("Authorization", value)]));
            assert_eq!(h.authorization, HeaderCount::Repeated(2));
            assert_eq!(h.first_repeated(), Some("Authorization"));
        }
    }

    #[test]
    fn a_single_token_credential_remains_usable() {
        for value in ["DPoP abc.def-_~+/=", "Bearer abc.def-_~+/="] {
            let h = extract(&raw(&[("Authorization", value)]));
            assert_eq!(h.authorization.single(), Some(value));
            assert_eq!(h.first_repeated(), None);
        }
    }
}
