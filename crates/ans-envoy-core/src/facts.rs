//! The proxy-neutral description of one inbound request.
//!
//! Nothing in this module names a proxy, a wire format, or a gRPC type. That is
//! the point: [`RequestFacts`] is the whole contract between a proxy adapter and
//! the verifier, so a second adapter (`ext_proc`, or a different proxy entirely)
//! reuses the ANS-6 §7.4/§7.5 orchestration untouched.

/// How many times a decision-bearing header appeared on the request.
///
/// ANS-6 §4.6 requires rejecting a request in which `DPoP`, `Authorization`,
/// `X-SCITT-Receipt`, or `X-ANS-Status-Token` appears more than once, because
/// "two hops reading different values of the same header reach different
/// conclusions about the same request".
///
/// Counting is the adapter's job and it is not always possible: a proxy that
/// coalesces repeated headers into one comma-joined value destroys the
/// distinction between two headers and one header containing a comma. An
/// adapter that cannot count MUST report [`HeaderCount::Uncountable`] rather
/// than guess — see [`SecurityHeaders::raw_values_available`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderCount {
    /// The header was not present.
    Absent,
    /// The header appeared exactly once, with this value.
    Once(String),
    /// Repeated fields, or an ambiguous comma-coalesced Authorization value.
    /// ANS-6 §4.6 rejects the request before credential parsing.
    Repeated(usize),
    /// The proxy could not supply uncoalesced values, so the count is unknown.
    Uncountable,
}

impl HeaderCount {
    /// The single value, when the header appeared exactly once.
    pub fn single(&self) -> Option<&str> {
        match self {
            Self::Once(v) => Some(v.as_str()),
            _ => None,
        }
    }

    /// True when ANS-6 §4.6 requires rejecting on this header.
    pub fn is_repeated(&self) -> bool {
        matches!(self, Self::Repeated(_))
    }

    /// Build from a list of observed values for one header name.
    pub fn from_values(values: &[String]) -> Self {
        match values {
            [] => Self::Absent,
            [one] => Self::Once(one.clone()),
            many => Self::Repeated(many.len()),
        }
    }
}

/// The four headers whose duplication ANS-6 §4.6 makes a rejection.
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    /// RFC 9449 possession proof.
    pub dpop: HeaderCount,
    /// Access token, when OAuth 2.0 is composed on top (§7.8).
    pub authorization: HeaderCount,
    /// `X-SCITT-Receipt` — standard-base64 `COSE_Sign1` (§4.3).
    pub receipt: HeaderCount,
    /// `X-ANS-Status-Token` — standard-base64 `COSE_Sign1` (§4.4).
    pub status_token: HeaderCount,
    /// Whether the proxy supplied uncoalesced header values at all.
    ///
    /// `false` means the deployment cannot satisfy §4.6, so every request is
    /// denied. Silently skipping the duplicate check would leave a MUST-level
    /// requirement unenforced with no outward sign; a loud, total failure is
    /// the only honest alternative.
    pub raw_values_available: bool,
}

impl SecurityHeaders {
    /// Header names this type tracks, in the order §7.4's preflight lists them.
    pub const NAMES: [&'static str; 4] = [
        "DPoP",
        "Authorization",
        "X-SCITT-Receipt",
        "X-ANS-Status-Token",
    ];

    /// The first header that appeared more than once, if any.
    pub fn first_repeated(&self) -> Option<&'static str> {
        let pairs: [(&'static str, &HeaderCount); 4] = [
            (Self::NAMES[0], &self.dpop),
            (Self::NAMES[1], &self.authorization),
            (Self::NAMES[2], &self.receipt),
            (Self::NAMES[3], &self.status_token),
        ];
        pairs
            .into_iter()
            .find(|(_, count)| count.is_repeated())
            .map(|(name, _)| name)
    }
}

/// Where the authority used for the `htu` comparison came from (ANS-6 §7.7).
///
/// The request's own `Host` / `:authority` is deliberately not representable
/// here. §7.7 calls deriving the comparison URL from it "the vulnerability, not
/// the defense", and the spec's own worked example A.6 is that exact attack: a
/// captured proof replayed against a different origin with a spoofed `Host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthoritySource {
    /// Asserted by the proxy out of band, per route or virtual host.
    ///
    /// For Envoy this is `ExtAuthzPerRoute.check_settings.context_extensions`,
    /// which is xDS-sourced and, per the proto, not forwarded upstream — so a
    /// client cannot reach it.
    ProxyAsserted(String),
    /// The single authority this callee was configured to answer as.
    ///
    /// Only valid for a one-authority deployment. With two configured
    /// authorities and no per-route assertion, a proof minted for A would pass
    /// on a request that actually arrived at B, so configuration validation
    /// rejects that combination.
    SoleConfigured(String),
}

impl AuthoritySource {
    /// The authority value, however it was sourced.
    pub fn authority(&self) -> &str {
        match self {
            Self::ProxyAsserted(a) | Self::SoleConfigured(a) => a.as_str(),
        }
    }

    /// Stable label for logs and metrics.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ProxyAsserted(_) => "proxy_asserted",
            Self::SoleConfigured(_) => "sole_configured",
        }
    }
}

/// One inbound request, reduced to what ANS-6 verification needs.
#[derive(Debug, Clone)]
pub struct RequestFacts {
    /// HTTP method, compared against the proof's `htm` (§7.2).
    pub method: String,
    /// The request target exactly as it arrived, query string included.
    ///
    /// §7.3 wants the path preserved byte-for-byte, so the adapter passes it
    /// through without normalization and the query is stripped downstream when
    /// the `htu` is formed. Keeping the query here rather than pre-stripping it
    /// leaves one normalization implementation in play instead of two.
    pub target: String,
    /// The externally-visible authority, per §7.7. `None` is a denial, not a
    /// fallback to `Host`.
    pub authority: Option<AuthoritySource>,
    /// The four §4.6 headers and whether they could be counted.
    pub headers: SecurityHeaders,
    /// PEM of the validated downstream client certificate, for Method A (§6.1).
    ///
    /// Present only where TLS terminates at this proxy and the chain already
    /// validated against the RA private CA. Absent for Method B, which exists
    /// precisely because an intermediary terminated TLS.
    pub peer_certificate_pem: Option<String>,
    /// The request content, for §7.13 `ans_content_digest` binding.
    pub content: RequestContent,
}

/// What the proxy could tell us about the request body (§7.13).
///
/// Preserve content octets until the SDK has bound the proof to a live ANS
/// identity. Hashing before that boundary violates §7.4 step 12. Empty content
/// is distinct from content the proxy failed to supply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestContent {
    /// No content; verification uses SHA-256 of the empty octet string.
    Absent,
    /// Complete content after transfer decoding, before content decoding.
    Bytes(Vec<u8>),
    /// Content exists, but not in a form that can be honestly hashed.
    Unavailable(ContentUnavailable),
}

/// Why the content could not be hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentUnavailable {
    /// The proxy is not buffering request bodies, so the content never arrived.
    ///
    /// For Envoy: `with_request_body` is unset on the `ext_authz` filter.
    NotBuffered,
    /// The proxy supplied only a prefix.
    ///
    /// For Envoy: `allow_partial_message: true` truncated the body at
    /// `max_request_bytes` and set `x-envoy-auth-partial-body: true`. A prefix
    /// hash never matches a whole-content digest, so it is indistinguishable from
    /// tampering — and §7.13 requires the comparison to complete "before acting on
    /// any of the content", which a prefix cannot support.
    Truncated,
}

impl ContentUnavailable {
    /// Stable label for logs and metrics.
    pub fn label(self) -> &'static str {
        match self {
            Self::NotBuffered => "not_buffered",
            Self::Truncated => "truncated",
        }
    }
}

impl RequestContent {
    /// Why the content is missing, if it is.
    pub fn unavailable(&self) -> Option<ContentUnavailable> {
        match self {
            Self::Unavailable(reason) => Some(*reason),
            Self::Absent | Self::Bytes(_) => None,
        }
    }
}

impl RequestFacts {
    /// Which caller-authentication method this request is asking for.
    ///
    /// A `DPoP` header selects Method B even when a client certificate is also
    /// present: the proof is the stronger, request-bound statement, and letting
    /// certificate presence silently downgrade to Method A would make the
    /// choice an attacker's rather than the deployment's.
    pub fn method_selector(&self) -> MethodSelector {
        if self.headers.dpop.single().is_some() || self.headers.dpop.is_repeated() {
            MethodSelector::MethodB
        } else if self.peer_certificate_pem.is_some() {
            MethodSelector::MethodA
        } else {
            MethodSelector::None
        }
    }
}

/// The caller-authentication method a request selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodSelector {
    /// ANS-6 §7 — application-layer proof of possession (`DPoP`).
    MethodB,
    /// ANS-6 §6 — mTLS, with identity and liveness from SCITT artifacts.
    MethodA,
    /// Neither a proof nor a client certificate: nothing to authenticate.
    None,
}

impl MethodSelector {
    /// Stable label for logs and metrics.
    pub fn label(self) -> &'static str {
        match self {
            Self::MethodB => "method_b",
            Self::MethodA => "method_a",
            Self::None => "none",
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    fn headers(dpop: HeaderCount) -> SecurityHeaders {
        SecurityHeaders {
            dpop,
            authorization: HeaderCount::Absent,
            receipt: HeaderCount::Absent,
            status_token: HeaderCount::Absent,
            raw_values_available: true,
        }
    }

    fn facts(dpop: HeaderCount, cert: Option<&str>) -> RequestFacts {
        RequestFacts {
            method: "POST".to_string(),
            target: "/api/task".to_string(),
            authority: Some(AuthoritySource::ProxyAsserted(
                "api.example.com".to_string(),
            )),
            headers: headers(dpop),
            peer_certificate_pem: cert.map(str::to_string),
            content: RequestContent::Absent,
        }
    }

    // ── HeaderCount ──────────────────────────────────────────────

    #[test]
    fn from_values_distinguishes_absent_single_and_repeated() {
        assert_eq!(HeaderCount::from_values(&[]), HeaderCount::Absent);
        assert_eq!(
            HeaderCount::from_values(&["a".to_string()]),
            HeaderCount::Once("a".to_string())
        );
        assert_eq!(
            HeaderCount::from_values(&["a".to_string(), "b".to_string()]),
            HeaderCount::Repeated(2)
        );
    }

    #[test]
    fn single_is_none_for_anything_but_one_occurrence() {
        assert!(HeaderCount::Absent.single().is_none());
        assert!(HeaderCount::Repeated(2).single().is_none());
        assert!(HeaderCount::Uncountable.single().is_none());
        assert_eq!(HeaderCount::Once("v".to_string()).single(), Some("v"));
    }

    #[test]
    fn uncountable_is_not_reported_as_repeated() {
        // Uncountable must not masquerade as a duplicate: it is a
        // misconfiguration with its own denial label, not a §4.6 violation.
        assert!(!HeaderCount::Uncountable.is_repeated());
    }

    // ── SecurityHeaders ──────────────────────────────────────────

    #[test]
    fn first_repeated_reports_in_preflight_order() {
        let h = SecurityHeaders {
            dpop: HeaderCount::Once("p".to_string()),
            authorization: HeaderCount::Repeated(2),
            receipt: HeaderCount::Repeated(3),
            status_token: HeaderCount::Absent,
            raw_values_available: true,
        };
        assert_eq!(h.first_repeated(), Some("Authorization"));
    }

    #[test]
    fn first_repeated_is_none_when_all_single_or_absent() {
        assert_eq!(
            headers(HeaderCount::Once("p".to_string())).first_repeated(),
            None
        );
    }

    // ── AuthoritySource ──────────────────────────────────────────

    #[test]
    fn authority_reads_through_both_sources() {
        assert_eq!(
            AuthoritySource::ProxyAsserted("a.example".to_string()).authority(),
            "a.example"
        );
        assert_eq!(
            AuthoritySource::SoleConfigured("b.example".to_string()).authority(),
            "b.example"
        );
    }

    // ── method selection ─────────────────────────────────────────

    #[test]
    fn dpop_selects_method_b() {
        let f = facts(HeaderCount::Once("proof".to_string()), None);
        assert_eq!(f.method_selector(), MethodSelector::MethodB);
    }

    #[test]
    fn client_cert_without_dpop_selects_method_a() {
        let f = facts(HeaderCount::Absent, Some("-----BEGIN CERTIFICATE-----"));
        assert_eq!(f.method_selector(), MethodSelector::MethodA);
    }

    #[test]
    fn dpop_wins_over_a_present_client_certificate() {
        // A caller that sent a proof gets Method B even on an mTLS connection.
        // Otherwise certificate presence would silently pick the weaker,
        // connection-scoped check, and which method ran would be the
        // attacker's choice rather than the deployment's.
        let f = facts(HeaderCount::Once("proof".to_string()), Some("cert"));
        assert_eq!(f.method_selector(), MethodSelector::MethodB);
    }

    #[test]
    fn repeated_dpop_still_selects_method_b_so_it_is_rejected_not_ignored() {
        // Duplicate DPoP must reach the §4.6 rejection. If it fell through to
        // MethodSelector::None the request would be denied with the wrong
        // label, and on an mTLS connection it would silently become Method A.
        let f = facts(HeaderCount::Repeated(2), Some("cert"));
        assert_eq!(f.method_selector(), MethodSelector::MethodB);
    }

    #[test]
    fn nothing_presented_selects_none() {
        let f = facts(HeaderCount::Absent, None);
        assert_eq!(f.method_selector(), MethodSelector::None);
    }
}
