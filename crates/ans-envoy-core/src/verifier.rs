//! The ANS-6 callee-side verifier.
//!
//! One entry point, [`Verifier::authenticate`], turning [`RequestFacts`] into a
//! [`Decision`]. It knows nothing about Envoy, gRPC, or HTTP framing.
//!
//! Every path through this function ends in `Allow` or `Deny`. There is
//! deliberately no third outcome: §7.6 makes a replay cache that is "at capacity
//! or erroring" a rejection and §9.6 makes a store timeout "a rejection, never a
//! skip", so ANS-6 leaves no indecision to express. An adapter that cannot
//! represent indecision cannot have it converted into an allow by a proxy's
//! fail-open setting.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ans_verify::{
    PopError, RefreshableKeyStore, ReplayCache, ScittHeaders, VerifiedArtifactCache,
    VerifyCallerOptions, verify_caller_with_content, verify_receipt, verify_status_token_at,
};

use sha2::{Digest, Sha256};

use crate::decision::{AuthenticatedCaller, Decision};
use crate::deny::{DenyReason, labels};
use crate::facts::{
    AuthoritySource, ContentUnavailable, MethodSelector, RequestContent, RequestFacts,
};
use crate::method_a::{bind_client_certificate, parse_peer_certificate};
use crate::policy::Policy;

/// Default status-token clock skew, matching the SDK's own default.
const DEFAULT_STATUS_SKEW: Duration = Duration::from_secs(60);

/// The ANS-6 verifier.
pub struct Verifier {
    keys: Arc<RefreshableKeyStore>,
    replay: Arc<dyn ReplayCache>,
    policy: Policy,
    artifacts: VerifiedArtifactCache,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    /// Build a verifier over a key store, a replay cache, and a policy.
    pub fn new(
        keys: Arc<RefreshableKeyStore>,
        replay: Arc<dyn ReplayCache>,
        policy: Policy,
        artifacts: VerifiedArtifactCache,
    ) -> Self {
        Self {
            keys,
            replay,
            policy,
            artifacts,
        }
    }

    /// The policy this verifier enforces.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Authenticate one request.
    pub async fn authenticate(&self, facts: &RequestFacts) -> Decision {
        // §7.4 request-level preflight, before any cryptography. Both items are
        // cheap and both are about the request as a whole rather than the proof,
        // so doing them first means a malformed request never buys signature
        // verification.
        if let Err(reason) = preflight(facts) {
            return Decision::Deny(reason);
        }

        let Some(authority) = facts.authority.as_ref() else {
            // §7.7 requires failing startup with no authority mechanism wired.
            // A process can do that; a per-route configuration push cannot, so
            // a route that arrives without an asserted authority is refused at
            // request time. Fail-closed here is the available substitute for
            // fail-at-startup.
            return Decision::Deny(DenyReason::deployment(
                labels::AUTHORITY_UNRESOLVED,
                "no trusted authority asserted for this route (ANS-6 §7.7)",
            ));
        };

        let raw_url = match build_comparison_url(authority, &facts.target) {
            Ok(url) => url,
            Err(reason) => return Decision::Deny(reason),
        };

        let selector = facts.method_selector();
        if !self.policy.permits(selector) {
            return match selector {
                MethodSelector::None => Decision::Deny(DenyReason::caller(
                    labels::NO_CREDENTIAL,
                    "request presented neither a DPoP proof nor a client certificate",
                )),
                MethodSelector::MethodA | MethodSelector::MethodB => {
                    Decision::Deny(DenyReason::caller(
                        labels::METHOD_NOT_ENABLED,
                        format!("{} is not enabled on this callee", selector.label()),
                    ))
                }
            };
        }

        match selector {
            MethodSelector::MethodB => self.authenticate_method_b(facts, &raw_url).await,
            MethodSelector::MethodA => self.authenticate_method_a(facts).await,
            // Unreachable: `permits` returns false for `None`, handled above.
            MethodSelector::None => Decision::Deny(DenyReason::caller(
                labels::NO_CREDENTIAL,
                "no credential presented",
            )),
        }
    }

    /// §7 — application-layer proof of possession.
    async fn authenticate_method_b(&self, facts: &RequestFacts, raw_url: &str) -> Decision {
        let Some(proof) = facts.headers.dpop.single() else {
            return Decision::Deny(DenyReason::caller(
                labels::NO_CREDENTIAL,
                "no DPoP proof on request",
            ));
        };

        let scitt = match ScittHeaders::from_base64(
            facts.headers.receipt.single(),
            facts.headers.status_token.single(),
        ) {
            Ok(h) => h,
            Err(e) => {
                return Decision::Deny(DenyReason::caller(
                    "MALFORMED_PROOF",
                    format!("SCITT header decode failed: {e}"),
                ));
            }
        };

        let access_token = facts
            .headers
            .authorization
            .single()
            .and_then(ans_verify::access_token_from_authorization)
            .map(str::to_string);

        let content = match Self::resolve_content(facts) {
            Ok(bytes) => bytes,
            Err(reason) => return Decision::Deny(reason),
        };

        let options = || VerifyCallerOptions {
            require_receipt: self.policy.require_receipt,
            allowed_ans_names: self.policy.allowed_ans_names.clone(),
            content_sha256: None,
            // Belt-and-braces on top of having built `raw_url` from a
            // proxy-asserted authority. The allowlist arm of §7.7 catches a
            // request target that smuggled its own authority past
            // `build_comparison_url`.
            trusted_authorities: vec![
                facts
                    .authority
                    .as_ref()
                    .map_or_else(String::new, |a| a.authority().to_string()),
            ],
            pop_skew: self.policy.pop_skew,
            status_skew: self.policy.status_skew,
            now: None,
            access_token: access_token.clone(),
            artifact_cache: Some(self.artifacts.clone()),
        };

        let keys = self.keys.current_snapshot().await;
        let first = verify_caller_with_content(
            proof,
            &scitt,
            &facts.method,
            raw_url,
            &keys,
            self.replay.as_ref(),
            options(),
            || async { Ok(Sha256::digest(content).into()) },
        )
        .await;

        let err = match first {
            Ok(identity) => {
                return Decision::Allow(Box::new(AuthenticatedCaller::from_method_b(&identity)));
            }
            Err(e) => e,
        };

        // §9.5 — an unrecognised `kid` is not immediately a forgery: the TL may
        // have added a key, and `/root-keys` is append-only. Refresh once,
        // cooldown-gated, and retry.
        //
        // Retrying cannot double-commit a `jti`. §7.6's record-after-trust rule
        // puts the replay commit after the status-token binding, and an unknown
        // `kid` fails during that verification — so the first attempt never
        // reached the cache.
        if !self.refresh_for_unknown_key(&err).await {
            return Decision::Deny(DenyReason::from_pop_error(&err));
        }

        let keys = self.keys.current_snapshot().await;
        match verify_caller_with_content(
            proof,
            &scitt,
            &facts.method,
            raw_url,
            &keys,
            self.replay.as_ref(),
            options(),
            || async { Ok(Sha256::digest(content).into()) },
        )
        .await
        {
            Ok(identity) => {
                Decision::Allow(Box::new(AuthenticatedCaller::from_method_b(&identity)))
            }
            Err(e) => Decision::Deny(DenyReason::from_pop_error(&e)),
        }
    }

    /// §6 — mTLS, bound to SCITT artifacts (§6.3).
    async fn authenticate_method_a(&self, facts: &RequestFacts) -> Decision {
        let Some(pem) = facts.peer_certificate_pem.as_deref() else {
            return Decision::Deny(DenyReason::caller(
                labels::NO_CREDENTIAL,
                "no downstream client certificate",
            ));
        };

        let cert = match parse_peer_certificate(pem) {
            Ok(c) => c,
            Err(reason) => return Decision::Deny(reason),
        };

        // §6.3: "Either header absent → fall back to the badge tier." This
        // deployment ships no badge tier, and §9.7 is explicit that where an
        // intermediary can strip headers, a missing artifact is a rejection
        // rather than a fallback trigger. So absence is refused.
        let Some(token_bytes) = facts.headers.status_token.single() else {
            return Decision::Deny(DenyReason::caller(
                "MISSING_HEADERS",
                "no X-ANS-Status-Token on request and no badge tier is configured",
            ));
        };

        let scitt =
            match ScittHeaders::from_base64(facts.headers.receipt.single(), Some(token_bytes)) {
                Ok(h) => h,
                Err(e) => {
                    return Decision::Deny(DenyReason::caller(
                        "MALFORMED_PROOF",
                        format!("SCITT header decode failed: {e}"),
                    ));
                }
            };

        let mut decision = self.bind_method_a_once(&cert, &scitt).await;

        // §9.5, same reasoning as Method B. There is no replay commit on this
        // path at all, so a retry is unconditionally safe.
        if let Decision::Deny(ref reason) = decision
            && reason.label == "UNKNOWN_KEY_ID"
            && self
                .keys
                .refresh_if_cooldown_elapsed()
                .await
                .unwrap_or(false)
        {
            decision = self.bind_method_a_once(&cert, &scitt).await;
        }

        decision
    }

    /// One pass of Method-A artifact verification plus §6.3 binding.
    async fn bind_method_a_once(
        &self,
        cert: &ans_verify::CertIdentity,
        scitt: &ScittHeaders,
    ) -> Decision {
        let keys = self.keys.current_snapshot().await;
        let now = unix_now();

        let Some(token_bytes) = scitt.status_token.as_deref() else {
            return Decision::Deny(DenyReason::caller(
                "MISSING_HEADERS",
                "no status token to verify",
            ));
        };

        let status = match verify_status_token_at(
            token_bytes,
            &keys,
            self.policy.status_skew.unwrap_or(DEFAULT_STATUS_SKEW),
            now,
        ) {
            Ok(v) => v,
            Err(e) => return Decision::Deny(scitt_denial("STATUS_INVALID", &e)),
        };

        // Method A requires both artifacts; the receipt waiver is Method B only.
        let receipt = if let Some(bytes) = scitt.receipt.as_deref() {
            match verify_receipt(bytes, &keys) {
                Ok(r) => r,
                Err(e) => return Decision::Deny(scitt_denial("RECEIPT_INVALID", &e)),
            }
        } else {
            // §6.3 requires both artifacts. The §7.1 reduced mode is Method B only;
            // this service has no badge tier to authenticate an mTLS fallback.
            return Decision::Deny(DenyReason::caller(
                "MISSING_HEADERS",
                "Method A requires X-SCITT-Receipt; no badge fallback is configured",
            ));
        };

        match bind_client_certificate(cert, &status.payload, &receipt, &self.policy) {
            Ok(caller) => Decision::Allow(Box::new(caller)),
            Err(reason) => Decision::Deny(reason),
        }
    }

    /// Check content availability without hashing unauthenticated input.
    fn resolve_content(facts: &RequestFacts) -> Result<&[u8], DenyReason> {
        match &facts.content {
            RequestContent::Absent => Ok(&[]),
            RequestContent::Bytes(bytes) => Ok(bytes),
            RequestContent::Unavailable(ContentUnavailable::Truncated) => {
                Err(DenyReason::deployment(
                    labels::CONTENT_TRUNCATED,
                    "proxy supplied partial content; set with_request_body.allow_partial_message: false",
                ))
            }
            RequestContent::Unavailable(ContentUnavailable::NotBuffered) => {
                Err(DenyReason::deployment(
                    labels::CONTENT_NOT_BUFFERED,
                    "proxy did not supply raw content; set with_request_body with pack_as_bytes: true",
                ))
            }
        }
    }

    /// Whether an unknown-`kid` failure was answered by a successful refresh.
    async fn refresh_for_unknown_key(&self, err: &PopError) -> bool {
        if !err.is_unknown_key_id() {
            return false;
        }
        match self.keys.refresh_if_cooldown_elapsed().await {
            Ok(refreshed) => refreshed,
            Err(e) => {
                // A failed refresh leaves the cached snapshot in place (§4.5);
                // the original denial stands.
                tracing::warn!(error = %e, "root-key refresh failed after unknown kid");
                false
            }
        }
    }
}

/// Map a SCITT verification failure onto a denial, preserving the unknown-`kid`
/// case so the §9.5 retry can recognise it.
fn scitt_denial(default_label: &'static str, err: &ans_verify::ScittError) -> DenyReason {
    if matches!(err, ans_verify::ScittError::UnknownKeyId(_)) {
        return DenyReason::caller("UNKNOWN_KEY_ID", err.to_string());
    }
    DenyReason::caller(default_label, err.to_string())
}

/// §7.4 preflight: the two request-level checks that precede all cryptography.
fn preflight(facts: &RequestFacts) -> Result<(), DenyReason> {
    // Rule: a proxy that cannot hand over uncoalesced header values makes §4.6
    // unenforceable, and an unenforceable MUST is worse than a visible outage.
    // Denying everything is loud; silently skipping the check is not.
    if !facts.headers.raw_values_available {
        return Err(DenyReason::deployment(
            labels::RAW_HEADERS_UNAVAILABLE,
            "proxy did not supply uncoalesced header values, so ANS-6 §4.6 \
             duplicate detection is impossible (for Envoy: set encode_raw_headers: true)",
        ));
    }

    if let Some(name) = facts.headers.first_repeated() {
        return Err(DenyReason::caller(
            labels::DUPLICATE_HEADER,
            format!("{name} appeared more than once (ANS-6 §4.6)"),
        ));
    }

    Ok(())
}

/// Build the URL the `htu` claim is compared against (§7.7).
///
/// The authority comes from configuration or the proxy; the path comes from this
/// request. Both halves are required: a `Host`-derived authority lets a proof
/// minted for another origin replay here, and a constant URL that ignores the
/// path "collapses `htu` to one value, so a proof minted for any path is
/// accepted on every path".
fn build_comparison_url(authority: &AuthoritySource, target: &str) -> Result<String, DenyReason> {
    // An origin-form target is the only shape that can be safely joined to a
    // configured authority. An absolute-form target (`https://elsewhere/p`,
    // legal in HTTP/1.1 request lines) would otherwise be concatenated into a
    // nonsense URL whose parsed host is neither value.
    if !target.starts_with('/') {
        return Err(DenyReason::caller(
            labels::MALFORMED_TARGET,
            format!("request target is not origin-form: {target:?}"),
        ));
    }
    Ok(format!("https://{}{}", authority.authority(), target))
}

/// Prove at startup that the `htu` reconstruction actually varies with the path.
///
/// §7.7: "Implementations SHOULD verify at wiring time that the configured
/// reconstruction varies with the path, and fail startup when it does not." The
/// failure it guards against is a reconstruction that returns a constant, which
/// "collapses `htu` to one value, so a proof minted for any path is accepted on
/// every path and only `htm` still binds the target".
///
/// Here variance is structural — the path is concatenated — so this cannot fail
/// as written. It is still run at startup rather than trusted, because "it is
/// obvious from the code" stops being true the first time someone edits
/// `build_comparison_url`, and a silent regression there is invisible in
/// behaviour: every request still authenticates, just against the wrong URL.
pub fn selftest_authority_reconstruction() -> Result<(), String> {
    let authority = AuthoritySource::SoleConfigured("selftest.invalid".to_string());

    let first = build_comparison_url(&authority, "/alpha")
        .map_err(|e| format!("reconstruction rejected a valid path: {}", e.detail))?;
    let second = build_comparison_url(&authority, "/beta")
        .map_err(|e| format!("reconstruction rejected a valid path: {}", e.detail))?;

    if first == second {
        return Err(format!(
            "htu reconstruction does not vary with the request path (both /alpha \
             and /beta produced {first}); a proof minted for any path would be \
             accepted on every path (ANS-6 §7.7)"
        ));
    }

    if !first.ends_with("/alpha") || !second.ends_with("/beta") {
        return Err(format!(
            "htu reconstruction did not preserve the request path (got {first} and \
             {second}); §7.3 requires the path byte-for-byte"
        ));
    }

    Ok(())
}

/// Current Unix time in seconds.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{HeaderCount, SecurityHeaders};

    fn headers() -> SecurityHeaders {
        SecurityHeaders {
            dpop: HeaderCount::Once("proof".to_string()),
            authorization: HeaderCount::Absent,
            receipt: HeaderCount::Absent,
            status_token: HeaderCount::Absent,
            raw_values_available: true,
        }
    }

    fn facts_with(headers: SecurityHeaders) -> RequestFacts {
        RequestFacts {
            method: "POST".to_string(),
            target: "/api/task".to_string(),
            authority: Some(AuthoritySource::ProxyAsserted(
                "api.example.com".to_string(),
            )),
            headers,
            peer_certificate_pem: None,
            content: RequestContent::Absent,
        }
    }

    // ── preflight ────────────────────────────────────────────────

    #[test]
    fn preflight_denies_when_raw_headers_are_unavailable() {
        let mut h = headers();
        h.raw_values_available = false;
        let err = preflight(&facts_with(h)).unwrap_err();
        assert_eq!(err.label, labels::RAW_HEADERS_UNAVAILABLE);
        // Deployment fault, so 500 and no misleading challenge to the caller.
        assert_eq!(err.status(), 500);
    }

    #[test]
    fn preflight_denies_a_duplicated_security_header() {
        let mut h = headers();
        h.dpop = HeaderCount::Repeated(2);
        let err = preflight(&facts_with(h)).unwrap_err();
        assert_eq!(err.label, labels::DUPLICATE_HEADER);
        assert_eq!(err.status(), 401);
    }

    #[test]
    fn preflight_checks_availability_before_duplication() {
        // With raw values unavailable, a "duplicate" verdict would be a guess.
        let mut h = headers();
        h.raw_values_available = false;
        h.dpop = HeaderCount::Repeated(2);
        let err = preflight(&facts_with(h)).unwrap_err();
        assert_eq!(err.label, labels::RAW_HEADERS_UNAVAILABLE);
    }

    #[test]
    fn preflight_passes_a_clean_request() {
        assert!(preflight(&facts_with(headers())).is_ok());
    }

    // ── §7.7 comparison URL ──────────────────────────────────────

    #[test]
    fn comparison_url_joins_configured_authority_with_this_requests_path() {
        let a = AuthoritySource::ProxyAsserted("api.example.com".to_string());
        assert_eq!(
            build_comparison_url(&a, "/api/task").unwrap(),
            "https://api.example.com/api/task"
        );
    }

    #[test]
    fn comparison_url_varies_with_the_path() {
        // §7.7 requires the reconstruction to incorporate the request path; a
        // constant URL would accept a proof minted for any path on every path.
        let a = AuthoritySource::SoleConfigured("api.example.com".to_string());
        let one = build_comparison_url(&a, "/a").unwrap();
        let two = build_comparison_url(&a, "/b").unwrap();
        assert_ne!(one, two);
    }

    #[test]
    fn comparison_url_keeps_the_query_string_for_downstream_normalization() {
        // §7.3 strips the query when forming `htu`. Keeping it here leaves one
        // normalization implementation in play rather than two.
        let a = AuthoritySource::ProxyAsserted("api.example.com".to_string());
        assert_eq!(
            build_comparison_url(&a, "/api/task?x=1").unwrap(),
            "https://api.example.com/api/task?x=1"
        );
    }

    #[test]
    fn comparison_url_rejects_an_absolute_form_target() {
        // Otherwise the concatenation yields a URL whose host is neither the
        // configured authority nor the attacker's.
        let a = AuthoritySource::ProxyAsserted("api.example.com".to_string());
        assert!(build_comparison_url(&a, "https://evil.example/p").is_err());
    }

    #[test]
    fn comparison_url_rejects_an_authority_form_target() {
        let a = AuthoritySource::ProxyAsserted("api.example.com".to_string());
        assert!(build_comparison_url(&a, "evil.example:443").is_err());
    }

    #[test]
    fn comparison_url_never_reads_the_request_host() {
        // Structural: build_comparison_url has no access to a Host value at
        // all. This test documents the invariant that example A.6 depends on.
        let a = AuthoritySource::ProxyAsserted("api.other.example".to_string());
        let url = build_comparison_url(&a, "/api/task").unwrap();
        assert!(url.starts_with("https://api.other.example/"));
        assert!(!url.contains("payments.example.com"));
    }

    // ── §7.7 wiring self-test ────────────────────────────────────

    #[test]
    fn the_reconstruction_selftest_passes_for_the_shipped_implementation() {
        assert!(selftest_authority_reconstruction().is_ok());
    }

    // ── clock ────────────────────────────────────────────────────

    #[test]
    fn unix_now_is_plausible() {
        // Sanity: after 2026-01-01 and before 2100.
        let now = unix_now();
        assert!(now > 1_767_225_600, "clock looks wrong: {now}");
        assert!(now < 4_102_444_800, "clock looks wrong: {now}");
    }
}
