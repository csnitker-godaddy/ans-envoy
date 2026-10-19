//! Why a request was refused, and what the caller is told.
//!
//! Every ANS-6 refusal is a refusal. There is no "could not decide" outcome on
//! the Method-B path: §7.6 says a replay cache "at capacity or erroring rejects
//! the request", and §9.6 says "a timeout is a rejection, never a skip". That
//! matters concretely at the Envoy boundary, where a response signalling
//! indecision is subject to the operator's `failure_mode_allow` and can be
//! turned into an *allow*. Producing only denials removes that lever.

use ans_verify::{PopError, PopErrorKind};

/// Denial labels this crate originates, for causes the SDK never sees.
///
/// The SDK's own labels come from [`PopErrorKind::as_str`] and are deliberately
/// reused verbatim: they are documented as matching the Go `pop` package's
/// categories, so an operator comparing a Rust callee to a Go one sees the same
/// vocabulary. These additions cover deployment faults that are invisible to a
/// library called with already-extracted values.
pub mod labels {
    /// The proxy could not supply uncoalesced header values, so ANS-6 §4.6
    /// duplicate detection is impossible.
    pub const RAW_HEADERS_UNAVAILABLE: &str = "RAW_HEADERS_UNAVAILABLE";
    /// A decision-bearing header appeared more than once (§4.6).
    pub const DUPLICATE_HEADER: &str = "DUPLICATE_HEADER";
    /// No trusted authority was asserted for this route (§7.7).
    pub const AUTHORITY_UNRESOLVED: &str = "AUTHORITY_UNRESOLVED";
    /// The request target was not origin-form, so it cannot be safely joined to
    /// a configured authority to form the `htu` comparison URL (§7.7).
    pub const MALFORMED_TARGET: &str = "MALFORMED_TARGET";
    /// Neither a `DPoP` proof nor a client certificate was presented.
    pub const NO_CREDENTIAL: &str = "NO_CREDENTIAL";
    /// The request selected a method this deployment does not implement.
    pub const METHOD_NOT_ENABLED: &str = "METHOD_NOT_ENABLED";
    /// The downstream client certificate could not be decoded.
    pub const PEER_CERT_INVALID: &str = "PEER_CERT_INVALID";
    /// The proxy supplied only a prefix of the request content (§7.13).
    pub const CONTENT_TRUNCATED: &str = "CONTENT_TRUNCATED";
    /// Content binding is required, but the proxy is not supplying bodies (§7.13).
    pub const CONTENT_NOT_BUFFERED: &str = "CONTENT_NOT_BUFFERED";
}

/// Where the fault lies, which decides the status code the caller sees.
///
/// Operators debug from status codes, so a deployment fault must not present as
/// a client error. A `401` on a misconfigured callee sends whoever is on call
/// to inspect the caller's proof, which is the wrong half of the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The request or its credentials were bad. RFC 9449 §7.1 shape.
    Caller,
    /// The caller proved who it is, but is not an accepted peer (§7.5.4).
    Peer,
    /// This deployment is wired wrong. Not the caller's fault, and not
    /// something a caller can fix by retrying.
    Deployment,
}

impl Fault {
    /// HTTP status for this fault class.
    pub fn status(self) -> u16 {
        match self {
            Self::Caller => 401,
            Self::Peer => 403,
            Self::Deployment => 500,
        }
    }

    /// Stable label for metrics.
    pub fn label(self) -> &'static str {
        match self {
            Self::Caller => "caller",
            Self::Peer => "peer",
            Self::Deployment => "deployment",
        }
    }
}

/// A refusal, with everything needed to answer and to alert.
#[derive(Debug, Clone)]
pub struct DenyReason {
    /// Stable `SCREAMING_SNAKE` label. Safe to expose and to build alerts on.
    pub label: &'static str,
    /// Who needs to fix this.
    pub fault: Fault,
    /// Human-readable detail for logs.
    ///
    /// Not returned to the caller. Denial detail is a side channel: it narrates
    /// which check failed, which is exactly the feedback an attacker probing a
    /// proof wants. The label goes on the wire; this goes to the operator.
    pub detail: String,
}

impl DenyReason {
    /// A refusal caused by the caller's request or credentials.
    pub fn caller(label: &'static str, detail: impl Into<String>) -> Self {
        Self {
            label,
            fault: Fault::Caller,
            detail: detail.into(),
        }
    }

    /// A refusal caused by this deployment's configuration.
    pub fn deployment(label: &'static str, detail: impl Into<String>) -> Self {
        Self {
            label,
            fault: Fault::Deployment,
            detail: detail.into(),
        }
    }

    /// A proven caller that is not in the accepted-peer set (§7.5.4).
    pub fn peer(label: &'static str, detail: impl Into<String>) -> Self {
        Self {
            label,
            fault: Fault::Peer,
            detail: detail.into(),
        }
    }

    /// Translate an SDK verification failure.
    ///
    /// The label is the SDK's own so the vocabulary stays shared. Only the fault
    /// class is decided here, because the SDK cannot know whether a given
    /// failure was a bad caller or a bad deployment.
    pub fn from_pop_error(err: &PopError) -> Self {
        let fault = match err.kind {
            // A missing dependency is a programmer or wiring error, and
            // §7.7's authority requirement is something the deployment
            // supplies, not something the caller can present.
            PopErrorKind::Misconfigured
            | PopErrorKind::ReplayCacheFull
            | PopErrorKind::ReplayCacheUnavailable => Fault::Deployment,
            PopErrorKind::ExpectedPeerMismatch => Fault::Peer,
            _ => Fault::Caller,
        };
        Self {
            label: err.kind.as_str(),
            fault,
            detail: err.to_string(),
        }
    }

    /// The `WWW-Authenticate` value, where RFC 9449 §7.1 calls for one.
    ///
    /// Only caller-fault denials get it: the header invites the caller to retry
    /// with a better proof, which is misleading advice when the callee is the
    /// thing that is broken.
    pub fn www_authenticate(&self) -> Option<&'static str> {
        match self.fault {
            Fault::Caller => Some(r#"DPoP error="invalid_dpop_proof""#),
            Fault::Peer | Fault::Deployment => None,
        }
    }

    /// HTTP status to return.
    pub fn status(&self) -> u16 {
        self.fault.status()
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_faults_are_401_with_rfc9449_challenge() {
        let d = DenyReason::caller(labels::DUPLICATE_HEADER, "two DPoP headers");
        assert_eq!(d.status(), 401);
        assert_eq!(
            d.www_authenticate(),
            Some(r#"DPoP error="invalid_dpop_proof""#)
        );
    }

    #[test]
    fn deployment_faults_are_500_and_carry_no_challenge() {
        // A misconfigured callee must not tell the caller to try a better
        // proof — no proof would have worked.
        let d = DenyReason::deployment(labels::RAW_HEADERS_UNAVAILABLE, "encode_raw_headers off");
        assert_eq!(d.status(), 500);
        assert!(d.www_authenticate().is_none());
    }

    #[test]
    fn peer_rejection_is_403_not_401() {
        // The caller authenticated fine; retrying with a new proof changes
        // nothing, so a 401 challenge would be a lie.
        let d = DenyReason::peer("EXPECTED_PEER_MISMATCH", "not an accepted peer");
        assert_eq!(d.status(), 403);
        assert!(d.www_authenticate().is_none());
    }

    #[test]
    fn fault_labels_are_stable() {
        assert_eq!(Fault::Caller.label(), "caller");
        assert_eq!(Fault::Peer.label(), "peer");
        assert_eq!(Fault::Deployment.label(), "deployment");
    }

    #[test]
    fn our_labels_do_not_collide_with_the_sdk_vocabulary() {
        // Reusing an SDK label for a different cause would make alerts built on
        // the label ambiguous across the two implementations.
        let sdk = [
            PopErrorKind::MalformedProof,
            PopErrorKind::UnsupportedAlg,
            PopErrorKind::HttpBindingMismatch,
            PopErrorKind::ProofStale,
            PopErrorKind::Replay,
            PopErrorKind::ReplayCacheFull,
            PopErrorKind::SignatureInvalid,
            PopErrorKind::CertInvalid,
            PopErrorKind::KeyMismatch,
            PopErrorKind::TokenBindingMismatch,
            PopErrorKind::BindingFailed,
            PopErrorKind::StatusInvalid,
            PopErrorKind::ReceiptInvalid,
            PopErrorKind::MissingHeaders,
            PopErrorKind::Misconfigured,
            PopErrorKind::ExpectedPeerMismatch,
            PopErrorKind::UntrustedAuthority,
        ]
        .map(PopErrorKind::as_str);

        let ours = [
            labels::RAW_HEADERS_UNAVAILABLE,
            labels::DUPLICATE_HEADER,
            labels::AUTHORITY_UNRESOLVED,
            labels::MALFORMED_TARGET,
            labels::NO_CREDENTIAL,
            labels::METHOD_NOT_ENABLED,
            labels::PEER_CERT_INVALID,
            labels::CONTENT_TRUNCATED,
            labels::CONTENT_NOT_BUFFERED,
        ];

        for label in ours {
            assert!(
                !sdk.contains(&label),
                "label {label} collides with an SDK PopErrorKind label"
            );
        }
    }
}
