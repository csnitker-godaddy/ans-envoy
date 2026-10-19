//! The verifier's output: an authenticated caller, or a refusal.

use ans_verify::CallerIdentity;

use crate::deny::DenyReason;
use crate::facts::MethodSelector;

/// A caller whose identity, liveness, and possession of its key are all proven.
///
/// This is **authentication only**. ANS-6 is explicit and repeats it in §1, §3.1,
/// §6.5 and §7.5: every procedure establishes *who* is calling, never *what*
/// they may do. The upstream service still has to authorize.
#[derive(Debug, Clone)]
pub struct AuthenticatedCaller {
    /// The caller's full `ans://` name, version segment included, taken from the
    /// verified status token.
    pub ans_name: String,
    /// The caller's agent id from the verified status token.
    pub agent_id: String,
    /// `SHA256:<hex>` of the identity certificate that proved possession.
    pub fingerprint: String,
    /// RFC 7638 thumbprint of the key that signed the proof.
    ///
    /// `None` under Method A: an mTLS handshake proves possession without any
    /// proof key, so there is no thumbprint to publish. Method B always has one,
    /// and it is the value §7.8 requires the *token validator* to compare
    /// against a DPoP-bound access token's `cnf.jkt`. Emitting it is how this
    /// service discharges its half of that split responsibility — the token is
    /// opaque here, so the comparison cannot happen here.
    pub jkt: Option<String>,
    /// Which method authenticated this caller.
    pub method: MethodSelector,
}

impl AuthenticatedCaller {
    /// Build from a Method-B (`DPoP`) verification result.
    pub fn from_method_b(identity: &CallerIdentity) -> Self {
        Self {
            ans_name: identity.ans_name.to_string(),
            agent_id: identity.agent_id.to_string(),
            fingerprint: identity.fingerprint.to_string(),
            jkt: Some(identity.jkt.clone()),
            method: MethodSelector::MethodB,
        }
    }
}

/// The outcome of authenticating one request.
#[derive(Debug, Clone)]
pub enum Decision {
    /// Authenticated. The caller still has to be authorized upstream.
    Allow(Box<AuthenticatedCaller>),
    /// Refused, with a stable label and a fault class.
    Deny(DenyReason),
}

impl Decision {
    /// Convenience for building a refusal.
    pub fn deny(reason: DenyReason) -> Self {
        Self::Deny(reason)
    }

    /// True when the request is authenticated.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow(_))
    }

    /// The stable label for metrics: `ALLOW`, or the denial label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow(_) => "ALLOW",
            Self::Deny(r) => r.label,
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::deny::labels;

    #[test]
    fn allow_reports_itself_as_allow() {
        let caller = AuthenticatedCaller {
            ans_name: "ans://v1.0.0.caller.example.com".to_string(),
            agent_id: "7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07".to_string(),
            fingerprint: "SHA256:aa".to_string(),
            jkt: Some("thumb".to_string()),
            method: MethodSelector::MethodB,
        };
        let d = Decision::Allow(Box::new(caller));
        assert!(d.is_allow());
        assert_eq!(d.label(), "ALLOW");
    }

    #[test]
    fn deny_surfaces_the_underlying_label() {
        let d = Decision::deny(DenyReason::caller(labels::NO_CREDENTIAL, "nothing sent"));
        assert!(!d.is_allow());
        assert_eq!(d.label(), labels::NO_CREDENTIAL);
    }
}
