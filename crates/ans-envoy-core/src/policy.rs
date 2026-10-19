//! Verification policy — the deployment's ANS-6 choices, resolved once at start.
//!
//! ANS-6 §9 requires a deployment to *choose* its failure behaviour and §11.1
//! requires it to document the values it runs. Both are served by making every
//! policy field explicit here and having configuration refuse to default the
//! security-relevant ones.

use std::time::Duration;

/// Which caller-authentication methods this callee accepts.
///
/// §10.1: "Implements at least one caller-authentication method (§6 or §7) and
/// documents which". Enabling neither is a configuration error, not a runtime
/// state, so it cannot be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnabledMethods {
    /// Method B only — the topology Method B exists for.
    MethodBOnly,
    /// Method A only — mTLS terminates here and no proofs are accepted.
    MethodAOnly,
    /// Both. A request selects by what it presents (`DPoP` wins, see
    /// [`crate::facts::RequestFacts::method_selector`]).
    Both,
}

impl EnabledMethods {
    /// Whether Method B (`DPoP`) proofs are accepted.
    pub fn method_b(self) -> bool {
        matches!(self, Self::MethodBOnly | Self::Both)
    }

    /// Whether Method A (mTLS) client certificates are accepted.
    pub fn method_a(self) -> bool {
        matches!(self, Self::MethodAOnly | Self::Both)
    }
}

/// Resolved verification policy.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Accepted caller-authentication methods (§10.1).
    pub methods: EnabledMethods,
    /// Require a SCITT receipt for Method B. Method A always requires one.
    ///
    /// §7.1 permits a "reduced mode" that accepts status token + proof alone,
    /// trading away the request-time inclusion proof, and requires the
    /// deployment to document the choice. Default is `true`; configuration
    /// demands a written justification to set it `false`.
    pub require_receipt: bool,
    /// Accepted-peer set as `ans://` names, compared by FQDN host (§7.5.4).
    /// Empty means any proven ANS agent authenticates.
    pub allowed_ans_names: Vec<String>,
    /// `DPoP` `iat` freshness window (§7.4 step 9). `None` uses the SDK default
    /// of ±120 seconds.
    ///
    /// §7.6 notes each halving of this window halves both replay exposure and
    /// replay-cache pressure — so this is the knob to reach for before growing
    /// the cache.
    pub pop_skew: Option<Duration>,
    /// Status-token clock-skew tolerance (§4.4 step 7, capped at 10 minutes by
    /// the spec). `None` uses the SDK default of 60 seconds.
    pub status_skew: Option<Duration>,
}

impl Policy {
    /// The strictest useful default: Method B, receipt required, no peer pinning.
    pub fn method_b_strict() -> Self {
        Self {
            methods: EnabledMethods::MethodBOnly,
            require_receipt: true,
            allowed_ans_names: Vec::new(),
            pop_skew: None,
            status_skew: None,
        }
    }

    /// Whether the selected method is enabled here.
    pub fn permits(&self, selector: crate::facts::MethodSelector) -> bool {
        match selector {
            crate::facts::MethodSelector::MethodB => self.methods.method_b(),
            crate::facts::MethodSelector::MethodA => self.methods.method_a(),
            crate::facts::MethodSelector::None => false,
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::MethodSelector;

    #[test]
    fn method_sets_report_membership() {
        assert!(EnabledMethods::MethodBOnly.method_b());
        assert!(!EnabledMethods::MethodBOnly.method_a());
        assert!(EnabledMethods::MethodAOnly.method_a());
        assert!(!EnabledMethods::MethodAOnly.method_b());
        assert!(EnabledMethods::Both.method_a());
        assert!(EnabledMethods::Both.method_b());
    }

    #[test]
    fn strict_default_is_method_b_with_receipt_required() {
        let p = Policy::method_b_strict();
        assert_eq!(p.methods, EnabledMethods::MethodBOnly);
        assert!(p.require_receipt);
        assert_eq!(p.allowed_ans_names, Vec::<String>::new());
    }

    #[test]
    fn permits_rejects_a_method_that_is_not_enabled() {
        let p = Policy::method_b_strict();
        assert!(p.permits(MethodSelector::MethodB));
        assert!(!p.permits(MethodSelector::MethodA));
    }

    #[test]
    fn permits_never_accepts_an_absent_credential() {
        let p = Policy {
            methods: EnabledMethods::Both,
            ..Policy::method_b_strict()
        };
        assert!(!p.permits(MethodSelector::None));
    }
}
