#![warn(missing_docs)]

//! # ANS-6 callee-side authentication logic
//!
//! The verification half of [`ans-envoy`](https://github.com/agentnameservice/ans-envoy),
//! deliberately kept free of any proxy's wire format. It takes a
//! [`RequestFacts`] and returns a [`Decision`].
//!
//! ## Why the indirection
//!
//! Nothing here mentions Envoy, gRPC, or `CheckRequest`. That is the whole
//! design rule of this crate. ANS-6 §7.4 fixes an *order* of twelve checks and
//! §7.5 fixes a set of bindings, and getting either wrong is a security bug — so
//! that orchestration should exist once, be tested once, and be reachable from
//! more than one host.
//!
//! Concretely: ANS-6 §7.13 request-content binding uses complete, size-bounded
//! body buffering through `ext_authz`. A future `ext_proc` adapter could support
//! streaming while reusing this crate's verification order.
//!
//! ## What this crate does not do
//!
//! - **It does not authorize.** ANS-6 says this in §1, §3.1, §6.5 and §7.5:
//!   every procedure establishes *who* is calling, never *what* they may do.
//!   [`AuthenticatedCaller`] is an identity, and the upstream service still has
//!   to decide what that identity is allowed to do.
//! - **It does not compare `cnf.jkt`.** §7.8 puts that with whoever validates the
//!   access token, "the token is opaque to the proof layer". This crate publishes
//!   the proof key's RFC 7638 thumbprint as [`AuthenticatedCaller::jkt`] so the
//!   token validator can do it. §11.7 is clear that skipping it leaves no defense
//!   against a stolen token.
//! - **It does not implement the badge tier.** §7.11 and §9.7 make badge fallback
//!   on a `DPoP` request a violation, so a Method-B deployment that ships no
//!   badge path cannot reach the wrong fallback.
//!
//! ## Fail-closed by construction
//!
//! [`Decision`] has two variants. There is no "undecided", because ANS-6 has no
//! such state on the Method-B path: §7.6 makes an erroring replay cache a
//! rejection, and §9.6 makes a store timeout "a rejection, never a skip". An
//! adapter that cannot express indecision cannot have a proxy's fail-open
//! setting turn indecision into an allow.

mod decision;
mod deny;
mod facts;
mod leaf;
mod method_a;
mod policy;
mod verifier;

/// Normalize an authority for comparison: lowercase, and drop a default port.
///
/// Re-exported from the SDK deliberately. §7.7 requires authorities to be
/// "compared case-insensitively with default ports dropped", and an adapter that
/// rolled its own normalizer could disagree with the one the SDK applies to the
/// proof's own `htu` — two normalizers is how a comparison silently stops
/// meaning what it says.
pub use ans_verify::normalize_authority;
pub use decision::{AuthenticatedCaller, Decision};
pub use deny::{DenyReason, Fault, labels};
pub use facts::{
    AuthoritySource, ContentUnavailable, HeaderCount, MethodSelector, RequestContent, RequestFacts,
    SecurityHeaders,
};
pub use leaf::{LeafError, LeafIdentity, parse_leaf_identity};
pub use method_a::{bind_client_certificate, parse_peer_certificate};
pub use policy::{EnabledMethods, Policy};
pub use verifier::{Verifier, selftest_authority_reconstruction};
