#![warn(missing_docs)]

//! # Envoy `ext_authz` wire adapter
//!
//! Translates between Envoy's `envoy.service.auth.v3` messages and the
//! proxy-neutral types in [`ans_envoy_core`]. It contains no verification logic
//! and makes no security decisions of its own — it reports facts, and
//! [`ans_envoy_core::Verifier`] decides.
//!
//! That split exists because ANS-6 §7.13 request-content binding has no
//! non-truncating home in `ext_authz`: `BufferSettings.max_request_bytes` is
//! mandatory, so a body is either rejected above the cap or silently truncated.
//! The eventual fix is a second adapter over `ext_proc`, and it should not require
//! touching the §7.4 check order to get there.
//!
//! ## The three Envoy settings this adapter depends on
//!
//! | Setting | Why | What happens without it |
//! | --- | --- | --- |
//! | `encode_raw_headers: true` | §4.6 duplicate detection needs uncoalesced header values | [`headers::extract`] reports `raw_values_available: false` and the verifier denies every request |
//! | `context_extensions` per route | §7.7 needs an authority a client cannot forge | [`authority::AuthorityResolver`] resolves nothing and the request is denied |
//! | `include_peer_certificate: true` | Method A needs the validated client certificate | no certificate reaches [`request::adapt`], so Method A cannot run |
//!
//! None of the three can be checked from inside this process at startup, which is
//! why `ans_envoy_config::envoy_lint` exists and why the first two are also
//! detected at request time.

pub mod authority;
pub mod headers;
pub mod request;
pub mod response;

pub use authority::AuthorityResolver;
pub use request::{AdaptError, adapt};
pub use response::to_check_response;
