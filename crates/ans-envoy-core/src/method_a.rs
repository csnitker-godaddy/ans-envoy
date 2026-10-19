//! ANS-6 §6 Method A — mTLS, with identity and liveness from SCITT artifacts.
//!
//! Method A splits its conformance across two artifacts by construction, and it
//! is worth being blunt about which half lives where:
//!
//! - **The proxy** validates the client certificate chain against the RA private
//!   CA and proves possession via the TLS `CertificateVerify`. Neither is
//!   reachable from here — by the time this code runs the handshake is over.
//! - **This code** does §6.3: it binds the already-validated certificate to the
//!   TL's statement about it.
//!
//! §6.1 explains why the second half is not optional. ANS-1 revocation revokes
//! identity certificates at the issuing private CA, but that CA "publishes no
//! CRL or OCSP endpoint, so a revoked certificate still chains cleanly". A
//! successful handshake therefore says nothing about revocation; the status
//! token is the revocation channel.

use ans_types::StatusTokenPayload;
use ans_verify::{CertIdentity, VerifiedReceipt};

use crate::decision::AuthenticatedCaller;
use crate::deny::{DenyReason, labels};
use crate::facts::MethodSelector;
use crate::leaf::parse_leaf_identity;
use crate::policy::Policy;

/// Parse the downstream client certificate out of PEM text.
///
/// Takes the first PEM block. Envoy may present a chain, and the leaf is first
/// by PEM convention; the trailing issuers are not consulted because trust here
/// comes from the status token, exactly as §7.5 describes for Method B. An empty
/// or unparseable input is a denial rather than a silent miss — a client
/// certificate that arrived but could not be read must never be treated the same
/// as no certificate at all.
pub fn parse_peer_certificate(pem: &str) -> Result<CertIdentity, DenyReason> {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| {
        DenyReason::caller(
            labels::PEER_CERT_INVALID,
            format!("downstream client certificate is not valid PEM: {e}"),
        )
    })?;

    CertIdentity::from_der(&block.contents).map_err(|e| {
        DenyReason::caller(
            labels::PEER_CERT_INVALID,
            format!("downstream client certificate is not a parseable X.509: {e}"),
        )
    })
}

/// Bind a validated client certificate to the TL's statement about it (§6.3).
///
/// The comparisons are §6.3's table:
///
/// | Client certificate | Artifact field | Requirement |
/// | --- | --- | --- |
/// | Fingerprint | Status token `validIdentityCerts` | Matches any entry |
/// | DNS SAN | Receipt event `agent.host` | Equal |
/// | URI SAN | Receipt event `ansName` / status token `ansName` | Equal |
///
/// Status and `exp` are already enforced by the status-token verification that
/// produced `status`, so they are not re-checked here.
pub fn bind_client_certificate(
    cert: &CertIdentity,
    status: &StatusTokenPayload,
    receipt: &VerifiedReceipt,
    policy: &Policy,
) -> Result<AuthenticatedCaller, DenyReason> {
    // §6.3 row 1 — the fingerprint must appear in the status token's identity
    // array. The array carries *every* currently-valid certificate, so a
    // rotation overlap matches without a refresh (§8.2).
    let fingerprint = cert.fingerprint();
    if !status
        .valid_identity_certs
        .iter()
        .any(|entry| &entry.fingerprint == fingerprint)
    {
        return Err(DenyReason::caller(
            "BINDING_FAILED",
            "client certificate fingerprint is not in the status token's validIdentityCerts",
        ));
    }

    // §6.3 row 3 — the certificate's ans:// URI SAN identifies the caller.
    // §6.1: "No URI SAN → not an ANS Identity Certificate."
    let cert_ans = cert.ans_name().ok_or_else(|| {
        DenyReason::caller(
            "BINDING_FAILED",
            "client certificate has no ans:// URI SAN, so it is not an ANS Identity Certificate",
        )
    })?;
    if !cert_ans
        .to_string()
        .eq_ignore_ascii_case(&status.ans_name.to_string())
    {
        return Err(DenyReason::caller(
            "BINDING_FAILED",
            "client certificate ans:// SAN does not match the full status token ansName",
        ));
    }

    // §6.3 row 2 — an actual DNS SAN, never a CN fallback, names the agent host.
    // Require agreement with both the status token and the sealed receipt.
    let dns_san = cert.dns_sans().first().ok_or_else(|| {
        DenyReason::caller("BINDING_FAILED", "client certificate carries no DNS SAN")
    })?;
    if !dns_san.eq_ignore_ascii_case(status.ans_name.fqdn().as_str()) {
        return Err(DenyReason::caller(
            "BINDING_FAILED",
            "client certificate DNS SAN does not match the status token ansName host",
        ));
    }

    bind_receipt(receipt, status, dns_san)?;

    // §7.5.4 peer pinning, applied identically to both methods.
    if !policy.allowed_ans_names.is_empty() {
        let host = status.ans_name.fqdn().as_str().to_ascii_lowercase();
        let permitted = policy.allowed_ans_names.iter().any(|name| {
            ans_types::AnsName::parse(name).map_or_else(
                |_| name.trim().eq_ignore_ascii_case(&host),
                |parsed| parsed.fqdn().as_str().eq_ignore_ascii_case(&host),
            )
        });
        if !permitted {
            return Err(DenyReason::peer(
                "EXPECTED_PEER_MISMATCH",
                "caller ans host is not in the accepted set",
            ));
        }
    }

    Ok(AuthenticatedCaller {
        ans_name: status.ans_name.to_string(),
        agent_id: status.agent_id.to_string(),
        fingerprint: fingerprint.to_string(),
        // No proof key exists under Method A: possession came from the TLS
        // handshake, so there is no RFC 7638 thumbprint to hand upstream.
        jkt: None,
        method: MethodSelector::MethodA,
    })
}

/// The receipt must name the same agent as the status token, and its sealed
/// `agent.host` must equal the certificate's DNS SAN (§6.3 row 2).
fn bind_receipt(
    receipt: &VerifiedReceipt,
    status: &StatusTokenPayload,
    dns_san: &str,
) -> Result<(), DenyReason> {
    let leaf = parse_leaf_identity(&receipt.event_bytes).map_err(|e| {
        DenyReason::caller("RECEIPT_INVALID", format!("receipt leaf unreadable: {e}"))
    })?;

    if leaf.ans_name.is_none() || leaf.agent_host.is_none() {
        return Err(DenyReason::caller(
            "RECEIPT_INVALID",
            "receipt leaf event must carry ansName and agent.host for Method A",
        ));
    }

    if let Some(id) = leaf.ans_id.as_deref() {
        let parsed = uuid::Uuid::parse_str(id).map_err(|e| {
            DenyReason::caller(
                "RECEIPT_INVALID",
                format!("receipt leaf ansId is not a UUID: {e}"),
            )
        })?;
        if parsed != status.agent_id {
            return Err(DenyReason::caller(
                "BINDING_FAILED",
                "receipt leaf ansId does not match the status token agentId",
            ));
        }
    }

    // Full-name comparison, version segment included — §7.5.3 is explicit that
    // the whole name is compared, so two versions of one agent never satisfy
    // each other's artifacts.
    if let Some(name) = leaf.ans_name.as_deref()
        && !name.eq_ignore_ascii_case(&status.ans_name.to_string())
    {
        return Err(DenyReason::caller(
            "BINDING_FAILED",
            "receipt leaf ansName does not match the status token ansName",
        ));
    }

    if let Some(host) = leaf.agent_host.as_deref()
        && !host.eq_ignore_ascii_case(dns_san)
    {
        return Err(DenyReason::caller(
            "BINDING_FAILED",
            "receipt leaf agent.host does not match the client certificate DNS SAN",
        ));
    }

    Ok(())
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pem_is_a_denial_not_a_missing_certificate() {
        let err = parse_peer_certificate("").unwrap_err();
        assert_eq!(err.label, labels::PEER_CERT_INVALID);
    }

    #[test]
    fn garbage_pem_is_a_denial() {
        let err = parse_peer_certificate("-----BEGIN CERTIFICATE-----\nnope\n").unwrap_err();
        assert_eq!(err.label, labels::PEER_CERT_INVALID);
    }

    #[test]
    fn a_well_formed_pem_wrapping_non_x509_der_is_a_denial() {
        // Base64 that decodes cleanly but is not a certificate. The PEM layer
        // succeeding must not be mistaken for a usable identity.
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(parse_peer_certificate(pem).is_err());
    }
}
