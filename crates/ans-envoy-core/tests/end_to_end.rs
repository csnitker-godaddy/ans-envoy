#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! End-to-end ANS-6 verification against real artifacts.
//!
//! Real P-256 keys, a real X.509 identity certificate with an `ans://` URI SAN,
//! real `COSE_Sign1` status tokens and receipts signed by a test Transparency Log
//! key, and a real RFC 9162 inclusion proof. The production verifier checks them.
//!
//! The negative cases carry the weight. A verifier that accepts a valid request is
//! easy; the interesting question is whether it refuses each specific way a
//! request can be wrong, with the right label — and in particular whether it
//! refuses the attack ANS-6 documents against its *own* worked example.

mod fixtures;

use std::sync::Arc;

use ans_envoy_core::{Decision, EnabledMethods, Policy, labels};
use ans_verify::MemoryReplayCache;
use fixtures::{
    CALLEE_AUTHORITY, CALLER_AGENT_ID, CALLER_ANS_NAME, FactsBuilder, StatusTokenSpec, callee_url,
    identity, now, receipt, status_token, tl_key, verifier, verifier_with_replay,
};

/// Method B, receipts required — the strict default.
fn strict() -> Policy {
    Policy::method_b_strict()
}

/// Method B without receipts, so a test can isolate the status-token path.
/// §7.1 permits this "reduced mode"; the deployment must document it.
fn no_receipt() -> Policy {
    Policy {
        require_receipt: false,
        ..Policy::method_b_strict()
    }
}

fn deny_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow(caller) => panic!("expected a denial, got allow for {}", caller.ans_name),
        Decision::Deny(reason) => reason.label,
    }
}

// ── Method B: the happy path ─────────────────────────────────────────────────

#[tokio::test]
async fn a_complete_method_b_request_authenticates() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));
    let rcpt = receipt(&tl, CALLER_AGENT_ID, CALLER_ANS_NAME, "caller.example.com");

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .receipt(&rcpt)
        .build();

    match verifier(&tl, strict()).authenticate(&facts).await {
        Decision::Allow(c) => {
            assert_eq!(c.ans_name, CALLER_ANS_NAME);
            assert_eq!(c.agent_id, CALLER_AGENT_ID);
            assert_eq!(c.fingerprint, caller.fingerprint.to_string());
            // §7.8: the thumbprint the token validator needs for `cnf.jkt`.
            assert!(c.jkt.is_some(), "Method B must publish the proof key jkt");
        }
        Decision::Deny(r) => panic!("expected allow, got {} — {}", r.label, r.detail),
    }
}

#[tokio::test]
async fn the_published_jkt_is_the_proof_keys_thumbprint() {
    // §7.8 puts the cnf.jkt comparison with whoever validates the access token.
    // That only works if the value we publish is the one the caller can compute.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let signer = caller.signer();

    let proof = signer.sign("POST", &callee_url("/api/task"), None).unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .build();

    match verifier(&tl, no_receipt()).authenticate(&facts).await {
        Decision::Allow(c) => assert_eq!(c.jkt.as_deref(), Some(signer.jkt().unwrap().as_str())),
        Decision::Deny(r) => panic!("expected allow, got {} — {}", r.label, r.detail),
    }
}

// ── §7.6 replay ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_same_proof_twice_is_refused_the_second_time() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let replay = Arc::new(MemoryReplayCache::new(1024));

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let build = || {
        FactsBuilder::method_b()
            .dpop(&proof)
            .status_token(&token)
            .build()
    };

    let v = verifier_with_replay(&tl, no_receipt(), replay);
    assert!(
        v.authenticate(&build()).await.is_allow(),
        "first presentation should authenticate"
    );
    assert_eq!(
        deny_label(&v.authenticate(&build()).await),
        "REPLAY",
        "the same jti must not be accepted twice"
    );
}

#[tokio::test]
async fn two_replicas_sharing_a_cache_reject_a_cross_replica_replay() {
    // §7.6: "Multi-replica deployments MUST share the replay cache across
    // replicas serving the same
    // `htu` authority." Two verifiers, one store — a proof accepted by the first
    // is refused by the second.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let shared = Arc::new(MemoryReplayCache::new(1024));

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));
    let build = || {
        FactsBuilder::method_b()
            .dpop(&proof)
            .status_token(&token)
            .build()
    };

    let replica_a = verifier_with_replay(&tl, no_receipt(), Arc::clone(&shared));
    let replica_b = verifier_with_replay(&tl, no_receipt(), shared);

    assert!(replica_a.authenticate(&build()).await.is_allow());
    assert_eq!(
        deny_label(&replica_b.authenticate(&build()).await),
        "REPLAY",
        "a proof spent on one replica must not be accepted on another"
    );
}

// ── §7.7 authority — the example A.6 attack ──────────────────────────────────

#[tokio::test]
async fn a_proof_minted_for_another_origin_is_refused() {
    // ANS-6 worked example A.6. The attacker captured a proof minted for
    // payments.example.com along with the public artifacts, and replays it at
    // api.other.example. Every cryptographic check passes; the proof is genuine
    // and unspent *here*. Only the authority comparison stops it.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof_for_payments = caller
        .signer()
        .sign("POST", "https://payments.example.com/api/task", None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .authority("api.other.example")
        .dpop(&proof_for_payments)
        .status_token(&token)
        .build();

    let label = deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await);
    assert!(
        label == "HTTP_BINDING_MISMATCH" || label == "UNTRUSTED_AUTHORITY",
        "a cross-origin proof replay must be refused, got {label}"
    );
}

#[tokio::test]
async fn a_proof_minted_for_another_path_is_refused() {
    // §7.7: a reconstruction that ignores the path "collapses `htu` to one value,
    // so a proof minted for any path is accepted on every path".
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof_for_health = caller
        .signer()
        .sign("POST", &callee_url("/health"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    // Signed for /health, presented at /api/task.
    let facts = FactsBuilder::method_b()
        .dpop(&proof_for_health)
        .status_token(&token)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await),
        "HTTP_BINDING_MISMATCH"
    );
}

#[tokio::test]
async fn a_proof_minted_for_another_method_is_refused() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .method("DELETE")
        .dpop(&proof)
        .status_token(&token)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await),
        "HTTP_BINDING_MISMATCH"
    );
}

#[tokio::test]
async fn a_route_with_no_asserted_authority_is_refused() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .no_authority()
        .dpop(&proof)
        .status_token(&token)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await),
        labels::AUTHORITY_UNRESOLVED
    );
}

// ── §4.6 header hygiene ──────────────────────────────────────────────────────

#[tokio::test]
async fn a_duplicated_dpop_header_is_refused_before_any_cryptography() {
    let tl = tl_key(0x11);
    let facts = FactsBuilder::method_b().duplicate_dpop().build();
    assert_eq!(
        deny_label(&verifier(&tl, strict()).authenticate(&facts).await),
        labels::DUPLICATE_HEADER
    );
}

#[tokio::test]
async fn a_proxy_that_coalesces_headers_denies_everything() {
    // Rather than silently skipping §4.6. The fault is the deployment's, so it is
    // reported as a deployment fault with a 500 — a 401 would send whoever is on
    // call to inspect the caller's proof, which is the wrong half of the system.
    let tl = tl_key(0x11);
    let facts = FactsBuilder::method_b().no_raw_headers().build();
    let decision = verifier(&tl, strict()).authenticate(&facts).await;
    assert_eq!(deny_label(&decision), labels::RAW_HEADERS_UNAVAILABLE);
    match decision {
        Decision::Deny(r) => assert_eq!(r.status(), 500),
        Decision::Allow(_) => unreachable!(),
    }
}

// ── §7.5 binding ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_certificate_absent_from_the_status_token_is_refused() {
    // The proof is cryptographically perfect and the token is genuine — they just
    // describe different certificates. §7.5 step 1.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let someone_else = identity("caller-alt", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    // Token vouches for a different certificate.
    let token = status_token(&tl, &StatusTokenSpec::active(&someone_else.fingerprint));

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await),
        "BINDING_FAILED"
    );
}

#[tokio::test]
async fn a_receipt_naming_a_different_agent_is_refused() {
    // §7.5 step 3: receipt and status token must name the same agent.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));
    let wrong = receipt(
        &tl,
        "019be7f3-5720-77c9-9672-adae3394502f",
        "ans://v1.0.0.other.example.com",
        "other.example.com",
    );

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .receipt(&wrong)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, strict()).authenticate(&facts).await),
        "BINDING_FAILED"
    );
}

// ── §4.4 liveness ────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_expired_status_token_is_refused() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let stale = now() - 7200;
    let token = status_token(
        &tl,
        &StatusTokenSpec {
            iat: stale,
            exp: stale + 3600,
            ..StatusTokenSpec::active(&caller.fingerprint)
        },
    );

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await),
        "STATUS_INVALID"
    );
}

#[tokio::test]
async fn a_revoked_agent_is_refused() {
    // §4.4: "Verifiers MUST treat the inability to obtain a fresh status token as
    // equivalent to revocation." A token that still says REVOKED is the clearer
    // signal, and terminal status must reject.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(
        &tl,
        &StatusTokenSpec {
            status: "REVOKED",
            ..StatusTokenSpec::active(&caller.fingerprint)
        },
    );

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await),
        "STATUS_INVALID"
    );
}

#[tokio::test]
async fn a_status_token_signed_by_an_untrusted_key_is_refused() {
    // The whole SCITT tier rests on this: a token is only evidence because the TL
    // signed it. A different key must not do.
    let tl = tl_key(0x11);
    let impostor = tl_key(0x99);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let forged = status_token(&impostor, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&forged)
        .build();

    // Verified against `tl`, which does not know the impostor's kid.
    assert_eq!(
        deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await),
        "STATUS_INVALID"
    );
}

// ── §7.11 missing evidence is a rejection, not a fallback ─────────────────────

#[tokio::test]
async fn a_dpop_request_with_no_status_token_is_refused() {
    // §7.11 and §9.7: where an intermediary can strip headers — Method B's
    // operating premise — a missing SCITT artifact is a rejection, not a trigger
    // to try a weaker tier.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();

    let facts = FactsBuilder::method_b().dpop(&proof).build();
    assert_eq!(
        deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await),
        "MISSING_HEADERS"
    );
}

#[tokio::test]
async fn a_request_requiring_a_receipt_without_one_is_refused() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, strict()).authenticate(&facts).await),
        "MISSING_HEADERS"
    );
}

#[tokio::test]
async fn a_request_with_no_credential_at_all_is_refused() {
    let tl = tl_key(0x11);
    let facts = FactsBuilder::method_b().build();
    assert_eq!(
        deny_label(&verifier(&tl, strict()).authenticate(&facts).await),
        labels::NO_CREDENTIAL
    );
}

// ── §10.1 method gating ──────────────────────────────────────────────────────

#[tokio::test]
async fn a_method_the_callee_does_not_enable_is_refused() {
    // §10.1 requires implementing at least one method and documenting which. A
    // request for the other one is refused rather than quietly handled.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let method_a_only = Policy {
        methods: EnabledMethods::MethodAOnly,
        ..no_receipt()
    };

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, method_a_only).authenticate(&facts).await),
        labels::METHOD_NOT_ENABLED
    );
}

// ── §6.3 Method A ────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_client_certificate_bound_to_its_status_token_authenticates() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));
    let rcpt = receipt(&tl, CALLER_AGENT_ID, CALLER_ANS_NAME, "caller.example.com");

    let policy = Policy {
        methods: EnabledMethods::MethodAOnly,
        ..Policy::method_b_strict()
    };

    let facts = FactsBuilder::method_b()
        .peer_certificate(&caller.cert_pem())
        .status_token(&token)
        .receipt(&rcpt)
        .build();

    match verifier(&tl, policy).authenticate(&facts).await {
        Decision::Allow(c) => {
            assert_eq!(c.ans_name, CALLER_ANS_NAME);
            assert_eq!(c.fingerprint, caller.fingerprint.to_string());
            // No proof key exists under Method A — possession came from the TLS
            // handshake, so there is no RFC 7638 thumbprint to publish.
            assert!(
                c.jkt.is_none(),
                "Method A must not publish a proof-key thumbprint"
            );
        }
        Decision::Deny(r) => panic!("expected allow, got {} — {}", r.label, r.detail),
    }
}

#[tokio::test]
async fn a_client_certificate_absent_from_the_status_token_is_refused() {
    // §6.1: the RA private CA publishes no CRL, so a revoked certificate still
    // chains cleanly and a successful handshake proves nothing about revocation.
    // This is the check that catches it.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let someone_else = identity("caller-alt", CALLER_ANS_NAME);

    let token = status_token(&tl, &StatusTokenSpec::active(&someone_else.fingerprint));
    let policy = Policy {
        methods: EnabledMethods::MethodAOnly,
        ..no_receipt()
    };

    let facts = FactsBuilder::method_b()
        .peer_certificate(&caller.cert_pem())
        .receipt(&receipt(
            &tl,
            CALLER_AGENT_ID,
            CALLER_ANS_NAME,
            "caller.example.com",
        ))
        .status_token(&token)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, policy).authenticate(&facts).await),
        "BINDING_FAILED"
    );
}

#[tokio::test]
async fn an_mtls_request_with_no_status_token_is_refused() {
    // §6.3 says fall back to the badge tier; this build ships none, and §9.7 makes
    // a stripped artifact a rejection rather than a fallback trigger.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let policy = Policy {
        methods: EnabledMethods::MethodAOnly,
        ..no_receipt()
    };

    let facts = FactsBuilder::method_b()
        .peer_certificate(&caller.cert_pem())
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, policy).authenticate(&facts).await),
        "MISSING_HEADERS"
    );
}

#[tokio::test]
async fn a_dpop_proof_wins_over_a_present_client_certificate() {
    // Otherwise certificate presence would silently select the weaker,
    // connection-scoped check, making the choice of method an attacker's rather
    // than the deployment's.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    // Method B only: if the certificate had selected Method A, this would be
    // refused as METHOD_NOT_ENABLED instead of authenticating.
    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .peer_certificate(&caller.cert_pem())
        .build();

    match verifier(&tl, no_receipt()).authenticate(&facts).await {
        Decision::Allow(c) => assert!(c.jkt.is_some(), "should have taken the Method B path"),
        Decision::Deny(r) => panic!(
            "expected allow via Method B, got {} — {}",
            r.label, r.detail
        ),
    }
}

// ── §7.5.4 peer pinning ──────────────────────────────────────────────────────

#[tokio::test]
async fn a_proven_caller_outside_the_accepted_set_is_refused_as_a_peer() {
    // Authentication succeeded; the caller is simply not one this callee talks to.
    // That is a 403, not a 401 — retrying with a new proof would change nothing.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let pinned = Policy {
        allowed_ans_names: vec!["ans://v1.0.0.someone.else.example.com".to_string()],
        ..no_receipt()
    };

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .build();

    let decision = verifier(&tl, pinned).authenticate(&facts).await;
    assert_eq!(deny_label(&decision), "EXPECTED_PEER_MISMATCH");
    match decision {
        Decision::Deny(r) => assert_eq!(r.status(), 403),
        Decision::Allow(_) => unreachable!(),
    }
}

#[tokio::test]
async fn a_pinned_caller_that_matches_authenticates() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let pinned = Policy {
        allowed_ans_names: vec![CALLER_ANS_NAME.to_string()],
        ..no_receipt()
    };

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .build();

    assert!(verifier(&tl, pinned).authenticate(&facts).await.is_allow());
}

// ── sanity on the fixtures themselves ────────────────────────────────────────

#[tokio::test]
async fn the_callee_authority_is_what_the_caller_signs() {
    // Guards the fixtures: if these drifted apart, every happy-path test above
    // would be asserting the wrong thing.
    assert_eq!(
        callee_url("/api/task"),
        format!("https://{CALLEE_AUTHORITY}/api/task")
    );
}

// ── §7.13 request-content binding ────────────────────────────────────────────

/// Method B, receipts off, content binding required.
fn require_content() -> Policy {
    no_receipt()
}

#[tokio::test]
async fn a_proof_that_binds_matching_content_authenticates() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let body = br#"{"amount":50000}"#;

    let proof = caller
        .signer()
        .sign_with_content("POST", &callee_url("/api/task"), None, body)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .content(body)
        .build();

    match verifier(&tl, require_content()).authenticate(&facts).await {
        Decision::Allow(c) => assert_eq!(c.ans_name, CALLER_ANS_NAME),
        Decision::Deny(r) => panic!("expected allow, got {} — {}", r.label, r.detail),
    }
}

#[tokio::test]
async fn content_altered_behind_the_tls_terminator_is_refused() {
    // §11.11, and the reason §7.13 exists: the hop that lets headers survive TLS
    // termination also sees and can rewrite the body. Doing so on a *first*
    // request trips no replay defence — the `jti` is unseen and the `iat` fresh.
    // Only the digest catches it.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let signed = br#"{"amount":100}"#;
    let delivered = br#"{"amount":900000}"#;

    let proof = caller
        .signer()
        .sign_with_content("POST", &callee_url("/api/task"), None, signed)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .content(delivered)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await),
        "CONTENT_BINDING_MISMATCH"
    );
}

#[tokio::test]
async fn a_proof_binding_content_on_a_bodyless_request_is_refused() {
    // §7.13, strict in both directions: "Claim present and the request carries no
    // content → reject."
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign_with_content("POST", &callee_url("/api/task"), None, b"something")
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await),
        "CONTENT_BINDING_MISMATCH"
    );
}

#[tokio::test]
async fn content_added_to_an_empty_signed_request_is_refused() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));
    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .content(b"added behind the TLS terminator")
        .build();
    assert_eq!(
        deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await),
        "CONTENT_BINDING_MISMATCH"
    );
}

#[tokio::test]
async fn unbound_content_is_refused_when_the_deployment_requires_binding() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .content(b"unbound")
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, require_content()).authenticate(&facts).await),
        "CONTENT_BINDING_MISMATCH"
    );
}

#[tokio::test]
async fn truncated_content_is_always_refused() {
    // A prefix hash never matches a whole-content digest, so it is
    // indistinguishable from tampering. There is no honest comparison to make, so
    // this is refused even under the permissive policy — and it is the
    // deployment's fault, hence 500.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let body = b"a long body that got cut off";

    let proof = caller
        .signer()
        .sign_with_content("POST", &callee_url("/api/task"), None, body)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .content_unavailable(ans_envoy_core::ContentUnavailable::Truncated)
        .build();

    let decision = verifier(&tl, no_receipt()).authenticate(&facts).await;
    assert_eq!(deny_label(&decision), labels::CONTENT_TRUNCATED);
    match decision {
        Decision::Deny(r) => assert_eq!(r.status(), 500),
        Decision::Allow(_) => unreachable!(),
    }
}

#[tokio::test]
async fn requiring_binding_without_body_buffering_is_refused_as_a_deployment_fault() {
    // Enforcing a policy that cannot be enforced is the "silently weaker" failure
    // §7.13 names. Refuse instead, and point at the Envoy setting.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .content_unavailable(ans_envoy_core::ContentUnavailable::NotBuffered)
        .build();

    let decision = verifier(&tl, require_content()).authenticate(&facts).await;
    assert_eq!(deny_label(&decision), labels::CONTENT_NOT_BUFFERED);
    match decision {
        Decision::Deny(r) => assert_eq!(r.status(), 500),
        Decision::Allow(_) => unreachable!(),
    }
}

#[tokio::test]
async fn a_content_bound_proof_fails_closed_when_bodies_are_not_buffered() {
    // Unavailable content is a deployment fault regardless of the proof digest.
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);

    let proof = caller
        .signer()
        .sign_with_content("POST", &callee_url("/api/task"), None, b"bound body")
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));

    let facts = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .content_unavailable(ans_envoy_core::ContentUnavailable::NotBuffered)
        .build();

    assert_eq!(
        deny_label(&verifier(&tl, no_receipt()).authenticate(&facts).await),
        "CONTENT_NOT_BUFFERED",
        "fail closed, even though the label points at the caller rather than the proxy"
    );
}

#[tokio::test]
async fn missing_or_malformed_content_digest_rejects_even_for_empty_requests() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));
    for digest in [
        None,
        Some(serde_json::Value::Null),
        Some(serde_json::json!("bad")),
    ] {
        let proof = caller
            .signer()
            .sign("POST", &callee_url("/api/task"), None)
            .unwrap();
        let proof = fixtures::rewrite_payload(&caller, &proof, |p| {
            if let Some(d) = digest {
                p["ans_content_digest"] = d;
            } else {
                p.as_object_mut().unwrap().remove("ans_content_digest");
            }
        });
        let facts = FactsBuilder::method_b()
            .dpop(&proof)
            .status_token(&token)
            .build();
        assert!(
            !verifier(&tl, no_receipt())
                .authenticate(&facts)
                .await
                .is_allow()
        );
    }
}

#[tokio::test]
async fn unsupported_or_malformed_profiles_reject() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));
    for profile in [
        serde_json::Value::Null,
        serde_json::json!(2),
        serde_json::json!("1"),
    ] {
        let proof = caller
            .signer()
            .sign("POST", &callee_url("/api/task"), None)
            .unwrap();
        let proof = fixtures::rewrite_payload(&caller, &proof, |p| p["ans_profile"] = profile);
        let facts = FactsBuilder::method_b()
            .dpop(&proof)
            .status_token(&token)
            .build();
        assert!(
            !verifier(&tl, no_receipt())
                .authenticate(&facts)
                .await
                .is_allow()
        );
    }
}

#[tokio::test]
async fn raw_path_aliases_do_not_authenticate_as_each_other() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));
    for (signed, received) in [
        ("/a/../b", "/b"),
        ("/a/%2e%2e/b", "/b"),
        ("/a%2fb", "/a%2Fb"),
    ] {
        let proof = caller
            .signer()
            .sign("POST", &callee_url(signed), None)
            .unwrap();
        let mut facts = FactsBuilder::method_b()
            .dpop(&proof)
            .status_token(&token)
            .build();
        facts.target = received.into();
        let v = verifier(&tl, no_receipt());
        assert_eq!(
            deny_label(&v.authenticate(&facts).await),
            "HTTP_BINDING_MISMATCH"
        );
        facts.target = signed.into();
        assert!(v.authenticate(&facts).await.is_allow());
    }
}

#[tokio::test]
async fn content_failure_does_not_spend_the_proof() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let body = b"\x1f\x8b\x08\x00\xff\x00compressed-content";
    let proof = caller
        .signer()
        .sign_with_content("POST", &callee_url("/api/task"), None, body)
        .unwrap();
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));
    let v = verifier(&tl, no_receipt());
    let bad = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .content(b"changed")
        .build();
    assert_eq!(
        deny_label(&v.authenticate(&bad).await),
        "CONTENT_BINDING_MISMATCH"
    );
    let good = FactsBuilder::method_b()
        .dpop(&proof)
        .status_token(&token)
        .content(body)
        .build();
    assert!(v.authenticate(&good).await.is_allow());
    assert_eq!(deny_label(&v.authenticate(&good).await), "REPLAY");
}

#[tokio::test]
async fn method_a_rejects_a_different_version_on_the_same_host() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let mut spec = StatusTokenSpec::active(&caller.fingerprint);
    spec.ans_name = "ans://v2.0.0.caller.example.com";
    let token = status_token(&tl, &spec);
    let facts = FactsBuilder::method_b()
        .peer_certificate(&caller.cert_pem())
        .receipt(&receipt(
            &tl,
            CALLER_AGENT_ID,
            CALLER_ANS_NAME,
            "caller.example.com",
        ))
        .status_token(&token)
        .build();
    let policy = Policy {
        methods: EnabledMethods::MethodAOnly,
        ..no_receipt()
    };
    assert_eq!(
        deny_label(&verifier(&tl, policy).authenticate(&facts).await),
        "BINDING_FAILED"
    );
}

#[tokio::test]
async fn supplied_receipts_are_verified_even_when_absence_is_waived() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));
    let proof = caller
        .signer()
        .sign("POST", &callee_url("/api/task"), None)
        .unwrap();
    for method_a in [false, true] {
        let policy = Policy {
            methods: EnabledMethods::Both,
            ..no_receipt()
        };
        let mut builder = FactsBuilder::method_b()
            .status_token(&token)
            .receipt(b"invalid COSE");
        if method_a {
            builder = builder.peer_certificate(&caller.cert_pem());
        } else {
            builder = builder.dpop(&proof);
        }
        assert_eq!(
            deny_label(&verifier(&tl, policy).authenticate(&builder.build()).await),
            "RECEIPT_INVALID"
        );
    }
}

#[tokio::test]
async fn method_a_binds_a_supplied_receipt_in_reduced_mode() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));
    let wrong = receipt(
        &tl,
        CALLER_AGENT_ID,
        "ans://v2.0.0.caller.example.com",
        "caller.example.com",
    );
    let facts = FactsBuilder::method_b()
        .peer_certificate(&caller.cert_pem())
        .status_token(&token)
        .receipt(&wrong)
        .build();
    let policy = Policy {
        methods: EnabledMethods::MethodAOnly,
        ..no_receipt()
    };
    assert_eq!(
        deny_label(&verifier(&tl, policy).authenticate(&facts).await),
        "BINDING_FAILED"
    );
}

#[tokio::test]
async fn method_a_cannot_waive_receipts_without_a_badge_tier() {
    let tl = tl_key(0x11);
    let caller = identity("caller", CALLER_ANS_NAME);
    let token = status_token(&tl, &StatusTokenSpec::active(&caller.fingerprint));
    let facts = FactsBuilder::method_b()
        .peer_certificate(&caller.cert_pem())
        .status_token(&token)
        .build();
    let policy = Policy {
        methods: EnabledMethods::MethodAOnly,
        ..no_receipt()
    };
    assert_eq!(
        deny_label(&verifier(&tl, policy).authenticate(&facts).await),
        "MISSING_HEADERS"
    );
}
