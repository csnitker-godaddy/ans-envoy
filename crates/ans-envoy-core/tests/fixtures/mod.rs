//! Real ANS-6 artifacts for the end-to-end verification tests.
//!
//! Nothing below the wire format is mocked. Real X.509 identity certificates
//! carrying an `ans://` URI SAN (committed under `testdata/demo-agents`), real P-256
//! Transparency Log keys, and real `COSE_Sign1` status tokens and receipts with a
//! real RFC 9162 inclusion proof — then the production verifier checks them.
//!
//! That matters because the bugs worth catching here live in the *bindings*: a
//! fingerprint compared against the wrong array, a name compared without its
//! version segment, a signature verified under a key the certificate does not
//! carry. A mock that returns "valid" cannot fail those ways.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ans_envoy_core::{
    AuthoritySource, HeaderCount, Policy, RequestContent, RequestFacts, SecurityHeaders, Verifier,
};
use ans_verify::{MemoryReplayCache, RefreshableKeyStore, ScittKeyStore, VerifiedArtifactCache};
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePublicKey as _;
use sha2::{Digest, Sha256};

/// The caller's ANS name across the fixtures.
pub const CALLER_ANS_NAME: &str = "ans://v1.0.0.caller.example.com";
/// The caller's agent id.
pub const CALLER_AGENT_ID: &str = "7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07";
/// The authority the callee answers as.
pub const CALLEE_AUTHORITY: &str = "payments.example.com";

/// Current Unix time. The verifier reads the system clock (`now: None`), so
/// fixtures are minted against real time rather than a frozen constant — which
/// also means the freshness and `exp` checks are genuinely exercised.
pub fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0)
}

/// A Transparency Log signing key, and a key store that trusts it.
pub struct TlKey {
    pub signing: SigningKey,
    pub store: ScittKeyStore,
}

/// Build a TL key and the C2SP signed-note line that publishes it (§4.5).
pub fn tl_key(seed: u8) -> TlKey {
    let signing = SigningKey::from_slice(&[seed; 32]).expect("seed is a valid scalar");
    let spki = signing
        .verifying_key()
        .to_public_key_der()
        .expect("SPKI encode");
    let digest = Sha256::digest(spki.as_bytes());
    let kid = [digest[0], digest[1], digest[2], digest[3]];
    let line = format!(
        "tl.example.com+{}+{}",
        hex::encode(kid),
        BASE64_STANDARD.encode(spki.as_bytes())
    );
    let store = ScittKeyStore::from_c2sp_keys(&[line]).expect("C2SP line should parse");
    TlKey { signing, store }
}

/// An agent identity, loaded from a committed certificate fixture.
pub struct Identity {
    pub pkcs8: Vec<u8>,
    pub cert_der: Vec<u8>,
    pub fingerprint: ans_types::CertFingerprint,
}

impl Identity {
    /// The certificate as PEM, the shape Envoy hands us for Method A.
    pub fn cert_pem(&self) -> String {
        let body = BASE64_STANDARD.encode(&self.cert_der);
        let wrapped: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap_or_default())
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            wrapped.join("\n")
        )
    }

    /// A `DPoP` signer for this identity.
    pub fn signer(&self) -> ans_verify::Signer {
        ans_verify::Signer::from_pkcs8_der(&self.pkcs8, self.cert_der.clone())
            .expect("signer should build")
    }
}

/// Load a committed identity certificate.
///
/// The fixtures under `testdata/demo-agents` carry the DNS SAN and `ans://` URI SAN that
/// §6.1 and §7.5 require, and are valid for ten years from generation. They are
/// committed rather than generated per run, so a failure here is a change in the
/// verifier and never a change in the fixture.
pub fn identity(name: &str, _ans_name: &str) -> Identity {
    // Shared with the ans-probe dev tool, so a demo run and the test suite
    // exercise the same certificates.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("testdata")
        .join("demo-agents");
    let cert_der = std::fs::read(dir.join(format!("{name}.cert.der")))
        .unwrap_or_else(|e| panic!("missing certificate fixture {name}: {e}"));
    let pkcs8 = std::fs::read(dir.join(format!("{name}.key.pk8")))
        .unwrap_or_else(|e| panic!("missing key fixture {name}: {e}"));
    let fingerprint = ans_types::CertFingerprint::from_der(&cert_der);
    Identity {
        pkcs8,
        cert_der,
        fingerprint,
    }
}

/// `Sig_structure` digest for a `COSE_Sign1`: `SHA-256(CBOR(["Signature1",
/// protected, h'', payload]))`.
///
/// Built here rather than via the SDK's `test-support` export, because Cargo
/// features unify across a workspace — enabling `test-support` for a dev
/// dependency would enable it for production builds too.
fn sig_structure_digest(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let structure = ciborium::Value::Array(vec![
        ciborium::Value::Text("Signature1".to_string()),
        ciborium::Value::Bytes(protected.to_vec()),
        ciborium::Value::Bytes(Vec::new()),
        ciborium::Value::Bytes(payload.to_vec()),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&structure, &mut buf).expect("CBOR encode");
    Sha256::digest(&buf).to_vec()
}

/// The COSE protected header a TL artifact carries (§4.3, §4.4).
fn protected_header(signing: &SigningKey, with_vds: bool) -> Vec<u8> {
    let spki = signing.verifying_key().to_public_key_der().expect("SPKI");
    let digest = Sha256::digest(spki.as_bytes());
    let kid = vec![digest[0], digest[1], digest[2], digest[3]];

    let mut pairs = vec![
        // 1 (alg) = -7 (ES256)
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer((-7_i64).into()),
        ),
        // 4 (kid) = SHA-256(SPKI-DER)[0:4]
        (
            ciborium::Value::Integer(4.into()),
            ciborium::Value::Bytes(kid),
        ),
    ];
    if with_vds {
        // 395 (vds) = 1 (RFC9162_SHA256)
        pairs.push((
            ciborium::Value::Integer(395.into()),
            ciborium::Value::Integer(1.into()),
        ));
    }

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(pairs), &mut buf).expect("CBOR encode");
    buf
}

/// Wrap and sign a `COSE_Sign1`.
fn sign_cose(
    signing: &SigningKey,
    protected: Vec<u8>,
    unprotected: ciborium::Value,
    payload: &[u8],
) -> Vec<u8> {
    let digest = sig_structure_digest(&protected, payload);
    let (sig, _): (Signature, _) = signing.sign_prehash(&digest).expect("ES256 sign");
    let array = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(protected),
        unprotected,
        ciborium::Value::Bytes(payload.to_vec()),
        // IEEE P1363 fixed-width R || S, per §7.9.
        ciborium::Value::Bytes(sig.to_bytes().to_vec()),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&array, &mut buf).expect("CBOR encode");
    buf
}

/// How a status token should be built, so tests can vary one thing at a time.
pub struct StatusTokenSpec<'a> {
    pub agent_id: &'a str,
    pub ans_name: &'a str,
    pub status: &'a str,
    pub iat: i64,
    pub exp: i64,
    /// Fingerprints to list in `validIdentityCerts` (§4.4 key 6).
    pub identity_fingerprints: Vec<ans_types::CertFingerprint>,
}

impl StatusTokenSpec<'_> {
    /// An ACTIVE token, valid for an hour, listing one identity certificate.
    pub fn active(fingerprint: &ans_types::CertFingerprint) -> Self {
        let iat = now();
        Self {
            agent_id: CALLER_AGENT_ID,
            ans_name: CALLER_ANS_NAME,
            status: "ACTIVE",
            iat,
            exp: iat + 3600,
            identity_fingerprints: vec![fingerprint.clone()],
        }
    }
}

/// Build a signed status token (§4.4): a `COSE_Sign1` over an integer-keyed CBOR map.
pub fn status_token(tl: &TlKey, spec: &StatusTokenSpec<'_>) -> Vec<u8> {
    let certs: Vec<ciborium::Value> = spec
        .identity_fingerprints
        .iter()
        .map(|fp| {
            ciborium::Value::Map(vec![
                // 1 = fingerprint, as the raw 32-byte SHA-256.
                (
                    ciborium::Value::Integer(1.into()),
                    ciborium::Value::Bytes(fp.as_bytes().to_vec()),
                ),
                // 2 = certificate type. Informational: §4.4 says verification
                // decisions compare fingerprints, never types.
                (
                    ciborium::Value::Integer(2.into()),
                    ciborium::Value::Text("X509-OV-CLIENT".to_string()),
                ),
            ])
        })
        .collect();

    let payload = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text(spec.agent_id.to_string()),
        ),
        (
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Text(spec.status.to_string()),
        ),
        (
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Integer(spec.iat.into()),
        ),
        (
            ciborium::Value::Integer(4.into()),
            ciborium::Value::Integer(spec.exp.into()),
        ),
        (
            ciborium::Value::Integer(5.into()),
            ciborium::Value::Text(spec.ans_name.to_string()),
        ),
        (
            ciborium::Value::Integer(6.into()),
            ciborium::Value::Array(certs),
        ),
        (
            ciborium::Value::Integer(7.into()),
            ciborium::Value::Array(Vec::new()),
        ),
    ]);

    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(&payload, &mut payload_bytes).expect("CBOR encode");

    sign_cose(
        &tl.signing,
        protected_header(&tl.signing, false),
        ciborium::Value::Map(Vec::new()),
        &payload_bytes,
    )
}

/// Build a signed receipt (§4.3) for a single-leaf log.
///
/// `tree_size: 1, leaf_index: 0` with an empty `hash_path` is a genuinely valid
/// RFC 9162 inclusion proof — the walk consumes no path elements and `sn` is
/// already zero — so this exercises the real Merkle verification rather than
/// bypassing it.
pub fn receipt(tl: &TlKey, agent_id: &str, ans_name: &str, agent_host: &str) -> Vec<u8> {
    let leaf = serde_json::json!({
        "schemaVersion": "V2",
        "status": "SEALED",
        "payload": {
            "logId": "550e8400-e29b-41d4-a716-446655440000",
            "producer": {
                "event": {
                    "ansId": agent_id,
                    "ansName": ans_name,
                    "eventType": "AGENT_REGISTERED",
                    "agent": { "host": agent_host, "name": "caller", "version": "1.0.0" }
                },
                "keyId": "test-key",
                "signature": "eyJhbGciOiJFUzI1NiJ9"
            }
        },
        "signature": "eyJhbGciOiJFUzI1NiJ9"
    });
    let event_bytes = serde_json::to_vec(&leaf).expect("JSON encode");

    // 396 (vdp): -1 tree_size, -2 leaf_index, -3 hash_path.
    let vdp = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer((-1_i64).into()),
            ciborium::Value::Integer(1.into()),
        ),
        (
            ciborium::Value::Integer((-2_i64).into()),
            ciborium::Value::Integer(0.into()),
        ),
        (
            ciborium::Value::Integer((-3_i64).into()),
            ciborium::Value::Array(Vec::new()),
        ),
    ]);
    let unprotected = ciborium::Value::Map(vec![(ciborium::Value::Integer(396.into()), vdp)]);

    sign_cose(
        &tl.signing,
        protected_header(&tl.signing, true),
        unprotected,
        &event_bytes,
    )
}

/// Standard-base64, the encoding §4.6 specifies for the SCITT headers.
pub fn b64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

/// A verifier over a static key store and an in-process replay cache.
///
/// `RefreshableKeyStore::from_static` means no network: §4.5 calls a pinned,
/// static deployment "a valid posture", and it is the right one for a test.
pub fn verifier(tl: &TlKey, policy: Policy) -> Verifier {
    Verifier::new(
        Arc::new(RefreshableKeyStore::from_static(tl.store.clone())),
        Arc::new(MemoryReplayCache::new(1024)),
        policy,
        VerifiedArtifactCache::new(0),
    )
}

/// A verifier sharing one replay cache, so replay across calls is observable.
pub fn verifier_with_replay(
    tl: &TlKey,
    policy: Policy,
    replay: Arc<MemoryReplayCache>,
) -> Verifier {
    Verifier::new(
        Arc::new(RefreshableKeyStore::from_static(tl.store.clone())),
        replay,
        policy,
        VerifiedArtifactCache::new(0),
    )
}

/// Builder for the `RequestFacts` a request would produce.
pub struct FactsBuilder {
    pub method: String,
    pub target: String,
    pub authority: Option<AuthoritySource>,
    pub dpop: HeaderCount,
    pub authorization: HeaderCount,
    pub receipt: HeaderCount,
    pub status_token: HeaderCount,
    pub raw_values_available: bool,
    pub peer_certificate_pem: Option<String>,
    pub content: RequestContent,
}

impl FactsBuilder {
    /// A well-formed Method-B request shape, with no credentials attached yet.
    pub fn method_b() -> Self {
        Self {
            method: "POST".to_string(),
            target: "/api/task".to_string(),
            authority: Some(AuthoritySource::ProxyAsserted(CALLEE_AUTHORITY.to_string())),
            dpop: HeaderCount::Absent,
            authorization: HeaderCount::Absent,
            receipt: HeaderCount::Absent,
            status_token: HeaderCount::Absent,
            raw_values_available: true,
            peer_certificate_pem: None,
            content: RequestContent::Absent,
        }
    }

    /// Attach content, digested as the adapter would.
    pub fn content(mut self, body: &[u8]) -> Self {
        self.content = RequestContent::Bytes(body.to_vec());
        self
    }

    /// Attach content the proxy could not supply.
    pub fn content_unavailable(mut self, reason: ans_envoy_core::ContentUnavailable) -> Self {
        self.content = RequestContent::Unavailable(reason);
        self
    }

    pub fn dpop(mut self, proof: &str) -> Self {
        self.dpop = HeaderCount::Once(proof.to_string());
        self
    }

    pub fn status_token(mut self, token: &[u8]) -> Self {
        self.status_token = HeaderCount::Once(b64(token));
        self
    }

    pub fn receipt(mut self, receipt: &[u8]) -> Self {
        self.receipt = HeaderCount::Once(b64(receipt));
        self
    }

    pub fn peer_certificate(mut self, pem: &str) -> Self {
        self.peer_certificate_pem = Some(pem.to_string());
        self
    }

    pub fn authority(mut self, authority: &str) -> Self {
        self.authority = Some(AuthoritySource::ProxyAsserted(authority.to_string()));
        self
    }

    pub fn no_authority(mut self) -> Self {
        self.authority = None;
        self
    }

    pub fn no_raw_headers(mut self) -> Self {
        self.raw_values_available = false;
        self.dpop = HeaderCount::Uncountable;
        self
    }

    pub fn duplicate_dpop(mut self) -> Self {
        self.dpop = HeaderCount::Repeated(2);
        self
    }

    pub fn method(mut self, method: &str) -> Self {
        self.method = method.to_string();
        self
    }

    pub fn build(self) -> RequestFacts {
        RequestFacts {
            method: self.method,
            target: self.target,
            authority: self.authority,
            headers: SecurityHeaders {
                dpop: self.dpop,
                authorization: self.authorization,
                receipt: self.receipt,
                status_token: self.status_token,
                raw_values_available: self.raw_values_available,
            },
            peer_certificate_pem: self.peer_certificate_pem,
            content: self.content,
        }
    }
}

/// The URL a caller signs when calling this callee.
pub fn callee_url(path: &str) -> String {
    format!("https://{CALLEE_AUTHORITY}{path}")
}

/// Re-sign a proof with selected payload changes for negative conformance cases.
pub fn rewrite_payload(
    identity: &Identity,
    proof: &str,
    change: impl FnOnce(&mut serde_json::Value),
) -> String {
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use p256::pkcs8::DecodePrivateKey as _;
    let parts: Vec<_> = proof.split('.').collect();
    let mut payload: serde_json::Value =
        serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    change(&mut payload);
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let input = format!("{}.{encoded}", parts[0]);
    let key = SigningKey::from_pkcs8_der(&identity.pkcs8).unwrap();
    let signature: Signature = key.sign_prehash(&Sha256::digest(input.as_bytes())).unwrap();
    format!(
        "{input}.{}",
        BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}
