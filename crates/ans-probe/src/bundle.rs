//! Minting the ANS-6 artifacts a demo deployment needs.
//!
//! A real deployment gets these from a Transparency Log. A demo does not need one:
//! §4.5 calls a pinned, static key store "a valid posture", so this mints its own
//! TL key, publishes it as a C2SP signed-note line for `static_root_keys`, and
//! signs a status token and receipt with it.
//!
//! The TL key is derived from a seed so re-running `mint` produces the same C2SP
//! line — the deployment's `ConfigMap` does not need regenerating between runs.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePublicKey as _;
use sha2::{Digest, Sha256};

/// Anything that can go wrong minting a bundle.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// A certificate or key fixture could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// Path attempted.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The TL seed did not yield a usable P-256 key.
    #[error("invalid TL signing key: {0}")]
    Key(String),
    /// CBOR encoding failed.
    #[error("CBOR encode failed: {0}")]
    Cbor(String),
    /// The identity certificate could not be turned into a `DPoP` signer.
    #[error("cannot build a DPoP signer: {0}")]
    Signer(String),
}

/// A complete demo bundle: everything a caller and a callee need.
pub struct Bundle {
    /// C2SP signed-note line for the callee's `static_root_keys` (§4.5).
    pub c2sp_line: String,
    /// Standard-base64 `X-ANS-Status-Token` header value.
    pub status_token_b64: String,
    /// Standard-base64 `X-SCITT-Receipt` header value.
    pub receipt_b64: String,
    /// The caller's `ans://` name.
    pub ans_name: String,
    /// The caller's agent id.
    pub agent_id: String,
    /// Identity certificate DER.
    pub cert_der: Vec<u8>,
    /// Identity private key, PKCS#8 DER.
    pub pkcs8: Vec<u8>,
    /// When the status token expires, Unix seconds.
    pub expires_at: i64,
}

impl std::fmt::Debug for Bundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bundle")
            .field("ans_name", &self.ans_name)
            .field("agent_id", &self.agent_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl Bundle {
    /// A `DPoP` signer for the caller identity in this bundle.
    pub fn signer(&self) -> Result<ans_verify::Signer, BundleError> {
        ans_verify::Signer::from_pkcs8_der(&self.pkcs8, self.cert_der.clone())
            .map_err(|e| BundleError::Signer(e.to_string()))
    }
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0)
}

fn read(path: &Path) -> Result<Vec<u8>, BundleError> {
    std::fs::read(path).map_err(|source| BundleError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn cbor(value: &ciborium::Value) -> Result<Vec<u8>, BundleError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|e| BundleError::Cbor(e.to_string()))?;
    Ok(buf)
}

/// Mint a bundle.
///
/// `agents_dir` holds the committed demo certificates — the same ones the test
/// suite uses, so a demo run and `cargo test` exercise identical material.
pub fn mint(
    agents_dir: &Path,
    agent: &str,
    ans_name: &str,
    agent_id: &str,
    tl_seed: u8,
    ttl_secs: i64,
) -> Result<Bundle, BundleError> {
    let cert_der = read(&agents_dir.join(format!("{agent}.cert.der")))?;
    let pkcs8 = read(&agents_dir.join(format!("{agent}.key.pk8")))?;
    let fingerprint = ans_types::CertFingerprint::from_der(&cert_der);

    let tl = SigningKey::from_slice(&[tl_seed; 32])
        .map_err(|e| BundleError::Key(format!("seed {tl_seed}: {e}")))?;
    let spki = tl
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| BundleError::Key(e.to_string()))?;
    let digest = Sha256::digest(spki.as_bytes());
    let kid = [digest[0], digest[1], digest[2], digest[3]];

    // §4.5 C2SP signed-note verifier line: <name>+<key_hash>+<base64 SPKI>
    let c2sp_line = format!(
        "tl.demo.invalid+{}+{}",
        hex::encode(kid),
        BASE64_STANDARD.encode(spki.as_bytes())
    );

    let iat = now();
    let exp = iat + ttl_secs;

    let status_token = status_token(&tl, agent_id, ans_name, &fingerprint, iat, exp)?;
    let host = ans_types::AnsName::parse(ans_name).map_or_else(
        |_| "caller.example.com".to_string(),
        |n| n.fqdn().as_str().to_string(),
    );
    let receipt = receipt(&tl, agent_id, ans_name, &host)?;

    Ok(Bundle {
        c2sp_line,
        status_token_b64: BASE64_STANDARD.encode(&status_token),
        receipt_b64: BASE64_STANDARD.encode(&receipt),
        ans_name: ans_name.to_string(),
        agent_id: agent_id.to_string(),
        cert_der,
        pkcs8,
        expires_at: exp,
    })
}

/// `SHA-256` over the `COSE_Sign1` `Sig_structure`.
fn sig_structure_digest(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, BundleError> {
    let structure = ciborium::Value::Array(vec![
        ciborium::Value::Text("Signature1".to_string()),
        ciborium::Value::Bytes(protected.to_vec()),
        ciborium::Value::Bytes(Vec::new()),
        ciborium::Value::Bytes(payload.to_vec()),
    ]);
    Ok(Sha256::digest(cbor(&structure)?).to_vec())
}

/// The protected header a TL artifact carries (§4.3, §4.4).
fn protected_header(tl: &SigningKey, with_vds: bool) -> Result<Vec<u8>, BundleError> {
    let spki = tl
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| BundleError::Key(e.to_string()))?;
    let digest = Sha256::digest(spki.as_bytes());

    let mut pairs = vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer((-7_i64).into()),
        ),
        (
            ciborium::Value::Integer(4.into()),
            ciborium::Value::Bytes(vec![digest[0], digest[1], digest[2], digest[3]]),
        ),
    ];
    if with_vds {
        pairs.push((
            ciborium::Value::Integer(395.into()),
            ciborium::Value::Integer(1.into()),
        ));
    }
    cbor(&ciborium::Value::Map(pairs))
}

fn sign_cose(
    tl: &SigningKey,
    protected: Vec<u8>,
    unprotected: ciborium::Value,
    payload: &[u8],
) -> Result<Vec<u8>, BundleError> {
    let digest = sig_structure_digest(&protected, payload)?;
    let (sig, _): (Signature, _) = tl
        .sign_prehash(&digest)
        .map_err(|e| BundleError::Key(e.to_string()))?;
    cbor(&ciborium::Value::Array(vec![
        ciborium::Value::Bytes(protected),
        unprotected,
        ciborium::Value::Bytes(payload.to_vec()),
        ciborium::Value::Bytes(sig.to_bytes().to_vec()),
    ]))
}

/// §4.4 status token: `COSE_Sign1` over an integer-keyed CBOR map.
fn status_token(
    tl: &SigningKey,
    agent_id: &str,
    ans_name: &str,
    fingerprint: &ans_types::CertFingerprint,
    iat: i64,
    exp: i64,
) -> Result<Vec<u8>, BundleError> {
    let cert_entry = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Bytes(fingerprint.as_bytes().to_vec()),
        ),
        (
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Text("X509-OV-CLIENT".to_string()),
        ),
    ]);

    let payload = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text(agent_id.to_string()),
        ),
        (
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Text("ACTIVE".to_string()),
        ),
        (
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Integer(iat.into()),
        ),
        (
            ciborium::Value::Integer(4.into()),
            ciborium::Value::Integer(exp.into()),
        ),
        (
            ciborium::Value::Integer(5.into()),
            ciborium::Value::Text(ans_name.to_string()),
        ),
        (
            ciborium::Value::Integer(6.into()),
            ciborium::Value::Array(vec![cert_entry]),
        ),
        (
            ciborium::Value::Integer(7.into()),
            ciborium::Value::Array(Vec::new()),
        ),
    ]);

    sign_cose(
        tl,
        protected_header(tl, false)?,
        ciborium::Value::Map(Vec::new()),
        &cbor(&payload)?,
    )
}

/// §4.3 receipt for a single-leaf log.
///
/// `tree_size: 1, leaf_index: 0` with an empty `hash_path` is a genuine RFC 9162
/// inclusion proof — the walk consumes no path elements and `sn` is already zero —
/// so the callee does real Merkle verification rather than skipping it.
fn receipt(
    tl: &SigningKey,
    agent_id: &str,
    ans_name: &str,
    agent_host: &str,
) -> Result<Vec<u8>, BundleError> {
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
                    "agent": { "host": agent_host, "name": "demo", "version": "1.0.0" }
                },
                "keyId": "demo",
                "signature": "eyJhbGciOiJFUzI1NiJ9"
            }
        },
        "signature": "eyJhbGciOiJFUzI1NiJ9"
    });
    let event_bytes = serde_json::to_vec(&leaf).map_err(|e| BundleError::Cbor(e.to_string()))?;

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

    sign_cose(
        tl,
        protected_header(tl, true)?,
        ciborium::Value::Map(vec![(ciborium::Value::Integer(396.into()), vdp)]),
        &event_bytes,
    )
}

/// Write a bundle to disk for reuse across probe invocations.
pub fn write(bundle: &Bundle, out: &Path) -> Result<Vec<PathBuf>, BundleError> {
    std::fs::create_dir_all(out).map_err(|source| BundleError::Io {
        path: out.display().to_string(),
        source,
    })?;

    let files = [
        ("tl-root-keys.txt", bundle.c2sp_line.as_bytes().to_vec()),
        (
            "status-token.b64",
            bundle.status_token_b64.as_bytes().to_vec(),
        ),
        ("receipt.b64", bundle.receipt_b64.as_bytes().to_vec()),
        ("caller.cert.der", bundle.cert_der.clone()),
        ("caller.key.pk8", bundle.pkcs8.clone()),
    ];

    let mut written = Vec::new();
    for (name, bytes) in files {
        let path = out.join(name);
        std::fs::write(&path, bytes).map_err(|source| BundleError::Io {
            path: path.display().to_string(),
            source,
        })?;
        written.push(path);
    }
    Ok(written)
}

/// Read a previously written bundle.
pub fn load(dir: &Path, ans_name: &str, agent_id: &str) -> Result<Bundle, BundleError> {
    let text = |name: &str| -> Result<String, BundleError> {
        Ok(String::from_utf8_lossy(&read(&dir.join(name))?)
            .trim()
            .to_string())
    };

    Ok(Bundle {
        c2sp_line: text("tl-root-keys.txt")?,
        status_token_b64: text("status-token.b64")?,
        receipt_b64: text("receipt.b64")?,
        ans_name: ans_name.to_string(),
        agent_id: agent_id.to_string(),
        cert_der: read(&dir.join("caller.cert.der"))?,
        pkcs8: read(&dir.join("caller.key.pk8"))?,
        // Not persisted; only `mint` reports it.
        expires_at: 0,
    })
}
