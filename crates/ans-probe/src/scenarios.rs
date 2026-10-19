//! The refusal matrix.
//!
//! Checking that a valid request succeeds tells you almost nothing — a deployment
//! with verification switched off passes that. What matters is whether each
//! specific way a request can be wrong is refused, and with the right reason.
//!
//! `ans-authz` returns the ANS-6 denial label in `x-ans-deny-label`, so each case
//! asserts the exact label rather than just "not 200". A deployment that refuses
//! everything for the wrong reason is also broken.

use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::bundle::Bundle;

/// One case in the matrix.
pub struct Outcome {
    /// What was attempted.
    pub name: &'static str,
    /// The ANS-6 section it exercises.
    pub spec: &'static str,
    /// What should have happened.
    pub expected: &'static str,
    /// What did happen.
    pub actual: String,
    /// Whether it matched.
    pub passed: bool,
}

impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outcome")
            .field("name", &self.name)
            .field("passed", &self.passed)
            .finish_non_exhaustive()
    }
}

/// How a request should be answered.
enum Expect {
    /// Authenticated.
    Allow,
    /// Refused, with this `x-ans-deny-label`.
    Deny(&'static str),
}

struct Sent {
    status: u16,
    label: Option<String>,
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

/// Run every case against a live endpoint.
///
/// `send_to` is where the request goes; `signed_origin` is the externally-visible
/// origin the caller signs into `htu`. They differ in every realistic deployment:
/// a caller signs `https://api.example.com/...` while the packet arrives at a
/// cluster IP or a forwarded local port. `ans-authz` compares against the origin
/// Envoy asserts, not the socket the request came in on — which is exactly what
/// ANS-6 §7.7 requires, and what makes the example A.6 attack fail.
pub async fn run(send_to: &str, signed_origin: &str, path: &str, bundle: &Bundle) -> Vec<Outcome> {
    let url = format!("{}{}", send_to.trim_end_matches('/'), path);
    let signed_url = format!("{}{}", signed_origin.trim_end_matches('/'), path);

    let client = match reqwest::Client::builder().build() {
        Ok(c) => c,
        Err(e) => {
            return vec![failed(
                "client",
                "—",
                format!("cannot build HTTP client: {e}"),
            )];
        }
    };
    let signer = match bundle.signer() {
        Ok(s) => s,
        Err(e) => {
            return vec![failed(
                "signer",
                "—",
                format!("cannot build a DPoP signer: {e}"),
            )];
        }
    };

    let ctx = Ctx {
        client,
        signer,
        url,
        signed_url,
        signed_origin: signed_origin.trim_end_matches('/').to_string(),
    };

    let mut out = Vec::new();
    out.extend(possession_cases(&ctx, bundle).await);
    out.extend(binding_cases(&ctx, bundle).await);
    out.extend(content_cases(&ctx, bundle).await);
    out
}

/// Everything a case needs, so the groups stay readable.
struct Ctx {
    client: reqwest::Client,
    /// Where the request is sent.
    url: String,
    /// The externally-visible URL the caller signs.
    signed_url: String,
    /// Origin part of `signed_url`, for the path-mismatch case.
    signed_origin: String,
    signer: ans_verify::Signer,
}

/// The happy path, replay, header hygiene, and missing evidence.
async fn possession_cases(ctx: &Ctx, bundle: &Bundle) -> Vec<Outcome> {
    let mut out = Vec::new();

    // Kept first so a total failure is obvious before reading the refusals.
    let proof = match ctx.signer.sign("POST", &ctx.signed_url, None) {
        Ok(p) => p,
        Err(e) => {
            out.push(failed(
                "valid request",
                "§7",
                format!("cannot mint a proof: {e}"),
            ));
            return out;
        }
    };
    out.push(check(
        "valid request",
        "§7",
        &Expect::Allow,
        send(
            ctx,
            "POST",
            std::slice::from_ref(&proof),
            bundle,
            true,
            true,
            None,
        )
        .await,
    ));

    // §7.6 — the *same* proof again. Single-use is the whole point of the jti.
    out.push(check(
        "replayed proof",
        "§7.6",
        &Expect::Deny("REPLAY"),
        send(ctx, "POST", &[proof], bundle, true, true, None).await,
    ));

    // §4.6 — only detectable when Envoy has encode_raw_headers: true. A 200 or a
    // MALFORMED_PROOF here means that field is missing.
    if let (Ok(a), Ok(b)) = (
        ctx.signer.sign("POST", &ctx.signed_url, None),
        ctx.signer.sign("POST", &ctx.signed_url, None),
    ) {
        out.push(check(
            "two DPoP headers",
            "§4.6",
            &Expect::Deny("DUPLICATE_HEADER"),
            send(ctx, "POST", &[a, b], bundle, true, true, None).await,
        ));
    }

    // §7.11 — a stripped artifact is a rejection, not a fallback trigger.
    if let Ok(p) = ctx.signer.sign("POST", &ctx.signed_url, None) {
        out.push(check(
            "no status token",
            "§7.11",
            &Expect::Deny("MISSING_HEADERS"),
            send(ctx, "POST", &[p], bundle, false, true, None).await,
        ));
    }

    out.push(check(
        "no credential at all",
        "§7.11",
        &Expect::Deny("NO_CREDENTIAL"),
        send(ctx, "POST", &[], bundle, true, true, None).await,
    ));

    out
}

/// What the proof is bound to: origin, path, method.
async fn binding_cases(ctx: &Ctx, bundle: &Bundle) -> Vec<Outcome> {
    let mut out = Vec::new();

    // §7.7, the example A.6 attack. The proof is genuine and unspent; only the
    // authority comparison stops it. If this passes, the comparison URL is coming
    // from the request rather than from context_extensions.
    if let Ok(p) = ctx
        .signer
        .sign("POST", "https://payments.other.invalid/api/task", None)
    {
        out.push(check(
            "proof minted for another origin",
            "§7.7 / A.6",
            &Expect::Deny("HTTP_BINDING_MISMATCH"),
            send(ctx, "POST", &[p], bundle, true, true, None).await,
        ));
    }

    // §7.3 — a reconstruction that ignored the path would accept this.
    let other_path = format!("{}/healthz", ctx.signed_origin);
    if let Ok(p) = ctx.signer.sign("POST", &other_path, None) {
        out.push(check(
            "proof minted for another path",
            "§7.3",
            &Expect::Deny("HTTP_BINDING_MISMATCH"),
            send(ctx, "POST", &[p], bundle, true, true, None).await,
        ));
    }

    // §7.2 — htm binds the method.
    if let Ok(p) = ctx.signer.sign("POST", &ctx.signed_url, None) {
        out.push(check(
            "proof minted for another method",
            "§7.2",
            &Expect::Deny("HTTP_BINDING_MISMATCH"),
            send(ctx, "DELETE", &[p], bundle, true, true, None).await,
        ));
    }

    out
}

/// §7.13 — what a TLS-terminating hop can do to a body.
async fn content_cases(ctx: &Ctx, bundle: &Bundle) -> Vec<Outcome> {
    let mut out = Vec::new();

    // Bind one body, deliver another. On a *first* request this trips no replay
    // defence — the jti is unseen and the iat fresh. Only the digest catches it.
    let signed = format!(r#"{{"amount":100,"n":{}}}"#, unique_suffix());
    if let Ok(p) = ctx
        .signer
        .sign_with_content("POST", &ctx.signed_url, None, signed.as_bytes())
    {
        out.push(check(
            "bound body altered in flight",
            "§7.13",
            &Expect::Deny("CONTENT_BINDING_MISMATCH"),
            send(
                ctx,
                "POST",
                &[p],
                bundle,
                true,
                true,
                Some(br#"{"amount":900000}"#.to_vec()),
            )
            .await,
        ));
    }

    // The same binding, honoured. A CONTENT_BINDING_MISMATCH here means Envoy is
    // not supplying bodies (`with_request_body`), so there was nothing to compare.
    let body = format!(r#"{{"amount":100,"n":{}}}"#, unique_suffix());
    if let Ok(p) = ctx
        .signer
        .sign_with_content("POST", &ctx.signed_url, None, body.as_bytes())
    {
        out.push(check(
            "bound body delivered intact",
            "§7.13",
            &Expect::Allow,
            send(
                ctx,
                "POST",
                &[p],
                bundle,
                true,
                true,
                Some(body.into_bytes()),
            )
            .await,
        ));
    }

    out
}

async fn send(
    ctx: &Ctx,
    method: &str,
    proofs: &[String],
    bundle: &Bundle,
    with_status_token: bool,
    with_receipt: bool,
    body: Option<Vec<u8>>,
) -> Result<Sent, String> {
    let mut headers = HeaderMap::new();

    // `append` rather than `insert`, so the duplicate-header case actually puts two
    // DPoP headers on the wire.
    for proof in proofs {
        let value = HeaderValue::from_str(proof).map_err(|e| e.to_string())?;
        headers.append(HeaderName::from_static("dpop"), value);
    }
    if with_status_token {
        headers.insert(
            HeaderName::from_static("x-ans-status-token"),
            HeaderValue::from_str(&bundle.status_token_b64).map_err(|e| e.to_string())?,
        );
    }
    if with_receipt {
        headers.insert(
            HeaderName::from_static("x-scitt-receipt"),
            HeaderValue::from_str(&bundle.receipt_b64).map_err(|e| e.to_string())?,
        );
    }

    let verb = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
    let mut request = ctx.client.request(verb, &ctx.url).headers(headers);
    if let Some(bytes) = body {
        request = request
            .header("content-type", "application/json")
            .body(bytes);
    }

    let response = request.send().await.map_err(|e| e.to_string())?;
    let status = response.status().as_u16();
    let label = response
        .headers()
        .get("x-ans-deny-label")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    Ok(Sent { status, label })
}

fn check(
    name: &'static str,
    spec: &'static str,
    expected: &Expect,
    sent: Result<Sent, String>,
) -> Outcome {
    let sent = match sent {
        Ok(s) => s,
        Err(e) => return failed(name, spec, format!("request failed: {e}")),
    };

    let describe = |s: &Sent| match s.label.as_deref() {
        Some(l) => format!("{} {}", s.status, l),
        None => s.status.to_string(),
    };

    match *expected {
        Expect::Allow => {
            let passed = (200..300).contains(&sent.status);
            Outcome {
                name,
                spec,
                expected: "2xx",
                actual: describe(&sent),
                passed,
            }
        }
        Expect::Deny(label) => {
            let passed = sent.status >= 400 && sent.label.as_deref() == Some(label);
            Outcome {
                name,
                spec,
                expected: label,
                actual: describe(&sent),
                passed,
            }
        }
    }
}

fn failed(name: &'static str, spec: &'static str, actual: String) -> Outcome {
    Outcome {
        name,
        spec,
        expected: "—",
        actual,
        passed: false,
    }
}
