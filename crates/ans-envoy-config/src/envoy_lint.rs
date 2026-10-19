//! Linting Envoy configuration for the settings ANS-6 conformance depends on.
//!
//! Five Envoy settings decide whether a deployment satisfies ANS-6, and none of
//! them live in this service's own configuration. A user who splices the shipped
//! filter fragment into an existing config and forgets `encode_raw_headers: true`
//! gets a deployment that passes every functional test and silently accepts
//! duplicate `DPoP` headers — a §4.6 MUST, unenforced, with no outward sign.
//!
//! This linter is the first of three defences. The second is request-time
//! detection (a `CheckRequest` with no raw header map means `encode_raw_headers`
//! is off, and every request is then denied). The third is documentation. Only the
//! second is not bypassable, and it cannot cover path normalization or filter
//! ordering — those remain config trust, which is inherent to running out of
//! process.
//!
//! The linter is deliberately structural rather than schema-aware: it walks the
//! YAML looking for typed configs by `@type` suffix, so it works on a full
//! bootstrap, a fragment, or an xDS response dump without needing Envoy's protos.

use serde_yaml::Value;

/// How much a finding matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Conformance is broken. Do not deploy.
    Error,
    /// Likely wrong, or a known footgun.
    Warning,
    /// Worth stating explicitly in config so a diff shows it.
    Note,
}

impl Severity {
    /// Short label for output.
    pub fn label(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Note => "note",
        }
    }
}

/// One thing the linter found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFinding {
    /// How much it matters.
    pub severity: Severity,
    /// The Envoy setting concerned.
    pub setting: &'static str,
    /// The ANS-6 section that motivates it.
    pub spec: &'static str,
    /// What is wrong and what to do.
    pub message: String,
}

impl std::fmt::Display for LintFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} [{}] — {}",
            self.severity.label(),
            self.setting,
            self.spec,
            self.message
        )
    }
}

/// Errors from running the linter.
#[derive(Debug, thiserror::Error)]
pub enum LintError {
    /// The input was not parseable YAML.
    #[error("not valid YAML: {0}")]
    NotYaml(#[from] serde_yaml::Error),
}

fn finding(
    severity: Severity,
    setting: &'static str,
    spec: &'static str,
    message: impl Into<String>,
) -> LintFinding {
    LintFinding {
        severity,
        setting,
        spec,
        message: message.into(),
    }
}

/// Lint an Envoy configuration document.
///
/// `expect_method_a` adds the checks that only matter when this deployment
/// accepts mTLS callers, so a Method-B-only config is not nagged about a client
/// certificate it does not want.
pub fn lint(yaml: &str, expect_method_a: bool) -> Result<Vec<LintFinding>, LintError> {
    let root: Value = serde_yaml::from_str(yaml)?;
    let mut out = Vec::new();

    let ext_authz = find_typed(&root, "ext_authz.v3.ExtAuthz");
    if ext_authz.is_empty() {
        out.push(finding(
            Severity::Warning,
            "envoy.filters.http.ext_authz",
            "—",
            "no ext_authz filter config found in this document. If this is a \
             fragment that is expected; if it is a full bootstrap, ANS-6 \
             verification is not wired in at all.",
        ));
    }

    for cfg in &ext_authz {
        lint_ext_authz(cfg, expect_method_a, &mut out);
    }

    for hcm in find_typed(&root, "HttpConnectionManager") {
        lint_path_fidelity(hcm, &mut out);
    }

    lint_route_rewrites(&root, &mut out);

    if find_typed(&root, "ExtAuthzPerRoute").is_empty() && !ext_authz.is_empty() {
        out.push(finding(
            Severity::Note,
            "typed_per_filter_config / ExtAuthzPerRoute",
            "§7.7",
            "no per-route ExtAuthzPerRoute found, so no context_extensions can \
             assert the externally-visible authority. That is fine only if \
             ans-authz runs with authority.mode = \"sole_configured\" and a single \
             authority.",
        ));
    }

    out.sort_by_key(|f| f.severity);
    Ok(out)
}

fn lint_ext_authz(cfg: &Value, expect_method_a: bool, out: &mut Vec<LintFinding>) {
    lint_fail_closed(cfg, out);
    lint_transport(cfg, expect_method_a, out);
    lint_body_buffering(cfg, out);
}

/// §4.6 duplicate detection and the fail-closed posture.
fn lint_fail_closed(cfg: &Value, out: &mut Vec<LintFinding>) {
    // §4.6 — the single most-missed field.
    match cfg.get("encode_raw_headers") {
        Some(Value::Bool(true)) => {}
        _ => out.push(finding(
            Severity::Error,
            "encode_raw_headers",
            "§4.6",
            "must be `true`. With it unset, Envoy comma-merges same-name headers \
             into the `headers` map, so two `DPoP` headers arrive indistinguishable \
             from one containing a comma and §4.6 duplicate rejection becomes \
             impossible. ans-authz denies every request when it detects this.",
        )),
    }

    // Fail-closed posture.
    if matches!(cfg.get("failure_mode_allow"), Some(Value::Bool(true))) {
        out.push(finding(
            Severity::Error,
            "failure_mode_allow",
            "§7.6, §9.6",
            "must be `false` (the default). With `true`, Envoy admits requests \
             whenever this authorizer is unreachable — the opposite of what §7.6 \
             and §9.6 require, and it converts an authenticator outage into an \
             open door.",
        ));
    } else if cfg.get("failure_mode_allow").is_none() {
        out.push(finding(
            Severity::Note,
            "failure_mode_allow",
            "§7.6",
            "defaults to false, which is correct. State it explicitly so a change \
             shows up in a diff.",
        ));
    }

    // `shadow_mode` is documented as equivalent to forced fail-open.
    if matches!(cfg.get("shadow_mode"), Some(Value::Bool(true))) {
        out.push(finding(
            Severity::Error,
            "shadow_mode",
            "§7.6",
            "must not be enabled: shadow mode is equivalent to forced fail-open, so \
             every denial this service issues would be ignored.",
        ));
    }
}

/// Transport-level settings and Method-A prerequisites.
fn lint_transport(cfg: &Value, expect_method_a: bool, out: &mut Vec<LintFinding>) {
    // The gRPC default timeout is 200ms, which is tight for two or three
    // signature verifications plus a shared-store round trip.
    let timeout = cfg
        .get("grpc_service")
        .and_then(|g| g.get("timeout"))
        .is_some();
    if !timeout {
        out.push(finding(
            Severity::Warning,
            "grpc_service.timeout",
            "§9.6",
            "not set, so Envoy uses its 200ms default. ANS-6 verification does two \
             or three ECDSA verifications and may consult a shared replay store; \
             set an explicit timeout above the replay deadline.",
        ));
    }

    if matches!(cfg.get("include_peer_certificate"), Some(Value::Bool(true))) {
        if !expect_method_a {
            out.push(finding(
                Severity::Note,
                "include_peer_certificate",
                "§6.1",
                "enabled, but this deployment is not configured for Method A. \
                 Harmless, but the certificate will be ignored.",
            ));
        }
    } else if expect_method_a {
        out.push(finding(
            Severity::Error,
            "include_peer_certificate",
            "§6.1",
            "must be `true` for Method A: without it the validated client \
             certificate never reaches this service, so there is no identity to \
             bind to a status token.",
        ));
    }

    if let Some(v) = cfg.get("transport_api_version")
        && v.as_str() != Some("V3")
    {
        out.push(finding(
            Severity::Warning,
            "transport_api_version",
            "—",
            "should be `V3`; this service implements envoy.service.auth.v3.",
        ));
    }
}

/// §7.13 body buffering.
fn lint_body_buffering(cfg: &Value, out: &mut Vec<LintFinding>) {
    let Some(body) = cfg
        .get("with_request_body")
        .filter(|b| !matches!(b, Value::Null))
    else {
        out.push(finding(
            Severity::Error,
            "with_request_body",
            "§7.13",
            "required: Method B always binds content, including empty content. Configure complete raw body buffering before deploying.",
        ));
        return;
    };

    // A prefix hash never matches a whole-content digest, so it is
    // indistinguishable from tampering — and §7.13 requires the comparison to
    // complete "before acting on any of the content", which a prefix cannot do.
    if matches!(body.get("allow_partial_message"), Some(Value::Bool(true))) {
        out.push(finding(
            Severity::Error,
            "with_request_body.allow_partial_message",
            "§7.13",
            "must be `false`. With `true`, Envoy truncates the body at
             max_request_bytes and flags it with `x-envoy-auth-partial-body`;
             hashing a prefix and comparing it to a whole-content digest is
             indistinguishable from tampering. ans-authz refuses such requests.",
        ));
    }

    // The string `body` field replaces non-UTF-8 bytes with '!', so a digest over
    // it is not a digest over what the caller signed.
    if !matches!(body.get("pack_as_bytes"), Some(Value::Bool(true))) {
        out.push(finding(
            Severity::Error,
            "with_request_body.pack_as_bytes",
            "§7.13",
            "must be `true`. Without it Envoy sends the body as a UTF-8 string with
             invalid bytes replaced, and a digest over replaced bytes does not match
             the octets the caller signed.",
        ));
    }

    match body.get("max_request_bytes").and_then(Value::as_u64) {
        Some(n) if n > 0 => {}
        _ => out.push(finding(
            Severity::Error,
            "with_request_body.max_request_bytes",
            "§7.13",
            "must be set and greater than zero — Envoy requires it. It is a hard
             ceiling: above it Envoy answers 413 itself and never calls ans-authz,
             which is a rejection rather than a silent pass. Size it for the largest
             legitimate request.",
        )),
    }
}

fn lint_path_fidelity(hcm: &Value, out: &mut Vec<LintFinding>) {
    // §7.3 wants the path preserved byte-for-byte. Envoy hands ext_authz the
    // path after HCM normalization, so these must be pinned off — and this is a
    // check the running service cannot make for itself, because a normalized path
    // is indistinguishable from one the client sent that way.
    for (field, expect_false) in [("normalize_path", true), ("merge_slashes", true)] {
        match hcm.get(field) {
            Some(Value::Bool(false)) => {}
            Some(Value::Bool(true)) => out.push(finding(
                Severity::Error,
                match field {
                    "normalize_path" => "normalize_path",
                    _ => "merge_slashes",
                },
                "§7.3",
                "must be `false` on a Method-B listener. Envoy rewrites the path \
                 before this service sees it, so `htu` would be compared against a \
                 path the caller never signed.",
            )),
            _ if expect_false => out.push(finding(
                Severity::Warning,
                match field {
                    "normalize_path" => "normalize_path",
                    _ => "merge_slashes",
                },
                "§7.3",
                "not set explicitly. Envoy's default has changed across versions \
                 and is runtime-guarded; pin it to `false` so §7.3 path fidelity \
                 does not depend on the Envoy build.",
            )),
            _ => {}
        }
    }

    match hcm
        .get("path_with_escaped_slashes_action")
        .and_then(Value::as_str)
    {
        Some("KEEP_UNCHANGED") => {}
        Some(other) => out.push(finding(
            Severity::Error,
            "path_with_escaped_slashes_action",
            "§7.3",
            format!(
                "is `{other}` but must be `KEEP_UNCHANGED`: rewriting %2F changes \
                 the path bytes the caller signed."
            ),
        )),
        None => out.push(finding(
            Severity::Warning,
            "path_with_escaped_slashes_action",
            "§7.3",
            "not set; pin it to `KEEP_UNCHANGED` so escaped-slash handling cannot \
             alter the signed path.",
        )),
    }
}

fn lint_route_rewrites(root: &Value, out: &mut Vec<LintFinding>) {
    for field in ["prefix_rewrite", "regex_rewrite"] {
        if contains_key(root, field) {
            out.push(finding(
                Severity::Error,
                match field {
                    "prefix_rewrite" => "route.prefix_rewrite",
                    _ => "route.regex_rewrite",
                },
                "§7.3, §11.5",
                "a path rewrite on a Method-B route breaks the `htu` binding by \
                 design: the proof binds the URL the caller signed, not what a \
                 middlebox produced. Terminate verification at a hop that sees the \
                 externally-visible path, or drop the rewrite.",
            ));
        }
    }
}

/// Collect every mapping whose `@type` ends with `suffix`.
fn find_typed<'a>(value: &'a Value, suffix: &str) -> Vec<&'a Value> {
    let mut out = Vec::new();
    walk(value, &mut |v| {
        if let Some(t) = v.get("@type").and_then(Value::as_str)
            && t.ends_with(suffix)
        {
            out.push(v);
        }
    });
    out
}

/// Whether any mapping anywhere carries `key`.
fn contains_key(value: &Value, key: &str) -> bool {
    let mut found = false;
    walk(value, &mut |v| {
        if v.get(key).is_some() {
            found = true;
        }
    });
    found
}

/// Visit every mapping in the document.
fn walk<'a>(value: &'a Value, f: &mut impl FnMut(&'a Value)) {
    match value {
        Value::Mapping(map) => {
            f(value);
            for (_, v) in map {
                walk(v, f);
            }
        }
        Value::Sequence(seq) => {
            for v in seq {
                walk(v, f);
            }
        }
        _ => {}
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    fn errors(findings: &[LintFinding]) -> Vec<&'static str> {
        findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .map(|f| f.setting)
            .collect()
    }

    const GOOD: &str = r#"
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    encode_raw_headers: true
    with_request_body:
      max_request_bytes: 1048576
      allow_partial_message: false
      pack_as_bytes: true
    failure_mode_allow: false
    grpc_service:
      envoy_grpc:
        cluster_name: ans_authz
      timeout: 1s
route_config:
  virtual_hosts:
  - name: api
    typed_per_filter_config:
      envoy.filters.http.ext_authz:
        "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
        check_settings:
          context_extensions:
            ans_trusted_authority: api.example.com
"#;

    #[test]
    fn a_correct_fragment_has_no_errors() {
        let f = lint(GOOD, false).unwrap();
        assert!(errors(&f).is_empty(), "unexpected errors: {f:?}");
    }

    #[test]
    fn missing_encode_raw_headers_is_an_error() {
        let bad = GOOD.replace("    encode_raw_headers: true\n", "");
        let f = lint(&bad, false).unwrap();
        assert!(errors(&f).contains(&"encode_raw_headers"));
    }

    #[test]
    fn encode_raw_headers_false_is_an_error() {
        let bad = GOOD.replace("encode_raw_headers: true", "encode_raw_headers: false");
        let f = lint(&bad, false).unwrap();
        assert!(errors(&f).contains(&"encode_raw_headers"));
    }

    #[test]
    fn failure_mode_allow_true_is_an_error() {
        let bad = GOOD.replace("failure_mode_allow: false", "failure_mode_allow: true");
        let f = lint(&bad, false).unwrap();
        assert!(errors(&f).contains(&"failure_mode_allow"));
    }

    #[test]
    fn shadow_mode_is_an_error() {
        let bad = GOOD.replace(
            "    encode_raw_headers: true",
            "    encode_raw_headers: true\n    shadow_mode: true",
        );
        let f = lint(&bad, false).unwrap();
        assert!(errors(&f).contains(&"shadow_mode"));
    }

    #[test]
    fn a_missing_grpc_timeout_is_a_warning_because_the_default_is_200ms() {
        let bad = GOOD.replace("      timeout: 1s\n", "");
        let f = lint(&bad, false).unwrap();
        assert!(
            f.iter()
                .any(|x| x.setting == "grpc_service.timeout" && x.severity == Severity::Warning)
        );
    }

    #[test]
    fn method_a_without_the_peer_certificate_is_an_error() {
        let f = lint(GOOD, true).unwrap();
        assert!(errors(&f).contains(&"include_peer_certificate"));
    }

    #[test]
    fn method_a_with_the_peer_certificate_is_clean() {
        let good_a = GOOD.replace(
            "    encode_raw_headers: true",
            "    encode_raw_headers: true\n    include_peer_certificate: true",
        );
        let f = lint(&good_a, true).unwrap();
        assert!(errors(&f).is_empty(), "unexpected: {f:?}");
    }

    #[test]
    fn partial_body_buffering_is_an_error() {
        let bad = GOOD.replace(
            "allow_partial_message: false",
            "allow_partial_message: true",
        );
        let f = lint(&bad, false).unwrap();
        assert!(errors(&f).contains(&"with_request_body.allow_partial_message"));
    }

    #[test]
    fn path_normalization_on_is_an_error() {
        let hcm = r#"
- name: envoy.filters.network.http_connection_manager
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
    normalize_path: true
    merge_slashes: false
    path_with_escaped_slashes_action: KEEP_UNCHANGED
"#;
        let f = lint(hcm, false).unwrap();
        assert!(errors(&f).contains(&"normalize_path"));
    }

    #[test]
    fn escaped_slash_rewriting_is_an_error() {
        let hcm = r#"
- name: hcm
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
    normalize_path: false
    merge_slashes: false
    path_with_escaped_slashes_action: UNESCAPE_AND_REDIRECT
"#;
        let f = lint(hcm, false).unwrap();
        assert!(errors(&f).contains(&"path_with_escaped_slashes_action"));
    }

    #[test]
    fn a_route_rewrite_is_an_error() {
        let bad = format!(
            "{GOOD}\n    routes:\n    - match: {{ prefix: / }}\n      route: {{ prefix_rewrite: /v2 }}\n"
        );
        let f = lint(&bad, false).unwrap();
        assert!(errors(&f).contains(&"route.prefix_rewrite"));
    }

    #[test]
    fn a_document_with_no_ext_authz_is_flagged() {
        let f = lint("clusters: []", false).unwrap();
        assert!(
            f.iter()
                .any(|x| x.setting == "envoy.filters.http.ext_authz")
        );
    }

    #[test]
    fn findings_are_ordered_errors_first() {
        let bad = GOOD.replace("encode_raw_headers: true", "encode_raw_headers: false");
        let f = lint(&bad, false).unwrap();
        assert_eq!(f.first().map(|x| x.severity), Some(Severity::Error));
    }

    #[test]
    fn invalid_yaml_is_an_error_not_a_silent_pass() {
        // A linter that treats an unparseable config as "no findings" is worse
        // than no linter: it reports success on a file it never read.
        assert!(lint("\t\tnot: [valid", false).is_err());
    }
    #[test]
    fn missing_body_buffering_is_an_error() {
        let bad = GOOD.replace("    with_request_body:\n      max_request_bytes: 1048576\n      allow_partial_message: false\n      pack_as_bytes: true\n", "");
        let f = lint(&bad, false).unwrap();
        assert!(errors(&f).contains(&"with_request_body"));
    }
}
