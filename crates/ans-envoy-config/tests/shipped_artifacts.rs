#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Conformance gating for the artifacts this repo ships.
//!
//! Five Envoy settings decide whether an `ans-envoy` deployment satisfies ANS-6,
//! and none of them live in the `ans-authz` binary. A regression in a shipped
//! YAML file is therefore a security regression that no unit test would catch, so
//! the shipped configs are linted here — in `cargo test`, not only in a CI shell
//! step, so it also fails locally before a push.
//!
//! The negative fixtures matter as much as the positive ones. A linter that
//! passes everything is indistinguishable from no linter, and the way that
//! happens in practice is a refactor that quietly stops detecting something.

use std::path::{Path, PathBuf};

use ans_envoy_config::{Severity, envoy_lint};

/// Repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("repo root should resolve")
}

fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn errors(findings: &[envoy_lint::LintFinding]) -> Vec<String> {
    findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .map(std::string::ToString::to_string)
        .collect()
}

// ── Positive: everything we ship must be conformant ──────────────────────────

#[test]
fn the_shipped_bootstrap_is_conformant() {
    let findings = envoy_lint::lint(&read("envoy/bootstrap/sidecar-loopback.yaml"), false).unwrap();
    let errs = errors(&findings);
    assert!(
        errs.is_empty(),
        "shipped bootstrap has conformance errors:\n{}",
        errs.join("\n")
    );
}

#[test]
fn the_shipped_method_a_fragment_is_conformant_under_method_a_rules() {
    let findings = envoy_lint::lint(&read("envoy/fragments/mtls-method-a.yaml"), true).unwrap();
    let errs = errors(&findings);
    assert!(
        errs.is_empty(),
        "Method A fragment has conformance errors:\n{}",
        errs.join("\n")
    );
}

#[test]
fn the_shipped_example_config_is_conformant() {
    let config: ans_envoy_config::Config =
        toml::from_str(&read("examples/ans-authz.toml")).expect("example config should parse");
    ans_envoy_config::validate(&config).expect("example config should be conformant");
}

// ── Negative: the fixtures must stay rejected ────────────────────────────────

#[test]
fn forgetting_encode_raw_headers_is_caught() {
    // The most likely real-world mistake: everything works, and §4.6 duplicate
    // detection is silently unenforceable.
    let findings = envoy_lint::lint(
        &read("envoy/testdata/misconfigured-forgot-raw-headers.yaml"),
        false,
    )
    .unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.setting == "encode_raw_headers"),
        "expected an encode_raw_headers error, got: {findings:?}"
    );
}

#[test]
fn fail_open_is_caught() {
    let findings =
        envoy_lint::lint(&read("envoy/testdata/misconfigured-fail-open.yaml"), false).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.setting == "failure_mode_allow"),
        "expected a failure_mode_allow error, got: {findings:?}"
    );
}

#[test]
fn path_rewriting_is_caught() {
    let findings = envoy_lint::lint(
        &read("envoy/testdata/misconfigured-path-rewrite.yaml"),
        false,
    )
    .unwrap();
    let settings: Vec<&str> = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .map(|f| f.setting)
        .collect();

    for expected in [
        "normalize_path",
        "merge_slashes",
        "path_with_escaped_slashes_action",
        "route.prefix_rewrite",
    ] {
        assert!(
            settings.contains(&expected),
            "expected {expected} to be flagged, got {settings:?}"
        );
    }
}

// ── Negative: the example bad configs must stay rejected ─────────────────────

#[test]
fn truncating_or_lossy_body_buffering_is_caught() {
    // §7.13: both of these corrupt the digest rather than merely weakening it — a
    // prefix hash and a hash over UTF-8-replaced bytes are both indistinguishable
    // from tampering.
    let findings = envoy_lint::lint(
        &read("envoy/testdata/misconfigured-truncating-body.yaml"),
        false,
    )
    .unwrap();
    let settings: Vec<&str> = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .map(|f| f.setting)
        .collect();
    for expected in [
        "with_request_body.allow_partial_message",
        "with_request_body.pack_as_bytes",
    ] {
        assert!(
            settings.contains(&expected),
            "expected {expected} to be flagged, got {settings:?}"
        );
    }
}

#[test]
fn every_bad_example_config_is_rejected_with_a_spec_citation() {
    // Each of these is a way a deployment can look healthy and be unconformant.
    // The spec citation is part of the contract: an operator should be able to go
    // read the paragraph that refused them.
    let cases = [
        ("examples/testdata/bad-no-authority.toml", "§7.7"),
        ("examples/testdata/bad-two-authorities.toml", "§7.7"),
        ("examples/testdata/bad-unshared-replay.toml", "§7.6"),
        ("examples/testdata/bad-skew-over-cap.toml", "§4.4"),
    ];

    for (path, spec) in cases {
        let config: ans_envoy_config::Config =
            toml::from_str(&read(path)).unwrap_or_else(|e| panic!("{path} should parse: {e}"));
        let errors =
            ans_envoy_config::validate(&config).expect_err(&format!("{path} must be rejected"));
        assert!(
            errors.iter().any(|e| e.spec == spec),
            "{path} should cite {spec}, got {errors:?}"
        );
    }
}
