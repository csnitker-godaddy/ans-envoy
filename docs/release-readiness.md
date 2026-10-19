# Release readiness

Status as of 2026-10-19: **pre-release**. The current implementation targets
merged ANS-6 revision 1 and the pinned Rust SDK revision documented in
[conformance](conformance.md). Raw Envoy is the primary integration target.

## Verified evidence

| Check | Result and scope |
| --- | --- |
| Rust workspace tests | 241 passed with real Redis after the Authorization-header correction |
| Rust tooling | Format, Clippy and Rust 1.88 compatibility checks passed; the final header change received focused adapter Clippy plus the workspace MSRV check |
| Rust documentation | `cargo doc --locked --workspace --no-deps` passed during the alignment run |
| Local container | Linux/arm64 `container` profile built and ran on Minikube; this is not a multi-platform release-image result |
| Synthetic TLS/Envoy traffic | 50/50 cases passed on Envoy 1.36.13 with two authorizers sharing Redis |
| Resilience | 4/5 checks passed; lost replay state after Redis restart re-admitted a spent proof |
| Live identity | 9/9 cases passed with a registered demo identity and live TL receipt/status token |
| TL network bootstrap/refresh | The native SDK fetched and refreshed the current live key with no static pin through a temporary host proxy; actual key rotation was not exercised |
| Dependencies | Audit reported zero known vulnerabilities after lockfile updates; `unsafe-libyaml` remains flagged as unmaintained; cargo-deny checks passed with duplicate-version warnings |
| Coverage | Hosted review CI measured 78.12% (3278/4196 lines), below the existing 82% gate and documented ANS 90% target; the earlier local alignment measured 78.00% |

The [documentation index](README.md#recorded-validation) links the reports and
machine-readable results. These claims are tied to those snapshots; rerun the
relevant checks after code, dependencies, proxy configuration or platform changes.

## Production release gates

1. **Replay-state recovery.** The demo Redis disables persistence. A spent proof
   was accepted after restart while it was still fresh. Shared `SET NX` and
   `noeviction` do not solve data loss. Establish and test persistence/failover
   guarantees or stop admission until all possibly lost proofs expire, including
   accepted future `iat` values. Startup currently warns if Redis refuses
   `CONFIG GET`; an operator must still establish the eviction policy.
2. **Coverage and hosted CI.** Reach the existing 82% gate, then the documented
   90% target. The measured gaps include CLI/startup, gRPC orchestration, Method A
   rejection paths and the development probe's traffic scenarios. Keep failures
   visible; do not lower the gate or exclude production code to obtain a pass.
3. **Supported runtime matrix.** Run the traffic probes in hosted CI against
   pinned Envoy versions and architectures. Extend validation to configuration
   reloads, bypass routes, multi-node failures and TL rotation. Istio and Envoy
   Gateway patches remain experimental until rendered xDS and actual requests
   are tested against specific platform versions.
4. **Deployment boundaries.** Restrict the authorizer to the intended proxy and
   the upstream to the protected gateway path. Establish TLS/private-CA and TL
   trust ownership, key-rotation procedures, request/read deadlines and body
   limits. OAuth composition must validate `cnf.jkt` outside this service.
5. **Performance and operations.** Measure latency distributions, throughput and
   memory under representative load and dependency failures. Verify deadlines,
   concurrency/connection limits, alerts and recovery procedures. Readiness is
   based on cumulative observations; it does not attest to current xDS or Redis
   health. No performance benchmark has been completed.
6. **Dependency maintenance.** Replace `serde_yaml`/unmaintained `unsafe-libyaml`
   or document a bounded exception for trusted operator configuration. Review
   hostile-input handling and add fuzzing evidence before claiming production
   support. This alignment was not an exhaustive security audit.

## Repository and release setup

The [MIT license](../LICENSE), [DCO](../DCO), [contribution policy](../CONTRIBUTING.md),
[Code of Conduct](../CODE_OF_CONDUCT.md) and [security policy](../SECURITY.md) follow
ANS conventions. Before merging/releasing, maintainers must configure the DCO
GitHub App, required CI/branch protections, review ownership and private security
reporting. A merge-group shim alone does not validate contribution sign-offs.

The Dockerfile and release-please configuration exist. Release automation must
still build and validate the intended artifacts, generate release notes and
retain required dependency notices, immutable image digests/checksums and SBOMs.
Only advertise architectures and platforms that have been built and tested.

SDK publication is a planned follow-up for 2026-10-19. Until a compatible
release is available, keep `ans-types` and `ans-verify` on the same pinned,
merged Git revision. This is an accepted dependency for implementation review
and source/container distribution; pending SDK publication is not a gate for
those activities.

The published 0.1.5 SDK crates predate Method B. Publishing the Envoy crates
to crates.io still requires registry dependencies: after the compatible SDK
release, switch both dependencies together, remove the git-source exception
and run packaging/publish dry runs in dependency order. `ans-probe` remains
`publish = false`.

The [committed fixture keys](../testdata/demo-agents/README.md) are intentionally
public. Generated bundles, live agent keys, kubeconfigs and credentials must stay
outside the repository. Scan the exact proposed publication contents; do not use
broad scanner exceptions for the entire fixture or documentation tree.

## Local demo state

The recorded local gateway uses the demo TL's HTTPS-verified key pin because
direct VM egress was unavailable. A temporary proxy proved native HTTPS bootstrap
and periodic refresh; the owner chose temporary testing only, so it was stopped
and the running gateway configuration remained pinned. That local networking
constraint is separate from the replay-state recovery blocker.

A source review can proceed with these limits recorded. A production release
must resolve the applicable gates rather than treating the existing smoke tests
as release certification.
