# Development

Use Rust 1.88 or newer. The workspace uses edition 2024, resolver 3, default
rustfmt formatting and the lints in `Cargo.toml`. Native cryptographic
dependencies need a C compiler and CMake.

`ans-types` and `ans-verify` use the same immutable SDK Git revision. Keep them
on one source and keep `Cargo.lock` checked in. The published 0.1.5 SDK predates
the required Method B API; do not replace only one of the dependencies.

## Checks

Run the checks appropriate to the change. Before proposing runtime changes:

```sh
cargo fmt --all -- --check
RUSTFLAGS=-Dwarnings cargo clippy --locked --workspace --all-targets
cargo test --locked --workspace
cargo +1.88 check --locked --workspace --all-targets
cargo doc --locked --workspace --no-deps
```

Redis integration tests run only when `ANS_ENVOY_TEST_REDIS_URL` is set. Use a
dedicated test Redis with `maxmemory-policy noeviction`; never point the suite at
production. For example, after starting a local test Redis:

```sh
ANS_ENVOY_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test --locked --workspace
```

Without that variable, a passing workspace run does not establish Redis
integration behavior. The tests use separate key prefixes but still require a
nonproduction store.

When dependencies change, install and run `cargo-audit` and `cargo-deny`:

```sh
cargo audit
cargo deny check
```

For coverage, install `cargo-llvm-cov` and the toolchain's `llvm-tools-preview`
component, then run with the test Redis configured:

```sh
ANS_ENVOY_TEST_REDIS_URL=redis://127.0.0.1:6379 \
  cargo llvm-cov --locked --workspace --fail-under-lines 82
```

The recorded initial-alignment coverage is 78.00%, below the current 82% gate
and the documented ANS 90% target. Keep that failure visible. Do not lower the
gate or omit production code to make a change appear ready. See
[release readiness](release-readiness.md) for the measured gaps.

## Configuration and integration

```sh
cargo build --locked -p ans-authz
./target/debug/ans-authz validate-config --config examples/ans-authz.toml
./target/debug/ans-authz validate-envoy envoy/bootstrap/sidecar-loopback.yaml
./target/debug/ans-authz validate-envoy envoy/fragments/mtls-method-a.yaml --method-a
```

The example's placeholder TL/authority values must be replaced before serving.
`validate-envoy` is an ANS configuration linter, not an Envoy schema validator;
CI also uses `envoy --mode validate`. Apply both to the rendered configuration.

Use [the Minikube probes](../tests/minikube/README.md) for actual TLS → Envoy →
authorizer → upstream behavior. The resilience probe deliberately fails when
the supplied ephemeral Redis loses live replay reservations on restart. That
failure is a release gate, not an expected behavior to silently accept.

## Review conventions

- Keep the core independent of Envoy wire types.
- Preserve the ANS verification order: preflight, identity/liveness/possession,
  content binding, then replay reservation and application action.
- Fail closed on invalid evidence and unavailable required dependencies.
- Keep discovery/egress, application authorization and token `cnf.jkt` validation
  outside this ingress verifier unless an explicitly reviewed design adds them.
- Document behavior changes, migration requirements and validation limits.
- Follow [CONTRIBUTING.md](../CONTRIBUTING.md), including human DCO sign-off and
  AI-assistance disclosure.
