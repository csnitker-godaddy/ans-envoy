# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code
in this repository.

## Build Commands

```bash
# The three checks CI gates on, in the order they fail fastest.
cargo fmt --all -- --check
RUSTFLAGS=-Dwarnings cargo clippy --workspace --all-targets
cargo test --workspace

# Dependency policy. `sources` will fail if the ans-verify git dependency is
# removed from deny.toml's allow-git before it is removed from Cargo.toml.
cargo deny check

# Coverage. Measured 78.00% on 2026-10-19, below the 82% gate. Org target: 90%.
# See the comment in
# .github/workflows/ci.yml for what is uncovered and why.
cargo llvm-cov --workspace --fail-under-lines 82

# The ANS-6 §7.6 replay integration tests need a real Redis. Without this they
# skip rather than fail.
ANS_ENVOY_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test --workspace

# The conformance gate: everything this repo ships must lint clean, and every
# negative fixture must stay rejected.
cargo build -p ans-authz
./target/debug/ans-authz validate-envoy envoy/bootstrap/sidecar-loopback.yaml
./target/debug/ans-authz validate-config --config examples/ans-authz.toml
```

## Non-negotiables

**Never return a gRPC error from `Check`.** Envoy treats a failed `Check` call as a
*communication failure* and applies the operator's `failure_mode_allow` to it — so
`Err(Status::internal(..))` hands the decision to a config setting. That is the
fail-open lever ANS-6 §7.6 and §9.6 exist to close. Every outcome is
`Ok(CheckResponse)` carrying `OK` or `PERMISSION_DENIED`.

**Never derive the `htu` authority from the request.** Not `Host`, not
`:authority`, not a client-supplied `X-Forwarded-*`. §7.7 calls that "the
vulnerability, not the defense", and the spec's worked example A.6 is the attack.
`AuthoritySource` has no variant that can represent it — keep it that way.

**Fail closed, and loudly.** A replay store that cannot answer, a proxy that
coalesces headers, a route with no asserted authority: all denials. Where the
fault is the deployment's, say so with a 500 rather than a 401 — a 401 sends
whoever is on call to inspect the caller's proof, which is the wrong half of the
system.

**`ans-envoy-core` must never see a `CheckRequest`.** It takes `RequestFacts`. That
is what lets a second adapter reuse the §7.4 check order rather than reimplementing
it — concretely `ext_proc`, which would lift the body-size ceiling `ext_authz`
imposes on §7.13. A shortcut here costs that.

**Zero TODOs on `main`.** If something is not complete, it does not ship. What is
deliberately not implemented is stated in `docs/conformance.md`, with the reason.

## Architecture

```
ans-envoy-core      the ANS-6 decision. No proxy types, no I/O beyond the clock.
ans-envoy-adapter   CheckRequest <-> RequestFacts. The only crate importing envoy-types.
ans-envoy-replay    §7.6 replay caches. Redis is the only conformant choice above one replica.
ans-envoy-config    schema, §7.7 startup validation, Envoy linting.
ans-authz           the binary: gRPC service, admin surface, CLI.
```

Verification itself is **not** implemented here — it comes from `ans-verify`'s
`pop` and `scitt` modules. This repo is the embedding service, and its value is the
two duties the SDK explicitly delegates: §7.7 startup enforcement ("this library
cannot see your startup") and the §4.6 duplicate-header preflight.

## The SDK dependency

`ans-verify` and `ans-types` use the same immutable merged-main revision,
`0a86cacfd4825edef3a2ea7ef9c2026e37ca7629`. Both Method B and ANS-6 are merged;
the published 0.1.5 crates predate the API. Keep the lockfile and `deny.toml`
source policy aligned. The `sdk-drift` job tests published replacements together.
Git dependencies block crates.io publication, not source/container releases.

Content binding is mandatory, including empty requests. Use
`verify_caller_with_content` so hashing starts after identity binding. Never
restore the old optional-content policy. Method A requires both SCITT artifacts;
the receipt waiver applies only to Method B. Supplied evidence always verifies.
The SDK now exposes `PopError::with_source`; replay failures must retain the
`REPLAY_CACHE_FULL` / `REPLAY_CACHE_UNAVAILABLE` distinction.

## Rust conventions

Matching `ans-sdk-rust`: edition 2024, MSRV 1.88, resolver 3, no `rustfmt.toml`
(default style), no `rust-toolchain.toml`. Workspace lints deny `unwrap_used`,
`expect_used`, `panic`, `todo`, `print_stdout`/`print_stderr`; `unsafe_code` is
forbidden. Test modules opt out with
`#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` placed *above*
`#[cfg(test)]`.

`thiserror` for errors, `#[non_exhaustive]` on public enums, nested modules as
re-export facades. A CLI that must print uses `#[allow(clippy::print_stdout)]` on
the specific function.

## Commits

Conventional Commits — release notes derive from the PR title.

Every contribution commit needs a human `Signed-off-by:` (`git commit -s`)
certifying the [DCO](DCO), as described in [CONTRIBUTING.md](CONTRIBUTING.md).
An assistant must obtain explicit human authorization before applying that
attestation. Do not infer it solely from a request to edit documentation.

**No AI `Co-Authored-By:` trailers.** The DCO is an assertion only a person can
make, and `noreply@` addresses cannot sign off. Disclose AI assistance in the pull
request's **AI assistance** section as `Assisted-by: <tool> (<model>)`.

## Domain terminology

- **Method A** — ANS-6 §6. mTLS; possession comes from the TLS handshake.
- **Method B** — ANS-6 §7. An RFC 9449 `DPoP` proof; exists because an L7 proxy
  terminated TLS and dropped the client certificate.
- **Receipt** — `COSE_Sign1` carrying the sealed leaf and its RFC 9162 inclusion
  proof. Proves *identity*. Never proves liveness: a receipt for a revoked agent
  verifies forever.
- **Status token** — short-lived `COSE_Sign1` asserting current lifecycle state.
  Proves *liveness*.
- **`htu` / `htm`** — the DPoP claims binding a proof to one URL and method.
- **`jti`** — the single-use proof identifier the §7.6 replay cache records.
- **`cnf.jkt`** — an access token's confirmation claim. §7.8 puts the comparison
  with the *token validator*, not here; we publish the thumbprint.
