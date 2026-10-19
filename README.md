# ans-envoy

ANS-6 caller authentication for agents behind Envoy. `ans-authz` implements
Envoy's `ext_authz` gRPC API and uses the ANS Rust SDK to verify identity,
liveness, and proof of possession before a request reaches the upstream agent.

The service supports application-layer DPoP authentication (Method B) and mTLS
with SCITT evidence (Method A). Envoy configuration is part of the verification
contract: the service depends on the proxy preserving headers, paths and content
and supplying a trusted authority.

> **Pre-release.** The implementation targets merged ANS-6 revision 1. Raw Envoy
> 1.36.13 has been exercised locally; Istio and Envoy Gateway examples still need
> platform validation. Replay-state recovery and test coverage remain release
> blockers. See [release readiness](docs/release-readiness.md).

## Verification model

| Evidence | Establishes |
| --- | --- |
| `X-SCITT-Receipt` | The Transparency Log signed the registered identity event |
| `X-ANS-Status-Token` | The current registration state and accepted certificates |
| `DPoP` or validated client TLS certificate | Possession of the identity key |

Method B binds the HTTP method, configured origin, raw path and exact content,
including empty content. A shared replay cache prevents a spent proof from being
accepted by another replica while its reservation remains available. Losing
that state on restart or failover is a [known deployment blocker](docs/release-readiness.md#production-release-gates).

These checks authenticate the caller. Application authorization and OAuth access
token validation remain the upstream application's responsibility. When composing
OAuth, its validator must compare `cnf.jkt` with the verified proof-key thumbprint.

## Build and configure

Requirements:

- Rust 1.88 or newer, with a C compiler and CMake for native dependencies.
- A trusted Transparency Log's HTTPS root-key endpoint or explicitly pinned keys.
- Redis configured with `maxmemory-policy noeviction` for multiple replicas.
- Envoy with the settings described below.

```sh
cargo build --locked --release -p ans-authz
cp examples/ans-authz.toml ans-authz.local.toml
```

Edit `ans-authz.local.toml` before starting the service:

1. Set the externally visible authority and the mechanism Envoy uses to assert it.
2. Configure the accepted methods and any allowed-peer restrictions.
3. Set the Redis connection, shared key prefix and declared replica count.
4. Set a real `transparency_log.root_keys_url` or trusted `static_root_keys`.

The example uses placeholder domains and expects Redis to exist; copying it alone
is not a working deployment. Keep credentials and local overrides out of Git.

```sh
./target/release/ans-authz validate-config --config ans-authz.local.toml
./target/release/ans-authz validate-envoy envoy/bootstrap/sidecar-loopback.yaml
./target/release/ans-authz serve --config ans-authz.local.toml
```

Use [the raw Envoy bootstrap](envoy/bootstrap/sidecar-loopback.yaml), with your
server certificate, private key and upstream endpoint. Restrict access to the
authorizer and upstream so clients cannot bypass the gateway. The supplied
[Kubernetes demo](deploy/kubernetes/envoy/) is for local testing; its Redis
configuration does not preserve replay state across restart.

For a container build, see [Dockerfile](Dockerfile). Its default `container`
profile disables LTO to reduce build resource use. Build the release profile
with `--build-arg PROFILE=release` when preparing a release artifact.

## Required Envoy settings

| Setting | Required value or condition |
| --- | --- |
| `encode_raw_headers` | `true`, so the adapter can count security headers |
| `failure_mode_allow` | `false`, so authorizer communication failures reject |
| `context_extensions.ans_trusted_authority` | Per virtual host, unless the authorizer uses a sole configured authority |
| Path handling | `normalize_path: false`, `merge_slashes: false`, `path_with_escaped_slashes_action: KEEP_UNCHANGED` |
| `with_request_body` | Positive `max_request_bytes`, `pack_as_bytes: true`, `allow_partial_message: false` |
| `grpc_service.timeout` | Explicit and longer than the configured replay deadline |

Envoy can combine `Authorization` fields before constructing the raw header map.
The adapter therefore also rejects comma-bearing Authorization values. OAuth
DPoP and Bearer token credentials do not permit commas; parameter-list schemes
such as Digest are outside this adapter's Authorization contract.

The linter checks the configuration document supplied to it; it does not inspect
a running proxy or correlate separate TOML and Envoy timeout values. Validate
rendered xDS and test real requests after control-plane or filter changes.
See [envoy/README.md](envoy/README.md) for the deployment contract.

## Authenticated identity headers

On an allow, the service overwrites these reserved upstream request headers and
removes any of them that does not apply to the selected authentication method:

| Header | Value |
| --- | --- |
| `x-ans-caller-ans-name` | Verified full `ans://` name |
| `x-ans-caller-agent-id` | Agent ID from the verified status token |
| `x-ans-caller-cert-fp` | Identity certificate fingerprint |
| `x-ans-caller-jkt` | RFC 7638 proof-key thumbprint; absent for Method A |
| `x-ans-caller-method` | `method_a` or `method_b` |

The upstream must trust these five headers only when the request arrived through
the protected gateway path. Arbitrary additional `x-ans-caller-*` names are not
identity claims defined by this project.

## Observability

The admin listener exposes `/healthz`, `/readyz` and `/metrics`.

Readiness reports whether raw headers and a trusted authority have been observed
since process start. These observations are cumulative; readiness is not a check
of current xDS, replay-store connectivity or complete deployment conformance.
Use denial counters, proxy validation and traffic probes alongside it.

Alert on `ans_replay_backend_errors_total`. Infrastructure failures reject with
`REPLAY_CACHE_UNAVAILABLE` or `REPLAY_CACHE_FULL` and HTTP 500. An actual repeated
proof rejects with `REPLAY` and HTTP 401.

## Development and documentation

| Path | Purpose |
| --- | --- |
| `crates/ans-envoy-core` | Proxy-independent verification policy and decisions |
| `crates/ans-envoy-adapter` | Envoy request/response adaptation |
| `crates/ans-envoy-replay` | Shared Redis and single-process replay backends |
| `crates/ans-envoy-config` | Configuration validation and Envoy linting |
| `crates/ans-authz` | gRPC service, admin endpoints and CLI |
| `crates/ans-probe` | Development artifact generation and traffic probes |

- [Development and validation](docs/development.md)
- [Conformance and migration](docs/conformance.md)
- [Release readiness](docs/release-readiness.md)
- [Validation evidence](docs/README.md)
- [Implementation comparison criteria](docs/comparison.md)
- [Local Minikube probes](tests/minikube/README.md)

## License and contributions

This project is licensed under the [MIT License](LICENSE), copyright GoDaddy
Operating Company, LLC. Dependencies retain their own licenses; see
[licensing and notices](docs/licensing.md).

Contributions follow the [ANS contribution guidelines](CONTRIBUTING.md),
[Code of Conduct](CODE_OF_CONDUCT.md), and [Developer Certificate of Origin](DCO).
Every contribution commit requires the human contributor's `Signed-off-by:`.
Report security issues privately as described in [SECURITY.md](SECURITY.md).
