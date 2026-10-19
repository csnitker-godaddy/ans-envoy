# The Envoy half

These files are part of the deliverable. Six Envoy settings decide whether an
`ans-envoy` deployment satisfies ANS-6, and none of them live in the `ans-authz`
binary — so `ans-authz` alone is not conformant, and neither is this directory.

Verify before deploying:

```bash
ans-authz validate-envoy envoy/bootstrap/sidecar-loopback.yaml
```

## The deployment contract

| Setting | Required | Requirement it carries | Detectable at runtime? |
| --- | --- | --- | --- |
| `encode_raw_headers` | `true` | §4.6 duplicate-header rejection | **Yes** — a `CheckRequest` with no `header_map` means it is off, and `ans-authz` then denies every request and records a denial |
| `failure_mode_allow` | `false` (default) | fail-closed posture, §7.6 / §9.6 | No |
| `context_extensions.ans_trusted_authority` per vhost | set | §7.7 authority a client cannot forge | **Yes** — an unresolved authority is a denial |
| `normalize_path`, `merge_slashes`, `path_with_escaped_slashes_action` | `false`, `false`, `KEEP_UNCHANGED` | §7.3 byte-for-byte path fidelity | **No** — see below |
| `grpc_service.timeout` | explicit, above `replay.deadline_ms` | the default is 200 ms | No |
| `with_request_body` | `pack_as_bytes: true`, `allow_partial_message: false`, `max_request_bytes` sized | §7.13 content binding | **Partly** — truncation announces itself via `x-envoy-auth-partial-body` and is always denied; a missing body is only detectable when the request declares a `content-length` |

The "detectable at runtime" column is the important one. Three of the six announce
themselves in a `CheckRequest`, so `ans-authz` fails closed and says why. The rest
are config trust, and path fidelity is the one that cannot be recovered:
**a normalized path is indistinguishable from one the client sent that way.** If
`normalize_path` is on, `htu` gets compared against a path the caller never signed,
the original path cannot be recovered by this service. The result depends on
what the caller signed and which transformations occurred.

That is inherent to running out of process. The linter is the mitigation, and it is
advisory for anything an xDS control plane delivers later.

## Files

| File | What it is |
| --- | --- |
| `bootstrap/sidecar-loopback.yaml` | Complete, runnable, and validated by `envoy --mode validate` in CI. Envoy on `:8443`, `ans-authz` on loopback `:10003`, agent on `:8080`. |
| `fragments/uds-cluster.yaml` | The `ans-authz` cluster over a Unix socket instead of loopback TCP. |
| `fragments/mtls-method-a.yaml` | The Method A (§6) additions: `include_peer_certificate`, and a `DownstreamTlsContext` anchored on the RA private CA. |
| `testdata/misconfigured-*.yaml` | Negative fixtures. CI asserts the linter rejects each. Useful for checking your own pipeline actually gates. |
| `istio/`, `envoy-gateway/` | Platform variants — read the caveat below first. |

## Filter ordering

`ext_authz` must come **before** the router, and before any body-transforming
filter (decompressor, gRPC-JSON transcoder). §7.13 binds "the content octets
exactly as the signer transmitted them", so a filter that rewrites the body ahead
of verification would present different bytes than the caller signed.

This bites now: content binding is implemented, so a filter that rewrites the body
ahead of `ext_authz` makes every bound request fail with
`CONTENT_BINDING_MISMATCH`.

Note also the body-size ceiling. `max_request_bytes` is mandatory, and above it
Envoy answers 413 itself without calling `ans-authz`. That is a rejection rather
than a silent pass, so it is conformant — but size it for your largest legitimate
request.

## Istio and Envoy Gateway

**Read this before deploying on either.**

Neither platform's CRD exposes the fields ANS-6 needs:

| Field | Istio `envoyExtAuthzGrpc` | Envoy Gateway `SecurityPolicy.extAuth` |
| --- | --- | --- |
| `encode_raw_headers` | absent | absent |
| `include_peer_certificate` | absent | absent |
| `context_extensions` | absent | present (`contextExtensions`) |

So on the two platforms most people actually run, a **MUST-level** requirement
(§4.6 duplicate-header rejection) needs an Istio `EnvoyFilter` or an Envoy Gateway
`EnvoyPatchPolicy` — and both projects document those as unsupported and
version-fragile.

Raw Envoy is the supported target. The platform variants here are best-effort:
they will need checking against your platform version, and a patch that silently
stops applying takes `encode_raw_headers` with it.

`ans-authz` covers the worst case: without `encode_raw_headers` it denies every
request rather than silently skipping §4.6, so a patch that stops applying is an
outage rather than a quiet weakening. Check readiness alongside denial metrics and real request probes; readiness
uses cumulative observations and is not a live configuration attestation.

## Verifying a deployment end to end

Once running, the things worth checking are the refusals, not the successes:

| Send | Expect |
| --- | --- |
| a valid Method-B request | 200 |
| the same request again | 401, `x-ans-deny-label: REPLAY` |
| two `DPoP` headers | 401, `DUPLICATE_HEADER` |
| a proof minted for another origin, with a spoofed `Host` | 401 — this is ANS-6 example A.6 |
| a request with no status token | 401, `MISSING_HEADERS` |
| a bound body altered in flight | 401, `CONTENT_BINDING_MISMATCH` |

If the fourth one succeeds, `context_extensions` is not reaching `ans-authz` and
the comparison URL is coming from somewhere it should not.

Envoy's inline Authorization handling can combine fields before the raw map is
built. The adapter rejects comma-bearing Authorization values as ambiguous.
Complete raw body buffering remains required even for bodyless Method B proofs.
