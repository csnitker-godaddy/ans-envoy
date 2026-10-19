# Comparing ANS Envoy implementations

Compare immutable source revisions under the same conditions. A result should
state which deployment needs it serves and which trade-offs remain; code size or
a single successful request is not enough to choose an authentication boundary.
No alternative implementation has been evaluated in this document.

## Establish the baseline

Record for each implementation:

- Repository URL, commit SHA, supported ANS revision and SDK/protocol dependencies.
- Integration model: `ext_authz`, in-process module, WASM, `ext_proc`, or another path.
- Envoy/control-plane version, architecture, resource limits, TLS topology,
  trusted authorities, accepted authentication methods and body-size limits.
- Replay-cache topology, persistence/failover guarantees, timeouts and key refresh.
- License, dependency notices, DCO requirements, maintainers and supported releases.

For this implementation, use the exact references in [conformance](conformance.md)
and the image IDs in the [Minikube report](minikube-validation.md). Rebuild both
candidates with comparable optimization settings before measuring performance.

## Required behavior

Treat the standard's mandatory properties as acceptance gates before comparing
performance or convenience:

| Area | Evidence to require from both candidates |
| --- | --- |
| Identity and liveness | Valid proofs accepted; expired/revoked status, wrong certificate/name and mismatched receipts rejected |
| Possession | A valid signature under the identity certificate is required; public status/receipt artifacts alone never authenticate a caller |
| Header handling | Duplicates rejected before verification, including Envoy's inline Authorization coalescing; reserved identity headers cannot be spoofed |
| Request binding | Method, configured origin and raw path are checked; dot-segment/encoding aliases do not authenticate as each other |
| Content | Empty, binary, compressed and chunked content handled correctly; changed, added, removed and oversized content rejected appropriately |
| Ordering | Content hashing follows identity binding; rejected content does not spend a proof; no denied request reaches the upstream |
| Replay | Atomic shared reservation across replicas, bounded retention, fail-closed timeout/capacity behavior, and preservation or safe admission control after data loss |
| Method A | TLS/private-CA possession and the full certificate/status/receipt bindings are established across the actual serving path |
| Trust refresh | HTTPS/key validation, unknown-key behavior, rotation and outages tested without accepting caller-selected trust sources |
| Deployment changes | Rendered configuration, filter ordering, bypass routes and xDS reloads tested on each claimed platform |

The supplied [traffic probes](../tests/minikube/README.md) can establish part of
this matrix when adapted to the candidate's endpoint and identity-output
contract. Keep the same signed input bytes and expected security outcomes;
record unavoidable interface differences rather than treating them as failures.

## Operational comparison

Measure p50/p95/p99 latency, sustained throughput, CPU and memory under equivalent
load. Include cold/warm artifact caches, realistic proof/header sizes, maximum
bodies, multiple replicas, slow/unavailable Redis and key-refresh failures.
Separate authorizer time from TLS, proxy and upstream time.

Also compare installation and upgrade steps, process isolation, dependencies,
configuration mistakes, observability, supported control planes and recovery
procedures. Record measurements and reproducible commands alongside conclusions.

## Current evidence and unresolved limits

This repository has 50 passing synthetic TLS/Envoy cases and nine passing cases
using live TL evidence. Its shared-store outage fails closed, but the demo Redis
loses spent proofs on restart. That resilience check currently fails. Coverage
was measured at 78.00% before the later header-handling regression tests, below
the 82% gate and the documented 90% target. Performance has not been measured.

The alternative's results remain unknown until its source revision and test
configuration are supplied. Do not infer that it is stronger or weaker from its
implementation language or integration model.
