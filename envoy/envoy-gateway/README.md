# Envoy Gateway integration example

These manifests are experimental starting points. They have not been validated
against a pinned Envoy Gateway release. Raw Envoy is the currently exercised target.

The example uses `SecurityPolicy.extAuth` for the gRPC backend, fail-closed policy
and trusted authority, plus `EnvoyPatchPolicy` for raw headers, body buffering
and path preservation. Enable patch-policy support only as documented for the
chosen control-plane version, then verify the generated resource names and JSON
patch paths. They must address the intended filter and listener.

Use one authority assertion for each externally visible authority. The value
must match the route's actual origin; a value copied across unrelated origins
can defeat request binding. Do not source it from client-controlled headers.

Restrict access to the authorizer and upstream. Remote gRPC needs authenticated
transport or equivalent enforced network isolation. Method A additionally needs
validated client TLS identity and peer-certificate delivery.

A successful policy apply does not prove ANS-6 conformance. Inspect rendered xDS,
run Envoy schema validation and exercise positive/negative requests through the
actual listener. If raw headers disappear, requests reject with
`RAW_HEADERS_UNAVAILABLE`. Readiness is based on cumulative observations; monitor
request denials and test configuration changes as well.

- [Security policy](securitypolicy.yaml)
- [Backend reference](backend.yaml)
- [Envoy patch](envoypatchpolicy-raw-headers.yaml)
- [Shared deployment contract](../README.md)
