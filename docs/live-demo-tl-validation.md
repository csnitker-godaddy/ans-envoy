# Live demo TL validation — 2026-10-19

The local `minikube` deployment in `ans-envoy-validation` now trusts
`https://tl.ans.snitker.dev`. Both authorizers use:

```toml
[transparency_log]
root_keys_url = "https://tl.ans.snitker.dev/root-keys"
# The current live key, fetched through verified HTTPS on the Mac, is pinned.
# The earlier synthetic test signing key was removed.
static_root_keys = ["tl.ans.snitker.dev+8f74b1bd+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHiAGZcTvTQNDJD7kLHvtYGU39K1pT+btAcoyxoRr22/eR2qUX0jOfWa9Er1FO72K4r6tOEA7/ZOTOFmEIMt1co="]
refresh_interval_secs = 1800
```

This URL is the Transparency Log endpoint associated with the demo RA. The
filter consumes TL-signed evidence; it does not register or modify agents.
No registration, metadata, certificate, key, or remote service configuration was
changed during this validation.

## Live identity and evidence

- ANS name: `ans://v1.1.0.demo.ans.snitker.dev`.
- Agent ID: `235aaad2-95d7-4ecb-bba0-50bbb8d44043`.
- Live status: ACTIVE; fetched token expires at 2026-10-19T17:07:04Z.
- Identity certificate fingerprint:
  `SHA256:617f30b7fdee8b3a6b8a30515aa98f6f8f46c2e31d0e401e8a39973381826d62`.
- Public receipt and status token were fetched from the live TL's
  `/v1/agents/{agentId}/receipt` and `/status-token` endpoints.
- Signing key ID: `8f74b1bd`; its advertised C2SP hash matched the decoded SPKI.
- The owner explicitly authorized use of this registered identity for the local
  tests. The private key remained on the demo host; only public certificate
  material and short-lived signed proofs returned to the Mac. They are not
  included in the repository evidence.

The existing Linux/arm64 authorizer image was reused:
`sha256:0ef99e38c2a278ef50374f1bf7e7e44711d9ae67c87913b29039c5b15b3cdcc3`.
Requests traversed the same verified-TLS Envoy 1.36.13 listeners, two authorizer
replicas, shared Redis and instrumented upstream as the earlier Minikube run.

## Results: 9/9 passed

| Check | Result |
| --- | --- |
| Registered demo identity, empty request | 200; correct ANSName, agent ID and certificate fingerprint delivered upstream |
| Same proof at the other replica | 401 `REPLAY`; no upstream request |
| Content changed after signing | 401 `CONTENT_BINDING_MISMATCH`; no upstream request |
| Original signed content after that failed attempt | 200; upstream digest matches the signed content |
| Missing live status token | 401 `MISSING_HEADERS`; no upstream request |
| Missing receipt | 401 `MISSING_HEADERS`; no upstream request |
| Invalid receipt | 401 `RECEIPT_INVALID`; no upstream request |
| Proof for a different origin | 401 `HTTP_BINDING_MISMATCH`; no upstream request |
| Modified proof signature | 401 `SIGNATURE_INVALID`; no upstream request |

These results exercise the real SDK verifier against live TL artifacts and a
registered identity's proof of possession. The earlier synthetic 50-case matrix
is separate evidence; it must not be described as 50 live-TL cases.

## Networking limitation

Direct public TL access from the pod failed: DNS resolution failed, and a
separate connection to the verified public IP timed out while retaining the
original hostname for TLS validation. Consequently, the authorizers bootstrap
from the verified public key pin; they did **not** successfully fetch that key
from inside Minikube. The URL remains configured for background refresh, but
successful refresh and key rotation are not established by this run.

Restore external DNS/HTTPS connectivity from Minikube and verify an actual
refresh before relying on automatic key discovery. Until then, a new TL signing
key requires an explicit verified pin update. Do not retain the synthetic key
as a fallback and do not disable TLS verification to work around connectivity.

The independently confirmed Redis restart replay-loss issue remains open; the
live TL does not replace the local replay cache or solve its durability problem.

## Current local state and reproduction

Both gateway replicas remain configured for this live TL. Temporary local
port-forwards were closed after the checks. Inspect the local workload with:

```sh
kubectl --context minikube -n ans-envoy-validation get pods
kubectl --context minikube -n ans-envoy-validation get configmap ans-authz-config
```

The synthetic setup helper in `tests/minikube/prepare.py` intentionally generates
a separate test trust configuration. Reapplying its generated manifests would
replace this live-TL configuration. Keep the two test modes distinct.

For another live run, fetch fresh public artifacts and obtain newly signed
request proofs using an explicitly authorized registered identity. The captured
proofs are single-use and expire; replaying saved artifacts is not a new test.

[Machine-readable results](test-evidence/minikube-2026-10-19/live-tl-results.json)

A later [temporary egress test](minikube-egress-validation.md) verified HTTPS
bootstrap with no static keys and successful native SDK background refresh
through a host-side proxy. The owner selected temporary testing only; the proxy
was stopped afterward and the regular deployment remains pinned. Persistent
connectivity and actual key rotation are still deployment follow-ups.
