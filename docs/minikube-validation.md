# Minikube validation — 2026-10-19

The updated authorizer was built as a Linux/arm64 container and tested through
real Envoy TLS listeners on two separate gateway pods sharing Redis. The normal
traffic matrix passed **50/50** cases. Resilience checks passed **4/5**: the demo
Redis's lost replay state after restart remains a confirmed production blocker.

## Environment and provenance

- Minikube profile: `minikube`; namespace: `ans-envoy-validation`.
- Kubernetes 1.35.1, containerd 2.2.1, arm64; one local node.
- Envoy 1.36.13, image ID `sha256:4280bde57e0752d7472014c07dcc196800a47d3a6c8b00aae8163e6e9338eb6c`.
- Authorizer: `localhost/ans-envoy/ans-authz:ans6-20261019-r2`, image ID
  `sha256:0ef99e38c2a278ef50374f1bf7e7e44711d9ae67c87913b29039c5b15b3cdcc3`.
- SDK revision: `0a86cacfd4825edef3a2ea7ef9c2026e37ca7629`.
- Two Envoy + authorizer pods, one shared Redis, one instrumented echo upstream.
- TLS clients verified the server's hostname and private test-CA chain. Method A
  used a client certificate issued by that CA. TLS verification was not disabled.
- TL artifacts used public demo signing material and generated/local identities;
  this did not contact a live registry, RA or Transparency Log.

The previous local profile could not start because containerd's bbolt metadata
was corrupt (`Page expected to be: 324, but self identifies as 0`). With the
owner's authorization, that profile was recreated. The temporary alternative
profile was removed. Other Kubernetes clusters were not used.

## Traffic results

All 50 cases passed after the fixes below, including:

- Valid empty requests, ASCII/binary/gzip content, and chunked transfer framing.
- Mandatory digest, addition/removal/modification of content, and proof reuse
  after a failed content check. Compressed bytes remained compressed when hashed.
- Duplicate DPoP/status/receipt/Authorization fields, including a proof whose
  `ath` matches Envoy's combined Authorization value.
- Origin/Host, HTTP method, raw path, dot-segment and percent-encoding binding.
- Expired proof/token, revoked registration, invalid receipt, receipt version
  mismatch, malformed/unsupported profiles, and tolerated unknown payload claims.
- Authentication header replacement; oversized bodies rejected by Envoy with 413.
- Method A mTLS, required receipt, certificate fingerprint and full ANSName
  binding, invalid receipts, and Method B selection when both credentials exist.
- A proof accepted on one pod rejected as `REPLAY` on the other pod.

Every expected denial asserted **zero additional requests at the upstream**.
The two replicas were addressed directly through separate port-forwards, so the
cross-replica result does not depend on load-balancer selection.

## Defects found and corrected

**Envoy coalesces Authorization before ext_authz.** Even with
`encode_raw_headers: true`, duplicate inline Authorization fields arrived as one
comma-joined value. Before the fix, two `Authorization: DPoP token` fields plus
an `ath` over `token,DPoP token` returned 200 and reached the upstream. Duplicate
Bearer fields also reached the upstream. The adapter now fails closed on a
comma-bearing Authorization value before token parsing. Supported OAuth DPoP and
Bearer token credentials cannot contain commas; parameter-list schemes such as
Digest are outside this adapter's Authorization contract. Focused tests preserve
valid single-token behavior. The deployed fix rejects both reproduced cases.

**The Kubernetes Envoy readiness probe used node loopback.** Kubelet HTTP probes
originate outside the pod; `host: 127.0.0.1` targeted the node. The Kubernetes
sample now binds Envoy admin to the pod interface and probes the pod IP. The
public gateway Service does not expose the admin port. Production must restrict
admin access inside the cluster. The sample's declared replica count now matches
the two gateway replicas.

After these changes, all **241 Rust workspace tests** passed with real Redis;
focused Clippy and the Rust 1.88 workspace check also passed.

## Remaining production blocker: replay state loss

The resilience test observed:

| Step | Result |
| --- | --- |
| Spend a fresh proof | 200; upstream receives it once |
| Stop the disposable Redis | 500 `REPLAY_CACHE_UNAVAILABLE`; upstream receives nothing |
| Restore Redis and reconnect both authorizers | Fresh requests succeed on both pods |
| Present the previously spent proof, still within its freshness window | **200; upstream receives it again. Expected 401 `REPLAY`.** |

The demo disables persistence. Shared atomic `SET NX` and `noeviction` prevent
concurrent/repeated use while state survives; they do not preserve reservations
through data loss. Production must provide an established persistence/failover
contract or reject admission until all potentially lost proofs expire. Enabling
AOF alone is not proof against every crash/failover loss window.

Redis reconnection can briefly return additional 500 denials. `/readyz` reports
observed proxy properties, not live Redis connectivity. The final normal matrix
was rerun after both replicas recovered and again passed 50/50.

## Scope and follow-up

This establishes local raw-Envoy interoperability for the recorded versions and
configuration. It does not establish Istio/Envoy Gateway support, multi-node
failover, live TL key rotation, production PKI, OAuth authorization/`cnf.jkt`
validation, performance limits, or a hosted release pipeline. The earlier
coverage measurement was 78.00%, below the existing 82% gate; this runtime run
was not an instrumented coverage measurement.

The namespace is left running with healthy agent, Redis and two gateway pods.
Local port-forwards used by the tests are closed. Inspect it with:

```sh
kubectl --context minikube -n ans-envoy-validation get pods
```

The test credentials are short-lived and are not production credentials.
Reproduction instructions and probes are in
[`tests/minikube`](../tests/minikube/README.md). Machine-readable evidence:

- [Environment and image IDs](test-evidence/minikube-2026-10-19/environment.json)
- [50-case traffic matrix](test-evidence/minikube-2026-10-19/matrix-results.json)
- [Resilience results, including the failure](test-evidence/minikube-2026-10-19/resilience-results.json)
- [Authorization reproduction before the fix](test-evidence/minikube-2026-10-19/authorization-before-fix.json)

The namespace was subsequently repointed to the owner's live demo TL. See
[the separate 9-case live validation](live-demo-tl-validation.md) for that result
and the key-refresh networking limitation. The 50-case results above used the
original synthetic fixtures.
