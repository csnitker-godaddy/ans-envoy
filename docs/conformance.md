# ANS-6 conformance and migration

This is an ingress caller verifier, with Method B and Method A on the SCITT tier.
Conformance depends on both `ans-authz` and the deployed Envoy configuration;
local Rust tests alone do not establish deployment conformance.

## Reference revisions

Reviewed on 2026-10-19:

- Standard: [`agentnameservice/ans-registry` at `70cefa5601f61db78883a63c2e91094bbb096fc1`](https://github.com/agentnameservice/ans-registry/blob/70cefa5601f61db78883a63c2e91094bbb096fc1/spec/ans-6-agent-authentication.md), ANS-6 revision 1. [PR #53](https://github.com/agentnameservice/ans-registry/pull/53) merged on 2026-09-14.
- SDK: [`agentnameservice/ans-sdk-rust` at `0a86cacfd4825edef3a2ea7ef9c2026e37ca7629`](https://github.com/agentnameservice/ans-sdk-rust/tree/0a86cacfd4825edef3a2ea7ef9c2026e37ca7629). [PR #105](https://github.com/agentnameservice/ans-sdk-rust/pull/105) merged on 2026-09-17. `ans-types` and `ans-verify` share this immutable source.
- Published SDK `0.1.5` predates Method B; a git dependency remains necessary.
- Proposed V3/versionless changes, including [spec PR #82](https://github.com/agentnameservice/ans-registry/pull/82), remain unmerged and are outside this baseline.

## Verification contract

| Requirement | Implementation and boundary |
| --- | --- |
| Duplicate security headers (§4.6) | Adapter counts raw values. No raw header map or a repeated security header rejects before cryptography. Envoy must use `encode_raw_headers: true`. Comma-bearing Authorization values also reject because Envoy may combine those fields before ext_authz. |
| Trusted authority (§7.7) | Startup validates a sole configured authority or proxy context extension. Missing per-request authority rejects. Client `Host` is not the comparison authority. |
| Raw path (§7.3) | Merged SDK preserves dot segments and percent-encoding octets. Envoy and intermediaries must also preserve them. Queries are excluded from DPoP binding; do not put authorization-bearing parameters there. |
| Proof/profile (§7.2–7.5, §7.12) | SDK verifies the closed ES256 JOSE profile, certificate/key equality and validity, method/target/freshness, supported profile, status token, receipt and identity agreement. |
| Content (§7.4, §7.13) | Every proof includes `ans_content_digest`, including SHA-256 of empty content. Adapter retains complete raw bytes; `verify_caller_with_content` hashes only after live identity binding. Mismatch rejects before replay reservation. Content coding remains applied. |
| Replay (§7.6, §9.6) | Redis uses one atomic `SET NX PX` with a deadline. Live proofs must be shared across replicas and never evicted or lost during failover. Memory is single-process only. |
| Replay failures | `REPLAY_CACHE_UNAVAILABLE` and `REPLAY_CACHE_FULL` reject as deployment faults (500). Actual `REPLAY` is a caller fault (401). Metrics distinguish these outcomes. |
| Method A (§6.1, §6.3) | Envoy validates the private-CA chain and possession. Core requires a DNS SAN, full URI-SAN/status ANSName equality, current identity fingerprint, and receipt name/id/host agreement. Both SCITT artifacts are required because no badge fallback exists. |
| Method B receipt waiver (§7.1) | Explicit configuration plus written justification may waive absence. A supplied receipt always verifies and binds, even when not required. The waiver does not apply to Method A. |
| Root keys (§4.5, §9.5) | Static keys or HTTPS bootstrap; background refresh and cooldown-gated refresh/retry on unknown `kid`. Trust comes from configured keys or the fetch channel. |
| Result (§6.5, §7.5) | Authenticated identity headers overwrite/remove the reserved caller headers. The upstream still decides authorization. OAuth token validation must compare `cnf.jkt` with `x-ans-caller-jkt`. |

The SDK owns cryptographic parsing, COSE verification and receipt verification.
The embedding service owns header preflight, trusted request reconstruction,
content availability, shared replay wiring, and Method A certificate binding.
The SDK's receipt-binding helper is internal to its module; Method A's local
binding logic is covered separately by this project's tests.

## Migrating from the September draft

1. Set `verification.content_binding = "required"`. Legacy `"optional"` is parsed
   only to give an actionable startup error for Method B or Both. The obsolete
   `Policy::require_content_binding` field has been removed.
2. Configure `with_request_body` with a positive `max_request_bytes`,
   `allow_partial_message: false`, and `pack_as_bytes: true`. The linter now treats
   missing buffering as an error. The Method A fragment retains these settings
   when used on a listener that also accepts Method B.
3. Update callers to the merged SDK: even a bodyless request must carry the empty
   content digest. Old proofs that omit it reject. A signature for empty content
   cannot authorize content added by an intermediary.
4. Preserve body octets through the proxy chain. Do not decompress or rewrite
   content on Method B routes. Nonempty string-only bodies, unavailable bodies,
   and truncated bodies reject as deployment faults.
5. Update alerting for the distinct replay-backend error labels. Errors no longer
   impersonate a replayed proof. Continue alerting on
   `ans_replay_backend_errors_total`.
6. Custom adapters now supply `RequestContent::Bytes` instead of a precomputed
   digest, so hashing occurs after identity authentication. The public Method A
   binding helper now takes a required receipt reference.

## Deployment conditions and limits

- Raw Envoy is the primary integration target. The Istio `EnvoyFilter` and Envoy
  Gateway JSON patches are examples that need version-specific rendered-xDS and
  traffic validation. A patch file alone is not evidence that the running proxy
  applied it.
- The default body limit is 1 MiB. Envoy rejects larger requests with 413 before
  calling the service. Size limits, body read timeouts, concurrency limits and
  a suitable authorization deadline must be established under load.
- Path fidelity, complete raw-body buffering, listener TLS validation, filter
  order and upstream access isolation are trusted deployment properties.
  `/readyz` observes header-map/authority availability; it does not prove these
  properties, Redis durability or whole-deployment conformance.
- Redis startup rejects a reported evicting policy. If `CONFIG GET` is unavailable
  or malformed, current code warns and relies on out-of-band verification.
  Production must establish `noeviction` explicitly. The demo Redis disables
  persistence and is not a production replay-store design.
- Losing live reservations during Redis restart, failover or memory-cache process
  restart can re-admit an already-used proof. Preserve reservations or stop
  admission until the entire possible freshness window has passed. That bound
  must include future-dated `iat` values accepted within the configured skew.
- Receipt verification trusts a TL-signed leaf. No signed-checkpoint anchoring,
  consistency proof or split-view detection is added here (§11.3).
- Badge fallback, callee/egress verification, proof minting in the proxy,
  delegation and application authorization are outside this ingress component.

## Revocation latency (§11.1)

The example sets status-token skew to 60 seconds, proof skew to 120 seconds,
and replay-store deadline to 50 milliseconds. There is no expired-status grace.
Status tokens must pass the time check even on artifact-cache hits.

Revocation latency is bounded by the remaining lifetime of an accepted status
token plus the configured skew. For a TL issuing one-hour tokens, the maximum is
one hour plus 60 seconds. The TL determines token TTL; this example does not
configure it. Shortening DPoP freshness reduces replay exposure, not token TTL.

## Evidence

`cargo test --locked --workspace` covers signed proofs/status tokens/receipts,
mandatory empty/nonempty content binding, missing/malformed digests and profiles,
raw-path aliases, content failures that do not spend a proof, full Method A names,
supplied-receipt handling, header preflight and configuration refusals.
`ANS_ENVOY_TEST_REDIS_URL` enables the real Redis atomicity and cross-connection
replay tests; a run without it is not Redis integration evidence.

The [Minikube run](minikube-validation.md) passed 50 synthetic TLS cases on
Envoy 1.36.13, including Method A and cross-replica Method B replay. The
[separate live run](live-demo-tl-validation.md) passed nine cases with a registered
identity and live receipt/status evidence. A [temporary egress test](minikube-egress-validation.md)
verified native HTTPS key bootstrap and periodic refresh without a static pin;
actual key rotation and the platform variants remain unvalidated.

Redis restart replay loss was confirmed live. See [release readiness](release-readiness.md)
for the remaining production gates and [the documentation index](README.md) for
the exact test reports. Results from one environment do not establish conformance
of another deployment.
