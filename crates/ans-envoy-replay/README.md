# ans-envoy-replay

ANS-6 §7.6 replay caches: single-use `DPoP` proof identifiers, stored so a proof
cannot be presented twice.

`RedisBackend` is the conformant choice above one replica. §7.6: "Multi-replica
deployments MUST share the replay cache across replicas serving the same `htu`
authority." Check-and-store is one `SET NX PX` — atomic, and the server's decision
rather than ours. The deployment must retain that shared state for the full replay window.

Two things to know before deploying:

**The store must not evict.** `connect` reads `maxmemory-policy` and refuses to
start unless it is `noeviction`. Under `allkeys-lru` Redis drops a live `jti` to
make room and the next presentation of that proof looks fresh — silent replay
admission, which §7.6 forbids. This is the sharpest failure mode in the design.

**Backend failures have distinct labels.** `FailClosedCache` maps capacity
exhaustion to `REPLAY_CACHE_FULL` and other backend failures to
`REPLAY_CACHE_UNAVAILABLE`. Both fail closed and produce deployment-error
responses. Alert on `ReplayMetrics::backend_errors`.

Part of [ans-envoy](https://github.com/agentnameservice/ans-envoy).
