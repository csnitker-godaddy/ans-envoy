# ans-envoy-config

Configuration, ANS-6 §7.7 startup validation, and Envoy config linting.

Two jobs ANS-6 assigns to "the embedding service" rather than to a verification
library.

**Fail startup, not requests.** §7.7: "Implementations MUST fail startup when
neither is configured, and MUST NOT fall back to deriving the comparison authority
from the request's own `Host` header." The SDK's own docs say it cannot do this —
"this library cannot see your startup, so enforce that in the embedding service."
`validate` is that enforcement, and it also refuses an in-process replay cache
behind more than one replica (§7.6), receipts disabled without a documented reason
(§7.1), and the obsolete `optional` content-binding setting for Method B
(§7.13).

Security-relevant settings have no defaults, so a deployment cannot choose a
policy by omission.

**Lint the half we ship but do not run.** `envoy_lint` checks the six groups of Envoy
settings conformance depends on. Advisory for anything an xDS control plane
delivers, so it is paired with request-time detection in the running service.

Part of [ans-envoy](https://github.com/agentnameservice/ans-envoy).
