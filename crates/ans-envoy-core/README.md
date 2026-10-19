# ans-envoy-core

The ANS-6 callee-side authentication decision, with no proxy in it.

Takes a `RequestFacts` — method, target, §7.7 authority, the four §4.6 headers,
optionally a client certificate — and returns `Allow(AuthenticatedCaller)` or
`Deny(DenyReason)`. Nothing here mentions Envoy, gRPC, or `CheckRequest`.

That separation is the point. ANS-6 §7.4 fixes an *order* of twelve checks and
§7.5 fixes a set of bindings; getting either wrong is a security bug, so the
orchestration exists once and is reachable from more than one host. Concretely:
§7.13 content binding uses complete buffered bodies through `ext_authz` today.
A future `ext_proc` adapter could support larger streamed bodies while reusing
this crate's verification order.

Two variants, deliberately. There is no "undecided" outcome, because ANS-6 has
none on the Method-B path — §7.6 makes an erroring replay cache a rejection and
§9.6 makes a store timeout "a rejection, never a skip". An adapter that cannot
express indecision cannot have a proxy's fail-open setting turn it into an allow.

Part of [ans-envoy](https://github.com/agentnameservice/ans-envoy).
