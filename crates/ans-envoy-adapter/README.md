# ans-envoy-adapter

Translates Envoy's `envoy.service.auth.v3` messages to and from
[`ans-envoy-core`](../ans-envoy-core)'s proxy-neutral types. The only crate that
touches Envoy's wire types, and it makes no security decisions of its own.

Three Envoy settings it depends on:

| Setting | Why | Without it |
| --- | --- | --- |
| `encode_raw_headers: true` | §4.6 duplicate detection needs uncoalesced header values | reports `raw_values_available: false`, and the verifier denies every request |
| `context_extensions` per route | §7.7 needs an authority a client cannot forge | resolves nothing, and the request is denied |
| `include_peer_certificate: true` | Method A needs the validated client certificate | no certificate arrives, so Method A cannot run |

`attributes.request.http.host` is never read. §7.7 calls deriving the comparison
URL from it "the vulnerability, not the defense".

Part of [ans-envoy](https://github.com/agentnameservice/ans-envoy).
