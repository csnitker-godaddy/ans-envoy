# ans-authz

The Envoy `ext_authz` authorization server for ANS-6 agent-to-agent
authentication.

```bash
ans-authz validate-config --config examples/ans-authz.toml   # the §7.7 startup check, in CI
ans-authz validate-envoy  envoy/bootstrap/sidecar-loopback.yaml
ans-authz serve           --config examples/ans-authz.toml
```

`check` never returns a gRPC error. Envoy treats a failed `Check` call as a
*communication failure* and applies `failure_mode_allow` to it, so answering an
unexpected condition with `Err(Status::internal(..))` would hand the decision to a
config setting — exactly the fail-open lever §7.6 and §9.6 exist to close. Every
outcome is `Ok`, carrying `OK` or `PERMISSION_DENIED`.

`/readyz` reports cumulative observations of raw headers and asserted authority.
It can reject an initially misconfigured deployment, but it is not a live xDS or
replay-store health check. Use denial metrics and actual traffic probes too.

Part of [ans-envoy](https://github.com/agentnameservice/ans-envoy).
