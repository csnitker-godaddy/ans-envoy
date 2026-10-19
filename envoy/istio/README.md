# Istio integration example

These manifests are experimental starting points. They have not been validated
against a pinned Istio release. Raw Envoy is the currently exercised target.

The example combines an `envoyExtAuthzGrpc` extension provider and CUSTOM
AuthorizationPolicy with an `EnvoyFilter` patch. The patch supplies raw headers,
complete raw body buffering and path-preservation settings required by ANS-6.
The generated filter names and patch matches depend on the Istio release.

## Authority and transport

Use `authority.mode = "sole_configured"` only when the deployment answers as
exactly one externally visible authority. A multi-authority deployment needs a
trusted per-route assertion; never derive it from client Host or forwarded
headers. See [the deployment contract](../README.md).

Restrict access to the authorizer. A remote gRPC service needs authenticated
transport or equivalent enforced network isolation. Enabling Method A also
requires the proxy to validate the client certificate and deliver its leaf to
the authorizer; a successful mesh workload identity handshake alone is not an
ANS identity check.

## Validation

Check the provider/CRD schema and generated xDS for your exact Istio and Envoy
versions. Verify all required settings survived patch application and that
`ext_authz` runs before the router and body transformations. Test real positive
and negative requests through the resulting listener.

If raw header delivery is absent, the authorizer rejects with
`RAW_HEADERS_UNAVAILABLE`. Readiness records cumulative observations, so use
request-denial metrics and traffic probes to detect later configuration changes.
Neither a successful apply nor readiness alone establishes conformance.

- [Extension provider](extension-provider.yaml)
- [Authorization policy](authorizationpolicy.yaml)
- [Envoy patch](envoyfilter-raw-headers.yaml)
