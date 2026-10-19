# Documentation

## Using and developing ans-envoy

- [Project overview and setup](../README.md)
- [Development and validation commands](development.md)
- [ANS-6 conformance and migration](conformance.md)
- [Envoy deployment contract](../envoy/README.md)
- [Kubernetes/Minikube test instructions](../tests/minikube/README.md)
- [Release readiness](release-readiness.md)
- [Implementation comparison criteria](comparison.md)
- [Licensing and notices](licensing.md)
- [Contributing and DCO](../CONTRIBUTING.md)
- [Security reporting](../SECURITY.md)

## Recorded validation

These reports describe bounded runs against specific revisions and environments.
They are evidence to reproduce, not a certification of every deployment.

| Report | Evidence |
| --- | --- |
| [Minikube validation](minikube-validation.md) | 50-case synthetic TLS/Envoy matrix; two replicas and real Redis; restart replay-loss reproduction |
| [Live demo TL validation](live-demo-tl-validation.md) | Nine cases with a registered demo identity, live status token and receipt |
| [Temporary HTTP/HTTPS egress](minikube-egress-validation.md) | Native SDK bootstrap and periodic refresh without a static key pin, through a temporary proxy |
| [Machine-readable results](test-evidence/minikube-2026-10-19/) | Environment, image IDs and individual pass/fail outcomes |

Keep synthetic evidence, live identity verification, network reachability and
production failure recovery distinct when reporting results. The remaining
release gates are collected in [release readiness](release-readiness.md).
