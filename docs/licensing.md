# Licensing and notices

## Project license

The source in this repository is distributed under the [MIT License](../LICENSE),
with the existing copyright notice:

```text
Copyright (c) 2026 GoDaddy Operating Company, LLC.
```

Preserve that notice and the permission notice in copies or substantial portions
of the software. The permission notice does not change the attribution of existing work.

## Contribution and community documents

The [Developer Certificate of Origin](../DCO) is the verbatim version 1.1 text
from [developercertificate.org](https://developercertificate.org/). It includes
its own permission to copy and distribute unchanged. Do not edit the certificate
text or treat it as a replacement for the MIT license.

The [Code of Conduct](../CODE_OF_CONDUCT.md) retains the Contributor Covenant 2.0
attribution and source links used by the other ANS repositories. Keep that
attribution when adapting the document.

Contributors certify their rights through DCO sign-off as described in
[CONTRIBUTING.md](../CONTRIBUTING.md). That attestation is distinct from a
cryptographic commit signature and from an AI-assistance disclosure.

## Dependencies and release artifacts

Dependencies retain their own licenses. The workspace's `license = "MIT"`
declaration does not relicense the Rust SDK, Envoy API bindings, Python test
libraries, or other dependencies. Dependency policy is in [deny.toml](../deny.toml).
Run `cargo deny check` for the resolved Rust dependency graph, and review Python
requirements and any copied/vendored material separately.

Before distributing binaries or container images, retain the dependency license
notices required by the exact built artifact and generate its SBOM. A passing
source dependency-policy check does not replace notices for a distributed image
or for its base operating-system packages.

The public keys and synthetic certificates under [testdata](../testdata/demo-agents/README.md)
are test material covered by this repository's license. Their private keys are
intentionally public and must never be reused outside isolated tests.

## ANS convention baseline

Documentation was checked against these immutable ANS revisions on 2026-10-19:

- [ans-sdk-rust](https://github.com/agentnameservice/ans-sdk-rust/tree/0a86cacfd4825edef3a2ea7ef9c2026e37ca7629)
- [ans-sdk-go](https://github.com/agentnameservice/ans-sdk-go/tree/4d3d2bb56ec38a9296947c36d14bb74f83d5dffa)
- [ans](https://github.com/agentnameservice/ans/tree/96a42233aab8cf1c45f71ec9c5eaf969990f6f29)

All three use MIT, the GoDaddy security-reporting policy, Contributor Covenant
and human DCO sign-off. This repository keeps those conventions; differences in
historical copyright years are not a reason to change existing attribution.
