# Public test identities

This directory intentionally contains certificate fixtures **and their private
keys** for `ans-probe` and the verification tests. These are public test values,
not credentials for a real service. Anyone with this repository can sign with
them. Never register, deploy or trust them in production.

| Files | Purpose |
| --- | --- |
| `caller.cert.der`, `caller.key.pk8` | Baseline `caller.example.com` identity |
| `caller-alt.cert.der`, `caller-alt.key.pk8` | Different key/certificate for the same caller |
| `other-agent.cert.der`, `other-agent.key.pk8` | Different agent identity for binding tests |

Certificates use DER; keys use DER-encoded PKCS#8. The tests load the exact
committed bytes and sign synthetic evidence with public, deterministic test TL
material. Fixtures are covered by the repository's [MIT License](../../LICENSE).

Generate local TLS keys and live test bundles outside the checkout. Those files
are not fixtures to commit. The live demo agent's private key was never included
here; the recorded live tests signed on its host.
