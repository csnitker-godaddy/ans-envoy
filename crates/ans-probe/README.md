# ans-probe

Development tool. Mints ANS-6 artifacts so a demo caller can produce a valid
Method-B request, then runs the refusal matrix against a deployed `ans-envoy`.

```bash
ans-probe mint                                    # writes ./demo-bundle + a C2SP key line
ans-probe scenarios --url http://localhost:18443  # runs the matrix
```

A real deployment gets its status token and receipt from a Transparency Log.
Standing one up for a local demo would be more work than the thing being
demonstrated, so this mints its own TL key and publishes it as a C2SP signed-note
line for the callee's `static_root_keys` — §4.5 calls that pinned, static posture
valid.

Checking that a valid request returns 200 proves very little; a deployment with
verification switched off does that too. The matrix checks the refusals, and
asserts the exact `x-ans-deny-label` rather than just a non-200.

`publish = false`. It writes private keys to disk and has no business near
production.
