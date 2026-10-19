# Temporary Minikube HTTP/HTTPS egress validation — 2026-10-19

The owner requested outbound HTTP/HTTPS and then explicitly selected
**temporary testing only** rather than a persistent host proxy.

## Findings

The cluster had no NetworkPolicy denying egress. The node and pods could reach
public IPv4 HTTP directly, but the VM's configured DNS forwarder failed. The
Mac routed the demo TL's IPv4 address through its VPN interface; the same target
from the VM timed out, including a test with DNS bypassed and TLS hostname
verification retained. Host access to the TL succeeded.

A proxy on the Mac's Minikube bridge provided a working path through the Mac's
normal network/VPN routing. No VPN route or firewall policy was disabled or
modified. TLS was tunneled, not decrypted.

## Restricted temporary proxy

Tinyproxy 1.11.3 was installed with Homebrew. It was run in the foreground with:

```conf
Listen 192.168.64.1
Port 18889
Allow 192.168.64.1
Allow 192.168.64.4
ConnectPort 443
Timeout 60
MaxClients 32
LogLevel Warning
```

Those addresses were the host bridge and the current Minikube node. Re-read
actual addresses before reusing this configuration; do not expose it on all
interfaces or expand its client allowlist without a deliberate decision.

A dedicated test pod received HTTP_PROXY/HTTPS_PROXY pointing to this listener.
NO_PROXY covered loopback, `.svc`, `.cluster.local`, the service/pod CIDRs and
the Minikube subnet, preserving direct in-cluster traffic.

## Results

- Node HTTP request to `http://1.1.1.1/` through the proxy returned HTTP 301.
- Pod HTTPS request to `https://tl.ans.snitker.dev/root-keys` returned HTTP 200
  with signing key ID `8f74b1bd`, using normal certificate verification.
- A short-lived pod running the existing authorizer image bootstrapped from
  `root_keys_url` with **`static_root_keys = []`**. The native Rust SDK fetched
  and validated the live TL key successfully.
- With a five-second interval for this bounded test, the SDK logged successful
  background key refresh. This proves fetching and refresh of the current key;
  it does not exercise a real TL key rotation.
- Redis remained reachable directly through cluster networking.

[Machine-readable bootstrap and refresh evidence](test-evidence/minikube-2026-10-19/egress-results.json)

## State after testing

The temporary authorizer pod and ConfigMap were deleted. The proxy and the
connectivity-test listener were stopped. No login-started service was installed,
and neither the gateway Deployment nor its TL ConfigMap was changed. The
existing two gateway replicas, Redis and echo upstream remained healthy.
Tinyproxy is installed as an inactive command-line tool for another explicitly
started test; installation alone does not provide network access.

**Ongoing Minikube HTTP/HTTPS egress was not enabled.** The current gateways
continue using the live TL public-key pin. A deliberately started proxy or a
separate VM/VPN networking fix is still required for their automatic key fetches.
This is the result of the owner's temporary-only choice, not a claim that direct
VM egress was repaired.
