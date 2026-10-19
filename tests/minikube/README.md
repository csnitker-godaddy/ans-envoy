# Local Minikube integration probes

These probes use generated TLS certificates and the public demo TL signing key.
They are for a disposable local namespace, not a production ANS deployment.
They do not reset or recreate a cluster. `resilience.py` scales only
`deployment/redis` in `ans-envoy-validation` on context `minikube` to zero and
back, and deliberately detects the demo Redis's replay-loss problem.

Prerequisites: a working local `minikube` profile, Python 3.11+, OpenSSL,
`kubectl`, the current `ans-probe` binary, and the four test images loaded into
Minikube. Run commands from the repository root. Keep all generated keys outside
this repository:

```sh
export ANS_ENVOY_TEST_DIR="$(mktemp -d)"
export ANS_ENVOY_TEST_IMAGE=localhost/ans-envoy/ans-authz:local-test
python3 -m venv "$ANS_ENVOY_TEST_DIR/venv"
"$ANS_ENVOY_TEST_DIR/venv/bin/pip" install -r tests/minikube/requirements.txt
cargo build --locked -p ans-probe
umask 077
./target/debug/ans-probe mint --out "$ANS_ENVOY_TEST_DIR/bundle" \
  --agents testdata/demo-agents
# This writes a private kubeconfig without changing the selected context.
kubectl --context minikube config view --minify --flatten --raw \
  > "$ANS_ENVOY_TEST_DIR/kubeconfig"
"$ANS_ENVOY_TEST_DIR/venv/bin/python" tests/minikube/prepare.py
```

Build the current authorizer image under `ANS_ENVOY_TEST_IMAGE`, then side-load
it and `envoyproxy/envoy:v1.36-latest`, `redis:7-alpine`, and
`python:3.12-alpine`. The manifests use `imagePullPolicy: Never`. Record actual
image IDs and versions; tags may move. The recorded run used Envoy 1.36.13.

Apply only to local Minikube and the isolated namespace. A pre-existing namespace
with this name must be your disposable test workload before applying:

```sh
kubectl --kubeconfig "$ANS_ENVOY_TEST_DIR/kubeconfig" --context minikube \
  apply -f "$ANS_ENVOY_TEST_DIR/test-manifests.yaml"
kubectl --kubeconfig "$ANS_ENVOY_TEST_DIR/kubeconfig" --context minikube \
  -n ans-envoy-validation rollout status deployment/ans-gateway
kubectl --kubeconfig "$ANS_ENVOY_TEST_DIR/kubeconfig" --context minikube \
  -n ans-envoy-validation get pods -l app=ans-gateway
```

In separate terminals, forward **two distinct gateway pods** to local 28443 and
28444, and `service/agent` to local 28080 (remote port 8080). Every forward must
use the explicit kubeconfig, `--context minikube`, `-n ans-envoy-validation`,
and `--address 127.0.0.1`. Gateway remote port is 8443. Restart these forwards if
pods roll. The traffic script verifies the server's chain and hostname using the
generated CA; it does not disable TLS verification.

```sh
"$ANS_ENVOY_TEST_DIR/venv/bin/python" tests/minikube/traffic.py
# Disruptive only to the disposable Redis; restores replicas in a finally block.
"$ANS_ENVOY_TEST_DIR/venv/bin/python" tests/minikube/resilience.py
```

Results are written to `matrix-results.json` and `resilience-results.json` under
the test directory. Every denial checks the upstream request counter. The normal
matrix should pass all 50 cases. The unmodified demo Redis currently fails the
spent-proof-after-restart check; this is an intentional production release gate,
not a test to disable. Tokens expire after an hour; regenerate the bundle for a
later run. Keep generated keys, manifests containing the TLS Secret, and
kubeconfig out of version control.

After inspection, remove only this test namespace if it is no longer needed:
`kubectl --context minikube delete namespace ans-envoy-validation`.
