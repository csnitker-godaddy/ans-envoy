#!/usr/bin/env bash
#
# Pull every image the demo needs on the HOST, then side-load it into minikube.
#
# Why not just let the node pull? Because on a corporate laptop it often can't.
# minikube hands the VM the vmnet gateway (192.168.64.1) as its resolver, that
# gateway forwards to the host's resolvers, and a VPN client will not carry
# queries that originated on the vmnet interface. The symptom is
# `lookup registry-1.docker.io: i/o timeout` on every pull while the host itself
# resolves fine.
#
# That is fixable inside the VM:
#
#     minikube ssh -- 'sudo mkdir -p /etc/systemd/resolved.conf.d \
#       && printf "[Resolve]\nDNS=8.8.8.8 1.1.1.1\n" \
#          | sudo tee /etc/systemd/resolved.conf.d/99-public-dns.conf >/dev/null \
#       && sudo systemctl restart systemd-resolved'
#     minikube kubectl -- -n kube-system rollout restart deployment coredns
#
# (CoreDNS needs the restart because its `forward . /etc/resolv.conf` reads that
# file at load time, and its `reload` plugin only watches the Corefile.)
#
# But that config lives in the VM's runtime state and does not survive
# `minikube stop`. Side-loading does survive, so it is the option that still
# works when you come back to this next week on a different network.
#
# Loaded images are only found by `imagePullPolicy: IfNotPresent` or `Never`.
# `Always` fails against a side-loaded image even though it is present locally —
# see check_pull_policies() at the end.
#
# Usage:
#     ISTIO_VERSION=1.31.0 ./deploy/kubernetes/load-images.sh
#     ./deploy/kubernetes/load-images.sh --skip-istio     # just the demo images
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="${TMPDIR:-/tmp}/ans-envoy-images"
SKIP_ISTIO=0
[[ "${1:-}" == "--skip-istio" ]] && SKIP_ISTIO=1

# ---------------------------------------------------------------------------
# Container tool. podman first: on a containerd minikube there is no
# `minikube docker-env` to point a docker client at, so the host tool is only
# ever used to build and save tarballs. Either works for that.
# ---------------------------------------------------------------------------
if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
  CTR=podman
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  CTR=docker
else
  echo "error: need a working podman or docker on the HOST to pull and save images." >&2
  echo "       podman: 'podman machine start' first." >&2
  exit 1
fi

command -v minikube >/dev/null 2>&1 || { echo "error: minikube not on PATH" >&2; exit 1; }

mkdir -p "$TMP"
echo "using $CTR; staging tarballs in $TMP"
echo

# Images already inside the cluster. Cheap to ask once rather than per image.
PRESENT="$(minikube image ls 2>/dev/null || true)"

# ---------------------------------------------------------------------------
# load_remote <image-ref>
#   Pull on the host, save, import into the node. Skips if already present.
# ---------------------------------------------------------------------------
load_remote() {
  local ref="$1"
  # minikube image ls prints refs with an explicit docker.io/library prefix for
  # Docker Hub shorthand, so match on the distinctive tail rather than the ref.
  local needle="${ref#docker.io/}"
  needle="${needle#library/}"
  if grep -qF -- "$needle" <<<"$PRESENT"; then
    echo "  present, skipping: $ref"
    return 0
  fi

  local tar="$TMP/$(tr '/:' '__' <<<"$ref").tar"
  echo "  pulling  $ref"
  "$CTR" pull "$ref" >/dev/null
  echo "  saving   -> $(basename "$tar")"
  "$CTR" save -o "$tar" "$ref"
  echo "  loading  into minikube"
  minikube image load "$tar"
  rm -f "$tar"
}

# ---------------------------------------------------------------------------
# The demo's own images.
#
# busybox is here because it is the tool of choice for in-cluster debugging
# (`kubectl run --image=busybox:1.36 -- nslookup ...`) and you do not want that
# to be the thing that fails when you are already debugging something else.
# ---------------------------------------------------------------------------
echo "== demo images"
for ref in \
  docker.io/library/redis:7-alpine \
  docker.io/library/python:3.12-alpine \
  docker.io/library/busybox:1.36 \
  docker.io/envoyproxy/envoy:v1.36-latest
do
  load_remote "$ref"
done
echo

# ---------------------------------------------------------------------------
# Istio. Version must be explicit: the control plane and the injected sidecar
# have to match, and guessing a tag here produces a mesh that half-works.
#
# Note the two names are NOT symmetrical — the control plane image is `pilot`
# even though the Deployment is called istiod.
# ---------------------------------------------------------------------------
if [[ "$SKIP_ISTIO" -eq 0 ]]; then
  if [[ -z "${ISTIO_VERSION:-}" ]]; then
    if command -v istioctl >/dev/null 2>&1; then
      # `istioctl version --remote=false` prints either a bare semver or
      # "client version: 1.31.0" depending on version, so pull the semver out
      # rather than trusting the line shape.
      ISTIO_VERSION="$(istioctl version --remote=false 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    fi
  fi
  if [[ -z "${ISTIO_VERSION:-}" ]]; then
    echo "error: set ISTIO_VERSION (e.g. ISTIO_VERSION=1.31.0 $0)." >&2
    echo "       It must match the control plane you install, so this script will" >&2
    echo "       not guess. Available: gh api repos/istio/istio/releases --jq '.[].tag_name'" >&2
    exit 1
  fi

  echo "== istio $ISTIO_VERSION"
  for ref in \
    "docker.io/istio/pilot:${ISTIO_VERSION}" \
    "docker.io/istio/proxyv2:${ISTIO_VERSION}"
  do
    load_remote "$ref"
  done
  echo
fi

# ---------------------------------------------------------------------------
# ans-authz, built from source rather than pulled.
#
# Built on the host, not in the VM: `minikube docker-env` needs the docker
# runtime and this cluster is containerd, and the build itself needs network to
# fetch the pinned ans-verify rev from GitHub.
# ---------------------------------------------------------------------------
echo "== ans-authz (local build)"
if grep -qF "ans-envoy/ans-authz:dev" <<<"$PRESENT"; then
  echo "  present in cluster. Rebuild with:"
  echo "    $CTR build -t ans-envoy/ans-authz:dev $REPO_ROOT"
  echo "  then re-run this script after 'minikube image rm ans-envoy/ans-authz:dev'."
else
  echo "  building (first build fetches the crate graph; expect several minutes)"
  "$CTR" build -t ans-envoy/ans-authz:dev "$REPO_ROOT"
  tar="$TMP/ans-authz.tar"
  "$CTR" save -o "$tar" ans-envoy/ans-authz:dev
  minikube image load "$tar"
  rm -f "$tar"
fi
echo

# ---------------------------------------------------------------------------
# The failure mode that wastes the most time: an image is loaded and present,
# but a manifest says `Always`, so the kubelet insists on contacting the
# registry and the pod sits in ErrImagePull looking exactly like a missing
# image. Catch it here rather than in a pod event.
# ---------------------------------------------------------------------------
check_pull_policies() {
  local hits
  hits="$(grep -rn "imagePullPolicy:[[:space:]]*Always" "$REPO_ROOT/deploy" 2>/dev/null || true)"
  if [[ -n "$hits" ]]; then
    echo "WARNING: 'imagePullPolicy: Always' will fail against a side-loaded image:"
    sed 's/^/  /' <<<"$hits"
    echo
  fi
}
check_pull_policies

echo "loaded. Verify with:"
echo "  minikube image ls | grep -E 'ans-authz|istio|redis|python|envoy'"
