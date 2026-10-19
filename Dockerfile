# ans-authz — the ANS-6 ext_authz authorization server.
#
# Build for minikube without a registry:
#
#     podman build -t ans-envoy/ans-authz:dev .
#     podman save -o /tmp/ans-authz.tar ans-envoy/ans-authz:dev
#     minikube image load /tmp/ans-authz.tar
#
# Build on the HOST and load, rather than building inside the VM. `minikube
# docker-env` only works with the docker runtime, so it is unavailable on a
# containerd cluster — and building in the VM needs working DNS there, which is
# not a given behind a corporate VPN (the VM is handed the vmnet gateway as its
# resolver, and that forwards to host resolvers a VPN may not carry).
#
# Loaded images are only found by `imagePullPolicy: IfNotPresent` or `Never`.
# `Always` fails against a side-loaded image even though it is present.
#
# The build needs network: ans-verify comes from a pinned git rev
# (agentnameservice/ans-sdk-rust) rather than crates.io, because the merged ANS-6 API
# has not yet been published to crates.io. Cargo.lock is committed, so the rev is exact.

FROM rust:1.88-bookworm AS builder

WORKDIR /src

# Dependencies first, so a source-only change does not refetch the world.
COPY Cargo.toml Cargo.lock ./
COPY crates/ans-envoy-core/Cargo.toml crates/ans-envoy-core/
COPY crates/ans-envoy-adapter/Cargo.toml crates/ans-envoy-adapter/
COPY crates/ans-envoy-replay/Cargo.toml crates/ans-envoy-replay/
COPY crates/ans-envoy-config/Cargo.toml crates/ans-envoy-config/
COPY crates/ans-authz/Cargo.toml crates/ans-authz/
COPY crates/ans-probe/Cargo.toml crates/ans-probe/
RUN mkdir -p crates/ans-envoy-core/src crates/ans-envoy-adapter/src \
             crates/ans-envoy-replay/src crates/ans-envoy-config/src \
             crates/ans-authz/src crates/ans-probe/src \
 && echo "" > crates/ans-envoy-core/src/lib.rs \
 && echo "" > crates/ans-envoy-adapter/src/lib.rs \
 && echo "" > crates/ans-envoy-replay/src/lib.rs \
 && echo "" > crates/ans-envoy-config/src/lib.rs \
 && echo "fn main() {}" > crates/ans-authz/src/main.rs \
 && echo "fn main() {}" > crates/ans-probe/src/main.rs \
 && cargo fetch --locked

COPY . .

# `container` rather than `release`: same binary, without thin LTO.
#
# The release profile's `lto = "thin"` + `codegen-units = 1` needs on the order of
# tens of GB of intermediates over this crate graph — envoy-types' 312 generated
# proto modules, plus aws-lc-sys and ring, both pulled unconditionally by
# ans-verify. That overflows a default podman/docker VM disk. See the profile
# comments in Cargo.toml.
#
# Build the shipped image with `--build-arg PROFILE=release` on a machine that
# has the disk for it.
ARG PROFILE=container

# `--locked` so a container build can never silently resolve a different
# ans-verify revision than the one the tests ran against.
RUN cargo build --profile "$PROFILE" --locked -p ans-authz \
 && mkdir -p /out \
 && cp "target/$PROFILE/ans-authz" /out/ans-authz \
 && rm -rf target

FROM debian:bookworm-slim

# ca-certificates only: ans-authz fetches /root-keys over HTTPS at startup when
# `transparency_log.root_keys_url` is set (§4.5). Nothing else is needed — the
# binary does not shell out.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged. This process parses attacker-supplied X.509, COSE and JWS all day;
# it has no reason to be able to write anything or bind a privileged port.
RUN useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin ansauthz
USER 65532:65532

COPY --from=builder /out/ans-authz /usr/local/bin/ans-authz

# gRPC ext_authz, and the admin surface (/healthz, /readyz, /metrics).
EXPOSE 10003 9901

ENTRYPOINT ["/usr/local/bin/ans-authz"]
CMD ["serve", "--config", "/etc/ans-authz/ans-authz.toml"]
