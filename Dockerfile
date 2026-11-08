#syntax=docker/dockerfile:1
# Official DepRadar agent image (ghcr.io/depradar/agent), used by the `container` mode.
# Build from agent/:  docker build -t depradar-agent .
# See docs/cadrage.md §6bis. Multi-arch (amd64/arm64) and cosign signing happen in CI (not yet set up).

ARG RUST_VERSION=1

# --- Build: static musl binary ------------------------------------------------
FROM rust:${RUST_VERSION}-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/depradar-agent /depradar-agent

# --- CA certificates (rustls needs them; the final image has no package manager) -
FROM alpine:3 AS certs
RUN apk add --no-cache ca-certificates

# --- Runtime: scratch, non-root ----------------------------------------------
FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /depradar-agent /agent
# Persistent state (private key, anti-replay memory) must live on a volume.
VOLUME ["/var/lib/agent"]
ENV AGENT_MODE=container
USER 65532:65532
ENTRYPOINT ["/agent"]
