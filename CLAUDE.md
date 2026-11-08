# DependencyVerifier agent (`agent/`)

Rust binary `depverify-agent`, licensed **Apache-2.0**. One binary for every deployment mode (`AGENT_MODE` = `host` / `container` / `embedded` / `ecs`).

> **Spec and design** live in the [`DependencyVerifier/.github`](https://github.com/DependencyVerifier/.github) repository: `docs/cadrage.md` (spec, French), `docs/design.md` (UI charter), `docs/brand/` (logo, social images). Any `docs/…` path in this repository refers to that repository.

**Read first:** `docs/cadrage.md` §6 (distribution, install trust chain, enrollment, protocol, orders, what is collected, privileges) and §6bis (containers, `AGENT_SCOPE`, `dev.depverify.*` labels). MVP modes: `host` and `container` only.

## Commands (always through Docker, from the repository root)

```bash
docker run --rm -v "$PWD":/work -w /work rust:1 cargo build
docker run --rm -v "$PWD":/work -w /work rust:1 cargo test
docker run --rm -v "$PWD":/work -w /work rust:1 cargo clippy --all-targets -- -D warnings
docker run --rm -v "$PWD":/work -w /work rust:1 cargo fmt
```

Official image `ghcr.io/dependencyverifier/agent` (`container` mode): built by the [`agent-image`](https://github.com/DependencyVerifier/agent-image) repository from this one (static musl binary on `scratch`, non-root, configured only through env vars and secrets). Keep the binary buildable with `cargo build --release --locked` on `rust:1-alpine`.

Docker access in `container` mode: the agent **never mounts the Docker socket** itself. It goes through a `tecnativa/docker-socket-proxy` sidecar that allows GET only (`CONTAINERS=1`, `IMAGES=1`, `INFO=1`, `VERSION=1`, `POST=0`) on an `internal: true` network. Hardening defaults for the agent service: `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true` (see §6bis for the full example).

## Hard rules

- Static binary, targets `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.
- TLS with **`rustls` only**, never OpenSSL.
- **Outbound HTTPS only**, no listening socket. Every request is Ed25519-signed (method, path, timestamp, body hash). Polling interval, `429` and `Retry-After` always come from the console; add jitter.
- The console public key is **pinned** at install. Refuse everything if it changes (rotation only via an order signed by the old key).
- **Closed order catalogue** (`SCAN_NOW`, `SET_CONFIG`; later `UPGRADE_AGENT`, `ROTATE_KEY`). Orders are signed, time-bounded, with persisted anti-replay. **Never run arbitrary shell commands**: external commands come from a fixed list (`rpm -qa --qf …`, `php -v`, `node -v`…), with no shell interpolation.
- Upgrades are verified with the **project release key embedded in the binary**, never with the console key.
- Private key `0600`, state in `/var/lib/depverify-agent` (or the container volume). Never log secrets or the token.
- Container scopes: apply the scope filter **before** any file read or image analysis, and test that behavior.
- Catalogers are written in-house (no Syft in Rust) and tested against **real fixtures** (dpkg status, apk installed, `installed.json`, lockfiles…).
- Output: one CycloneDX SBOM per AppInstance, plus host facts, compressed and signed. Send only the content hash when nothing changed.

## Expected crates (add when needed)

`tokio`, `rustls` (HTTP client on top of it), `ed25519-dalek`, `minisign-verify`, `serde` / `serde_json` / `serde_yaml`, `bollard`, `cyclonedx-bom`.

## Conventions

English code and comments. Keep `main.rs` thin; split into modules (`config`, `enroll`, `protocol`, `orders`, `catalogers::{dpkg,rpm,apk,composer,npm,yarn,pnpm,docker}`, `sbom`) as the code grows. Move to a Cargo workspace only when there is a real need.
