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

CI (`.github/workflows/ci.yml`): `cargo fmt --check`, `clippy -D warnings`, `cargo test` on `rust:1`, and a static musl release build on `rust:1-alpine`. Dependabot updates crates and Actions weekly.

Official image `ghcr.io/dependencyverifier/agent` (`container` mode): built by the [`agent-image`](https://github.com/DependencyVerifier/agent-image) repository from this one (static musl binary on `scratch`, non-root, configured only through env vars and secrets). Keep the binary buildable with `cargo build --release --locked` on `rust:1-alpine`.

Docker access in `container` mode: the agent **never mounts the Docker socket** itself. It goes through a `tecnativa/docker-socket-proxy` sidecar that allows GET only (`CONTAINERS=1`, `IMAGES=1`, `INFO=1`, `VERSION=1`, `POST=0`) on an `internal: true` network. Hardening defaults for the agent service: `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true` (see §6bis for the full example).

## Hard rules

- Static binary, targets `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.
- TLS with **`rustls` only**, never OpenSSL.
- **Outbound HTTPS only**, no listening socket. Every request is Ed25519-signed (method, path, timestamp, body hash). Polling interval, `429` and `Retry-After` always come from the console; add jitter.
- The console public key is **pinned** at install. Refuse everything if it changes (rotation only via an order signed by the old key).
- **Closed order catalogue** (`SCAN_NOW`, `SET_CONFIG`; later `UPGRADE_AGENT`, `ROTATE_KEY`). Orders are signed, time-bounded, with persisted anti-replay. **Never run arbitrary shell commands**: external commands come from a fixed list (`rpm -qa --qf …`, `php -v`, `node -v`…), with no shell interpolation.
- Upgrades are verified with the **project release key embedded in the binary** (`release::RELEASE_KEY`), never with the console key.
- Private key `0600`, state in `/var/lib/depverify-agent` (or the container volume). Never log secrets or the token.
- Container scopes: apply the scope filter **before** any file read or image analysis, and test that behavior.
- Catalogers are written in-house (no Syft in Rust) and tested against **real fixtures** (dpkg status, apk installed, `installed.json`, lockfiles…).
- Output: one CycloneDX SBOM per AppInstance, plus host facts, compressed and signed. Send only the content hash when nothing changed.

## Design (v0.1)

- **Synchronous**, no async runtime: one loop (poll, orders, inventory), `std::thread::sleep` between polls. HTTP to the console with `ureq` 3 (rustls, built-in Mozilla roots or `AGENT_CA_FILE`, `HTTPS_PROXY` honoured, no redirect, 90 s timeout); the Docker API through a minimal read-only HTTP/1.1 client (`docker.rs`, TCP or Unix socket, chunked, streamed). Crates: `ureq`, `ed25519-dalek`, `sha2`, `base64`, `serde_json`, `flate2` (pure Rust), `tar`, `uuid`, `globset`, `getrandom`.
- Modules: `config` (env only), `state` (state dir, atomic 0600 writes), `keys`, `signing` (§4, vector test), `jcs` (RFC 8785), `orders` (§7.2 in order, vector test), `client` (signed requests, clock offset, one retry on `clock_skew` / `invalid_signature` / `replayed_request`), `agent` (enroll, poll loop, inventory send, §9 reactions; exit status 3 = stopped for good), `inventory::{osrelease, purl, os, php, node, apps, discovery, runtimes, facts, containers, sbom, collect}`.
- Determinism: SBOMs and host facts are `serde_json` values with sorted keys, components sorted by purl, no timestamp: an unchanged machine re-uploads nothing.
- Containers: the scope filter (`containers::in_scope`) runs on the container list **before** any inspect or file read (tested). Application files come from `GET /containers/{id}/archive` (label paths, else the working directory and usual places); image OS packages from `GET /images/{id}/get`, layers streamed (legacy and OCI layouts, gzip or not), whiteouts applied, cached per image id and agent version in `<state>/images/`. The runtime of a containerized application is the `PHP_VERSION` / `NODE_VERSION` variable of its container (these two only, never the rest of the environment); every application subject also carries `requires` (`require.php` of `composer.json`, `engines.node` of `package.json`).
- Releases: a tag `vX.Y.Z` runs `.github/workflows/release.yml` (both architectures with `cargo-zigbuild` 0.24 / zig 0.17, `SHA256SUMS` signed with minisign, GitHub release). The console verifies them (`AGENT_RELEASE_PUBKEY`) and serves `install.sh` and the binaries.
- RPM databases are read without `rpm` (`inventory/rpmdb`, pure Rust, bounded): SQLite (`rpmdb.sqlite`) and Berkeley DB hash (`Packages`); each header becomes the line `rpm -qa --qf RPM_QUERY_FORMAT` prints, read by `os::rpm`. Tested against the real databases of `rockylinux:9-minimal` and `rockylinux:8-minimal` (compressed) and the `rpm -qa` output of those images. SUSE's ndb is not read.
- The runtime of a path application comes from the PHP-FPM pool its web server passes it to (`inventory/fpm`: pools of Debian, RHEL and Remi, nginx `root` + `fastcgi_pass`, Apache `DocumentRoot` + `SetHandler proxy:` / `ProxyPassMatch fcgi:`, files only), else the host's default `php`. `Files::list` and the symbolic links of a `Root` are resolved inside the root.
- `UPGRADE_AGENT` (host mode, `upgrade.rs`): the release downloaded from the console, its `SHA256SUMS` minisign-verified with the embedded key (`Ed` and `ED`), version and SHA-256 checked, kept in `<state>/bin/X.Y.Z/` with the pointer `bin/current`; the agent then `exec`s it. At each start, `run` verifies a newer installed release again before executing it (`DEPVERIFY_AGENT_REEXEC` stops a second look).
- `ROTATE_KEY`: a new key written to `agent.key.next`, announced by `POST /agent/v1/key-rotations` (signed by the current key, with a proof signed by the new one), then promoted; the old key stays as `agent.key.previous` until a request with the new one succeeds (an `invalid_signature` brings it back; a `next` key left at start is tried first). `ROTATE_CONSOLE_KEY`: the new console key is kept in `state.json` (`console_key`) and prevails over `AGENT_CONSOLE_PUBKEY`.
- Not yet: `embedded` / `ecs` modes.

## End-to-end test against a local console

`depverify-agent inventory --dry-run` prints what would be sent, without a console. Against the dev console (`console/`): join its Docker network (`--network depverifier-console_default --add-host console.depverify.localhost:<php container IP>`), pass its Caddy root CA (`/data/caddy/pki/authorities/local/root.crt` of the `php` container) as `AGENT_CA_FILE`, its public key as `AGENT_CONSOLE_PUBKEY` (Enrollment section of a team) and a token from the console. For the container mode, run `tecnativa/docker-socket-proxy` on the same network and give the agent's container the `com.docker.compose.project` label.

## Conventions

English code and comments. Keep `main.rs` thin. Move to a Cargo workspace only when there is a real need. Catalogers are tested against real files in `tests/fixtures` (taken from official images and real projects), never hand-written samples only.
