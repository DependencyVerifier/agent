# depverify-agent

Lightweight agent of [DependencyVerifier](https://github.com/DependencyVerifier). It inventories what is deployed on a machine (OS packages, runtimes, Composer and npm dependencies, Docker images) and reports a signed CycloneDX SBOM to the [console](https://github.com/DependencyVerifier/console) over an outbound-only HTTPS connection.

- Static Rust binary (musl), Linux x86_64 and aarch64.
- Outbound HTTPS only, no listening port; every request signed with Ed25519; the console key is pinned at install.
- Closed catalogue of signed orders, never arbitrary shell commands.
- Container image: [`agent-image`](https://github.com/DependencyVerifier/agent-image) (`ghcr.io/dependencyverifier/agent`).

> Status: protocol v1 complete (enrollment, signed polling, `SCAN_NOW` / `SET_CONFIG` orders, inventories), modes
> `host` and `container`. Not released yet: build it from source or with [`agent-image`](https://github.com/DependencyVerifier/agent-image).

## What it collects

| Source | How |
|---|---|
| OS packages | `/var/lib/dpkg/status` (and distroless `status.d/`), `/lib/apk/db/installed`, the fixed command `rpm -qa --qf …` (host mode) |
| Runtimes | fixed commands: `php -v` / `-m`, `php-fpm* -v`, `composer --version`, `node -v`, `npm -v`, `yarn -v`, `pnpm -v` |
| Applications | under the discovery roots (`/var/www`, `/srv`, `/opt` by default) and the declared paths: `vendor/composer/installed.json` (else `composer.lock`), `package-lock.json`, `yarn.lock` (v1 and berry), `pnpm-lock.yaml` |
| Containers | through the Docker API (GET only): the containers in scope, their application files (`/containers/{id}/archive`), their images analysed layer by layer (dpkg, apk), once per image id |

Never a shell, never a command or path received from the network outside the closed order catalogue.

## Host mode (systemd)

```bash
install -m 0755 depverify-agent /usr/local/bin/
useradd --system --no-create-home --shell /usr/sbin/nologin depverify-agent
install -d -m 0750 -g depverify-agent /etc/depverify-agent
install -m 0640 -g depverify-agent packaging/agent.env.example /etc/depverify-agent/agent.env   # then edit it
printf '%s' "$AGENT_TOKEN" | install -m 0640 -g depverify-agent /dev/stdin /etc/depverify-agent/token
install -m 0644 packaging/depverify-agent.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now depverify-agent
journalctl -u depverify-agent   # the fingerprint to compare before approving the agent in the console
```

The agent user needs read access to the application directories (group or ACL). The unit is hardened
(`ProtectSystem=strict`, `NoNewPrivileges`, no capability); exit status 3 means stopped for good (revoked agent,
refused token, console key mismatch).

## Container mode

See [`agent-image`](https://github.com/DependencyVerifier/agent-image): one service in the Compose project and a
read-only Docker socket proxy. `AGENT_SCOPE` = `compose` (default), `labeled` or `host`; labels `dev.depverify.*`.

## Settings

| Variable | Default | |
|---|---|---|
| `AGENT_CONSOLE_URL` | | `https://` base URL of the console |
| `AGENT_CONSOLE_PUBKEY` | | `ed25519:…`, the pinned console key |
| `AGENT_TOKEN` / `AGENT_TOKEN_FILE` | | enrollment token, read once |
| `AGENT_MODE` | `host` | `host` or `container` |
| `AGENT_SCOPE` | `compose` | container mode: `compose`, `labeled`, `host` |
| `AGENT_STATE_DIR` | `/var/lib/depverify-agent` (host), `/var/lib/agent` (container) | private key (0600), agent id, applied configuration, anti-replay store, image cache |
| `AGENT_DOCKER` | off | host mode: read Docker too |
| `AGENT_DOCKER_HOST` / `DOCKER_HOST` | `tcp://depverify-docker-proxy:2375` (container), `unix:///var/run/docker.sock` (host) | |
| `AGENT_HOST_ROOT` | `/` (host), `/host` (container, scope `host`) | where the host file system is read |
| `AGENT_COMPOSE_PROJECT` | read from the agent's own container | |
| `AGENT_CA_FILE` | built-in Mozilla roots | PEM of a private CA of the console |
| `HTTPS_PROXY` / `NO_PROXY` | | outbound proxy |

Commands: `depverify-agent run` (default), `enroll`, `fingerprint`, `inventory --dry-run` (prints what would be sent,
no console needed), `version`.

## Development

```bash
docker run --rm -v "$PWD":/work -w /work rust:1 cargo build
docker run --rm -v "$PWD":/work -w /work rust:1 cargo test
docker run --rm -v "$PWD":/work -w /work rust:1 sh -c 'rustup component add clippy rustfmt && cargo fmt --check && cargo clippy --all-targets -- -D warnings'
```

The signatures reproduce the protocol test vectors byte for byte (`signing.rs`, `orders.rs`); the catalogers are
tested against real files (`tests/fixtures`: dpkg, apk and rpm databases of official images, Composer and Node
lockfiles).

## Documentation

Specification (agent protocol, enrollment, privileges): [`DependencyVerifier/.github`](https://github.com/DependencyVerifier/.github).

## License

[Apache-2.0](LICENSE).
