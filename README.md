# depverify-agent

Lightweight agent of [DependencyVerifier](https://github.com/DependencyVerifier). It inventories what is deployed on a machine (OS packages, runtimes, Composer and npm dependencies, Docker images) and reports a signed CycloneDX SBOM to the [console](https://github.com/DependencyVerifier/console) over an outbound-only HTTPS connection.

- Static Rust binary (musl), Linux x86_64 and aarch64.
- Outbound HTTPS only, no listening port; every request signed with Ed25519; the console key is pinned at install.
- Closed catalogue of signed orders, never arbitrary shell commands.
- Container image: [`agent-image`](https://github.com/DependencyVerifier/agent-image) (`ghcr.io/dependencyverifier/agent`).

> Status: early development, nothing usable yet.

## Development

```bash
docker run --rm -v "$PWD":/work -w /work rust:1 cargo build
docker run --rm -v "$PWD":/work -w /work rust:1 cargo test
```

## Documentation

Specification (agent protocol, enrollment, privileges): [`DependencyVerifier/.github`](https://github.com/DependencyVerifier/.github).

## License

[Apache-2.0](LICENSE).
