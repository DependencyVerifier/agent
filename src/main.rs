//! DepRadar agent.
//!
//! Inventories what is deployed (OS packages, runtimes, Composer/npm
//! dependencies, Docker images) and reports it to the console over an
//! outbound-only, Ed25519-signed connection. See `docs/cadrage.md` §6 and §6bis.

fn main() {
    println!("depradar-agent {}", env!("CARGO_PKG_VERSION"));
}
