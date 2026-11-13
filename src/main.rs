//! DependencyVerifier agent.
//!
//! Inventories what is deployed (OS packages, runtimes, Composer/npm dependencies, Docker images) and reports it to
//! the console over an outbound-only, Ed25519-signed connection. See `docs/cadrage.md` §6 and §6bis, and the
//! protocol in `docs/protocol.md`.

mod agent;
mod client;
mod config;
mod docker;
mod inventory;
mod jcs;
mod keys;
mod orders;
mod signing;
mod state;
mod time;

use std::process::ExitCode;

use agent::log;

const USAGE: &str = "usage: depverify-agent [run | enroll | fingerprint | inventory --dry-run | version]

Settings come from the environment: AGENT_CONSOLE_URL, AGENT_CONSOLE_PUBKEY, AGENT_TOKEN or AGENT_TOKEN_FILE,
AGENT_MODE (host, container), AGENT_SCOPE (compose, labeled, host), AGENT_STATE_DIR, AGENT_DOCKER (host mode),
AGENT_DOCKER_HOST, AGENT_HOST_ROOT, AGENT_COMPOSE_PROJECT, AGENT_CA_FILE.";

/// A stop the service manager must not restart in a loop (systemd: `RestartPreventExitStatus=3`).
const STOPPED: u8 = 3;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("run");
    match command {
        "version" | "--version" | "-V" => {
            println!("depverify-agent {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        "inventory" if args.iter().any(|a| a == "--dry-run") => {
            let config = match config::Config::offline() {
                Ok(config) => config,
                Err(e) => return fail(&e),
            };
            let collect = state::Store::open(&config.state_dir)
                .and_then(|s| s.load())
                .map(|s| s.config)
                .unwrap_or_default();
            match agent::dry_run(&config, &collect) {
                Ok(report) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).expect("serializable")
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e),
            }
        }
        "run" | "enroll" | "fingerprint" => {
            let config = match config::Config::from_env() {
                Ok(config) => config,
                Err(e) => return fail(&e),
            };
            let mut agent = match agent::Agent::new(config) {
                Ok(agent) => agent,
                Err(e) => return fail(&e),
            };
            let outcome = match command {
                "fingerprint" => {
                    println!("{}", agent.fingerprint());
                    return ExitCode::SUCCESS;
                }
                "enroll" if agent.is_enrolled() => {
                    log!("already enrolled; fingerprint {}", agent.fingerprint());
                    return ExitCode::SUCCESS;
                }
                "enroll" => agent.enroll(),
                _ => agent.run(),
            };
            match outcome {
                Ok(()) => ExitCode::SUCCESS,
                Err(stop) => {
                    log!("stopped: {}", stop.0);
                    ExitCode::from(STOPPED)
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn fail(message: &str) -> ExitCode {
    log!("{message}");
    ExitCode::from(1)
}
