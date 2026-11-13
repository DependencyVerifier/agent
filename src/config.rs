//! Install-time settings (protocol §11), all from environment variables: the binary needs no configuration file.

use std::env;
use std::path::PathBuf;

use crate::keys::ConsoleKey;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Host,
    Container,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Host => "host",
            Mode::Container => "container",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    Compose,
    Labeled,
    Host,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Compose => "compose",
            Scope::Labeled => "labeled",
            Scope::Host => "host",
        }
    }
}

pub struct Config {
    pub console_url: String,
    pub console_key: ConsoleKey,
    pub token: Option<String>,
    pub mode: Mode,
    /// Container mode only.
    pub scope: Option<Scope>,
    pub state_dir: PathBuf,
    /// Docker Engine API, `unix:///…` or `tcp://host:port`; none when Docker is not to be read.
    pub docker_host: Option<String>,
    /// Where the host's file system is seen: `/` in host mode, the `/host` mount in container mode with scope `host`.
    pub host_root: Option<PathBuf>,
    /// The Compose project of the agent's own container, when it cannot be read from Docker.
    pub compose_project: Option<String>,
    /// PEM bundle of the console's CA (a private CA), instead of the built-in Mozilla roots.
    pub ca_file: Option<PathBuf>,
}

fn var(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

impl Config {
    /// For `inventory --dry-run`: no console needed.
    pub fn offline() -> Result<Self, String> {
        // SAFETY: single-threaded at this point, before any other thread exists.
        unsafe {
            if var("AGENT_CONSOLE_URL").is_none() {
                env::set_var("AGENT_CONSOLE_URL", "https://offline.invalid");
            }
            if var("AGENT_CONSOLE_PUBKEY").is_none() {
                env::set_var(
                    "AGENT_CONSOLE_PUBKEY",
                    "ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
                );
            }
        }
        Self::from_env()
    }

    pub fn from_env() -> Result<Self, String> {
        let console_url = var("AGENT_CONSOLE_URL").ok_or("AGENT_CONSOLE_URL is required")?;
        let console_url = console_url.trim_end_matches('/').to_owned();
        if !console_url.starts_with("https://") {
            return Err("AGENT_CONSOLE_URL must be an https:// URL".into());
        }
        let console_key = ConsoleKey::parse(
            &var("AGENT_CONSOLE_PUBKEY").ok_or("AGENT_CONSOLE_PUBKEY is required")?,
        )?;
        let token = match var("AGENT_TOKEN") {
            Some(token) => Some(token),
            None => match var("AGENT_TOKEN_FILE") {
                Some(file) => Some(
                    std::fs::read_to_string(&file)
                        .map_err(|e| format!("AGENT_TOKEN_FILE {file}: {e}"))?
                        .trim()
                        .to_owned(),
                ),
                None => None,
            },
        };
        let mode = match var("AGENT_MODE").as_deref().unwrap_or("host") {
            "host" => Mode::Host,
            "container" => Mode::Container,
            other => {
                return Err(format!(
                    "AGENT_MODE {other} is not supported (host or container)"
                ));
            }
        };
        let scope = match mode {
            Mode::Host => None,
            Mode::Container => Some(match var("AGENT_SCOPE").as_deref().unwrap_or("compose") {
                "compose" => Scope::Compose,
                "labeled" => Scope::Labeled,
                "host" => Scope::Host,
                other => {
                    return Err(format!(
                        "AGENT_SCOPE {other} is not supported (compose, labeled or host)"
                    ));
                }
            }),
        };
        let state_dir = PathBuf::from(var("AGENT_STATE_DIR").unwrap_or_else(|| match mode {
            Mode::Host => "/var/lib/depverify-agent".into(),
            Mode::Container => "/var/lib/agent".into(),
        }));
        let docker_host = match mode {
            Mode::Container => Some(
                var("AGENT_DOCKER_HOST")
                    .or_else(|| var("DOCKER_HOST"))
                    .unwrap_or_else(|| "tcp://depverify-docker-proxy:2375".into()),
            ),
            Mode::Host => {
                if matches!(var("AGENT_DOCKER").as_deref(), Some("1" | "true" | "yes")) {
                    Some(
                        var("AGENT_DOCKER_HOST")
                            .or_else(|| var("DOCKER_HOST"))
                            .unwrap_or_else(|| "unix:///var/run/docker.sock".into()),
                    )
                } else {
                    None
                }
            }
        };
        let host_root = match (mode, scope) {
            (Mode::Host, _) => Some(PathBuf::from(
                var("AGENT_HOST_ROOT").unwrap_or_else(|| "/".into()),
            )),
            (Mode::Container, Some(Scope::Host)) => {
                let root = PathBuf::from(var("AGENT_HOST_ROOT").unwrap_or_else(|| "/host".into()));
                root.join("etc").is_dir().then_some(root)
            }
            _ => None,
        };

        Ok(Self {
            console_url,
            console_key,
            token,
            mode,
            scope,
            state_dir,
            docker_host,
            host_root,
            compose_project: var("AGENT_COMPOSE_PROJECT"),
            ca_file: var("AGENT_CA_FILE").map(PathBuf::from),
        })
    }
}
