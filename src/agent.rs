//! The agent's life: enrollment (§5), then polling (§6) driven by the console, orders (§7) and inventories (§8),
//! with the error reactions of §9.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::time::Duration;

use serde_json::{Value, json};

use crate::client::{Body, Console, Failure};
use crate::config::{Config, Mode, Scope};
use crate::inventory::collect::{self, Context};
use crate::inventory::{Document, facts};
use crate::keys::AgentKey;
use crate::orders::{self, Order};
use crate::state::{OrderResult, State, Store};
use crate::time;

macro_rules! log {
    ($($arg:tt)*) => {
        eprintln!("{} {}", crate::time::rfc3339(crate::time::now()), format!($($arg)*))
    };
}
pub(crate) use log;

/// Why the agent stops for good (a new installation is needed).
#[derive(Debug)]
pub struct Stop(pub String);

pub struct Agent {
    config: Config,
    store: Store,
    key: AgentKey,
    state: State,
    console: Console,
    context: Context,
    scanned_since_start: bool,
    images: Option<BTreeSet<String>>,
}

fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("the system random generator");
    u32::from_le_bytes(bytes)
}

/// `seconds` ±10 % (§6.1).
fn jittered(seconds: u64) -> Duration {
    let spread = (seconds / 10).max(1);
    let offset = u64::from(random_u32()) % (2 * spread + 1);
    Duration::from_secs(seconds - spread.min(seconds) + offset)
}

fn sleep(seconds: u64) {
    std::thread::sleep(jittered(seconds.max(1)));
}

impl Agent {
    pub fn new(config: Config) -> Result<Self, String> {
        let store = Store::open(&config.state_dir)?;
        let key = store.key()?;
        let state = store.load()?;
        let console = Console::new(
            &config.console_url,
            config.ca_file.as_deref(),
            state.clock_offset,
        )?;
        let context = Context::new(&config)?;
        Ok(Self {
            config,
            store,
            key,
            state,
            console,
            context,
            scanned_since_start: false,
            images: None,
        })
    }

    pub fn fingerprint(&self) -> String {
        self.key.fingerprint()
    }

    fn save(&mut self) {
        self.state.clock_offset = self.console.offset;
        if let Err(e) = self.store.save(&self.state) {
            log!("cannot save the state: {e}");
        }
    }

    pub fn is_enrolled(&self) -> bool {
        self.state.agent_id.is_some()
    }

    /// §5: proof of possession of the new key, the token sent once, the console key checked against the pinned one.
    pub fn enroll(&mut self) -> Result<(), Stop> {
        let token = self.config.token.clone().ok_or_else(|| {
            Stop("not enrolled yet and no AGENT_TOKEN / AGENT_TOKEN_FILE given".into())
        })?;
        let root = self
            .config
            .host_root
            .clone()
            .map(crate::inventory::files::Root);
        let empty = crate::inventory::files::Memory::default();
        let source: &dyn crate::inventory::files::Files = match &root {
            Some(root) => root,
            None => &empty,
        };
        let (docker_facts, docker_name) = match &self.context.docker {
            Some(docker) => crate::inventory::containers::docker_facts(docker),
            None => (Value::Null, None),
        };
        let host = facts::read(
            source,
            if self.config.mode == Mode::Container {
                docker_name
            } else {
                None
            },
        );
        let mut body = json!({
            "protocol_version": 1,
            "enrollment_token": token,
            "public_key": self.key.public_text(),
            "agent_version": env!("CARGO_PKG_VERSION"),
            "mode": self.config.mode.as_str(),
            "host": host.enrollment(docker_facts.get("engine_id").and_then(Value::as_str).filter(|id| !id.is_empty())),
        });
        if let Some(scope) = self.config.scope {
            body["scope"] = json!(scope.as_str());
            if scope != Scope::Host {
                let project = self.context.project.clone().ok_or_else(|| {
                    Stop("cannot read the Compose project of the agent's own container: set AGENT_COMPOSE_PROJECT".into())
                })?;
                body["compose_project"] = json!(project);
            }
        }
        let bytes = serde_json::to_vec(&body).expect("serializable");
        let mut backoff = 30;
        loop {
            match self.console.send(
                &self.key,
                "POST",
                "/agent/v1/enrollments",
                Some(Body {
                    bytes: &bytes,
                    content_type: "application/json",
                    gzip: false,
                }),
            ) {
                Ok(reply) => {
                    let console_key_id = reply
                        .json
                        .get("console_key_id")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if console_key_id != self.config.console_key.fingerprint() {
                        return Err(Stop(format!(
                            "console_key_mismatch: the console signs with {console_key_id}, not with the pinned key"
                        )));
                    }
                    let agent_id = reply
                        .json
                        .get("agent_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| Stop("the enrollment answer has no agent_id".into()))?;
                    self.state.agent_id = Some(agent_id.to_owned());
                    self.save();
                    log!(
                        "enrolled as agent {agent_id}, status {}; fingerprint {} (compare it with the one the console shows before approving)",
                        reply
                            .json
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("?"),
                        self.key.fingerprint()
                    );
                    return Ok(());
                }
                Err(Failure::Problem { code, .. })
                    if matches!(
                        code.as_str(),
                        "token_invalid" | "token_expired" | "invalid_payload" | "unknown_agent"
                    ) =>
                {
                    return Err(Stop(format!(
                        "enrollment refused: {code} (a new token is needed)"
                    )));
                }
                Err(failure) => {
                    let wait = match &failure {
                        Failure::Problem {
                            retry_after: Some(after),
                            ..
                        } => *after,
                        _ => backoff,
                    };
                    log!("enrollment failed ({failure}), retrying in about {wait} s");
                    sleep(wait);
                    backoff = (backoff * 2).min(3600);
                }
            }
        }
    }

    /// Polls until stopped (revoked, unknown, or a fatal error).
    pub fn run(&mut self) -> Result<(), Stop> {
        if !self.is_enrolled() {
            self.enroll()?;
        }
        log!(
            "agent {} ({} mode) polling {}",
            self.state.agent_id.as_deref().unwrap_or("?"),
            self.config.mode.as_str(),
            self.config.console_url
        );
        let mut backoff = 30u64;
        loop {
            match self.poll() {
                Ok(next) => {
                    backoff = 30;
                    sleep(next);
                }
                Err(Failure::Problem { code, .. })
                    if matches!(code.as_str(), "agent_revoked" | "unknown_agent") =>
                {
                    return Err(Stop(format!(
                        "{code}: the console no longer accepts this agent; reinstall it with a new token"
                    )));
                }
                Err(Failure::Problem {
                    code,
                    retry_after: Some(after),
                    ..
                }) => {
                    log!("poll: {code}, waiting {after} s as asked");
                    std::thread::sleep(Duration::from_secs(after));
                }
                Err(failure) => {
                    log!("poll failed ({failure}), retrying in about {backoff} s");
                    sleep(backoff);
                    backoff = (backoff * 2).min(3600);
                }
            }
        }
    }

    /// One poll (§6): the pending results, then the orders received, then an inventory when one is due.
    fn poll(&mut self) -> Result<u64, Failure> {
        orders::prune(&mut self.state, time::now());
        let body = json!({
            "protocol_version": 1,
            "agent_version": env!("CARGO_PKG_VERSION"),
            "config_version": self.state.config.version,
            "order_results": self.state.pending_results,
        });
        let bytes = serde_json::to_vec(&body).expect("serializable");
        let reply = self.console.send(
            &self.key,
            "POST",
            "/agent/v1/poll",
            Some(Body {
                bytes: &bytes,
                content_type: "application/json",
                gzip: false,
            }),
        )?;
        self.state.pending_results.clear();
        let next = reply
            .json
            .get("next_poll_in")
            .and_then(Value::as_u64)
            .unwrap_or(300)
            .clamp(30, 3600);
        let approved = reply.json.get("status").and_then(Value::as_str) == Some("approved");

        let mut scan_now = false;
        let mut upgraded: Option<std::path::PathBuf> = None;
        for envelope in reply
            .json
            .get("orders")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let checked = orders::check(
                &envelope,
                &self.config.console_key,
                &mut self.state,
                time::now() + self.console.offset,
            );
            let (status, reason) = match checked.outcome {
                Ok(Order::ScanNow) if scan_now => ("executed", Some("already_running")),
                Ok(Order::ScanNow) => {
                    scan_now = true;
                    ("executed", None)
                }
                Ok(Order::SetConfig(config)) => {
                    if config.version > self.state.config.version {
                        log!(
                            "configuration {} applied (scan every {} min)",
                            config.version,
                            config.scan_interval_minutes
                        );
                        self.state.config = config;
                    }
                    ("executed", None)
                }
                Ok(Order::UpgradeAgent(version)) => match self.upgrade(&version) {
                    Ok(path) => {
                        log!("version {version} verified and installed");
                        upgraded = Some(path);
                        ("executed", None)
                    }
                    Err(("rejected", reason)) => {
                        log!("upgrade to {version} refused: {reason}");
                        ("rejected", Some(reason))
                    }
                    Err((status, reason)) => {
                        log!("upgrade to {version} failed: {reason}");
                        (status, Some(reason))
                    }
                },
                Err(reason) => {
                    log!("order {} rejected: {reason}", checked.order_id);
                    ("rejected", Some(reason))
                }
            };
            self.state.pending_results.push(OrderResult {
                order_id: checked.order_id,
                status: status.into(),
                reason: reason.map(str::to_owned),
                finished_at: time::rfc3339(time::now() + self.console.offset),
            });
        }
        self.save();
        if let Some(path) = upgraded {
            // The new binary reports the result at its first poll.
            let error = crate::upgrade::exec(&path);
            log!("could not run {}: {error}", path.display());
        }

        if approved {
            let due = self.state.last_scan.is_none_or(|last| {
                time::now() >= last + (self.state.config.scan_interval_minutes as i64) * 60
            });
            let trigger = if scan_now {
                Some("scan_now")
            } else if !self.scanned_since_start {
                Some("startup")
            } else if due {
                Some("scheduled")
            } else if self.image_changed() {
                Some("image_change")
            } else {
                None
            };
            if let Some(trigger) = trigger {
                if let Err(failure) = self.inventory(trigger) {
                    match &failure {
                        Failure::Problem { code, .. }
                            if code == "agent_revoked" || code == "unknown_agent" =>
                        {
                            return Err(failure);
                        }
                        _ => log!("inventory ({trigger}) not delivered: {failure}"),
                    }
                    if scan_now {
                        if let Some(result) = self
                            .state
                            .pending_results
                            .iter_mut()
                            .rev()
                            .find(|r| r.status == "executed" && r.reason.is_none())
                        {
                            result.status = "failed".into();
                            result.reason = Some("scan_error".into());
                        }
                        self.save();
                    }
                }
            }
        }
        // A finished SCAN_NOW is reported at once (§6.2).
        Ok(if scan_now { 30 } else { next })
    }

    /// `UPGRADE_AGENT`: host mode only, a newer version, its release downloaded from the console and verified with
    /// the release key embedded in this binary, then installed in the state directory.
    fn upgrade(&self, version: &str) -> Result<std::path::PathBuf, (&'static str, &'static str)> {
        use crate::{release, upgrade};
        if self.config.mode != Mode::Host {
            return Err(("rejected", "unsupported_mode"));
        }
        if !release::is_newer(version, env!("CARGO_PKG_VERSION")) {
            return Err(("rejected", "not_newer"));
        }
        let get = |name: &str, max: u64| {
            self.console
                .download(&format!("/downloads/agent/{version}/{name}"), max)
                .map_err(|e| {
                    log!("download of {name} failed: {e}");
                    ("failed", "download_failed")
                })
        };
        let sums = get(upgrade::SUMS, 64 * 1024)?;
        let signature = String::from_utf8(get(upgrade::SIGNATURE, 64 * 1024)?)
            .map_err(|_| ("failed", "bad_signature"))?;
        let name = upgrade::binary_name();
        let binary = get(&name, 64 * 1024 * 1024)?;
        upgrade::check(
            &release::ReleaseKey::embedded(),
            version,
            &name,
            &binary,
            &sums,
            &signature,
        )
        .map_err(|reason| ("failed", reason))?;
        upgrade::install(&self.config.state_dir, version, &binary, &sums, &signature).map_err(|e| {
            log!("install of {version} failed: {e}");
            ("failed", "install_failed")
        })
    }

    fn image_changed(&mut self) -> bool {
        match collect::image_set(&self.context, &self.config) {
            Some(now) => self.images.as_ref().is_some_and(|before| *before != now),
            None => false,
        }
    }

    /// §8: manifest, missing snapshots (gzip), complete.
    pub fn inventory(&mut self, trigger: &str) -> Result<(), Failure> {
        let started = time::now() + self.console.offset;
        let cache = self.store.cache_dir("images");
        let inventory = collect::collect(&self.config, &self.state.config, &self.context, &cache)
            .map_err(Failure::Transport)?;
        let completed = time::now() + self.console.offset;
        let id = uuid::Uuid::now_v7().to_string();
        let mut documents: BTreeMap<String, &Document> = BTreeMap::new();
        documents.insert(inventory.facts.digest.clone(), &inventory.facts);
        let subjects: Vec<Value> = inventory
            .subjects
            .iter()
            .map(|(fields, document)| {
                documents.insert(document.digest.clone(), document);
                let mut subject = fields.clone();
                subject["sbom"] = document.reference();
                subject
            })
            .collect();
        let manifest = json!({
            "protocol_version": 1,
            "inventory_id": id,
            "trigger": trigger,
            "started_at": time::rfc3339(started),
            "completed_at": time::rfc3339(completed),
            "host_facts": inventory.facts.reference(),
            "subjects": subjects,
        });
        let bytes = serde_json::to_vec(&manifest).expect("serializable");
        let reply = self.console.send(
            &self.key,
            "POST",
            "/agent/v1/inventories",
            Some(Body {
                bytes: &bytes,
                content_type: "application/json",
                gzip: false,
            }),
        )?;
        let missing = digests(&reply.json);
        self.upload(&id, &missing, &documents)?;

        let complete = br#"{"protocol_version":1}"#;
        let path = format!("/agent/v1/inventories/{id}/complete");
        let body = || {
            Some(Body {
                bytes: complete,
                content_type: "application/json",
                gzip: false,
            })
        };
        match self.console.send(&self.key, "POST", &path, body()) {
            Ok(_) => {}
            Err(Failure::Problem {
                code,
                body: problem,
                ..
            }) if code == "missing_snapshots" => {
                self.upload(&id, &digests(&problem), &documents)?;
                self.console.send(&self.key, "POST", &path, body())?;
            }
            Err(failure) => return Err(failure),
        }
        self.state.last_scan = Some(time::now());
        self.scanned_since_start = true;
        self.images = Some(inventory.images);
        self.save();
        log!(
            "inventory {id} ({trigger}): {} subjects, {} snapshots uploaded",
            subjects.len(),
            missing.len()
        );
        Ok(())
    }

    fn upload(
        &mut self,
        id: &str,
        missing: &[String],
        documents: &BTreeMap<String, &Document>,
    ) -> Result<(), Failure> {
        for digest in missing {
            let Some(document) = documents.get(digest) else {
                continue;
            };
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(&document.bytes)
                .map_err(|e| Failure::Transport(e.to_string()))?;
            let compressed = gz.finish().map_err(|e| Failure::Transport(e.to_string()))?;
            let path = format!("/agent/v1/inventories/{id}/snapshots/{digest}");
            match self.console.send(
                &self.key,
                "PUT",
                &path,
                Some(Body {
                    bytes: &compressed,
                    content_type: document.media_type,
                    gzip: true,
                }),
            ) {
                Ok(_) => {}
                Err(Failure::Problem { code, .. })
                    if code == "payload_too_large" || code == "digest_mismatch" =>
                {
                    log!("snapshot {digest} refused ({code}), skipped until the next run");
                }
                Err(failure) => return Err(failure),
            }
        }
        Ok(())
    }
}

fn digests(json: &Value) -> Vec<String> {
    json.get("missing")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|d| d.as_str().map(str::to_owned))
        .collect()
}

/// `depverify-agent inventory --dry-run`: what would be sent, without a console.
pub fn dry_run(
    config: &Config,
    collect_config: &crate::state::CollectConfig,
) -> Result<Value, String> {
    let context = Context::new(config)?;
    // A fresh private directory (created exclusively, 0700): never a shared, predictable path.
    let cache = std::env::temp_dir().join(format!("depverify-agent-{}", uuid::Uuid::now_v7()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&cache)
        .map_err(|e| format!("{}: {e}", cache.display()))?;
    let inventory = collect::collect(config, collect_config, &context, &cache);
    let _ = std::fs::remove_dir_all(&cache);
    let inventory = inventory?;
    let facts: Value = serde_json::from_slice(&inventory.facts.bytes).unwrap_or(Value::Null);
    let subjects: Vec<Value> = inventory
        .subjects
        .iter()
        .map(|(fields, document)| {
            let bom: Value = serde_json::from_slice(&document.bytes).unwrap_or(Value::Null);
            let purls: Vec<Value> = bom["components"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|c| c["purl"].clone())
                .collect();
            let mut subject = fields.clone();
            subject["sbom"] = document.reference();
            subject["packages"] = json!(purls);
            subject
        })
        .collect();
    Ok(json!({"host_facts": facts, "subjects": subjects}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitters_within_ten_percent() {
        for _ in 0..200 {
            let d = jittered(300).as_secs();
            assert!((270..=330).contains(&d), "{d}");
        }
        assert!(jittered(1).as_secs() <= 2);
    }
}
