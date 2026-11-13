//! What survives a restart (protocol §11): the private key (`agent.key`, 0600), the agent id, the console clock
//! offset, the applied configuration, the anti-replay store of orders, the order results not reported yet.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::keys::AgentKey;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CollectConfig {
    pub version: u64,
    pub scan_interval_minutes: u64,
    pub discovery_roots: Vec<String>,
    pub declared_paths: Vec<String>,
    pub exclusions: Vec<String>,
}

impl Default for CollectConfig {
    fn default() -> Self {
        Self {
            version: 0,
            scan_interval_minutes: 360,
            discovery_roots: vec!["/var/www".into(), "/srv".into(), "/opt".into()],
            declared_paths: vec![],
            exclusions: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OrderResult {
    pub order_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub finished_at: String,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct State {
    pub agent_id: Option<String>,
    #[serde(default)]
    pub clock_offset: i64,
    #[serde(default)]
    pub config: CollectConfig,
    /// order id → the time it may be forgotten (`expires_at` + 10 minutes).
    #[serde(default)]
    pub seen_orders: BTreeMap<String, i64>,
    #[serde(default)]
    pub pending_results: Vec<OrderResult>,
    #[serde(default)]
    pub last_scan: Option<i64>,
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| format!("state directory {}: {e}", dir.display()))?;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// The agent's key, created at the first start (never logged, never sent).
    pub fn key(&self) -> Result<AgentKey, String> {
        let path = self.dir.join("agent.key");
        match fs::read_to_string(&path) {
            Ok(text) => {
                let seed: [u8; 32] = STANDARD
                    .decode(text.trim())
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| format!("{} is corrupted", path.display()))?;
                Ok(AgentKey::from_seed(seed))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = AgentKey::generate();
                write_private(&path, STANDARD.encode(key.seed()).as_bytes())?;
                Ok(key)
            }
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn load(&self) -> Result<State, String> {
        let path = self.dir.join("state.json");
        match fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn save(&self, state: &State) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?;
        write_private(&self.dir.join("state.json"), &bytes)
    }

    pub fn cache_dir(&self, name: &str) -> PathBuf {
        let dir = self.dir.join(name);
        let _ = fs::create_dir_all(&dir);
        dir
    }
}

/// Written to a temporary file then renamed: a crash never leaves half a file. Mode 0600.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_key_and_the_state_private_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = store.key().unwrap();
        assert_eq!(store.key().unwrap().fingerprint(), key.fingerprint());
        let mode = fs::metadata(dir.path().join("agent.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let mut state = store.load().unwrap();
        assert_eq!(state.config.scan_interval_minutes, 360);
        state.agent_id = Some("019a6b2c-1f00-7a11-8b22-3c44d55e6f01".into());
        state.seen_orders.insert("o1".into(), 42);
        store.save(&state).unwrap();
        let again = store.load().unwrap();
        assert_eq!(again.agent_id, state.agent_id);
        assert_eq!(again.seen_orders.get("o1"), Some(&42));
    }
}
