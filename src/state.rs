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
    /// The console key pinned by a `ROTATE_CONSOLE_KEY` order; it prevails over `AGENT_CONSOLE_PUBKEY`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console_key: Option<String>,
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

    fn read_key(path: &Path) -> Option<AgentKey> {
        let seed: [u8; 32] = STANDARD
            .decode(fs::read_to_string(path).ok()?.trim())
            .ok()?
            .try_into()
            .ok()?;
        Some(AgentKey::from_seed(seed))
    }

    /// `ROTATE_KEY`: the new key, written before the console is told (`agent.key.next`).
    pub fn write_next(&self, key: &AgentKey) -> Result<(), String> {
        write_private(
            &self.dir.join("agent.key.next"),
            STANDARD.encode(key.seed()).as_bytes(),
        )
    }

    /// A new key left by an interrupted rotation.
    pub fn next_key(&self) -> Option<AgentKey> {
        Self::read_key(&self.dir.join("agent.key.next"))
    }

    pub fn discard_next(&self) {
        let _ = fs::remove_file(self.dir.join("agent.key.next"));
    }

    /// The new key becomes the key; the old one is kept (`agent.key.previous`) until the console accepts the new one.
    pub fn promote_next(&self) -> Result<AgentKey, String> {
        let next = self.next_key().ok_or("no new key to use")?;
        let (key, previous) = (
            self.dir.join("agent.key"),
            self.dir.join("agent.key.previous"),
        );
        fs::rename(&key, &previous).map_err(|e| e.to_string())?;
        fs::rename(self.dir.join("agent.key.next"), &key).map_err(|e| e.to_string())?;
        Ok(next)
    }

    /// The console refuses the new key (the rotation never reached it): back to the previous one.
    pub fn restore_previous(&self) -> Option<AgentKey> {
        let previous = Self::read_key(&self.dir.join("agent.key.previous"))?;
        fs::rename(
            self.dir.join("agent.key.previous"),
            self.dir.join("agent.key"),
        )
        .ok()?;
        Some(previous)
    }

    /// The console accepted the key in use: the previous one is gone for good.
    pub fn forget_previous(&self) {
        let _ = fs::remove_file(self.dir.join("agent.key.previous"));
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
    // A leftover (or planted) temporary file is removed, never followed: the new one is created exclusively and
    // `O_NOFOLLOW` refuses a symbolic link.
    let _ = fs::remove_file(&tmp);
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// `O_NOFOLLOW` of Linux (x86_64 and aarch64).
const O_NOFOLLOW: i32 = if cfg!(target_arch = "aarch64") {
    0o100_000
} else {
    0o400_000
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_the_key_and_keeps_the_previous_one_until_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let old = store.key().unwrap();
        assert!(store.next_key().is_none() && store.restore_previous().is_none());
        assert!(store.promote_next().is_err(), "No new key.");

        let next = AgentKey::generate();
        store.write_next(&next).unwrap();
        assert_eq!(store.next_key().unwrap().fingerprint(), next.fingerprint());
        assert_eq!(
            store.promote_next().unwrap().fingerprint(),
            next.fingerprint()
        );
        assert_eq!(store.key().unwrap().fingerprint(), next.fingerprint());
        assert!(store.next_key().is_none());
        let mode = fs::metadata(dir.path().join("agent.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        assert_eq!(
            store.restore_previous().unwrap().fingerprint(),
            old.fingerprint(),
            "Refused: back to the old key."
        );
        assert_eq!(store.key().unwrap().fingerprint(), old.fingerprint());
        store.write_next(&next).unwrap();
        store.promote_next().unwrap();
        store.forget_previous();
        assert!(
            store.restore_previous().is_none(),
            "Confirmed: no way back."
        );
        store.write_next(&AgentKey::generate()).unwrap();
        store.discard_next();
        assert!(store.next_key().is_none());

        let state = State {
            console_key: Some("ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".into()),
            ..State::default()
        };
        store.save(&state).unwrap();
        assert_eq!(store.load().unwrap().console_key, state.console_key);
        assert!(
            !serde_json::to_string(&State::default())
                .unwrap()
                .contains("console_key"),
            "Absent until rotated."
        );
    }

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

        // A planted link in place of the temporary file is replaced, its target left untouched.
        let target = dir.path().join("elsewhere");
        fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("state.tmp")).unwrap();
        store.save(&state).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
    }
}
