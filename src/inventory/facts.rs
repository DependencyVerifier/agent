//! The host facts snapshot (`application/vnd.depverify.host-facts+json;version=1`): no timestamp inside.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::files::{self, Files};
use super::osrelease::{self, OsRelease};
use super::{Document, FACTS_MEDIA_TYPE};

pub struct HostFacts {
    pub hostname: String,
    pub os: OsRelease,
    pub kernel: String,
    pub machine_id_hash: Option<String>,
}

pub fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        _ => "x86_64",
    }
}

pub fn os_release(files: &dyn Files) -> OsRelease {
    files::text(files, "/etc/os-release")
        .or_else(|| files::text(files, "/usr/lib/os-release"))
        .map(|t| osrelease::parse(&t))
        .unwrap_or_default()
}

/// Read under the host root (`/` or `/host`); the kernel is the running one, shared by containers.
pub fn read(root: &dyn Files, hostname_override: Option<String>) -> HostFacts {
    let hostname = hostname_override
        .or_else(|| {
            files::text(root, "/etc/hostname")
                .map(|h| h.trim().to_owned())
                .filter(|h| !h.is_empty())
        })
        .or_else(|| {
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .ok()
                .map(|h| h.trim().to_owned())
        })
        .unwrap_or_else(|| "unknown".into());
    let machine_id_hash = files::text(root, "/etc/machine-id")
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty())
        .map(|id| format!("{:x}", Sha256::digest(id.as_bytes())));
    HostFacts {
        hostname,
        os: os_release(root),
        kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|k| k.trim().to_owned())
            .unwrap_or_default(),
        machine_id_hash,
    }
}

impl HostFacts {
    /// The short facts of the enrollment request (§5.1).
    pub fn enrollment(&self, docker_engine_id: Option<&str>) -> Value {
        let mut host = json!({"hostname": self.hostname, "os": self.os.json(), "kernel": self.kernel, "arch": arch()});
        if let Some(id) = docker_engine_id {
            host["docker_engine_id"] = json!(id);
        }
        if let Some(hash) = &self.machine_id_hash {
            host["machine_id_hash"] = json!(hash);
        }
        host
    }

    pub fn document(&self, runtimes: Vec<Value>, docker: Value, agent: Value) -> Document {
        let mut facts = json!({
            "format_version": 1,
            "hostname": self.hostname,
            "os": self.os.json(),
            "kernel": self.kernel,
            "arch": arch(),
            "runtimes": runtimes,
            "docker": docker,
            "agent": agent,
        });
        if let Some(hash) = &self.machine_id_hash {
            facts["machine_id_hash"] = json!(hash);
        }
        Document::new(
            serde_json::to_vec(&facts).expect("serializable"),
            FACTS_MEDIA_TYPE,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::files::Memory;

    #[test]
    fn hashes_the_machine_id_and_stays_deterministic() {
        let mut files = Memory::default();
        files.0.insert("/etc/hostname".into(), b"web-01\n".to_vec());
        files.0.insert("/etc/machine-id".into(), b"abc\n".to_vec());
        files.0.insert(
            "/etc/os-release".into(),
            b"ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"
                .to_vec(),
        );
        let facts = read(&files, None);
        assert_eq!(facts.hostname, "web-01");
        assert_eq!(
            facts.machine_id_hash.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        let agent = json!({"version": "0.1.0", "mode": "host", "config_version": 0});
        let a = facts.document(vec![], Value::Null, agent.clone());
        let b = facts.document(vec![], Value::Null, agent);
        assert_eq!(a.digest, b.digest);
        let doc: Value = serde_json::from_slice(&a.bytes).unwrap();
        assert_eq!(doc["os"]["id"], "debian");
        assert_eq!(doc["docker"], Value::Null);
        assert_eq!(
            facts
                .enrollment(Some("e"))
                .get("docker_engine_id")
                .and_then(Value::as_str),
            Some("e")
        );
        assert_eq!(
            read(&Memory::default(), Some("forced".into())).hostname,
            "forced"
        );
    }
}
