//! `/etc/os-release`: the OS of the host facts, and the `distro` qualifier of the OS packages (§8.5).

use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct OsRelease {
    pub id: String,
    pub version_id: String,
    pub pretty_name: String,
    /// RHEL only: the update channel (`eus`, `e4s`, `aus`, `tus`) and the release dnf is locked on (`rhel.rs`).
    pub channel: Option<String>,
    pub releasever: Option<String>,
}

pub fn parse(text: &str) -> OsRelease {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            values.insert(
                key.trim().to_owned(),
                value
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'')
                    .to_owned(),
            );
        }
    }
    let get = |key: &str| values.get(key).cloned().unwrap_or_default();
    OsRelease {
        id: get("ID").to_lowercase(),
        version_id: get("VERSION_ID"),
        pretty_name: get("PRETTY_NAME"),
        channel: None,
        releasever: None,
    }
}

impl OsRelease {
    /// `debian-12`, `ubuntu-24.04`, `alpine-3.20`, `rocky-9`, `rhel-9.4`, `sles-15.6`, `opensuse-leap-15.6`,
    /// `opensuse-tumbleweed`… ; none without a version (Debian testing): its packages are then left unmatched by the
    /// console, never guessed. RHEL and SUSE keep their minor release (a service pack, an EUS release); SLES for SAP
    /// is SLES.
    pub fn distro(&self) -> Option<String> {
        if self.id == "opensuse-tumbleweed" {
            return Some(self.id.clone());
        }
        let version = match self.id.as_str() {
            "rhel" => self.releasever.as_deref().unwrap_or(&self.version_id),
            _ => &self.version_id,
        };
        if self.id.is_empty() || version.is_empty() {
            return None;
        }
        let id = if self.id == "sles_sap" {
            "sles"
        } else {
            &self.id
        };
        let mut parts = version.split('.');
        let major = parts.next()?;
        let minor = parts.next();
        Some(match (id, minor) {
            (
                "ubuntu" | "alpine" | "rhel" | "sles" | "sle-micro" | "sl-micro" | "opensuse-leap",
                Some(minor),
            ) => format!("{id}-{major}.{minor}"),
            _ => format!("{id}-{major}"),
        })
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({"id": self.id, "version_id": self.version_id, "pretty_name": self.pretty_name})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> OsRelease {
        parse(
            &std::fs::read_to_string(format!(
                "{}/tests/fixtures/{name}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
    }

    #[test]
    fn reads_the_distro_of_real_releases() {
        let debian = fixture("os-release-debian12");
        assert_eq!(
            (debian.id.as_str(), debian.distro().as_deref()),
            ("debian", Some("debian-12"))
        );
        assert!(debian.pretty_name.starts_with("Debian GNU/Linux 12"));
        assert_eq!(
            fixture("os-release-ubuntu2404").distro().as_deref(),
            Some("ubuntu-24.04")
        );
        assert_eq!(
            fixture("os-release-alpine320").distro().as_deref(),
            Some("alpine-3.20")
        );
        assert_eq!(
            fixture("os-release-rocky9").distro().as_deref(),
            Some("rocky-9")
        );
        assert_eq!(
            parse("ID=debian\nPRETTY_NAME=\"Debian GNU/Linux trixie/sid\"").distro(),
            None
        );
        assert_eq!(
            fixture("os-release-ubi9").distro().as_deref(),
            Some("rhel-9.9")
        );
        assert_eq!(
            fixture("os-release-sles156").distro().as_deref(),
            Some("sles-15.6")
        );
        assert_eq!(
            fixture("os-release-leap156").distro().as_deref(),
            Some("opensuse-leap-15.6")
        );
        assert_eq!(
            fixture("os-release-tumbleweed").distro().as_deref(),
            Some("opensuse-tumbleweed"),
            "A rolling release: its snapshot date is no release."
        );
        assert_eq!(
            parse("ID=\"sles_sap\"\nVERSION_ID=\"15.6\"")
                .distro()
                .as_deref(),
            Some("sles-15.6")
        );
        assert_eq!(
            parse("ID=sl-micro\nVERSION_ID=6.1").distro().as_deref(),
            Some("sl-micro-6.1")
        );
        let locked = OsRelease {
            releasever: Some("9.4".into()),
            ..fixture("os-release-ubi9")
        };
        assert_eq!(
            locked.distro().as_deref(),
            Some("rhel-9.4"),
            "The release dnf is locked on."
        );
    }
}
