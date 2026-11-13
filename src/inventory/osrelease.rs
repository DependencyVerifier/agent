//! `/etc/os-release`: the OS of the host facts, and the `distro` qualifier of the OS packages (§8.5).

use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct OsRelease {
    pub id: String,
    pub version_id: String,
    pub pretty_name: String,
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
    }
}

impl OsRelease {
    /// `debian-12`, `ubuntu-24.04`, `alpine-3.20`, `rocky-9`… ; none without a version (Debian testing): its
    /// packages are then left unmatched by the console, never guessed.
    pub fn distro(&self) -> Option<String> {
        if self.id.is_empty() || self.version_id.is_empty() {
            return None;
        }
        let mut parts = self.version_id.split('.');
        let major = parts.next()?;
        let minor = parts.next();
        Some(match (self.id.as_str(), minor) {
            ("ubuntu" | "alpine", Some(minor)) => format!("{}-{major}.{minor}", self.id),
            _ => format!("{}-{major}", self.id),
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
    }
}
