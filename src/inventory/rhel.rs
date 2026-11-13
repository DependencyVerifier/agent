//! The Red Hat update channel of a subscribed RHEL host, read from files only (never `subscription-manager` nor
//! `dnf`): the BaseOS repository enabled in `/etc/yum.repos.d/redhat.repo` (written by subscription-manager) tells the
//! channel, `/etc/dnf/vars/releasever` the minor release it is locked on. Red Hat publishes the fixes of each channel
//! with their own builds (`Red Hat:rhel_eus:9.4`…): matching an EUS host against the main stream would be wrong.

use super::files::{self, Files};

/// The channels the console follows; the main stream has none.
const CHANNELS: [&str; 4] = ["eus", "e4s", "aus", "tus"];

/// `eus`, `e4s` (Update Services for SAP Solutions), `aus` or `tus`, from the enabled BaseOS repository
/// (`rhel-9-for-x86_64-baseos-eus-rpms`); none for the main stream or without subscription data (images).
pub fn channel(files: &dyn Files) -> Option<&'static str> {
    let repo = files::text(files, "/etc/yum.repos.d/redhat.repo")?;
    let mut section: Option<&str> = None;
    let mut found = None;
    for line in repo.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = Some(name);
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "enabled" || value.trim() != "1" {
            continue;
        }
        let Some(id) = section.filter(|s| s.contains("-baseos-")) else {
            continue;
        };
        found = Some(
            CHANNELS
                .into_iter()
                .find(|c| id.ends_with(&format!("-{c}-rpms"))),
        );
    }
    found.flatten()
}

/// The release dnf is locked on (`9.4`), when it is one.
pub fn releasever(files: &dyn Files) -> Option<String> {
    let value = files::text(files, "/etc/dnf/vars/releasever")?;
    let value = value.trim();
    let mut parts = value.split('.');
    let numeric =
        |p: Option<&str>| p.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    (numeric(parts.next()) && numeric(parts.next()) && parts.next().is_none())
        .then(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::files::Memory;

    fn files(entries: &[(&str, &str)]) -> Memory {
        Memory(
            entries
                .iter()
                .map(|(p, t)| ((*p).to_owned(), t.as_bytes().to_vec()))
                .collect(),
        )
    }

    /// The layout subscription-manager writes (one section per repository of the entitlement).
    fn repo(baseos: &str, enabled: &str) -> String {
        format!(
            "#\n# Certificate-Based Repositories\n# Managed by (rhsm) subscription-manager\n#\n\n\
             [rhel-9-for-x86_64-appstream-eus-rpms]\nname = Red Hat Enterprise Linux 9 for x86_64 - AppStream - \
             Extended Update Support (RPMs)\nbaseurl = https://cdn.redhat.com/content/eus/rhel9/$releasever/x86_64/\
             appstream/os\nenabled = 1\ngpgcheck = 1\n\n\
             [{baseos}]\nname = Red Hat Enterprise Linux 9 for x86_64 - BaseOS (RPMs)\n\
             baseurl = https://cdn.redhat.com/content/dist/rhel9/$releasever/x86_64/baseos/os\n\
             enabled = {enabled}\ngpgcheck = 1\nsslverify = 1\n\n\
             [rhel-9-for-x86_64-baseos-debug-rpms]\nenabled = 0\n"
        )
    }

    #[test]
    fn reads_the_channel_of_the_enabled_baseos_repository() {
        let channel_of = |baseos: &str, enabled: &str| {
            channel(&files(&[(
                "/etc/yum.repos.d/redhat.repo",
                &repo(baseos, enabled),
            )]))
        };
        assert_eq!(
            channel_of("rhel-9-for-x86_64-baseos-eus-rpms", "1"),
            Some("eus")
        );
        assert_eq!(
            channel_of("rhel-9-for-x86_64-baseos-e4s-rpms", "1"),
            Some("e4s")
        );
        assert_eq!(
            channel_of("rhel-8-for-x86_64-baseos-aus-rpms", "1"),
            Some("aus")
        );
        assert_eq!(
            channel_of("rhel-8-for-x86_64-baseos-tus-rpms", "1"),
            Some("tus")
        );
        assert_eq!(
            channel_of("rhel-9-for-x86_64-baseos-rpms", "1"),
            None,
            "The main stream, though AppStream EUS is enabled."
        );
        assert_eq!(
            channel_of("rhel-9-for-x86_64-baseos-eus-rpms", "0"),
            None,
            "A disabled repository."
        );
        assert_eq!(channel(&Memory::default()), None, "No subscription data.");
    }

    #[test]
    fn reads_a_locked_release() {
        let release = |text: &str| releasever(&files(&[("/etc/dnf/vars/releasever", text)]));
        assert_eq!(release("9.4\n").as_deref(), Some("9.4"));
        assert_eq!(release("9"), None, "Not a minor release.");
        assert_eq!(release("9.4.1"), None);
        assert_eq!(release("$foo"), None);
        assert_eq!(releasever(&Memory::default()), None);
    }
}
