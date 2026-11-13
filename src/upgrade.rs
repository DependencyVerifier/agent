//! `UPGRADE_AGENT` (host mode): the release files are downloaded from the console, **verified with the release key
//! embedded in this binary** (signature of `SHA256SUMS`, its version, then the binary's SHA-256), and kept in the
//! state directory (`bin/X.Y.Z/`, then the pointer `bin/current`). The agent then executes the new binary in place.
//! At each start the installed binary verifies that release again before executing it: nothing planted in the
//! state directory ever runs. The agent needs no privilege for this (its service unit stays as installed).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::release::{self, ReleaseKey};
use crate::state::write_private;

/// Set on the executed binary: it does not look for a newer one again.
pub const REEXEC: &str = "DEPVERIFY_AGENT_REEXEC";

pub const SUMS: &str = "SHA256SUMS";
pub const SIGNATURE: &str = "SHA256SUMS.minisig";
const BINARY: &str = "depverify-agent";

/// The release binary of this machine (`depverify-agent-x86_64-linux`).
pub fn binary_name() -> String {
    format!("depverify-agent-{}-linux", std::env::consts::ARCH)
}

/// What the release files must prove before anything runs (a machine reason when they do not).
pub fn check(
    key: &ReleaseKey,
    version: &str,
    name: &str,
    binary: &[u8],
    sums: &[u8],
    signature: &str,
) -> Result<(), &'static str> {
    let comment = key.verify(sums, signature).ok_or("bad_signature")?;
    if comment != format!("depverify-agent {version}")
        && comment != format!("depverify-agent v{version}")
    {
        return Err("wrong_version");
    }
    let expected = release::sum_of(&String::from_utf8_lossy(sums), name).ok_or("unknown_binary")?;
    if release::sha256_hex(binary) != expected {
        return Err("bad_checksum");
    }
    Ok(())
}

/// Keeps a verified release in `<state>/bin/X.Y.Z/` and points `bin/current` at it; the path of its binary.
pub fn install(
    state_dir: &Path,
    version: &str,
    binary: &[u8],
    sums: &[u8],
    signature: &str,
) -> Result<PathBuf, String> {
    let dir = state_dir.join("bin").join(version);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    write_private(&dir.join(SUMS), sums)?;
    write_private(&dir.join(SIGNATURE), signature.as_bytes())?;
    let path = dir.join(BINARY);
    write_private(&path, binary)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    write_private(&state_dir.join("bin").join("current"), version.as_bytes())?;
    Ok(path)
}

/// The installed binary to run instead of this one: newer, and its release verified again now. None otherwise.
pub fn installed(state_dir: &Path, key: &ReleaseKey, current: &str) -> Option<PathBuf> {
    let bin = state_dir.join("bin");
    let version = std::fs::read_to_string(bin.join("current"))
        .ok()?
        .trim()
        .to_owned();
    if !release::is_version(&version) || !release::is_newer(&version, current) {
        return None;
    }
    let dir = bin.join(&version);
    let path = dir.join(BINARY);
    let binary = std::fs::read(&path).ok()?;
    let sums = std::fs::read(dir.join(SUMS)).ok()?;
    let signature = std::fs::read_to_string(dir.join(SIGNATURE)).ok()?;
    check(key, &version, &binary_name(), &binary, &sums, &signature).ok()?;
    Some(path)
}

/// Replaces this process by the binary (same arguments and environment, marked as executed). Returns only on
/// failure.
pub fn exec(path: &Path) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    std::process::Command::new(path)
        .args(std::env::args_os().skip(1))
        .env(REEXEC, "1")
        .exec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/release/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn key() -> ReleaseKey {
        ReleaseKey::parse(
            String::from_utf8(fixture("test.pub"))
                .unwrap()
                .lines()
                .nth(1)
                .unwrap(),
        )
        .unwrap()
    }

    fn signature() -> String {
        String::from_utf8(fixture("SHA256SUMS.minisig")).unwrap()
    }

    #[test]
    fn checks_a_release_before_anything_runs() {
        let (key, sums, binary) = (
            key(),
            fixture("SHA256SUMS"),
            fixture("depverify-agent-x86_64-linux"),
        );
        let name = "depverify-agent-x86_64-linux";
        assert_eq!(
            check(&key, "0.1.0", name, &binary, &sums, &signature()),
            Ok(())
        );
        assert_eq!(
            check(&key, "0.2.0", name, &binary, &sums, &signature()),
            Err("wrong_version"),
            "Signed for another version."
        );
        assert_eq!(
            check(
                &key,
                "0.1.0",
                "depverify-agent-riscv64-linux",
                &binary,
                &sums,
                &signature()
            ),
            Err("unknown_binary")
        );
        assert_eq!(
            check(&key, "0.1.0", name, b"planted", &sums, &signature()),
            Err("bad_checksum")
        );
        assert_eq!(
            check(&key, "0.1.0", name, &binary, b"other sums", &signature()),
            Err("bad_signature")
        );
        assert_eq!(
            check(
                &ReleaseKey::embedded(),
                "0.1.0",
                name,
                &binary,
                &sums,
                &signature()
            ),
            Err("bad_signature"),
            "Never another key."
        );
        let legacy = String::from_utf8(fixture("legacy.txt.minisig")).unwrap();
        let legacy_sums = fixture("legacy.txt");
        assert_eq!(
            check(&key, "0.0.9", name, &binary, &legacy_sums, &legacy),
            Ok(()),
            "The legacy algorithm (`Ed`, the file itself) too."
        );
        assert!(binary_name().starts_with("depverify-agent-") && binary_name().ends_with("-linux"));
    }

    #[test]
    fn installs_a_release_and_runs_it_only_once_verified_again() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path();
        let binary = fixture(&binary_name());
        let path = install(
            state,
            "0.1.0",
            &binary,
            &fixture("SHA256SUMS"),
            &signature(),
        )
        .unwrap();
        assert_eq!(path, state.join("bin/0.1.0/depverify-agent"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(state.join("bin/0.1.0"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::read_to_string(state.join("bin/current")).unwrap(),
            "0.1.0"
        );

        assert_eq!(installed(state, &key(), "0.0.1"), Some(path.clone()));
        assert_eq!(
            installed(state, &key(), "0.1.0"),
            None,
            "Not newer than this one."
        );
        assert_eq!(
            installed(state, &ReleaseKey::embedded(), "0.0.1"),
            None,
            "Signed by another key."
        );
        std::fs::write(&path, b"planted").unwrap();
        assert_eq!(
            installed(state, &key(), "0.0.1"),
            None,
            "Changed since: never run."
        );
        std::fs::write(state.join("bin/current"), b"../../etc").unwrap();
        assert_eq!(installed(state, &key(), "0.0.1"), None, "Not a version.");
        assert_eq!(
            installed(dir.path().join("none").as_path(), &key(), "0.0.1"),
            None
        );
    }
}
