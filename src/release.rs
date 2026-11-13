//! The releases of the agent (cadrage §6, decision 71): `SHA256SUMS` signed with minisign by the **project release
//! key embedded here**, never the console's (a compromised console can never make an agent run another binary).
//! Both minisign algorithms are read: `Ed` (the file itself) and `ED` (its BLAKE2b-512 hash).

use base64::{Engine, engine::general_purpose::STANDARD};
use blake2::{Blake2b512, Digest};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::Sha256;

/// The minisign public key of the project (id `EBDDB456A4BF3356`), the one `release.yml` signs with.
pub const RELEASE_KEY: &str = "RWRWM7+kVrTd63TMnDIUOLjb78MC3QJTImbW3Gi/8ooaxK7iF2tC/ZSz";

pub struct ReleaseKey {
    id: [u8; 8],
    key: VerifyingKey,
}

impl ReleaseKey {
    /// A minisign public key: `Ed`, its 8-byte id, the Ed25519 key, in base64.
    pub fn parse(text: &str) -> Option<Self> {
        let raw = STANDARD.decode(text.trim()).ok()?;
        if raw.len() != 42 || &raw[..2] != b"Ed" {
            return None;
        }
        Some(Self {
            id: raw[2..10].try_into().ok()?,
            key: VerifyingKey::from_bytes(&raw[10..42].try_into().ok()?).ok()?,
        })
    }

    pub fn embedded() -> Self {
        Self::parse(RELEASE_KEY).expect("the embedded release key is valid")
    }

    /// The trusted comment of a minisign signature of `data`, if this key made it; none otherwise.
    pub fn verify(&self, data: &[u8], signature_file: &str) -> Option<String> {
        let mut lines = signature_file.lines();
        lines.next()?.strip_prefix("untrusted comment:")?;
        let signature = STANDARD.decode(lines.next()?.trim()).ok()?;
        let comment = lines.next()?.strip_prefix("trusted comment: ")?.to_owned();
        let global = STANDARD.decode(lines.next()?.trim()).ok()?;
        if signature.len() != 74 || signature[2..10] != self.id || global.len() != 64 {
            return None;
        }
        let message = match &signature[..2] {
            b"Ed" => data.to_vec(),
            b"ED" => Blake2b512::digest(data).to_vec(),
            _ => return None,
        };
        let bytes: [u8; 64] = signature[10..74].try_into().ok()?;
        self.key
            .verify_strict(&message, &Signature::from_bytes(&bytes))
            .ok()?;
        let signed = [&bytes[..], comment.as_bytes()].concat();
        self.key
            .verify_strict(&signed, &Signature::from_bytes(&global.try_into().ok()?))
            .ok()?;
        Some(comment)
    }
}

/// The SHA-256 a `SHA256SUMS` file gives a name (`<hex>  <name>` or `<hex> *<name>`).
pub fn sum_of(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (hex, file) = line.split_once(' ')?;
        (file.trim_start().trim_start_matches('*') == name && hex.len() == 64)
            .then(|| hex.to_ascii_lowercase())
    })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A release version: `X.Y.Z`, optionally `-prerelease` (letters, digits, dots, dashes), 64 characters at most.
pub fn is_version(text: &str) -> bool {
    let (core, pre) = text.split_once('-').unwrap_or((text, ""));
    let parts: Vec<&str> = core.split('.').collect();
    text.len() <= 64
        && parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && (!text.contains('-')
            || (!pre.is_empty()
                && pre
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')))
}

/// Whether `candidate` comes after `current` (numbers first; a prerelease before its release).
pub fn is_newer(candidate: &str, current: &str) -> bool {
    fn key(version: &str) -> Option<(u64, u64, u64, bool, String)> {
        let (core, pre) = version.split_once('-').unwrap_or((version, ""));
        let mut numbers = core.split('.').map(|n| n.parse::<u64>().ok());
        Some((
            numbers.next()??,
            numbers.next()??,
            numbers.next()??,
            pre.is_empty(),
            pre.to_owned(),
        ))
    }
    match (key(candidate), key(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/release/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn test_key() -> ReleaseKey {
        ReleaseKey::parse(fixture("test.pub").lines().nth(1).unwrap()).unwrap()
    }

    #[test]
    fn verifies_both_minisign_algorithms() {
        let key = test_key();
        assert_eq!(
            key.verify(
                fixture("SHA256SUMS").as_bytes(),
                &fixture("SHA256SUMS.minisig")
            )
            .as_deref(),
            Some("depverify-agent 0.1.0"),
            "ED: prehashed."
        );
        assert_eq!(
            key.verify(
                fixture("legacy.txt").as_bytes(),
                &fixture("legacy.txt.minisig")
            )
            .as_deref(),
            Some("depverify-agent 0.0.9"),
            "Ed: the file."
        );
        assert_eq!(
            key.verify(b"tampered", &fixture("SHA256SUMS.minisig")),
            None
        );
        let comment =
            fixture("SHA256SUMS.minisig").replace("depverify-agent 0.1.0", "depverify-agent 9.9.9");
        assert_eq!(
            key.verify(fixture("SHA256SUMS").as_bytes(), &comment),
            None,
            "The trusted comment is signed."
        );
        assert_eq!(
            ReleaseKey::embedded().verify(
                fixture("SHA256SUMS").as_bytes(),
                &fixture("SHA256SUMS.minisig")
            ),
            None,
            "Another key."
        );
        assert_eq!(key.verify(b"", "nonsense"), None);
        assert!(ReleaseKey::parse("RWQO").is_none());
        assert_eq!(
            ReleaseKey::embedded().id,
            [0x56, 0x33, 0xbf, 0xa4, 0x56, 0xb4, 0xdd, 0xeb],
            "Id EBDDB456A4BF3356, little endian."
        );
    }

    #[test]
    fn reads_the_sums_and_the_versions() {
        let sums = fixture("SHA256SUMS");
        assert_eq!(
            sum_of(&sums, "depverify-agent-x86_64-linux").as_deref(),
            Some("b291be535fba5643f1c953c1fbf1722adde1f74093a5c3e86b6d95f8c8e283a7")
        );
        assert_eq!(
            sha256_hex(fixture("depverify-agent-x86_64-linux").as_bytes()),
            sum_of(&sums, "depverify-agent-x86_64-linux").unwrap()
        );
        assert_eq!(sum_of(&sums, "depverify-agent-riscv64-linux"), None);
        assert_eq!(sum_of("abc *x", "x"), None, "Not a SHA-256.");
        assert_eq!(
            sum_of(&format!("{} *x", "A".repeat(64)), "x"),
            Some("a".repeat(64))
        );

        for valid in ["0.2.0", "10.20.30", "1.0.0-rc.1", "1.0.0-beta-2"] {
            assert!(is_version(valid), "{valid}");
        }
        for invalid in [
            "",
            "1.0",
            "1.0.0.0",
            "v1.0.0",
            "1.0.x",
            "1.0.0-",
            "1.0.0-rc/1",
            "1..0",
        ] {
            assert!(!is_version(invalid), "{invalid}");
        }
        assert!(!is_version(&format!("1.0.0-{}", "a".repeat(60))));
        assert!(
            is_newer("0.2.0", "0.1.9")
                && is_newer("0.10.0", "0.9.0")
                && is_newer("1.0.0", "1.0.0-rc.1")
        );
        assert!(
            !is_newer("0.1.0", "0.1.0")
                && !is_newer("0.1.0", "0.2.0")
                && !is_newer("1.0.0-rc.1", "1.0.0")
        );
        assert!(is_newer("1.0.0-rc.2", "1.0.0-rc.1") && !is_newer("x", "0.1.0"));
    }
}
