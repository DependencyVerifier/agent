//! One inventory (protocol §8): the host facts and one CycloneDX SBOM per subject, all deterministic so that an
//! unchanged machine gives unchanged digests.

pub mod apps;
pub mod collect;
pub mod containers;
pub mod discovery;
pub mod facts;
pub mod files;
pub mod fpm;
pub mod node;
pub mod os;
pub mod osrelease;
pub mod php;
pub mod purl;
pub mod rhel;
pub mod rpmdb;
pub mod runtimes;
pub mod sbom;

use serde_json::Value;

/// One package found, as an SBOM component.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Package {
    pub purl: String,
    pub name: String,
    pub version: String,
    /// `composer`, `npm`, `yarn`, `pnpm`, `dpkg`, `rpm`, `apk`.
    pub manager: &'static str,
    /// The file the data came from (`composer.lock`, `/var/lib/dpkg/status`…).
    pub source: String,
    pub direct: bool,
}

pub const FACTS_MEDIA_TYPE: &str = "application/vnd.depverify.host-facts+json;version=1";
pub const CYCLONEDX_MEDIA_TYPE: &str = "application/vnd.cyclonedx+json;version=1.6";

/// A document with its digest (`sha256:` of its exact bytes, §8.1).
pub struct Document {
    pub bytes: Vec<u8>,
    pub media_type: &'static str,
    pub digest: String,
}

impl Document {
    pub fn new(bytes: Vec<u8>, media_type: &'static str) -> Self {
        use sha2::{Digest, Sha256};
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        Self {
            bytes,
            media_type,
            digest,
        }
    }

    pub fn reference(&self) -> Value {
        serde_json::json!({"digest": self.digest, "size": self.bytes.len(), "media_type": self.media_type})
    }
}
