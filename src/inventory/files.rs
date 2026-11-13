//! Where the catalogers read: the host file system (under a root: `/`, or the `/host` mount), the files read from a
//! running container (Docker archive API) or the files kept from the layers of an image. Reads are bounded.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

/// A lockfile or a package database larger than this is skipped (and reported as such in the logs).
pub const MAX_FILE: u64 = 64 * 1024 * 1024;

pub trait Files {
    /// The bytes of an absolute path, none when absent or unreadable.
    fn read(&self, path: &str) -> Option<Vec<u8>>;
}

pub struct Root(pub PathBuf);

impl Root {
    pub fn resolve(&self, path: &str) -> PathBuf {
        self.0.join(path.trim_start_matches('/'))
    }
}

impl Files for Root {
    fn read(&self, path: &str) -> Option<Vec<u8>> {
        let file = std::fs::File::open(self.resolve(path)).ok()?;
        if !file.metadata().ok()?.is_file() {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(MAX_FILE).read_to_end(&mut bytes).ok()?;
        Some(bytes)
    }
}

/// Files already in memory, by absolute path.
#[derive(Default)]
pub struct Memory(pub BTreeMap<String, Vec<u8>>);

impl Files for Memory {
    fn read(&self, path: &str) -> Option<Vec<u8>> {
        self.0.get(path).cloned()
    }
}

pub fn join(dir: &str, file: &str) -> String {
    format!("{}/{}", dir.trim_end_matches('/'), file)
}

pub fn text(files: &dyn Files, path: &str) -> Option<String> {
    files
        .read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}
