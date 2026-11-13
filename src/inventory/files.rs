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

    /// The names in a directory, sorted (none when it is not one).
    fn list(&self, dir: &str) -> Vec<String>;
}

/// Symbolic links followed at most, inside the root.
const MAX_LINKS: usize = 8;

pub struct Root(pub PathBuf);

impl Root {
    pub fn resolve(&self, path: &str) -> PathBuf {
        self.0.join(path.trim_start_matches('/'))
    }
}

impl Root {
    /// The real path of an absolute path under the root, its symbolic links resolved **inside the root** (an absolute
    /// target is read under the root too, never on the agent's own file system).
    fn real(&self, path: &str) -> Option<PathBuf> {
        let mut current = path.to_owned();
        for _ in 0..=MAX_LINKS {
            let resolved = self.resolve(&current);
            let metadata = std::fs::symlink_metadata(&resolved).ok()?;
            if !metadata.file_type().is_symlink() {
                return Some(resolved);
            }
            let target = std::fs::read_link(&resolved).ok()?;
            let target = target.to_str()?;
            current = if target.starts_with('/') {
                target.to_owned()
            } else {
                let parent = current.rsplit_once('/').map_or("", |(p, _)| p);
                format!("{parent}/{target}")
            };
        }
        None
    }
}

impl Files for Root {
    fn list(&self, dir: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .real(dir)
            .and_then(|d| std::fs::read_dir(d).ok())
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        names.sort();
        names
    }

    fn read(&self, path: &str) -> Option<Vec<u8>> {
        let file = std::fs::File::open(self.real(path)?).ok()?;
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

    fn list(&self, dir: &str) -> Vec<String> {
        let prefix = format!("{}/", dir.trim_end_matches('/'));
        let mut names: Vec<String> = self
            .0
            .keys()
            .filter_map(|k| {
                k.strip_prefix(&prefix)?
                    .split('/')
                    .next()
                    .map(str::to_owned)
            })
            .collect();
        names.dedup();
        names
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
