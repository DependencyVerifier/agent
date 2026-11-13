//! Where the catalogers read: the host file system (under a root: `/`, or the `/host` mount), the files read from a
//! running container (Docker archive API) or the files kept from the layers of an image. Reads are bounded.

use std::collections::{BTreeMap, VecDeque};
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

/// Symbolic links followed at most for one path, inside the root (Linux's own limit).
const MAX_LINKS: usize = 40;

pub struct Root(pub PathBuf);

/// The components of an absolute path: `.` dropped, `..` applied, never above the root.
fn components(path: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part.to_owned()),
        }
    }
    parts
}

impl Root {
    /// An absolute path under the root, lexically (`..` never climbs above the root).
    pub fn resolve(&self, path: &str) -> PathBuf {
        components(path)
            .iter()
            .fold(self.0.clone(), |p, c| p.join(c))
    }

    /// The real path of an absolute path under the root: **every** component's symbolic link resolved inside the
    /// root, one component at a time (an absolute target starts again from the root, `..` never climbs above it), so
    /// nothing outside the root is ever read, whatever the links of the inspected file system say.
    fn real(&self, path: &str) -> Option<PathBuf> {
        let mut pending: VecDeque<String> = components(path).into();
        let mut done: Vec<String> = Vec::new();
        let mut links = 0;
        while let Some(part) = pending.pop_front() {
            if part == ".." {
                done.pop();
                continue;
            }
            let candidate = done
                .iter()
                .chain([&part])
                .fold(self.0.clone(), |p, c| p.join(c));
            if !std::fs::symlink_metadata(&candidate)
                .ok()?
                .file_type()
                .is_symlink()
            {
                done.push(part);
                continue;
            }
            links += 1;
            if links > MAX_LINKS {
                return None;
            }
            let target = std::fs::read_link(&candidate).ok()?;
            let target = target.to_str()?;
            if target.starts_with('/') {
                done.clear();
            }
            let mut next: VecDeque<String> = target
                .split('/')
                .filter(|p| !p.is_empty() && *p != ".")
                .map(str::to_owned)
                .collect();
            next.extend(pending.drain(..));
            pending = next;
        }
        Some(done.iter().fold(self.0.clone(), |p, c| p.join(c)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn never_reads_outside_the_root() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"outside").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = Root(dir.path().join("root"));
        std::fs::create_dir_all(root.0.join("etc/nginx/sites-available")).unwrap();
        std::fs::create_dir_all(root.0.join("etc/real")).unwrap();
        std::fs::write(root.0.join("etc/nginx/sites-available/shop"), b"inside").unwrap();
        std::fs::write(root.0.join("etc/real/secret"), b"the root's").unwrap();
        let out = outside.path().to_str().unwrap();

        symlink(
            "../nginx/sites-available/shop",
            root.0.join("etc/nginx/relative"),
        )
        .unwrap();
        symlink(
            "/etc/nginx/sites-available/shop",
            root.0.join("etc/nginx/absolute"),
        )
        .unwrap();
        symlink(
            format!("../../../../../../../../{out}/secret"),
            root.0.join("etc/climb"),
        )
        .unwrap();
        symlink(out, root.0.join("etc/outside")).unwrap();
        symlink("/etc/real", root.0.join("etc/dir")).unwrap();
        symlink("loop", root.0.join("etc/loop")).unwrap();

        assert_eq!(root.read("/etc/nginx/relative").unwrap(), b"inside");
        assert_eq!(
            root.read("/etc/nginx/absolute").unwrap(),
            b"inside",
            "An absolute target, under the root."
        );
        assert_eq!(
            root.read("/etc/climb"),
            None,
            "`..` never climbs above the root."
        );
        assert_eq!(
            root.read("/etc/outside/secret"),
            None,
            "An absolute directory link, under the root: nothing there."
        );
        assert_eq!(
            root.read("/etc/dir/secret").unwrap(),
            b"the root's",
            "A directory link resolved inside the root."
        );
        assert_eq!(root.read("/etc/loop"), None);
        assert_eq!(
            root.read("/../../etc/nginx/sites-available/shop").unwrap(),
            b"inside"
        );
        assert_eq!(root.resolve("/../../x/./y/../z"), root.0.join("x/z"));
        assert_eq!(root.list("/etc/dir"), vec!["secret".to_owned()]);
    }
}
