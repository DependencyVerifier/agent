//! The applications of a host: every directory under the discovery roots holding a Composer or Node manifest
//! (depth 5, symbolic links never followed, `node_modules`, `vendor` and hidden directories skipped, exclusions
//! applied), plus the declared paths.

use globset::{Glob, GlobSet, GlobSetBuilder};

use super::apps::MARKERS;
use super::files::Root;
use crate::state::CollectConfig;

pub const MAX_DEPTH: usize = 5;
pub const MAX_APPS: usize = 500;

pub struct Found {
    pub path: String,
    pub declared: bool,
}

pub fn exclusions(patterns: &[String]) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
        }
    }
    builder.build().unwrap_or_else(|_| GlobSet::empty())
}

pub fn discover(root: &Root, config: &CollectConfig) -> Vec<Found> {
    let excluded = exclusions(&config.exclusions);
    let mut found: Vec<Found> = Vec::new();
    for path in &config.declared_paths {
        if root.resolve(path).is_dir() && !excluded.is_match(path) {
            found.push(Found {
                path: path.trim_end_matches('/').to_owned(),
                declared: true,
            });
        }
    }
    for base in &config.discovery_roots {
        walk(root, base.trim_end_matches('/'), 0, &excluded, &mut found);
    }
    found.sort_by(|a, b| a.path.cmp(&b.path).then(b.declared.cmp(&a.declared)));
    found.dedup_by(|a, b| a.path == b.path);
    found.truncate(MAX_APPS);
    found
}

fn walk(root: &Root, dir: &str, depth: usize, excluded: &GlobSet, found: &mut Vec<Found>) {
    if found.len() >= MAX_APPS || excluded.is_match(dir) {
        return;
    }
    let real = root.resolve(dir);
    if MARKERS.iter().any(|m| real.join(m).is_file()) {
        found.push(Found {
            path: if dir.is_empty() {
                "/".into()
            } else {
                dir.to_owned()
            },
            declared: false,
        });
        return;
    }
    if depth >= MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(&real) else {
        return;
    };
    let mut children: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type()
                .map(|t| t.is_dir() && !t.is_symlink())
                .unwrap_or(false)
        })
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| !name.starts_with('.') && name != "node_modules" && name != "vendor")
        .collect();
    children.sort();
    for name in children {
        walk(root, &format!("{dir}/{name}"), depth + 1, excluded, found);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn finds_the_applications_under_the_roots() {
        let dir = tempfile::tempdir().unwrap();
        let make = |path: &str, file: &str| {
            let full = dir.path().join(path.trim_start_matches('/'));
            fs::create_dir_all(&full).unwrap();
            fs::write(full.join(file), "{}").unwrap();
        };
        make("/var/www/shop", "composer.lock");
        make("/var/www/shop/vendor/x/y", "composer.json");
        make("/var/www/blog/front", "package-lock.json");
        make("/var/www/blog/front/node_modules/z", "package.json");
        make("/var/www/old", "composer.json");
        make("/srv/.hidden/app", "composer.json");
        make("/opt/legacy", "composer.lock");
        let root = Root(dir.path().to_path_buf());
        let config = CollectConfig {
            discovery_roots: vec!["/var/www".into(), "/srv".into()],
            declared_paths: vec!["/opt/legacy".into(), "/opt/missing".into()],
            exclusions: vec!["/var/www/old".into()],
            ..CollectConfig::default()
        };
        let found = discover(&root, &config);
        let paths: Vec<(&str, bool)> = found
            .iter()
            .map(|f| (f.path.as_str(), f.declared))
            .collect();
        assert_eq!(
            paths,
            vec![
                ("/opt/legacy", true),
                ("/var/www/blog/front", false),
                ("/var/www/shop", false)
            ]
        );
    }
}
