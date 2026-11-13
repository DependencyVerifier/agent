//! The dependencies of one application directory, whatever it is read from (host, container, image).

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::Package;
use super::files::{self, Files};
use super::{node, php};

/// The longest version constraint kept: a real one is a few characters, anything longer is not one.
const MAX_CONSTRAINT: usize = 100;

#[derive(Default)]
pub struct AppPackages {
    pub packages: Vec<Package>,
    pub php: bool,
    pub node: bool,
    /// The runtime versions the project declares: `require.php` of `composer.json`, `engines.node` of
    /// `package.json`.
    pub requires: BTreeMap<&'static str, String>,
}

impl AppPackages {
    pub fn is_empty(&self) -> bool {
        !self.php && !self.node
    }

    /// The `requires` field of a subject, none when the project declares nothing.
    pub fn requires_field(&self) -> Option<Value> {
        (!self.requires.is_empty()).then(|| json!(self.requires))
    }

    fn absorb(&mut self, other: Self) {
        self.packages.extend(other.packages);
        self.php |= other.php;
        self.node |= other.node;
        for (name, constraint) in other.requires {
            self.requires.entry(name).or_insert(constraint);
        }
    }
}

/// Merges the applications of several directories of one container (every labelled path counts).
pub fn merge(apps: impl IntoIterator<Item = AppPackages>) -> AppPackages {
    let mut merged = AppPackages::default();
    for app in apps {
        merged.absorb(app);
    }
    merged
}

/// A constraint read from a manifest: a short string, else nothing.
fn constraint(manifest: Option<&str>, path: &[&str]) -> Option<String> {
    let json: Value = serde_json::from_str(manifest?).ok()?;
    let value = path
        .iter()
        .try_fold(&json, |v, key| v.get(key))?
        .as_str()?
        .trim();
    (!value.is_empty() && value.len() <= MAX_CONSTRAINT && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}

/// Composer: `vendor/composer/installed.json`, else `composer.lock`. Node: `package-lock.json`, else
/// `node_modules/.package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`.
pub fn catalog(files: &dyn Files, dir: &str) -> AppPackages {
    let mut app = AppPackages::default();
    let read = |name: &str| files::text(files, &files::join(dir, name));

    let composer_json = read("composer.json");
    if let Some(php) = constraint(composer_json.as_deref(), &["require", "php"]) {
        app.requires.insert("php", php);
    }
    let direct = php::direct(composer_json.as_deref());
    if let Some(installed) = read("vendor/composer/installed.json") {
        app.packages.extend(php::installed(&installed, &direct));
        app.php = true;
    } else if let Some(lock) = read("composer.lock") {
        app.packages.extend(php::lock(&lock, &direct));
        app.php = true;
    } else if composer_json.is_some() {
        app.php = true;
    }

    let package_json = read("package.json");
    let direct = node::direct(package_json.as_deref());
    if let Some(lock) = read("package-lock.json") {
        app.packages
            .extend(node::package_lock(&lock, &direct, "package-lock.json"));
        app.node = true;
    } else if let Some(lock) = read("node_modules/.package-lock.json") {
        app.packages.extend(node::package_lock(
            &lock,
            &direct,
            "node_modules/.package-lock.json",
        ));
        app.node = true;
    } else if let Some(lock) = read("yarn.lock") {
        app.packages.extend(node::yarn_lock(&lock, &direct));
        app.node = true;
    } else if let Some(lock) = read("pnpm-lock.yaml") {
        app.packages.extend(node::pnpm_lock(&lock, &direct));
        app.node = true;
    }
    if app.node {
        if let Some(node) = constraint(package_json.as_deref(), &["engines", "node"]) {
            app.requires.insert("node", node);
        }
    }
    app
}

/// The files an application directory is recognized by.
pub const MARKERS: [&str; 7] = [
    "composer.json",
    "composer.lock",
    "vendor/composer/installed.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "node_modules/.package-lock.json",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::files::Memory;

    #[test]
    fn prefers_what_is_installed() {
        let mut files = Memory::default();
        files.0.insert(
            "/app/composer.json".into(),
            br#"{"require":{"a/b":"^1"}}"#.to_vec(),
        );
        files.0.insert(
            "/app/composer.lock".into(),
            br#"{"packages":[{"name":"a/b","version":"1.0.0"}]}"#.to_vec(),
        );
        files.0.insert(
            "/app/vendor/composer/installed.json".into(),
            br#"{"packages":[{"name":"a/b","version":"1.0.1"}]}"#.to_vec(),
        );
        let app = catalog(&files, "/app/");
        assert!(app.php && !app.node);
        assert_eq!(app.packages.len(), 1);
        assert_eq!(app.packages[0].version, "1.0.1");
        assert!(app.packages[0].direct);
        assert!(catalog(&files, "/elsewhere").is_empty());
        assert!(app.requires.is_empty() && app.requires_field().is_none());
    }

    #[test]
    fn reads_the_declared_runtime_versions() {
        let mut files = Memory::default();
        files.0.insert(
            "/app/composer.json".into(),
            br#"{"require":{"php":" >=8.2 ","a/b":"^1"}}"#.to_vec(),
        );
        files.0.insert(
            "/app/package.json".into(),
            br#"{"engines":{"node":"^20 || ^22"}}"#.to_vec(),
        );
        files.0.insert(
            "/app/package-lock.json".into(),
            br#"{"packages":{}}"#.to_vec(),
        );
        let app = catalog(&files, "/app");
        assert_eq!(
            app.requires_field(),
            Some(json!({"node": "^20 || ^22", "php": ">=8.2"}))
        );

        let long = format!(r#"{{"require":{{"php":"{}"}}}}"#, "1".repeat(101));
        for composer in [
            long.as_str(),
            r#"{"require":{"php":""}}"#,
            r#"{"require":{"php":8}}"#,
            r#"{"require":{"php":"8\n2"}}"#,
            "not json",
        ] {
            let mut files = Memory::default();
            files
                .0
                .insert("/app/composer.json".into(), composer.as_bytes().to_vec());
            assert!(catalog(&files, "/app").requires.is_empty(), "{composer}");
        }

        let mut only_manifest = Memory::default();
        only_manifest.0.insert(
            "/app/package.json".into(),
            br#"{"engines":{"node":">=20"}}"#.to_vec(),
        );
        assert!(
            catalog(&only_manifest, "/app").requires.is_empty(),
            "Not a Node application without a lockfile."
        );
    }

    #[test]
    fn merges_several_directories() {
        let first = AppPackages {
            php: true,
            requires: BTreeMap::from([("php", "^8.2".to_owned())]),
            ..AppPackages::default()
        };
        let second = AppPackages {
            node: true,
            requires: BTreeMap::from([("php", "^8.4".to_owned()), ("node", ">=22".to_owned())]),
            ..AppPackages::default()
        };
        let merged = merge([first, second]);
        assert!(merged.php && merged.node);
        assert_eq!(
            merged.requires_field(),
            Some(json!({"node": ">=22", "php": "^8.2"})),
            "The first directory wins."
        );
    }
}
