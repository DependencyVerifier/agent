//! The dependencies of one application directory, whatever it is read from (host, container, image).

use super::Package;
use super::files::{self, Files};
use super::{node, php};

#[derive(Default)]
pub struct AppPackages {
    pub packages: Vec<Package>,
    pub php: bool,
    pub node: bool,
}

impl AppPackages {
    pub fn is_empty(&self) -> bool {
        !self.php && !self.node
    }
}

/// Composer: `vendor/composer/installed.json`, else `composer.lock`. Node: `package-lock.json`, else
/// `node_modules/.package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`.
pub fn catalog(files: &dyn Files, dir: &str) -> AppPackages {
    let mut app = AppPackages::default();
    let read = |name: &str| files::text(files, &files::join(dir, name));

    let composer_json = read("composer.json");
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
    }
}
