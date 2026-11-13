//! Composer: `vendor/composer/installed.json` first (what is really installed), else `composer.lock`. Direct
//! dependencies are the `require` and `require-dev` of `composer.json`.

use std::collections::BTreeSet;

use serde_json::Value;

use super::Package;
use super::purl;

/// The names `composer.json` requires directly, lower-cased.
pub fn direct(composer_json: Option<&str>) -> BTreeSet<String> {
    let Some(json) = composer_json.and_then(|t| serde_json::from_str::<Value>(t).ok()) else {
        return BTreeSet::new();
    };
    ["require", "require-dev"]
        .iter()
        .filter_map(|section| json.get(section).and_then(Value::as_object))
        .flat_map(|map| map.keys().map(|k| k.to_lowercase()))
        .collect()
}

fn package(entry: &Value, direct: &BTreeSet<String>, source: &str) -> Option<Package> {
    let name = entry.get("name")?.as_str()?.to_lowercase();
    let version = entry.get("version")?.as_str()?;
    // A path or dev branch has no released version to match.
    if version.starts_with("dev-") || !name.contains('/') {
        return None;
    }
    let version = version
        .strip_prefix('v')
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        .unwrap_or(version);
    let (vendor, project) = name.split_once('/')?;
    Some(Package {
        purl: purl::build("composer", &[vendor], project, version, &[]),
        name: name.clone(),
        version: version.to_owned(),
        manager: "composer",
        source: source.to_owned(),
        direct: direct.contains(&name),
    })
}

/// `installed.json`, Composer 2 (`{"packages": [...]}`) or 1 (a list).
pub fn installed(text: &str, direct: &BTreeSet<String>) -> Vec<Package> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return vec![];
    };
    let list = json
        .get("packages")
        .and_then(Value::as_array)
        .or_else(|| json.as_array());
    list.into_iter()
        .flatten()
        .filter_map(|e| package(e, direct, "vendor/composer/installed.json"))
        .collect()
}

pub fn lock(text: &str, direct: &BTreeSet<String>) -> Vec<Package> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return vec![];
    };
    ["packages", "packages-dev"]
        .iter()
        .filter_map(|section| json.get(section).and_then(Value::as_array))
        .flatten()
        .filter_map(|e| package(e, direct, "composer.lock"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/app-composer/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn reads_a_real_installed_json_and_lock() {
        let direct = direct(Some(&fixture("composer.json")));
        assert!(direct.contains("symfony/framework-bundle"));
        let installed = installed(&fixture("installed.json"), &direct);
        let lock = lock(&fixture("composer.lock"), &direct);
        assert!(installed.len() > 50);
        assert_eq!(
            installed.len(),
            lock.len(),
            "the same packages, installed or locked"
        );
        let kernel = installed
            .iter()
            .find(|p| p.name == "symfony/http-kernel")
            .unwrap();
        assert!(
            kernel
                .purl
                .starts_with("pkg:composer/symfony/http-kernel@8."),
            "{}",
            kernel.purl
        );
        assert!(!kernel.version.starts_with('v'));
        assert!(installed.iter().any(|p| p.direct) && installed.iter().any(|p| !p.direct));
        assert!(
            installed
                .iter()
                .all(|p| p.source == "vendor/composer/installed.json")
        );
    }

    #[test]
    fn leaves_out_the_dev_branches() {
        let packages = lock(
            r#"{"packages":[{"name":"a/b","version":"dev-main"},{"name":"c/d","version":"v1.2.3"}]}"#,
            &BTreeSet::new(),
        );
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:composer/c/d@1.2.3");
    }
}
