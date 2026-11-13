//! Node: `package-lock.json` (v1 to v3, also `node_modules/.package-lock.json`), `yarn.lock` (v1 and berry),
//! `pnpm-lock.yaml`. Direct dependencies are those of `package.json`.

use std::collections::BTreeSet;

use serde_json::Value;

use super::Package;
use super::purl;

pub fn direct(package_json: Option<&str>) -> BTreeSet<String> {
    let Some(json) = package_json.and_then(|t| serde_json::from_str::<Value>(t).ok()) else {
        return BTreeSet::new();
    };
    ["dependencies", "devDependencies", "optionalDependencies"]
        .iter()
        .filter_map(|s| json.get(s).and_then(Value::as_object))
        .flat_map(|m| m.keys().cloned())
        .collect()
}

fn package(
    name: &str,
    version: &str,
    manager: &'static str,
    source: &str,
    direct: &BTreeSet<String>,
) -> Option<Package> {
    if name.is_empty() || version.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None; // links, workspaces, git or file dependencies
    }
    let (namespace, short) = match name.strip_prefix('@').and_then(|n| n.split_once('/')) {
        Some((scope, short)) => (format!("@{scope}"), short),
        None => (String::new(), name),
    };
    Some(Package {
        purl: purl::build("npm", &[namespace.as_str()], short, version, &[]),
        name: name.to_owned(),
        version: version.to_owned(),
        manager,
        source: source.to_owned(),
        direct: direct.contains(name),
    })
}

pub fn package_lock(text: &str, direct: &BTreeSet<String>, source: &str) -> Vec<Package> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return vec![];
    };
    let mut packages = Vec::new();
    if let Some(map) = json.get("packages").and_then(Value::as_object) {
        for (path, entry) in map {
            if path.is_empty() || entry.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let Some(name) = path
                .rsplit_once("node_modules/")
                .map(|(_, n)| n)
                .or(entry.get("name").and_then(Value::as_str))
            else {
                continue;
            };
            if let Some(p) = entry
                .get("version")
                .and_then(Value::as_str)
                .and_then(|v| package(name, v, "npm", source, direct))
            {
                packages.push(p);
            }
        }
        return packages;
    }
    fn walk(
        map: &serde_json::Map<String, Value>,
        direct: &BTreeSet<String>,
        source: &str,
        out: &mut Vec<Package>,
    ) {
        for (name, entry) in map {
            if let Some(p) = entry
                .get("version")
                .and_then(Value::as_str)
                .and_then(|v| package(name, v, "npm", source, direct))
            {
                out.push(p);
            }
            if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
                walk(nested, direct, source, out);
            }
        }
    }
    if let Some(map) = json.get("dependencies").and_then(Value::as_object) {
        walk(map, direct, source, &mut packages);
    }
    packages
}

/// The name in a yarn descriptor: `@scope/name@^1`, `name@npm:^1`, `"name@^1, name@^1.2"`.
fn descriptor_name(descriptor: &str) -> &str {
    let first = descriptor
        .trim()
        .trim_matches('"')
        .split(", ")
        .next()
        .unwrap_or("")
        .trim_matches('"');
    let search_from = usize::from(first.starts_with('@'));
    match first[search_from..].find('@') {
        Some(at) => &first[..at + search_from],
        None => first,
    }
}

/// yarn.lock v1 (`version "1.2.3"`) and berry (`version: 1.2.3`, `__metadata`, workspace entries skipped).
pub fn yarn_lock(text: &str, direct: &BTreeSet<String>) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            let key = line.trim_end_matches(':');
            current = if key == "__metadata"
                || key.contains("@workspace:")
                || key.contains("@link:")
                || key.contains("@portal:")
                || key.contains("@patch:")
            {
                None
            } else {
                Some(descriptor_name(key).to_owned())
            };
            continue;
        }
        let trimmed = line.trim();
        let version = trimmed
            .strip_prefix("version ")
            .or_else(|| trimmed.strip_prefix("version: "));
        if let (Some(name), Some(version)) = (current.as_deref(), version) {
            if let Some(p) = package(name, version.trim_matches('"'), "yarn", "yarn.lock", direct) {
                packages.push(p);
            }
            current = None;
        }
    }
    packages
}

/// pnpm-lock.yaml: the keys of `packages:` (`/name/1.2.3`, `/@scope/name@1.2.3(peer)`, `'@scope/name@1.2.3'`).
pub fn pnpm_lock(text: &str, direct: &BTreeSet<String>) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut in_packages = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages || !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        let key = line
            .trim()
            .trim_end_matches(':')
            .trim_matches(|c| c == '\'' || c == '"');
        let key = key.trim_start_matches('/');
        let key = key.split('(').next().unwrap_or(key);
        let search_from = usize::from(key.starts_with('@'));
        let (name, version) = match key[search_from..].find('@') {
            Some(at) => (&key[..at + search_from], &key[at + search_from + 1..]),
            None => match key.rsplit_once('/') {
                Some((name, version)) => (name, version),
                None => continue,
            },
        };
        if let Some(p) = package(name, version, "pnpm", "pnpm-lock.yaml", direct) {
            packages.push(p);
        }
    }
    packages
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/node-app/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn names(packages: &[Package]) -> BTreeSet<String> {
        packages
            .iter()
            .map(|p| {
                format!(
                    "{}@{}{}",
                    p.name,
                    p.version,
                    if p.direct { " direct" } else { "" }
                )
            })
            .collect()
    }

    #[test]
    fn the_three_lockfiles_of_one_project_agree() {
        let direct = direct(Some(&fixture("package.json")));
        assert_eq!(direct.len(), 4);
        let npm = package_lock(&fixture("package-lock.json"), &direct, "package-lock.json");
        let yarn = yarn_lock(&fixture("yarn.lock"), &direct);
        let pnpm = pnpm_lock(&fixture("pnpm-lock.yaml"), &direct);
        assert!(names(&npm).contains("lodash@4.17.20 direct"));
        assert!(names(&npm).contains("@hotwired/turbo@8.0.12 direct"));
        assert!(
            names(&npm)
                .iter()
                .any(|n| n.starts_with("follow-redirects@") && !n.ends_with("direct"))
        );
        let core = |set: BTreeSet<String>| {
            set.into_iter()
                .filter(|n| {
                    ["lodash@", "axios@", "@hotwired/turbo@", "is-number@"]
                        .iter()
                        .any(|p| n.starts_with(p))
                })
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(core(names(&npm)), core(names(&yarn)));
        assert_eq!(core(names(&npm)), core(names(&pnpm)));
        assert_eq!(npm.len(), yarn.len());
        assert_eq!(npm.len(), pnpm.len());
        assert!(
            npm.iter()
                .find(|p| p.name == "@hotwired/turbo")
                .unwrap()
                .purl
                == "pkg:npm/%40hotwired/turbo@8.0.12"
        );
    }

    #[test]
    fn reads_a_real_yarn_berry_lock() {
        let packages = yarn_lock(&fixture("yarn-berry.lock"), &BTreeSet::new());
        assert!(packages.len() > 50);
        assert!(
            packages
                .iter()
                .all(|p| p.version.starts_with(|c: char| c.is_ascii_digit()))
        );
        assert!(packages.iter().any(|p| p.name.starts_with('@')));
        assert!(!packages.iter().any(|p| p.name.contains("workspace")));
    }

    #[test]
    fn reads_the_old_formats() {
        let v1 = r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}},"c":{"version":"file:../c"}}}"#;
        assert_eq!(
            names(&package_lock(v1, &BTreeSet::new(), "package-lock.json")),
            BTreeSet::from(["a@1.0.0".to_owned(), "b@2.0.0".to_owned()])
        );
        let pnpm5 = "lockfileVersion: 5.4\npackages:\n\n  /lodash/4.17.20:\n    resolution: {integrity: x}\n  /@scope/name/1.0.0:\n    dev: false\n";
        assert_eq!(
            names(&pnpm_lock(pnpm5, &BTreeSet::new())),
            BTreeSet::from(["lodash@4.17.20".to_owned(), "@scope/name@1.0.0".to_owned()])
        );
    }
}
