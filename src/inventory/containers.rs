//! Containers (cadrage §6bis): the scope filter comes **first**, before any inspection or file read; then one
//! subject per Compose service (or standalone container, scope `host` only) with the dependencies read in the running
//! container, and one subject per image with its OS packages, analysed once per image id (cached).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use serde_json::{Value, json};

use super::apps::AppPackages;
use super::files::{MAX_FILE, Memory};
use super::{Document, Package, apps, os, sbom};
use crate::config::Scope;
use crate::docker::Docker;

#[derive(Clone, Debug)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image_id: String,
    pub labels: BTreeMap<String, String>,
}

pub const PROJECT: &str = "com.docker.compose.project";
pub const SERVICE: &str = "com.docker.compose.service";
const DEFAULT_DIRS: [&str; 6] = [
    "/app",
    "/var/www/html",
    "/var/www",
    "/srv/app",
    "/srv",
    "/usr/src/app",
];

impl Container {
    fn from(value: &Value) -> Option<Self> {
        let labels = value
            .get("Labels")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            id: value.get("Id")?.as_str()?.to_owned(),
            name: value
                .get("Names")
                .and_then(Value::as_array)
                .and_then(|n| n.first())
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim_start_matches('/')
                .to_owned(),
            image_id: value.get("ImageID")?.as_str()?.to_owned(),
            labels,
        })
    }

    fn label(&self, name: &str) -> Option<&str> {
        self.labels.get(name).map(String::as_str)
    }
}

/// `AGENT_SCOPE` (§6bis): `compose` its project but `monitor=false`, `labeled` its project and `monitor=true` only,
/// `host` everything but `monitor=false`. The agent's own container never.
pub fn in_scope(
    container: &Container,
    scope: Scope,
    project: Option<&str>,
    own_id: Option<&str>,
) -> bool {
    if own_id.is_some_and(|own| !own.is_empty() && container.id.starts_with(own)) {
        return false;
    }
    let monitor = container.label("dev.depverify.monitor");
    let same_project = project.is_some() && container.label(PROJECT) == project;
    match scope {
        Scope::Compose => same_project && monitor != Some("false"),
        Scope::Labeled => same_project && monitor == Some("true"),
        Scope::Host => monitor != Some("false"),
    }
}

pub fn running(docker: &Docker) -> Result<Vec<Container>, String> {
    let list = docker.json("/containers/json")?;
    Ok(list
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Container::from)
        .collect())
}

/// The Compose project of the agent's own container (its hostname is its short id).
pub fn own_project(docker: &Docker, own_id: Option<&str>) -> Option<String> {
    let id = own_id?;
    let inspect = docker.json(&format!("/containers/{id}/json")).ok()?;
    inspect
        .get("Config")?
        .get("Labels")?
        .get(PROJECT)?
        .as_str()
        .map(str::to_owned)
}

pub fn docker_facts(docker: &Docker) -> (Value, Option<String>) {
    let info = docker.json("/info").ok();
    let version = docker.json("/version").ok();
    match (&info, &version) {
        (Some(info), Some(version)) => {
            let mut facts = json!({
                "engine_id": info.get("ID").and_then(Value::as_str).unwrap_or(""),
                "engine_version": version.get("Version").and_then(Value::as_str).unwrap_or(""),
            });
            for component in version
                .get("Components")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let (name, v) = (
                    component.get("Name").and_then(Value::as_str),
                    component.get("Version").and_then(Value::as_str),
                );
                match (name, v) {
                    (Some("containerd"), Some(v)) => facts["containerd_version"] = json!(v),
                    (Some("runc"), Some(v)) => facts["runc_version"] = json!(v),
                    _ => {}
                }
            }
            (
                facts,
                info.get("Name").and_then(Value::as_str).map(str::to_owned),
            )
        }
        _ => (Value::Null, None),
    }
}

pub struct Collected {
    pub subjects: Vec<(Value, Document)>,
    /// The image ids in use, to detect an image change between scans.
    pub images: BTreeSet<String>,
}

fn is_uuid7(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 36
        && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')
        && b[14] == b'7'
        && matches!(b[19], b'8' | b'9' | b'a' | b'b')
        && text.chars().enumerate().all(|(i, c)| {
            [8, 13, 18, 23].contains(&i) || c.is_ascii_digit() || ('a'..='f').contains(&c)
        })
}

fn label_paths(container: &Container) -> Vec<String> {
    container
        .label("dev.depverify.paths")
        .map(|paths| {
            paths
                .split(',')
                .map(str::trim)
                .filter(|p| p.starts_with('/'))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The dependencies of an application running in a container: the label paths, else its working directory and the
/// usual places; the first directory holding a manifest wins.
fn app_packages(docker: &Docker, container: &Container, inspect: Option<&Value>) -> AppPackages {
    let labelled = label_paths(container);
    let mut dirs = labelled.clone();
    if dirs.is_empty() {
        if let Some(dir) = inspect
            .and_then(|i| i.get("Config"))
            .and_then(|c| c.get("WorkingDir"))
            .and_then(Value::as_str)
            .filter(|d| d.starts_with('/') && *d != "/")
        {
            dirs.push(dir.to_owned());
        }
        dirs.extend(DEFAULT_DIRS.iter().map(|d| (*d).to_owned()));
        dirs.dedup();
    }
    let mut found = Vec::new();
    for dir in dirs {
        let mut files = Memory::default();
        for marker in [
            "composer.json",
            "composer.lock",
            "vendor/composer/installed.json",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
        ] {
            let path = super::files::join(&dir, marker);
            if let Some(bytes) = docker.container_file(&container.id, &path) {
                files.0.insert(path, bytes);
            }
        }
        let app = apps::catalog(&files, &dir);
        if !app.is_empty() {
            found.push(app);
            if labelled.is_empty() {
                break; // every labelled path counts
            }
        }
    }
    apps::merge(found)
}

/// The runtime of an application in a container, from the version the official images set in the environment
/// (`PHP_VERSION`, `NODE_VERSION`). Only these two variables are read, never the others: they may hold secrets.
pub fn runtime(inspect: Option<&Value>, app: &AppPackages) -> Option<Value> {
    let (name, variable) = if app.php {
        ("php", "PHP_VERSION")
    } else if app.node {
        ("node", "NODE_VERSION")
    } else {
        return None;
    };
    let version = inspect?
        .get("Config")?
        .get("Env")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find_map(|entry| entry.strip_prefix(variable)?.strip_prefix('='))?;
    let valid = version.len() <= 32
        && version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".+-_".contains(c));
    valid.then(|| json!({"name": name, "version": version}))
}

/// The application fields read in the running container: its runtime and the versions its project declares.
fn app_fields(docker: &Docker, container: &Container, fields: &mut Value) -> Vec<Package> {
    let inspect = docker
        .json(&format!("/containers/{}/json", container.id))
        .ok();
    let app = app_packages(docker, container, inspect.as_ref());
    if let Some(runtime) = runtime(inspect.as_ref(), &app) {
        fields["runtime"] = runtime;
    }
    if let Some(requires) = app.requires_field() {
        fields["requires"] = requires;
    }
    app.packages
}

pub fn collect(
    docker: &Docker,
    scope: Scope,
    project: Option<&str>,
    own_id: Option<&str>,
    cache: &Path,
) -> Result<Collected, String> {
    let selected: Vec<Container> = running(docker)?
        .into_iter()
        .filter(|c| in_scope(c, scope, project, own_id))
        .collect();
    let mut services: BTreeMap<(String, String), Vec<Container>> = BTreeMap::new();
    let mut standalone = Vec::new();
    for container in selected {
        match (container.label(PROJECT), container.label(SERVICE)) {
            (Some(p), Some(s)) => services
                .entry((p.to_owned(), s.to_owned()))
                .or_default()
                .push(container),
            _ if scope == Scope::Host => standalone.push(container),
            _ => {}
        }
    }

    let mut subjects = Vec::new();
    let mut images = BTreeSet::new();
    for ((project, service), containers) in &services {
        let first = &containers[0];
        let key = format!("compose:{project}/{service}");
        let mut ids: Vec<&str> = containers.iter().map(|c| c.id.as_str()).collect();
        ids.sort();
        let mut fields = json!({"subject_key": key, "kind": "compose_service", "compose_project": project, "service": service, "container_ids": ids, "image_id": first.image_id});
        let mut labels = json!({});
        if let Some(name) = first.label("dev.depverify.name") {
            labels["name"] = json!(name);
        }
        if let Some(environment) = first
            .label("dev.depverify.environment")
            .filter(|e| is_uuid7(e))
        {
            labels["environment"] = json!(environment);
        }
        let paths = label_paths(first);
        if !paths.is_empty() {
            labels["paths"] = json!(paths);
        }
        if labels.as_object().is_some_and(|l| !l.is_empty()) {
            fields["labels"] = labels;
        }
        let name = first.label("dev.depverify.name").unwrap_or(service);
        let packages = app_fields(docker, first, &mut fields);
        let document = sbom::document(&key, "application", name, &packages);
        images.insert(first.image_id.clone());
        subjects.push((fields, document));
    }
    for container in &standalone {
        let key = format!("container:{}", container.name);
        let mut fields = json!({"subject_key": key, "kind": "container", "container_name": container.name, "container_id": container.id, "image_id": container.image_id});
        let packages = app_fields(docker, container, &mut fields);
        let document = sbom::document(&key, "application", &container.name, &packages);
        images.insert(container.image_id.clone());
        subjects.push((fields, document));
    }
    for image_id in &images {
        if let Some(subject) = image_subject(docker, image_id, cache) {
            subjects.push(subject);
        }
    }
    Ok(Collected { subjects, images })
}

/// The `container_image` subject: tags, digests and provenance from Docker; OS packages from the layers, once per
/// image id (and agent version).
fn image_subject(docker: &Docker, image_id: &str, cache: &Path) -> Option<(Value, Document)> {
    let hex = image_id
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))?;
    let inspect = docker.json(&format!("/images/{image_id}/json")).ok()?;
    let strings = |field: &str| -> Vec<String> {
        let mut values: Vec<String> = inspect
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .filter(|v| v != "<none>:<none>" && v != "<none>@<none>")
            .collect();
        values.sort();
        values
    };
    let (tags, digests) = (strings("RepoTags"), strings("RepoDigests"));
    let key = format!("image:{image_id}");
    let mut fields = json!({"subject_key": key, "kind": "container_image", "image_id": image_id, "repo_digests": digests, "tags": tags, "provenance": if digests.is_empty() { "local-build" } else { "registry" }});
    if let Some(base) = inspect
        .get("Config")
        .and_then(|c| c.get("Labels"))
        .and_then(|l| l.get("org.opencontainers.image.base.name"))
        .and_then(Value::as_str)
    {
        fields["base_image"] = json!(base);
    }

    let cached = cache.join(format!("{hex}-{}.cdx.json", env!("CARGO_PKG_VERSION")));
    let document = match std::fs::read(&cached) {
        Ok(bytes) => Document::new(bytes, super::CYCLONEDX_MEDIA_TYPE),
        Err(_) => {
            let files = image_files(docker, image_id).ok()?;
            let name = tags.first().cloned().unwrap_or_else(|| image_id.to_owned());
            let document = sbom::document(&key, "container", &name, &image_packages(&files));
            let _ = crate::state::write_private(&cached, &document.bytes);
            document
        }
    };
    Some((fields, document))
}

pub fn image_packages(files: &Memory) -> Vec<Package> {
    let os = super::facts::os_release(files);
    let mut packages = Vec::new();
    if let Some(status) = super::files::text(files, "/var/lib/dpkg/status") {
        packages.extend(os::dpkg(&status, &os, "/var/lib/dpkg/status"));
    }
    // Distroless: one status file per package.
    for (path, bytes) in files.0.range("/var/lib/dpkg/status.d/".to_owned()..) {
        if !path.starts_with("/var/lib/dpkg/status.d/") {
            break;
        }
        if !path.ends_with(".md5sums") {
            packages.extend(os::dpkg(
                &String::from_utf8_lossy(bytes),
                &os,
                "/var/lib/dpkg/status.d",
            ));
        }
    }
    if let Some(installed) = super::files::text(files, "/lib/apk/db/installed") {
        packages.extend(os::apk(&installed, &os, "/lib/apk/db/installed"));
    }
    // The first RPM database found (the new location first), read without `rpm`.
    if let Some(lines) = RPM_DATABASES
        .iter()
        .find_map(|path| files.0.get(&format!("/{path}")))
        .and_then(|bytes| super::rpmdb::query_lines(bytes))
    {
        packages.extend(os::rpm(&lines, &os));
    }
    packages
}

/// Where an image keeps its RPM database: SQLite (RHEL 9, Fedora, Amazon Linux 2023), else Berkeley DB (RHEL 7, 8).
const RPM_DATABASES: [&str; 4] = [
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "var/lib/rpm/rpmdb.sqlite",
    "usr/lib/sysimage/rpm/Packages",
    "var/lib/rpm/Packages",
];

/// The files kept from the layers of an image.
fn wanted(path: &str) -> bool {
    matches!(
        path,
        "etc/os-release" | "usr/lib/os-release" | "var/lib/dpkg/status" | "lib/apk/db/installed"
    ) || RPM_DATABASES.contains(&path)
        || (path.starts_with("var/lib/dpkg/status.d/") && path.len() > 23)
}

fn concerns(target: &str) -> bool {
    [
        "etc/os-release",
        "usr/lib/os-release",
        "var/lib/dpkg/status",
        "lib/apk/db/installed",
        "var/lib/dpkg/status.d",
        "usr/lib/sysimage/rpm/rpmdb.sqlite",
        "var/lib/rpm/rpmdb.sqlite",
        "usr/lib/sysimage/rpm/Packages",
        "var/lib/rpm/Packages",
    ]
    .iter()
    .any(|w| w.starts_with(target) || target.starts_with(w))
}

#[derive(Default)]
struct Layer {
    files: BTreeMap<String, Vec<u8>>,
    deleted: Vec<String>,
    opaque: Vec<String>,
}

/// What an image analysis may keep in memory at most (package databases of every layer), and how many entries it
/// reads: an image built to exhaust the agent is refused, not followed.
const IMAGE_BUDGET: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: u64 = 2_000_000;

struct Budget {
    bytes: u64,
    entries: u64,
}

impl Budget {
    fn spend(&mut self, bytes: u64) -> bool {
        self.entries += 1;
        self.bytes += bytes;
        self.within()
    }

    fn within(&self) -> bool {
        self.bytes <= IMAGE_BUDGET && self.entries <= MAX_ENTRIES
    }
}

fn read_layer(reader: impl Read, budget: &mut Budget) -> Option<Layer> {
    let mut buffered = BufReader::new(reader);
    let gzip = buffered.fill_buf().ok()?.starts_with(&[0x1f, 0x8b]);
    let reader: Box<dyn Read> = if gzip {
        Box::new(flate2::read::GzDecoder::new(buffered))
    } else {
        Box::new(buffered)
    };
    let mut archive = tar::Archive::new(reader);
    let mut layer = Layer::default();
    let mut any = false;
    for entry in archive.entries().ok()? {
        let Ok(mut entry) = entry else {
            break;
        };
        any = true;
        if !budget.spend(0) {
            return None;
        }
        let Ok(path) = entry.path().map(|p| {
            p.to_string_lossy()
                .trim_start_matches("./")
                .trim_start_matches('/')
                .to_owned()
        }) else {
            continue;
        };
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        if name == ".wh..wh..opq" {
            if concerns(dir) {
                layer.opaque.push(dir.to_owned());
            }
        } else if let Some(target) = name.strip_prefix(".wh.") {
            let target = if dir.is_empty() {
                target.to_owned()
            } else {
                format!("{dir}/{target}")
            };
            if concerns(&target) {
                layer.deleted.push(target);
            }
        } else if entry.header().entry_type().is_file() && wanted(&path) {
            let mut bytes = Vec::new();
            if (&mut entry).take(MAX_FILE).read_to_end(&mut bytes).is_ok() {
                if !budget.spend(bytes.len() as u64) {
                    return None;
                }
                layer.files.insert(path, bytes);
            }
        }
    }
    any.then_some(layer)
}

/// `GET /images/{id}/get`: the image as a tar of layers (Docker's legacy layout or OCI), each layer read as a stream
/// and only the package databases kept; then the layers applied in their order, whiteouts included.
pub fn image_files(docker: &Docker, image_id: &str) -> Result<Memory, String> {
    let response = docker.get(&format!("/images/{image_id}/get"))?;
    if response.status != 200 {
        return Err(format!("image export: HTTP {}", response.status));
    }
    layers_to_files(response.body)
}

pub fn layers_to_files(export: impl Read) -> Result<Memory, String> {
    let mut archive = tar::Archive::new(export);
    let mut layers: BTreeMap<String, Layer> = BTreeMap::new();
    let mut manifest: Option<Value> = None;
    let mut budget = Budget {
        bytes: 0,
        entries: 0,
    };
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();
        if path == "manifest.json" {
            let mut bytes = Vec::new();
            (&mut entry)
                .take(8 * 1024 * 1024)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            manifest = serde_json::from_slice(&bytes).ok();
        } else if !path.ends_with(".json") && path != "oci-layout" && path != "repositories" {
            if let Some(layer) = read_layer(&mut entry, &mut budget) {
                layers.insert(path, layer);
            }
            if !budget.within() {
                return Err("image analysis over its memory budget: skipped".into());
            }
        }
    }
    let order: Vec<String> = manifest
        .as_ref()
        .and_then(|m| m.get(0))
        .and_then(|m| m.get("Layers"))
        .and_then(Value::as_array)
        .map(|l| {
            l.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .ok_or("image export without manifest.json")?;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for name in order {
        let Some(layer) = layers.remove(&name) else {
            continue;
        };
        for dir in &layer.opaque {
            let prefix = format!("{dir}/");
            files.retain(|path, _| !path.starts_with(&prefix));
        }
        for target in &layer.deleted {
            let prefix = format!("{target}/");
            files.retain(|path, _| path != target && !path.starts_with(&prefix));
        }
        files.extend(layer.files);
    }
    Ok(Memory(
        files
            .into_iter()
            .map(|(path, bytes)| (format!("/{path}"), bytes))
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(id: &str, labels: &[(&str, &str)]) -> Container {
        Container {
            id: id.into(),
            name: id.into(),
            image_id: "sha256:x".into(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
        }
    }

    #[test]
    fn applies_the_scope_before_anything() {
        let app = container("aaa1", &[(PROJECT, "shop"), (SERVICE, "app")]);
        let redis = container(
            "bbb2",
            &[
                (PROJECT, "shop"),
                (SERVICE, "redis"),
                ("dev.depverify.monitor", "false"),
            ],
        );
        let worker = container(
            "ccc3",
            &[
                (PROJECT, "shop"),
                (SERVICE, "worker"),
                ("dev.depverify.monitor", "true"),
            ],
        );
        let other = container("ddd4", &[(PROJECT, "blog"), (SERVICE, "app")]);
        let lone = container("eee5", &[]);
        let me = container("fff6abcdef", &[(PROJECT, "shop"), (SERVICE, "agent")]);
        let all = [&app, &redis, &worker, &other, &lone, &me];
        let pick = |scope: Scope| -> Vec<&str> {
            all.iter()
                .filter(|c| in_scope(c, scope, Some("shop"), Some("fff6ab")))
                .map(|c| c.id.as_str())
                .collect()
        };
        assert_eq!(pick(Scope::Compose), vec!["aaa1", "ccc3"]);
        assert_eq!(pick(Scope::Labeled), vec!["ccc3"]);
        assert_eq!(pick(Scope::Host), vec!["aaa1", "ccc3", "ddd4", "eee5"]);
        assert!(
            !in_scope(&app, Scope::Compose, None, None),
            "no project known: nothing in compose scope"
        );
    }

    #[test]
    fn reads_only_the_runtime_version_of_the_environment() {
        let inspect = json!({"Config": {"Env": ["APP_SECRET=s3cr3t", "PHP_VERSION=8.3.14", "NODE_VERSION=22.11.0", "PHP_VERSION_X=1"]}});
        let php = AppPackages {
            php: true,
            node: true,
            ..AppPackages::default()
        };
        let node = AppPackages {
            node: true,
            ..AppPackages::default()
        };
        assert_eq!(
            runtime(Some(&inspect), &php),
            Some(json!({"name": "php", "version": "8.3.14"})),
            "PHP first."
        );
        assert_eq!(
            runtime(Some(&inspect), &node),
            Some(json!({"name": "node", "version": "22.11.0"}))
        );
        assert_eq!(
            runtime(Some(&inspect), &AppPackages::default()),
            None,
            "No application, no runtime."
        );
        assert_eq!(runtime(None, &php), None);
        for env in [
            "PHP_VERSION=",
            "PHP_VERSION=latest",
            "PHP_VERSION=8.3 && rm",
            "PHP_VERSION_X=8.3",
            "PHPVERSION=8.3",
        ] {
            let inspect = json!({"Config": {"Env": [env]}});
            assert_eq!(runtime(Some(&inspect), &php), None, "{env}");
        }
        let long = json!({"Config": {"Env": [format!("PHP_VERSION=8.{}", "1".repeat(31))]}});
        assert_eq!(runtime(Some(&long), &php), None);
        let edge = json!({"Config": {"Env": [format!("PHP_VERSION=8.{}", "1".repeat(30))]}});
        assert!(
            runtime(Some(&edge), &php).is_some(),
            "32 characters at most."
        );
        let rc = json!({"Config": {"Env": ["PHP_VERSION=8.5.0RC1-dev_x+1"]}});
        assert!(runtime(Some(&rc), &php).is_some());
    }

    #[test]
    fn checks_the_environment_label() {
        assert!(is_uuid7("019a6b2c-1f00-7a11-8b22-3c44d55e6f01"));
        assert!(!is_uuid7("019a6b2c-1f00-4a11-8b22-3c44d55e6f01"));
        assert!(!is_uuid7("production"));
    }

    fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            builder.append_data(&mut header, path, *bytes).unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn reads_the_rpm_database_of_an_image() {
        use std::io::Read;
        let mut sqlite = Vec::new();
        flate2::read::GzDecoder::new(
            std::fs::File::open(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/rpmdb/rocky9-rpmdb.sqlite.gz"
            ))
            .unwrap(),
        )
        .read_to_end(&mut sqlite)
        .unwrap();
        assert!(wanted("var/lib/rpm/rpmdb.sqlite") && wanted("usr/lib/sysimage/rpm/Packages"));
        assert!(!wanted("var/lib/rpm/Basenames"));
        assert!(concerns("var/lib/rpm") && concerns("usr/lib/sysimage"));

        let mut files = Memory::default();
        files.0.insert(
            "/etc/os-release".into(),
            b"ID=\"rocky\"\nVERSION_ID=\"9.3\"\n".to_vec(),
        );
        files.0.insert("/var/lib/rpm/rpmdb.sqlite".into(), sqlite);
        let packages = image_packages(&files);
        assert_eq!(
            packages.len(),
            118,
            "Every package of rockylinux:9-minimal."
        );
        let openssl = packages.iter().find(|p| p.name == "openssl-libs").unwrap();
        assert!(
            openssl.purl.starts_with("pkg:rpm/rocky/openssl-libs@"),
            "{}",
            openssl.purl
        );
        assert!(
            openssl.purl.contains("distro=rocky-9&")
                && openssl.purl.contains("epoch=1")
                && openssl.purl.contains("upstream=openssl"),
            "{}",
            openssl.purl
        );

        files.0.insert(
            "/var/lib/rpm/rpmdb.sqlite".into(),
            b"not a database".to_vec(),
        );
        assert!(
            image_packages(&files).is_empty(),
            "A damaged database: nothing, never a guess."
        );
    }

    #[test]
    fn applies_the_layers_in_order_with_their_whiteouts() {
        let base = tar_of(&[
            ("etc/os-release", b"ID=debian\nVERSION_ID=12\n"),
            (
                "var/lib/dpkg/status",
                b"Package: old\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n",
            ),
            ("usr/bin/x", b"bin"),
        ]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar_of(&[("var/lib/dpkg/status", b"Package: curl\nStatus: install ok installed\nVersion: 7.88.1-10\nArchitecture: amd64\n"), ("lib/apk/.wh.db", b"")])).unwrap();
        let upper = gz.finish().unwrap();
        let manifest =
            br#"[{"Config":"blobs/sha256/c","Layers":["blobs/sha256/l1","blobs/sha256/l2"]}]"#;
        let export = tar_of(&[
            ("blobs/sha256/l2", &upper),
            ("blobs/sha256/c", b"{}"),
            ("blobs/sha256/l1", &base),
            ("manifest.json", manifest),
            ("index.json", b"{}"),
        ]);

        let files = layers_to_files(std::io::Cursor::new(export)).unwrap();
        assert_eq!(
            files.0.keys().cloned().collect::<Vec<_>>(),
            vec!["/etc/os-release", "/var/lib/dpkg/status"]
        );
        let packages = image_packages(&files);
        assert_eq!(packages.len(), 1);
        assert_eq!(
            packages[0].purl,
            "pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12"
        );

        let deleting = tar_of(&[("var/lib/dpkg/.wh.status", b"")]);
        let manifest = br#"[{"Layers":["a/layer.tar","b/layer.tar"]}]"#;
        let export = tar_of(&[
            ("a/layer.tar", &base),
            ("b/layer.tar", &deleting),
            ("manifest.json", manifest),
        ]);
        let files = layers_to_files(std::io::Cursor::new(export)).unwrap();
        assert!(
            !files.0.contains_key("/var/lib/dpkg/status"),
            "removed by a whiteout"
        );
        assert!(files.0.contains_key("/etc/os-release"));

        let mut budget = Budget {
            bytes: IMAGE_BUDGET - 3,
            entries: 0,
        };
        let big = tar_of(&[("var/lib/dpkg/status", b"1234")]);
        assert!(
            read_layer(std::io::Cursor::new(big), &mut budget).is_none(),
            "over the budget"
        );
    }
}
