//! One collection run: the host facts, the host's OS packages and applications (host mode), the containers and
//! images in scope (container mode, or host mode with Docker).

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Value, json};

use super::files::{Files, Memory, Root};
use super::{Document, apps, containers, discovery, facts, fpm, os, runtimes, sbom};
use crate::config::{Config, Mode, Scope};
use crate::docker::Docker;
use crate::state::CollectConfig;

pub struct Inventory {
    pub facts: Document,
    pub subjects: Vec<(Value, Document)>,
    pub images: BTreeSet<String>,
}

/// The container's short id, which Docker gives as its hostname.
pub fn own_container_id(config: &Config) -> Option<String> {
    (config.mode == Mode::Container)
        .then(|| std::env::var("HOSTNAME").ok())
        .flatten()
        .filter(|h| !h.is_empty())
}

pub struct Context {
    pub docker: Option<Docker>,
    pub own_id: Option<String>,
    pub project: Option<String>,
}

impl Context {
    pub fn new(config: &Config) -> Result<Self, String> {
        let docker = config.docker_host.as_deref().map(Docker::new).transpose()?;
        let own_id = own_container_id(config);
        let project = config.compose_project.clone().or_else(|| {
            docker
                .as_ref()
                .and_then(|d| containers::own_project(d, own_id.as_deref()))
        });
        Ok(Self {
            docker,
            own_id,
            project,
        })
    }

    pub fn scope(&self, config: &Config) -> Scope {
        config.scope.unwrap_or(Scope::Host)
    }
}

/// Searched for applications in embedded mode besides the configured roots: where images usually keep them.
const EMBEDDED_ROOTS: [&str; 2] = ["/app", "/usr/src/app"];

/// The OS packages under a root: dpkg, apk, and rpm through the fixed `rpm -qa` command in host mode, else (embedded
/// mode, a mounted host) its database read without `rpm`.
fn host_packages(root: &Root, run_rpm: bool) -> Option<Vec<super::Package>> {
    let os = facts::os_release(root);
    let mut packages = Vec::new();
    let mut found = false;
    if let Some(status) = super::files::text(root, "/var/lib/dpkg/status") {
        packages.extend(os::dpkg(&status, &os, "/var/lib/dpkg/status"));
        found = true;
    }
    if let Some(installed) = super::files::text(root, "/lib/apk/db/installed") {
        packages.extend(os::apk(&installed, &os, "/lib/apk/db/installed"));
        found = true;
    }
    if run_rpm && root.resolve("/var/lib/rpm").is_dir() {
        for rpm in ["/usr/bin/rpm", "/bin/rpm"] {
            if let Some(output) =
                runtimes::run(Path::new(rpm), &["-qa", "--qf", os::RPM_QUERY_FORMAT])
            {
                packages.extend(os::rpm(&output, &os));
                found = true;
                break;
            }
        }
    } else if !run_rpm {
        if let Some(lines) = containers::RPM_DATABASES
            .iter()
            .find_map(|path| root.read(&format!("/{path}")))
            .and_then(|bytes| super::rpmdb::query_lines(&bytes))
        {
            packages.extend(os::rpm(&lines, &os));
            found = true;
        }
    }
    found.then_some(packages)
}

pub fn collect(
    config: &Config,
    collect: &CollectConfig,
    context: &Context,
    cache: &Path,
) -> Result<Inventory, String> {
    let (docker_facts, docker_name, docker_kernel) = match &context.docker {
        Some(docker) => {
            let (facts, name) = containers::docker_facts(docker);
            let kernel = docker.json("/info").ok().and_then(|i| {
                i.get("KernelVersion")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
            (facts, name, kernel)
        }
        None => (Value::Null, None, None),
    };
    let root = config.host_root.clone().map(Root);
    let empty = Memory::default();
    let source: &dyn Files = match &root {
        Some(root) => root,
        None => &empty,
    };
    let hostname = if config.mode == Mode::Container {
        docker_name
    } else {
        None
    };
    let mut host = facts::read(source, hostname);
    if host.os.id.is_empty() {
        if let Some(docker) = &context.docker {
            if let Ok(info) = docker.json("/info") {
                host.os.pretty_name = info
                    .get("OperatingSystem")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
            }
        }
    }
    if let Some(kernel) = docker_kernel.filter(|_| host.kernel.is_empty()) {
        host.kernel = kernel;
    }

    let host_runtimes = if matches!(config.mode, Mode::Host | Mode::Embedded) {
        runtimes::collect()
    } else {
        vec![]
    };
    let mut agent = json!({"version": env!("CARGO_PKG_VERSION"), "mode": config.mode.as_str(), "config_version": collect.version});
    if let Some(scope) = config.scope {
        agent["scope"] = json!(scope.as_str());
    }
    let facts = host.document(host_runtimes.clone(), docker_facts, agent);

    let mut subjects = Vec::new();
    if let Some(root) = &root {
        if let Some(packages) = host_packages(root, config.mode == Mode::Host) {
            subjects.push((
                json!({"subject_key": "host", "kind": "host"}),
                sbom::document("host", "application", &host.hostname, &packages),
            ));
        }
    }
    if matches!(config.mode, Mode::Host | Mode::Embedded) {
        let root = root
            .as_ref()
            .expect("host and embedded modes read their file system");
        let mut collect = collect.clone();
        if config.mode == Mode::Embedded {
            collect
                .discovery_roots
                .extend(EMBEDDED_ROOTS.iter().map(|r| (*r).to_owned()));
        }
        let collect = &collect;
        let version_of = |name: &str| {
            host_runtimes
                .iter()
                .find(|r| r["name"] == name)
                .and_then(|r| r["version"].as_str())
                .map(str::to_owned)
        };
        let served = fpm::served(root);
        for found in discovery::discover(root, collect) {
            let app = apps::catalog(root, &found.path);
            if app.is_empty() && !found.declared {
                continue;
            }
            let key = format!("path:{}", found.path);
            let mut fields = json!({"subject_key": key, "kind": "path", "path": found.path, "origin": if found.declared { "declared" } else { "discovered" }});
            // The pool its web server passes it to, else the default `php` (or `node`) of the host.
            let served_by = app
                .php
                .then(|| fpm::runtime_for(&found.path, &served, &host_runtimes))
                .flatten();
            let runtime = if app.php {
                version_of("php").map(|v| ("php", v))
            } else if app.node {
                version_of("node").map(|v| ("node", v))
            } else {
                None
            };
            if let Some(runtime) = served_by {
                fields["runtime"] = runtime;
            } else if let Some((name, version)) = runtime {
                fields["runtime"] = json!({"name": name, "version": version});
            }
            if let Some(requires) = app.requires_field() {
                fields["requires"] = requires;
            }
            let name = found
                .path
                .rsplit('/')
                .find(|s| !s.is_empty())
                .unwrap_or("/")
                .to_owned();
            subjects.push((
                fields,
                sbom::document(&key, "application", &name, &app.packages),
            ));
        }
    }

    let mut images = BTreeSet::new();
    if let Some(docker) = &context.docker {
        let collected = containers::collect(
            docker,
            context.scope(config),
            context.project.as_deref(),
            context.own_id.as_deref(),
            cache,
        )?;
        subjects.extend(collected.subjects);
        images = collected.images;
    }
    subjects.sort_by(|a, b| {
        a.0["subject_key"]
            .as_str()
            .cmp(&b.0["subject_key"].as_str())
    });
    Ok(Inventory {
        facts,
        subjects,
        images,
    })
}

/// The image ids in use now (a cheap check between scans, to report an image change at once).
pub fn image_set(context: &Context, config: &Config) -> Option<BTreeSet<String>> {
    let docker = context.docker.as_ref()?;
    let scope = context.scope(config);
    let running = containers::running(docker).ok()?;
    Some(
        running
            .into_iter()
            .filter(|c| {
                containers::in_scope(
                    c,
                    scope,
                    context.project.as_deref(),
                    context.own_id.as_deref(),
                )
            })
            .map(|c| c.image_id)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn reads_the_rpm_database_of_its_own_file_system_without_rpm() {
        let dir = tempfile::tempdir().unwrap();
        let fixtures = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::fs::create_dir_all(dir.path().join("usr/lib/sysimage/rpm")).unwrap();
        std::fs::copy(
            format!("{fixtures}/os-release-sles156"),
            dir.path().join("etc/os-release"),
        )
        .unwrap();
        let mut database = Vec::new();
        flate2::read::GzDecoder::new(
            std::fs::File::open(format!("{fixtures}/rpmdb/sles156-Packages.db.gz")).unwrap(),
        )
        .read_to_end(&mut database)
        .unwrap();
        std::fs::write(
            dir.path().join("usr/lib/sysimage/rpm/Packages.db"),
            database,
        )
        .unwrap();

        let packages = host_packages(&Root(dir.path().to_owned()), false).unwrap();
        assert_eq!(
            packages.len(),
            138,
            "The packages of bci-base:15.6, as an embedded agent sees them."
        );
        assert!(packages.iter().all(|p| p.purl.contains("distro=sles-15.6")));
        assert!(
            host_packages(&Root(dir.path().join("nothing")), false).is_none(),
            "No package database."
        );
    }
}
