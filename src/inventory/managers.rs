//! Runtimes installed outside the fixed commands of `runtimes`: by a version manager in a home (nvm, pyenv, rbenv,
//! sdkman, rustup…) or in a system location no package database describes (`/usr/local/go`, `/usr/lib/jvm`,
//! `/usr/local/rustup`). Read **from files only**: these binaries may belong to any user, so the agent never runs
//! them. The version always comes from a file the installation carries (a header, `VERSION`, `release`, a
//! manifest), never from a directory name: without that file, nothing is reported.

use serde_json::{Map, Value, json};

use super::files::{Files, join, text};

/// Homes read from `/etc/passwd` at most.
const MAX_HOMES: usize = 1000;
/// Installations read in one directory at most.
const MAX_INSTALLS: usize = 50;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Node,
    Php,
    Python,
    Go,
    Ruby,
    Java,
    Rust,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Node => "node",
            Kind::Php => "php",
            Kind::Python => "python",
            Kind::Go => "go",
            Kind::Ruby => "ruby",
            Kind::Java => "java",
            Kind::Rust => "rust",
        }
    }

    /// The binary of an installation, reported as its path.
    fn binary(self) -> &'static str {
        match self {
            Kind::Node => "bin/node",
            Kind::Php => "bin/php",
            Kind::Python => "bin/python3",
            Kind::Go => "bin/go",
            Kind::Ruby => "bin/ruby",
            Kind::Java => "bin/java",
            Kind::Rust => "bin/rustc",
        }
    }
}

/// Which names of a directory are installations.
enum Entries {
    Any,
    Named(&'static str),
    Prefix(&'static str),
    Contains(&'static str),
}

impl Entries {
    fn matches(&self, name: &str) -> bool {
        !name.starts_with('.')
            && match self {
                Entries::Any => true,
                Entries::Named(n) => name == *n,
                Entries::Prefix(p) => name.starts_with(p),
                Entries::Contains(c) => name.contains(c),
            }
    }
}

/// Where installations of a runtime live: `dir` relative to every home, or absolute; each matching entry of it,
/// plus `inside`, is one installation.
struct Layout {
    kind: Kind,
    manager: Option<&'static str>,
    dir: &'static str,
    entries: Entries,
    inside: &'static str,
}

const fn at(
    kind: Kind,
    manager: Option<&'static str>,
    dir: &'static str,
    entries: Entries,
    inside: &'static str,
) -> Layout {
    Layout {
        kind,
        manager,
        dir,
        entries,
        inside,
    }
}

const LAYOUTS: [Layout; 38] = [
    at(
        Kind::Node,
        Some("nvm"),
        ".nvm/versions/node",
        Entries::Any,
        "",
    ),
    at(
        Kind::Node,
        Some("fnm"),
        ".local/share/fnm/node-versions",
        Entries::Any,
        "installation",
    ),
    at(
        Kind::Node,
        Some("fnm"),
        ".fnm/node-versions",
        Entries::Any,
        "installation",
    ),
    at(
        Kind::Node,
        Some("volta"),
        ".volta/tools/image/node",
        Entries::Any,
        "",
    ),
    at(
        Kind::Node,
        Some("asdf"),
        ".asdf/installs/nodejs",
        Entries::Any,
        "",
    ),
    at(
        Kind::Node,
        Some("mise"),
        ".local/share/mise/installs/node",
        Entries::Any,
        "",
    ),
    at(
        Kind::Node,
        Some("n"),
        "/usr/local/n/versions/node",
        Entries::Any,
        "",
    ),
    at(
        Kind::Node,
        Some("nvm"),
        "/usr/local/nvm/versions/node",
        Entries::Any,
        "",
    ),
    at(
        Kind::Node,
        Some("nvm"),
        "/opt/nvm/versions/node",
        Entries::Any,
        "",
    ),
    at(
        Kind::Php,
        Some("phpenv"),
        ".phpenv/versions",
        Entries::Any,
        "",
    ),
    at(Kind::Php, Some("phpbrew"), ".phpbrew/php", Entries::Any, ""),
    at(
        Kind::Php,
        Some("asdf"),
        ".asdf/installs/php",
        Entries::Any,
        "",
    ),
    at(
        Kind::Php,
        Some("mise"),
        ".local/share/mise/installs/php",
        Entries::Any,
        "",
    ),
    at(
        Kind::Python,
        Some("pyenv"),
        ".pyenv/versions",
        Entries::Any,
        "",
    ),
    at(
        Kind::Python,
        Some("asdf"),
        ".asdf/installs/python",
        Entries::Any,
        "",
    ),
    at(
        Kind::Python,
        Some("mise"),
        ".local/share/mise/installs/python",
        Entries::Any,
        "",
    ),
    at(
        Kind::Python,
        Some("uv"),
        ".local/share/uv/python",
        Entries::Any,
        "",
    ),
    at(Kind::Go, Some("goenv"), ".goenv/versions", Entries::Any, ""),
    at(Kind::Go, Some("gvm"), ".gvm/gos", Entries::Any, ""),
    at(
        Kind::Go,
        Some("asdf"),
        ".asdf/installs/golang",
        Entries::Any,
        "go",
    ),
    at(
        Kind::Go,
        Some("mise"),
        ".local/share/mise/installs/go",
        Entries::Any,
        "",
    ),
    at(Kind::Go, Some("go-dl"), "sdk", Entries::Prefix("go"), ""),
    at(Kind::Go, None, "/usr/local", Entries::Named("go"), ""),
    at(Kind::Go, None, "/usr/lib", Entries::Prefix("go-"), ""),
    at(
        Kind::Ruby,
        Some("rbenv"),
        ".rbenv/versions",
        Entries::Any,
        "",
    ),
    at(Kind::Ruby, Some("rvm"), ".rvm/rubies", Entries::Any, ""),
    at(
        Kind::Ruby,
        Some("asdf"),
        ".asdf/installs/ruby",
        Entries::Any,
        "",
    ),
    at(
        Kind::Ruby,
        Some("mise"),
        ".local/share/mise/installs/ruby",
        Entries::Any,
        "",
    ),
    at(Kind::Ruby, Some("chruby"), ".rubies", Entries::Any, ""),
    at(Kind::Ruby, Some("chruby"), "/opt/rubies", Entries::Any, ""),
    at(
        Kind::Java,
        Some("sdkman"),
        ".sdkman/candidates/java",
        Entries::Any,
        "",
    ),
    at(
        Kind::Java,
        Some("asdf"),
        ".asdf/installs/java",
        Entries::Any,
        "",
    ),
    at(
        Kind::Java,
        Some("mise"),
        ".local/share/mise/installs/java",
        Entries::Any,
        "",
    ),
    at(Kind::Java, None, "/usr/lib/jvm", Entries::Any, ""),
    at(Kind::Java, None, "/opt/java", Entries::Named("openjdk"), ""),
    at(Kind::Java, None, "/opt", Entries::Contains("jdk"), ""),
    at(
        Kind::Rust,
        Some("rustup"),
        ".rustup/toolchains",
        Entries::Any,
        "",
    ),
    at(
        Kind::Rust,
        None,
        "/usr/local/rustup/toolchains",
        Entries::Any,
        "",
    ),
];

/// The homes of `/etc/passwd`, without duplicates, `/` nor `/nonexistent`.
pub fn homes(files: &dyn Files) -> Vec<String> {
    let mut homes: Vec<String> = text(files, "/etc/passwd")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split(':').nth(5))
        .map(|home| home.trim_end_matches('/').to_owned())
        .filter(|home| home.starts_with('/') && home != "/nonexistent")
        .collect();
    homes.sort();
    homes.dedup();
    homes.truncate(MAX_HOMES);
    homes
}

/// The value of a C `#define` (`#define PHP_VERSION "8.1.34"` → `8.1.34`).
fn define(header: &str, name: &str) -> Option<String> {
    header.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next() == Some("#define") && words.next() == Some(name))
            .then(|| words.next())
            .flatten()
            .map(|v| v.trim_matches('"').to_owned())
    })
}

/// A `KEY="value"` line of a JDK's `release` file.
fn release_value(release: &str, key: &str) -> Option<String> {
    release.lines().find_map(|line| {
        line.strip_prefix(key)?
            .strip_prefix('=')
            .map(|v| v.trim().trim_matches('"').to_owned())
    })
}

/// A `CONFIG["KEY"] = "value"` line of Ruby's `rbconfig.rb`.
fn ruby_config(rbconfig: &str, key: &str) -> Option<String> {
    let prefix = format!("CONFIG[\"{key}\"] = \"");
    rbconfig.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&prefix)?
            .strip_suffix('"')
            .map(str::to_owned)
    })
}

/// The first line of Go's `VERSION` (`go1.22.12`) → `1.22.12`.
fn go_version(version: &str) -> Option<String> {
    version
        .lines()
        .next()?
        .trim()
        .strip_prefix("go")
        .map(str::to_owned)
}

/// `[pkg.rustc] version = "1.100.0 (0ef1bc386 2026-11-09)"` of a rustup channel manifest → `1.100.0`.
fn rust_version(manifest: &str) -> Option<String> {
    let mut lines = manifest.lines().skip_while(|l| l.trim() != "[pkg.rustc]");
    lines.next()?;
    lines
        .take_while(|l| !l.trim_start().starts_with('['))
        .find_map(|l| l.trim().strip_prefix("version = \""))?
        .split([' ', '"'])
        .next()
        .map(str::to_owned)
}

fn is_version(version: &str) -> bool {
    version.starts_with(|c: char| c.is_ascii_digit()) && version.contains('.')
}

/// The first file found among the entries of `dir` that `pick` keeps, at `entry/file` (bounded).
fn first_under(
    files: &dyn Files,
    dir: &str,
    pick: impl Fn(&str) -> bool,
    file: &str,
) -> Option<String> {
    files
        .list(dir)
        .iter()
        .filter(|n| pick(n))
        .take(MAX_INSTALLS)
        .find_map(|n| text(files, &join(&join(dir, n), file)))
}

/// What an installation says of itself: its version, and for a JDK its implementor and build type.
fn read(files: &dyn Files, kind: Kind, install: &str) -> Option<Map<String, Value>> {
    let file = |path: &str| text(files, &join(install, path));
    let mut fields = Map::new();
    let version = match kind {
        Kind::Node => {
            let header = file("include/node/node_version.h")?;
            let part = |name| define(&header, name);
            format!(
                "{}.{}.{}",
                part("NODE_MAJOR_VERSION")?,
                part("NODE_MINOR_VERSION")?,
                part("NODE_PATCH_VERSION")?
            )
        }
        Kind::Php => define(&file("include/php/main/php_version.h")?, "PHP_VERSION")?,
        Kind::Python => define(
            &first_under(
                files,
                &join(install, "include"),
                |n| n.starts_with("python3"),
                "patchlevel.h",
            )?,
            "PY_VERSION",
        )?,
        Kind::Go => go_version(&file("VERSION")?)?,
        Kind::Ruby => {
            let lib = join(install, "lib/ruby");
            let rbconfig = files
                .list(&lib)
                .iter()
                .filter(|n| n.starts_with(|c: char| c.is_ascii_digit()))
                .take(MAX_INSTALLS)
                .find_map(|n| {
                    first_under(
                        files,
                        &join(&lib, n),
                        |a| a.contains("-linux"),
                        "rbconfig.rb",
                    )
                })?;
            let part = |key| ruby_config(&rbconfig, key);
            format!("{}.{}.{}", part("MAJOR")?, part("MINOR")?, part("TEENY")?)
        }
        Kind::Java => {
            let release = file("release")?;
            for (key, field) in [("IMPLEMENTOR", "implementor"), ("BUILD_TYPE", "build_type")] {
                if let Some(value) = release_value(&release, key).filter(|v| !v.is_empty()) {
                    fields.insert(field.into(), json!(value));
                }
            }
            release_value(&release, "JAVA_VERSION")?
        }
        Kind::Rust => rust_version(&file("lib/rustlib/multirust-channel-manifest.toml")?)?,
    };
    is_version(&version).then(|| {
        fields.insert("version".into(), json!(version));
        fields
    })
}

/// The installations of one directory, the same one reached twice (a `current` or `/etc/alternatives` link) kept once.
fn scan(files: &dyn Files, layout: &Layout, dir: &str) -> Vec<Value> {
    let mut seen: Vec<Map<String, Value>> = Vec::new();
    let mut found = Vec::new();
    for entry in files
        .list(dir)
        .into_iter()
        .filter(|n| layout.entries.matches(n))
        .take(MAX_INSTALLS)
    {
        let mut install = join(dir, &entry);
        if !layout.inside.is_empty() {
            install = join(&install, layout.inside);
        }
        let Some(mut runtime) = read(files, layout.kind, &install) else {
            continue;
        };
        runtime.insert("name".into(), json!(layout.kind.name()));
        if let Some(manager) = layout.manager {
            runtime.insert("manager".into(), json!(manager));
        }
        if seen.contains(&runtime) {
            continue;
        }
        seen.push(runtime.clone());
        runtime.insert("path".into(), json!(join(&install, layout.kind.binary())));
        found.push(Value::Object(runtime));
    }
    found
}

/// Every installation of the layouts, under the homes of `/etc/passwd` and in the system locations.
pub fn collect(files: &dyn Files) -> Vec<Value> {
    let homes = homes(files);
    let mut runtimes = Vec::new();
    for layout in &LAYOUTS {
        if layout.dir.starts_with('/') {
            runtimes.extend(scan(files, layout, layout.dir));
        } else {
            for home in &homes {
                runtimes.extend(scan(files, layout, &join(home, layout.dir)));
            }
        }
    }
    super::runtimes::sort(&mut runtimes);
    runtimes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::files::{Memory, Root};
    use std::io::Read;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/runtimes/{name}")).unwrap()
    }

    fn rust_manifest() -> Vec<u8> {
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(&fixture("multirust-channel-manifest.toml.gz")[..])
            .read_to_end(&mut bytes)
            .unwrap();
        bytes
    }

    fn passwd(homes: &[&str]) -> Vec<u8> {
        homes
            .iter()
            .enumerate()
            .map(|(i, h)| format!("u{i}:x:{}:{}::{h}:/bin/sh\n", 1000 + i, 1000 + i))
            .collect::<String>()
            .into_bytes()
    }

    fn memory(entries: &[(&str, Vec<u8>)]) -> Memory {
        Memory(
            entries
                .iter()
                .map(|(p, b)| ((*p).to_owned(), b.clone()))
                .collect(),
        )
    }

    #[test]
    fn reads_the_version_files_of_real_installations() {
        let files = memory(&[
            ("/n/include/node/node_version.h", fixture("node_version.h")),
            (
                "/p/include/php/main/php_version.h",
                fixture("php_version.h"),
            ),
            (
                "/y/include/python3.12/patchlevel.h",
                fixture("patchlevel.h"),
            ),
            ("/g/VERSION", fixture("go-VERSION")),
            (
                "/r/lib/ruby/3.3.0/aarch64-linux/rbconfig.rb",
                fixture("rbconfig.rb"),
            ),
            ("/j/release", fixture("release-temurin21")),
            ("/j8/release", fixture("release-temurin8")),
            ("/c/release", fixture("release-corretto17")),
            ("/z/release", fixture("release-zulu17")),
            ("/d/release", fixture("release-debian-openjdk17")),
            (
                "/t/lib/rustlib/multirust-channel-manifest.toml",
                rust_manifest(),
            ),
        ]);
        let version = |kind, install| read(&files, kind, install).map(Value::Object);

        assert_eq!(
            version(Kind::Node, "/n"),
            Some(json!({"version": "22.23.5"}))
        );
        assert_eq!(version(Kind::Php, "/p"), Some(json!({"version": "8.1.34"})));
        assert_eq!(
            version(Kind::Python, "/y"),
            Some(json!({"version": "3.12.16"}))
        );
        assert_eq!(version(Kind::Go, "/g"), Some(json!({"version": "1.22.12"})));
        assert_eq!(
            version(Kind::Ruby, "/r"),
            Some(json!({"version": "3.3.14"}))
        );
        assert_eq!(
            version(Kind::Java, "/j"),
            Some(json!({"version": "21.0.13", "implementor": "Eclipse Adoptium"}))
        );
        assert_eq!(
            version(Kind::Java, "/j8"),
            Some(json!({"version": "1.8.0_512", "implementor": "Eclipse Adoptium"})),
            "Read as written: the console reads Java 8's numbering."
        );
        assert_eq!(
            version(Kind::Java, "/c"),
            Some(json!({"version": "17.0.21.1", "implementor": "Amazon.com Inc."}))
        );
        assert_eq!(
            version(Kind::Java, "/z"),
            Some(json!({"version": "17.0.21.1", "implementor": "Azul Systems, Inc."}))
        );
        assert_eq!(
            version(Kind::Java, "/d"),
            Some(json!({"version": "17.0.21.1", "implementor": "Debian"}))
        );
        assert_eq!(
            version(Kind::Rust, "/t"),
            Some(json!({"version": "1.100.0"}))
        );
    }

    #[test]
    fn reports_nothing_without_a_readable_version_file() {
        let files = memory(&[
            ("/n/bin/node", b"\x7fELF".to_vec()),
            ("/g/VERSION", b"devel go1.23-abcdef\n".to_vec()),
            ("/j/release", b"IMPLEMENTOR=\"Eclipse Adoptium\"\n".to_vec()),
            (
                "/p/include/php/main/php_version.h",
                b"#define PHP_VERSION \"\"\n".to_vec(),
            ),
        ]);

        for (kind, install) in [
            (Kind::Node, "/n"),
            (Kind::Go, "/g"),
            (Kind::Java, "/j"),
            (Kind::Php, "/p"),
            (Kind::Ruby, "/missing"),
            (Kind::Python, "/missing"),
            (Kind::Rust, "/missing"),
        ] {
            assert_eq!(read(&files, kind, install), None, "{kind:?} at {install}");
        }
    }

    #[test]
    fn reads_the_homes_of_passwd() {
        let files = memory(&[("/etc/passwd", fixture("passwd-ubuntu2404"))]);
        let homes = homes(&files);

        assert!(homes.contains(&"/root".to_owned()));
        assert!(homes.contains(&"/var/www".to_owned()), "www-data's home.");
        assert!(!homes.contains(&"/nonexistent".to_owned()));
        assert!(!homes.iter().any(String::is_empty), "`/` is no home.");
        let mut sorted = homes.clone();
        sorted.dedup();
        assert_eq!(
            homes, sorted,
            "Sorted, each once (`/usr/sbin` is several users' home)."
        );

        let files = memory(&[(
            "/etc/passwd",
            passwd(&["relative", "/home/a/", "/home/a", ""]),
        )]);
        assert_eq!(super::homes(&files), vec!["/home/a"]);
    }

    #[test]
    fn finds_the_installations_of_every_manager() {
        let node = fixture("node_version.h");
        let files = memory(&[
            ("/etc/passwd", passwd(&["/root", "/home/dev", "/var/www"])),
            (
                "/root/.nvm/versions/node/v22.23.5/include/node/node_version.h",
                node.clone(),
            ),
            (
                "/home/dev/.local/share/fnm/node-versions/v22.23.5/installation/include/node/node_version.h",
                node.clone(),
            ),
            (
                "/usr/local/n/versions/node/22.23.5/include/node/node_version.h",
                node.clone(),
            ),
            (
                "/var/www/.phpenv/versions/8.1.34/include/php/main/php_version.h",
                fixture("php_version.h"),
            ),
            (
                "/home/dev/.local/share/uv/python/cpython-3.12.16-linux-aarch64-gnu/include/python3.12/patchlevel.h",
                fixture("patchlevel.h"),
            ),
            (
                "/home/dev/.asdf/installs/golang/1.22.12/go/VERSION",
                fixture("go-VERSION"),
            ),
            ("/home/dev/sdk/go1.22.12/VERSION", fixture("go-VERSION")),
            ("/home/dev/sdk/gotools/VERSION", b"not go\n".to_vec()),
            ("/usr/local/go/VERSION", fixture("go-VERSION")),
            (
                "/home/dev/.rbenv/versions/3.3.14/lib/ruby/3.3.0/aarch64-linux/rbconfig.rb",
                fixture("rbconfig.rb"),
            ),
            (
                "/home/dev/.sdkman/candidates/java/21.0.13-tem/release",
                fixture("release-temurin21"),
            ),
            (
                "/home/dev/.sdkman/candidates/java/current/release",
                fixture("release-temurin21"),
            ),
            (
                "/usr/lib/jvm/java-1.17.0-openjdk-arm64/release",
                fixture("release-debian-openjdk17"),
            ),
            (
                "/usr/lib/jvm/java-17-openjdk-arm64/release",
                fixture("release-debian-openjdk17"),
            ),
            (
                "/usr/lib/jvm/.java-1.17.0-openjdk-arm64.jinfo",
                b"name=java".to_vec(),
            ),
            (
                "/home/dev/.rustup/toolchains/stable-aarch64-unknown-linux-gnu/lib/rustlib/multirust-channel-manifest.toml",
                rust_manifest(),
            ),
        ]);

        let found: Vec<(String, String, String, String)> = collect(&files)
            .iter()
            .map(|r| {
                let field = |k: &str| r[k].as_str().unwrap_or("").to_owned();
                (
                    field("name"),
                    field("version"),
                    field("manager"),
                    field("path"),
                )
            })
            .collect();
        let row = |n: &str, v: &str, m: &str, p: &str| (n.into(), v.into(), m.into(), p.into());

        assert_eq!(
            found,
            vec![
                row(
                    "go",
                    "1.22.12",
                    "asdf",
                    "/home/dev/.asdf/installs/golang/1.22.12/go/bin/go"
                ),
                row("go", "1.22.12", "go-dl", "/home/dev/sdk/go1.22.12/bin/go"),
                row("go", "1.22.12", "", "/usr/local/go/bin/go"),
                row(
                    "java",
                    "21.0.13",
                    "sdkman",
                    "/home/dev/.sdkman/candidates/java/21.0.13-tem/bin/java"
                ),
                row(
                    "java",
                    "17.0.21.1",
                    "",
                    "/usr/lib/jvm/java-1.17.0-openjdk-arm64/bin/java"
                ),
                row(
                    "node",
                    "22.23.5",
                    "fnm",
                    "/home/dev/.local/share/fnm/node-versions/v22.23.5/installation/bin/node"
                ),
                row(
                    "node",
                    "22.23.5",
                    "nvm",
                    "/root/.nvm/versions/node/v22.23.5/bin/node"
                ),
                row(
                    "node",
                    "22.23.5",
                    "n",
                    "/usr/local/n/versions/node/22.23.5/bin/node"
                ),
                row(
                    "php",
                    "8.1.34",
                    "phpenv",
                    "/var/www/.phpenv/versions/8.1.34/bin/php"
                ),
                row(
                    "python",
                    "3.12.16",
                    "uv",
                    "/home/dev/.local/share/uv/python/cpython-3.12.16-linux-aarch64-gnu/bin/python3"
                ),
                row(
                    "ruby",
                    "3.3.14",
                    "rbenv",
                    "/home/dev/.rbenv/versions/3.3.14/bin/ruby"
                ),
                row(
                    "rust",
                    "1.100.0",
                    "rustup",
                    "/home/dev/.rustup/toolchains/stable-aarch64-unknown-linux-gnu/bin/rustc"
                ),
            ],
            "Sorted by name then path; a link to an installation already found (`current`, an alternative) kept once."
        );
        assert_eq!(
            collect(&files)
                .iter()
                .find(|r| r["name"] == "java" && r["manager"].is_null())
                .unwrap()["implementor"],
            "Debian"
        );
    }

    #[test]
    fn reads_a_bounded_number_of_installations() {
        let node = fixture("node_version.h");
        let mut entries: Vec<(String, Vec<u8>)> = (0..MAX_INSTALLS + 10)
            .map(|i| {
                (
                    format!("/home/dev/.nvm/versions/node/v{i:03}/include/node/node_version.h"),
                    node.clone(),
                )
            })
            .collect();
        entries.push(("/etc/passwd".into(), passwd(&["/home/dev"])));
        let files = Memory(entries.into_iter().collect());

        assert_eq!(
            scan(&files, &LAYOUTS[0], "/home/dev/.nvm/versions/node").len(),
            1,
            "The same version everywhere: kept once."
        );
        let read = std::cell::Cell::new(0);
        struct Counting<'a>(&'a Memory, &'a std::cell::Cell<usize>);
        impl Files for Counting<'_> {
            fn read(&self, path: &str) -> Option<Vec<u8>> {
                self.1.set(self.1.get() + 1);
                self.0.read(path)
            }
            fn list(&self, dir: &str) -> Vec<String> {
                self.0.list(dir)
            }
        }
        scan(
            &Counting(&files, &read),
            &LAYOUTS[0],
            "/home/dev/.nvm/versions/node",
        );
        assert_eq!(read.get(), MAX_INSTALLS);

        let many: Vec<String> = (0..MAX_HOMES + 5)
            .map(|i| format!("/home/u{i:04}"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let files = memory(&[("/etc/passwd", passwd(&many))]);
        assert_eq!(homes(&files).len(), MAX_HOMES);
    }

    #[test]
    fn never_follows_a_link_out_of_the_root() {
        let outside = tempfile::tempdir().unwrap();
        let nvm = outside.path().join("versions/node/v22.23.5/include/node");
        std::fs::create_dir_all(&nvm).unwrap();
        std::fs::write(nvm.join("node_version.h"), fixture("node_version.h")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = Root(dir.path().to_path_buf());
        std::fs::create_dir_all(root.0.join("etc")).unwrap();
        std::fs::create_dir_all(root.0.join("home/dev")).unwrap();
        std::fs::write(root.0.join("etc/passwd"), passwd(&["/home/dev"])).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.0.join("home/dev/.nvm")).unwrap();

        assert_eq!(collect(&root), Vec::<Value>::new());
    }
}
