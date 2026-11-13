//! Runtimes of a host, from a **fixed list of commands** (cadrage §6): never a shell, never an argument from the
//! network, a timeout on each.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const TIMEOUT: Duration = Duration::from_secs(10);
const DIRS: [&str; 6] = [
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/local/sbin",
    "/usr/sbin",
    "/sbin",
];

/// Runs a fixed program with fixed arguments; its standard output, none on failure or timeout.
pub fn run(program: &Path, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LANG", "C")
        .env("COMPOSER_ALLOW_SUPERUSER", "1")
        .env("HOME", "/nonexistent")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                child
                    .stdout
                    .take()?
                    .take(1024 * 1024)
                    .read_to_string(&mut out)
                    .ok()?;
                return status.success().then_some(out);
            }
            Ok(None) if started.elapsed() < TIMEOUT => {
                std::thread::sleep(Duration::from_millis(50))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn find(name: &str) -> Option<PathBuf> {
    DIRS.iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

/// The binaries of a directory whose name matches (`php8.2`, `php-fpm8.3`…).
fn matching(dir: &str, prefix: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                n.strip_prefix(prefix).is_some_and(|rest| {
                    rest.is_empty() || rest.chars().all(|c| c.is_ascii_digit() || c == '.')
                })
            })
        })
        .collect();
    found.sort();
    found
}

/// `PHP 8.2.26 (cli) …` → `8.2.26`; `v20.18.1` → `20.18.1`; `Composer version 2.8.4 …` → `2.8.4`.
pub fn version_of(output: &str) -> Option<String> {
    let line = output.lines().find(|l| !l.trim().is_empty())?;
    line.split_whitespace()
        .map(|w| w.trim_start_matches('v'))
        .find(|w| w.starts_with(|c: char| c.is_ascii_digit()) && w.contains('.'))
        .map(|w| w.trim_end_matches(',').to_owned())
}

pub fn php_extensions(output: &str) -> Vec<String> {
    let mut extensions: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('['))
        .map(str::to_lowercase)
        .collect();
    extensions.sort();
    extensions.dedup();
    extensions
}

/// The runtimes of the host this agent runs on (host mode), sorted by name then path.
pub fn collect() -> Vec<Value> {
    let mut runtimes = Vec::new();
    let mut php_paths: Vec<PathBuf> = find("php").into_iter().collect();
    php_paths.extend(matching("/usr/bin", "php"));
    php_paths.sort();
    php_paths.dedup();
    for path in php_paths {
        if let Some(version) = run(&path, &["-v"]).as_deref().and_then(version_of) {
            let extensions = run(&path, &["-m"])
                .map(|o| php_extensions(&o))
                .unwrap_or_default();
            runtimes.push(json!({"name": "php", "version": version, "path": path.to_string_lossy(), "extensions": extensions}));
        }
    }
    let mut fpm: Vec<PathBuf> = matching("/usr/sbin", "php-fpm");
    fpm.extend(matching("/usr/local/sbin", "php-fpm"));
    for path in fpm {
        if let Some(version) = run(&path, &["-v"]).as_deref().and_then(version_of) {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let mut runtime =
                json!({"name": "php-fpm", "version": version, "path": path.to_string_lossy()});
            if let Some(branch) = name.strip_prefix("php-fpm").filter(|b| !b.is_empty()) {
                runtime["service"] = json!(format!("php{branch}-fpm"));
            }
            runtimes.push(runtime);
        }
    }
    for (name, args) in [
        (
            "composer",
            &["--version", "--no-plugins", "--no-interaction"][..],
        ),
        ("node", &["-v"][..]),
        ("npm", &["-v"][..]),
        ("yarn", &["-v"][..]),
        ("pnpm", &["-v"][..]),
    ] {
        if let Some(path) = find(name) {
            if let Some(version) = run(&path, args).as_deref().and_then(version_of) {
                runtimes.push(
                    json!({"name": name, "version": version, "path": path.to_string_lossy()}),
                );
            }
        }
    }
    runtimes.sort_by(|a, b| {
        (a["name"].as_str(), a["path"].as_str()).cmp(&(b["name"].as_str(), b["path"].as_str()))
    });
    runtimes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_versions_the_commands_print() {
        assert_eq!(
            version_of("PHP 8.2.26 (cli) (built: Nov 21 2024 10:00:00) (NTS)\nCopyright"),
            Some("8.2.26".into())
        );
        assert_eq!(version_of("v20.18.1\n"), Some("20.18.1".into()));
        assert_eq!(
            version_of("Composer version 2.8.4 2024-12-11 11:57:47\n"),
            Some("2.8.4".into())
        );
        assert_eq!(version_of("10.9.2"), Some("10.9.2".into()));
        assert_eq!(version_of("nothing here"), None);
        assert_eq!(
            php_extensions("[PHP Modules]\nCore\nctype\n\n[Zend Modules]\nZend OPcache\nctype\n"),
            vec!["core", "ctype", "zend opcache"]
        );
    }

    #[test]
    fn runs_a_fixed_command_with_a_timeout() {
        assert_eq!(
            run(Path::new("/bin/echo"), &["v1.2.3"])
                .as_deref()
                .and_then(version_of),
            Some("1.2.3".into())
        );
        assert_eq!(run(Path::new("/nonexistent/binary"), &[]), None);
        assert_eq!(run(Path::new("/bin/false"), &[]), None);
    }
}
