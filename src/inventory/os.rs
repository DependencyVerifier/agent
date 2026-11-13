//! OS packages: dpkg (`/var/lib/dpkg/status` and distroless `status.d/`), apk (`/lib/apk/db/installed`), rpm (the
//! fixed command `rpm -qa --qf …`). Each carries `distro` and, when its source package differs, `upstream` (§8.5).

use super::Package;
use super::osrelease::OsRelease;
use super::purl;

fn deb_arch(arch: &str) -> &str {
    arch
}

/// dpkg status paragraphs: installed packages only.
pub fn dpkg(text: &str, os: &OsRelease, source: &str) -> Vec<Package> {
    let distro = os.distro().unwrap_or_default();
    let namespace = if os.id.is_empty() {
        "debian"
    } else {
        os.id.as_str()
    };
    let mut packages = Vec::new();
    for paragraph in text.split("\n\n") {
        let mut fields = std::collections::BTreeMap::new();
        let mut last: Option<&str> = None;
        for line in paragraph.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                continue; // continuation of a multi-line field (Description, Conffiles)
            }
            if let Some((key, value)) = line.split_once(':') {
                fields.insert(key, value.trim());
                last = Some(key);
            }
        }
        let _ = last;
        let (Some(name), Some(version)) = (fields.get("Package"), fields.get("Version")) else {
            continue;
        };
        if let Some(status) = fields.get("Status") {
            if !status.ends_with(" installed") {
                continue;
            }
        }
        let arch = fields.get("Architecture").copied().unwrap_or("");
        let upstream = fields.get("Source").map(|source| {
            // `openssl` or `openssl (3.0.11-1)`.
            match source.split_once(' ') {
                Some((src, rest)) => {
                    let src_version = rest.trim().trim_start_matches('(').trim_end_matches(')');
                    if src_version == *version {
                        src.to_owned()
                    } else {
                        format!("{src}@{src_version}")
                    }
                }
                None => source.to_string(),
            }
        });
        let upstream = upstream.filter(|u| u.split('@').next() != Some(name));
        let purl = purl::build(
            "deb",
            &[namespace],
            name,
            version,
            &[
                ("arch", deb_arch(arch)),
                ("distro", &distro),
                ("upstream", upstream.as_deref().unwrap_or("")),
            ],
        );
        packages.push(Package {
            purl,
            name: name.to_string(),
            version: version.to_string(),
            manager: "dpkg",
            source: source.into(),
            direct: true,
        });
    }
    packages
}

/// apk installed database: `P:` name, `V:` version, `A:` arch, `o:` origin (source package).
pub fn apk(text: &str, os: &OsRelease, source: &str) -> Vec<Package> {
    let distro = os.distro().unwrap_or_default();
    let mut packages = Vec::new();
    for record in text.split("\n\n") {
        let field = |prefix: &str| {
            record
                .lines()
                .find_map(|l| l.strip_prefix(prefix))
                .unwrap_or("")
        };
        let (name, version) = (field("P:"), field("V:"));
        if name.is_empty() || version.is_empty() {
            continue;
        }
        let origin = field("o:");
        let upstream = if origin.is_empty() || origin == name {
            ""
        } else {
            origin
        };
        let purl = purl::build(
            "apk",
            &["alpine"],
            name,
            version,
            &[
                ("arch", field("A:")),
                ("distro", &distro),
                ("upstream", upstream),
            ],
        );
        packages.push(Package {
            purl,
            name: name.into(),
            version: version.into(),
            manager: "apk",
            source: source.into(),
            direct: true,
        });
    }
    packages
}

/// The query format of the fixed `rpm -qa` command.
pub const RPM_QUERY_FORMAT: &str =
    "%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n";

/// Lines of `rpm -qa --qf RPM_QUERY_FORMAT`.
pub fn rpm(text: &str, os: &OsRelease) -> Vec<Package> {
    let distro = os.distro().unwrap_or_default();
    let channel = os.channel.as_deref().unwrap_or("");
    let namespace = if os.id.is_empty() {
        "redhat"
    } else {
        os.id.as_str()
    };
    let mut packages = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let [name, epoch, version, release, arch, source_rpm] = fields[..] else {
            continue;
        };
        if name == "gpg-pubkey" || name.is_empty() {
            continue;
        }
        let epoch = if epoch == "(none)" { "" } else { epoch };
        let arch = if arch == "(none)" { "" } else { arch };
        // `openssl-3.0.7-25.el9_3.src.rpm` → `openssl`.
        let source_name = source_rpm
            .strip_suffix(".src.rpm")
            .and_then(|s| s.rsplitn(3, '-').nth(2))
            .unwrap_or("");
        let upstream = if source_name.is_empty() || source_name == name {
            ""
        } else {
            source_name
        };
        let full = format!("{version}-{release}");
        let purl = purl::build(
            "rpm",
            &[namespace],
            name,
            &full,
            &[
                ("arch", arch),
                ("channel", channel),
                ("distro", &distro),
                ("epoch", epoch),
                ("upstream", upstream),
            ],
        );
        packages.push(Package {
            purl,
            name: name.into(),
            version: full,
            manager: "rpm",
            source: "rpmdb".into(),
            direct: true,
        });
    }
    packages
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::osrelease;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn reads_a_real_dpkg_status() {
        let os = osrelease::parse(&fixture("os-release-debian12"));
        let packages = dpkg(
            &fixture("dpkg-status-debian12"),
            &os,
            "/var/lib/dpkg/status",
        );
        assert_eq!(packages.len(), 88);
        let bash = packages.iter().find(|p| p.name == "bash").unwrap();
        assert!(
            bash.purl.starts_with("pkg:deb/debian/bash@5.2.15-2"),
            "{}",
            bash.purl
        );
        assert!(bash.purl.contains("distro=debian-12"));
        let libc = packages.iter().find(|p| p.name == "libc6").unwrap();
        assert!(libc.purl.contains("upstream=glibc"), "{}", libc.purl);
        let mount = packages.iter().find(|p| p.name == "mount").unwrap();
        assert!(mount.purl.contains("upstream=util-linux"), "{}", mount.purl);
        assert!(
            packages
                .iter()
                .all(|p| p.manager == "dpkg" && p.purl.contains("arch="))
        );
        assert!(packages.iter().all(|p| !p.purl.contains("upstream=bash&")
            && !p.purl.ends_with(&format!("upstream={}", p.name))));
    }

    #[test]
    fn skips_the_packages_not_installed() {
        let os = osrelease::parse("ID=debian\nVERSION_ID=12");
        let text = "Package: gone\nStatus: deinstall ok config-files\nVersion: 1\n\nPackage: kept\nStatus: install ok installed\nVersion: 2:1.0+dfsg-1\nArchitecture: all\nSource: kept-src (1.0+dfsg-0)\n";
        let packages = dpkg(text, &os, "s");
        assert_eq!(packages.len(), 1);
        assert_eq!(
            packages[0].purl,
            "pkg:deb/debian/kept@2%3A1.0%2Bdfsg-1?arch=all&distro=debian-12&upstream=kept-src%401.0%2Bdfsg-0"
        );
    }

    #[test]
    fn reads_a_real_apk_database() {
        let os = osrelease::parse(&fixture("os-release-alpine320"));
        let packages = apk(
            &fixture("apk-installed-alpine320"),
            &os,
            "/lib/apk/db/installed",
        );
        assert!(packages.len() > 10);
        let ssl = packages.iter().find(|p| p.name == "libssl3").unwrap();
        assert!(ssl.purl.starts_with("pkg:apk/alpine/libssl3@"));
        assert!(
            ssl.purl.contains("distro=alpine-3.20") && ssl.purl.contains("upstream=openssl"),
            "{}",
            ssl.purl
        );
        let busybox = packages.iter().find(|p| p.name == "busybox").unwrap();
        assert!(!busybox.purl.contains("upstream="));
    }

    #[test]
    fn reads_a_real_rpm_query() {
        let os = osrelease::parse(&fixture("os-release-rocky9"));
        let packages = rpm(&fixture("rpm-qa-rocky9"), &os);
        assert_eq!(packages.len(), 118);
        let libgcc = packages.iter().find(|p| p.name == "libgcc").unwrap();
        assert_eq!(
            libgcc.purl,
            "pkg:rpm/rocky/libgcc@11.4.1-2.1.el9?arch=x86_64&distro=rocky-9&upstream=gcc"
        );
        assert!(packages.iter().all(|p| p.purl.contains("distro=rocky-9")));
    }

    #[test]
    fn marks_the_channel_of_a_subscribed_rhel() {
        let line = "openssl\t1\t3.0.7\t27.el9_4\tx86_64\topenssl-3.0.7-27.el9_4.src.rpm\n";
        let mut os = osrelease::parse(&fixture("os-release-ubi9"));
        assert_eq!(
            rpm(line, &os)[0].purl,
            "pkg:rpm/rhel/openssl@3.0.7-27.el9_4?arch=x86_64&distro=rhel-9.9&epoch=1"
        );
        os.channel = Some("eus".into());
        os.releasever = Some("9.4".into());
        assert_eq!(
            rpm(line, &os)[0].purl,
            "pkg:rpm/rhel/openssl@3.0.7-27.el9_4?arch=x86_64&channel=eus&distro=rhel-9.4&epoch=1"
        );
    }

    #[test]
    fn reads_a_real_suse_rpm_query() {
        let os = osrelease::parse(&fixture("os-release-sles156"));
        let packages = rpm(&fixture("rpmdb/sles156-rpm-qa.txt"), &os);
        assert_eq!(packages.len(), 138, "Without the 6 gpg-pubkey.");
        let libssl = packages.iter().find(|p| p.name == "libopenssl3").unwrap();
        assert!(
            libssl.purl.starts_with("pkg:rpm/sles/libopenssl3@")
                && libssl.purl.contains("distro=sles-15.6&upstream=openssl-3"),
            "{}",
            libssl.purl
        );
    }
}
