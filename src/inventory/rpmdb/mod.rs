//! RPM databases read without `rpm` (an image has no command to run, and the agent runs none in it): SQLite
//! (`rpmdb.sqlite`, RHEL 9, Fedora 33+, Amazon Linux 2023) and Berkeley DB hash (`Packages`, RHEL 7 and 8, CentOS),
//! in pure Rust, read only, bounded. Each package header gives the same fields as the fixed `rpm -qa` command, so the
//! same cataloger reads both (`os::rpm`).

pub mod bdb;
pub mod header;
pub mod sqlite;

/// The headers of a database, by its format: SQLite (its magic), else Berkeley DB.
pub fn headers(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    if bytes.starts_with(sqlite::MAGIC) {
        sqlite::blobs(bytes, "Packages", "blob")
    } else {
        bdb::values(bytes)
    }
}

/// The packages of a database, as the lines of `rpm -qa --qf RPM_QUERY_FORMAT`.
pub fn query_lines(bytes: &[u8]) -> Option<String> {
    let mut lines: Vec<String> = headers(bytes)?
        .iter()
        .filter_map(|blob| header::Header::parse(blob))
        .map(|h| h.query_line())
        .collect();
    lines.sort();
    Some(lines.join(""))
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    fn fixture(name: &str) -> Vec<u8> {
        let file = std::fs::File::open(format!(
            "{}/tests/fixtures/rpmdb/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(file)
            .read_to_end(&mut bytes)
            .unwrap();
        bytes
    }

    fn expected(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/rpmdb/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn reads_an_sqlite_database_like_rpm_does() {
        assert_eq!(
            super::query_lines(&fixture("rocky9-rpmdb.sqlite.gz")).unwrap(),
            expected("rocky9-rpm-qa.txt"),
            "The 118 packages of rockylinux:9-minimal, as `rpm -qa` lists them."
        );
    }

    #[test]
    fn reads_a_berkeley_db_database_like_rpm_does() {
        assert_eq!(
            super::query_lines(&fixture("rocky8-Packages.gz")).unwrap(),
            expected("rocky8-rpm-qa.txt"),
            "The 95 packages of rockylinux:8-minimal, as `rpm -qa` lists them."
        );
    }

    #[test]
    fn refuses_what_is_not_a_database() {
        assert_eq!(super::query_lines(b""), None);
        assert_eq!(super::query_lines(&[0u8; 100]), None);
        assert_eq!(super::query_lines(b"SQLite format 3\0"), None);
        let mut truncated = fixture("rocky9-rpmdb.sqlite.gz");
        truncated.truncate(8192);
        assert!(super::query_lines(&truncated).is_none_or(|l| l.lines().count() < 118));
        let mut truncated = fixture("rocky8-Packages.gz");
        truncated.truncate(8192);
        assert!(super::query_lines(&truncated).is_none_or(|l| l.lines().count() < 95));
    }
}
