//! Package URLs as the console reads them (it percent-decodes every segment and qualifier value).

/// Everything but the unreserved characters is percent-encoded.
pub fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `pkg:<type>/<namespace…>/<name>@<version>?<qualifiers>`; qualifiers sorted by key, empty ones left out.
pub fn build(
    kind: &str,
    namespace: &[&str],
    name: &str,
    version: &str,
    qualifiers: &[(&str, &str)],
) -> String {
    let mut purl = format!("pkg:{kind}/");
    for segment in namespace.iter().filter(|s| !s.is_empty()) {
        purl.push_str(&encode(segment));
        purl.push('/');
    }
    purl.push_str(&encode(name));
    purl.push('@');
    purl.push_str(&encode(version));
    let mut qualifiers: Vec<_> = qualifiers.iter().filter(|(_, v)| !v.is_empty()).collect();
    qualifiers.sort();
    for (i, (key, value)) in qualifiers.iter().enumerate() {
        purl.push(if i == 0 { '?' } else { '&' });
        purl.push_str(key);
        purl.push('=');
        purl.push_str(&encode(value));
    }
    purl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_purls_of_the_profile() {
        assert_eq!(
            build(
                "deb",
                &["debian"],
                "libssl3",
                "3.0.11-1~deb12u2",
                &[
                    ("arch", "amd64"),
                    ("distro", "debian-12"),
                    ("upstream", "openssl")
                ]
            ),
            "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl"
        );
        assert_eq!(
            build("npm", &["@hotwired"], "turbo", "8.0.12", &[]),
            "pkg:npm/%40hotwired/turbo@8.0.12"
        );
        assert_eq!(
            build(
                "rpm",
                &["rocky"],
                "bash",
                "5.1.8-9.el9",
                &[("epoch", ""), ("arch", "x86_64")]
            ),
            "pkg:rpm/rocky/bash@5.1.8-9.el9?arch=x86_64"
        );
        assert_eq!(encode("1:2.3+dfsg"), "1%3A2.3%2Bdfsg");
    }
}
