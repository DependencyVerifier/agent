//! An RPM header as the database stores it: `il` and `dl` (big endian), `il` index entries of 16 bytes (tag, type,
//! offset, count), then `dl` bytes of data. Only the tags of `rpm -qa --qf RPM_QUERY_FORMAT` are read.

const NAME: i32 = 1000;
const VERSION: i32 = 1001;
const RELEASE: i32 = 1002;
const EPOCH: i32 = 1003;
const ARCH: i32 = 1022;
const SOURCERPM: i32 = 1044;

const INT32: u32 = 4;
const STRING: u32 = 6;
const I18NSTRING: u32 = 9;

/// The index entries a header may have at most (rpm's own limit is far lower than its data).
const MAX_ENTRIES: usize = 0x10000;

pub struct Header {
    pub name: String,
    pub epoch: Option<u32>,
    pub version: String,
    pub release: String,
    pub arch: Option<String>,
    pub source_rpm: Option<String>,
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

impl Header {
    pub fn parse(blob: &[u8]) -> Option<Self> {
        let entries = be32(blob, 0)? as usize;
        let data_length = be32(blob, 4)? as usize;
        if entries == 0 || entries > MAX_ENTRIES {
            return None;
        }
        let data_start = 8usize.checked_add(entries.checked_mul(16)?)?;
        let data = blob.get(data_start..data_start.checked_add(data_length)?)?;
        let mut header = Header {
            name: String::new(),
            epoch: None,
            version: String::new(),
            release: String::new(),
            arch: None,
            source_rpm: None,
        };
        for index in 0..entries {
            let at = 8 + index * 16;
            let tag = be32(blob, at)? as i32;
            let kind = be32(blob, at + 4)?;
            let offset = be32(blob, at + 8)? as usize;
            let string = || -> Option<String> {
                if kind != STRING && kind != I18NSTRING {
                    return None;
                }
                let rest = data.get(offset..)?;
                let end = rest.iter().position(|&b| b == 0)?;
                Some(String::from_utf8_lossy(&rest[..end]).into_owned())
            };
            match tag {
                NAME => header.name = string()?,
                VERSION => header.version = string()?,
                RELEASE => header.release = string()?,
                ARCH => header.arch = string(),
                SOURCERPM => header.source_rpm = string(),
                EPOCH if kind == INT32 => header.epoch = be32(data, offset),
                _ => {}
            }
        }
        (!header.name.is_empty() && !header.version.is_empty()).then_some(header)
    }

    /// The line `rpm -qa --qf RPM_QUERY_FORMAT` prints for it (`(none)` for what it lacks).
    pub fn query_line(&self) -> String {
        let none = || "(none)".to_owned();
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            self.name,
            self.epoch.map_or_else(none, |e| e.to_string()),
            self.version,
            self.release,
            self.arch.clone().unwrap_or_else(none),
            self.source_rpm.clone().unwrap_or_else(none)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header with these entries `(tag, type, data)`, laid out like rpm does.
    pub fn build(entries: &[(i32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut index: Vec<u8> = Vec::new();
        let mut data: Vec<u8> = Vec::new();
        for (tag, kind, bytes) in entries {
            index.extend(tag.to_be_bytes());
            index.extend(kind.to_be_bytes());
            index.extend((data.len() as u32).to_be_bytes());
            index.extend(1u32.to_be_bytes());
            data.extend(bytes);
        }
        let mut blob = Vec::new();
        blob.extend((entries.len() as u32).to_be_bytes());
        blob.extend((data.len() as u32).to_be_bytes());
        blob.extend(index);
        blob.extend(data);
        blob
    }

    fn text(s: &str) -> Vec<u8> {
        let mut b = s.as_bytes().to_vec();
        b.push(0);
        b
    }

    #[test]
    fn reads_the_fields_of_rpm_qa() {
        let blob = build(&[
            (NAME, STRING, text("openssl-libs")),
            (VERSION, STRING, text("3.0.7")),
            (RELEASE, STRING, text("27.el9")),
            (EPOCH, INT32, 1u32.to_be_bytes().to_vec()),
            (ARCH, STRING, text("x86_64")),
            (SOURCERPM, STRING, text("openssl-3.0.7-27.el9.src.rpm")),
            (1004, I18NSTRING, text("Summary")),
        ]);
        let header = Header::parse(&blob).unwrap();
        assert_eq!(
            header.query_line(),
            "openssl-libs\t1\t3.0.7\t27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\n"
        );
        let bare = Header::parse(&build(&[
            (NAME, STRING, text("gpg-pubkey")),
            (VERSION, STRING, text("1")),
            (RELEASE, STRING, text("2")),
        ]))
        .unwrap();
        assert_eq!(
            bare.query_line(),
            "gpg-pubkey\t(none)\t1\t2\t(none)\t(none)\n"
        );
    }

    #[test]
    fn refuses_a_damaged_header() {
        assert!(Header::parse(&[]).is_none());
        assert!(Header::parse(&build(&[])).is_none(), "No entry.");
        assert!(
            Header::parse(&build(&[(NAME, STRING, text("a"))])).is_none(),
            "No version."
        );
        assert!(
            Header::parse(&build(&[
                (NAME, INT32, vec![0, 0, 0, 1]),
                (VERSION, STRING, text("1"))
            ]))
            .is_none(),
            "A name that is no string."
        );
        let mut blob = build(&[(NAME, STRING, text("a")), (VERSION, STRING, text("1"))]);
        blob.truncate(blob.len() - 1);
        assert!(Header::parse(&blob).is_none(), "Data cut short.");
        let mut unterminated = build(&[
            (NAME, STRING, b"a".to_vec()),
            (VERSION, STRING, b"1".to_vec()),
        ]);
        unterminated.truncate(unterminated.len());
        assert!(
            Header::parse(&unterminated).is_none(),
            "A string without its end."
        );
        let mut huge = vec![0xff, 0xff, 0xff, 0xff];
        huge.extend([0, 0, 0, 0]);
        assert!(Header::parse(&huge).is_none());
    }
}
