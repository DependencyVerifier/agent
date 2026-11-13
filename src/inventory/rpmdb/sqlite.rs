//! A read-only reader of one table of an SQLite file (format 3): the schema table to find it, then its table B-tree
//! (interior and leaf pages, overflow chains), then the column asked of each record. Enough for `rpmdb.sqlite`
//! (`Packages (hnum INTEGER PRIMARY KEY, blob BLOB)`); every offset is checked, every walk bounded. The write-ahead log
//! is not read (an image's database is checkpointed).

use std::collections::HashSet;

pub const MAGIC: &[u8] = b"SQLite format 3\0";

#[derive(Debug, PartialEq)]
enum Value {
    Null,
    Int(i64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

struct Database<'a> {
    bytes: &'a [u8],
    page_size: usize,
    usable: usize,
}

/// An SQLite varint: 1 to 9 bytes, big endian, 7 bits each but the ninth (8).
fn varint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for i in 0..9 {
        let byte = *bytes.get(at + i)?;
        if i == 8 {
            return Some(((value << 8) | u64::from(byte), 9));
        }
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

fn be16(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize)
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

impl<'a> Database<'a> {
    fn open(bytes: &'a [u8]) -> Option<Self> {
        if !bytes.starts_with(MAGIC) {
            return None;
        }
        let page_size = match be16(bytes, 16)? {
            1 => 65536,
            n if n >= 512 && n.is_power_of_two() => n,
            _ => return None,
        };
        let usable = page_size.checked_sub(usize::from(*bytes.get(20)?))?;
        (usable >= 480).then_some(Self {
            bytes,
            page_size,
            usable,
        })
    }

    fn page(&self, number: u32) -> Option<&'a [u8]> {
        let start = (number as usize)
            .checked_sub(1)?
            .checked_mul(self.page_size)?;
        self.bytes.get(start..start.checked_add(self.page_size)?)
    }

    /// The payload of a table leaf cell: its local part, then its overflow chain. A payload larger than the file, or
    /// a page already seen in this walk, is a damaged file: nothing is read twice, so a walk reads at most the file.
    fn payload(
        &self,
        page: &[u8],
        at: usize,
        size: usize,
        seen: &mut HashSet<u32>,
    ) -> Option<Vec<u8>> {
        if size > self.bytes.len() {
            return None;
        }
        let most = self.usable - 35;
        let local = if size <= most {
            size
        } else {
            let least = (self.usable - 12) * 32 / 255 - 23;
            let fit = least + (size - least) % (self.usable - 4);
            if fit <= most { fit } else { least }
        };
        let mut payload = page.get(at..at.checked_add(local)?)?.to_vec();
        let mut next = if local < size {
            be32(page, at + local)?
        } else {
            0
        };
        while payload.len() < size {
            if next == 0 || !seen.insert(next) {
                return None;
            }
            let overflow = self.page(next)?;
            next = be32(overflow, 0)?;
            let take = (size - payload.len()).min(self.usable - 4);
            payload.extend_from_slice(overflow.get(4..4 + take)?);
        }
        Some(payload)
    }

    /// The payload of every row of a table B-tree, in key order; every page at most once (a loop is a damaged file),
    /// and never more bytes in all than the file holds (cells of a page pointing to the same bytes).
    fn rows(&self, root: u32) -> Option<Vec<Vec<u8>>> {
        let mut rows = Vec::new();
        let mut stack = vec![root];
        let mut seen = HashSet::new();
        let mut total = 0usize;
        while let Some(number) = stack.pop() {
            if !seen.insert(number) {
                return None;
            }
            let page = self.page(number)?;
            let header = if number == 1 { 100 } else { 0 };
            let cells = be16(page, header + 3)?;
            match page.get(header)? {
                0x0d => {
                    for cell in 0..cells {
                        let at = be16(page, header + 8 + cell * 2)?;
                        let (size, read) = varint(page, at)?;
                        let (_, key) = varint(page, at + read)?;
                        let size = usize::try_from(size).ok()?;
                        total = total.checked_add(size)?;
                        if total > self.bytes.len() {
                            return None;
                        }
                        rows.push(self.payload(page, at + read + key, size, &mut seen)?);
                    }
                }
                0x05 => {
                    // Children pushed right to left: popped left to right.
                    stack.push(be32(page, header + 8)?);
                    for cell in (0..cells).rev() {
                        stack.push(be32(page, be16(page, header + 12 + cell * 2)?)?);
                    }
                }
                _ => return None,
            }
        }
        Some(rows)
    }
}

/// The values of a record (header of serial types, then the values).
fn record(payload: &[u8]) -> Option<Vec<Value>> {
    let (header_size, mut at) = varint(payload, 0)?;
    let header_size = usize::try_from(header_size).ok()?;
    let mut body = header_size;
    let mut values = Vec::new();
    while at < header_size {
        let (serial, read) = varint(payload, at)?;
        at += read;
        let size = match serial {
            0 | 8 | 9 => 0,
            1..=4 => serial as usize,
            5 => 6,
            6 | 7 => 8,
            n if n >= 12 => usize::try_from((n - 12) / 2).ok()?,
            _ => return None,
        };
        let bytes = payload.get(body..body.checked_add(size)?)?;
        body += size;
        values.push(match serial {
            0 => Value::Null,
            8 => Value::Int(0),
            9 => Value::Int(1),
            1..=6 => {
                let mut int = if bytes[0] & 0x80 != 0 { -1i64 } else { 0 };
                for b in bytes {
                    int = (int << 8) | i64::from(*b);
                }
                Value::Int(int)
            }
            7 => Value::Null,
            n if n % 2 == 0 => Value::Blob(bytes.to_vec()),
            _ => Value::Text(bytes.to_vec()),
        });
    }
    Some(values)
}

/// The position of a column in a `CREATE TABLE … (a TYPE, b TYPE…)` statement.
fn column(sql: &str, name: &str) -> Option<usize> {
    let columns = sql.split_once('(')?.1.rsplit_once(')')?.0;
    columns.split(',').position(|definition| {
        definition
            .split_whitespace()
            .next()
            .map(|c| c.trim_matches(['"', '\'', '`', '[', ']']))
            == Some(name)
    })
}

/// The `column` of every row of `table`, when it is a blob.
pub fn blobs(bytes: &[u8], table: &str, column_name: &str) -> Option<Vec<Vec<u8>>> {
    let database = Database::open(bytes)?;
    let (root, sql) = database.rows(1)?.iter().find_map(|row| {
        let values = record(row)?;
        match &values[..] {
            [
                Value::Text(kind),
                Value::Text(name),
                _,
                Value::Int(root),
                Value::Text(sql),
                ..,
            ] if kind == b"table" && name == table.as_bytes() => Some((
                u32::try_from(*root).ok()?,
                String::from_utf8_lossy(sql).into_owned(),
            )),
            _ => None,
        }
    })?;
    let index = column(&sql, column_name)?;
    Some(
        database
            .rows(root)?
            .iter()
            .filter_map(|row| match record(row)?.into_iter().nth(index)? {
                Value::Blob(blob) => Some(blob),
                _ => None,
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_varints() {
        assert_eq!(varint(&[0x05], 0), Some((5, 1)));
        assert_eq!(varint(&[0x81, 0x00], 0), Some((128, 2)));
        assert_eq!(varint(&[0xff; 9], 0), Some((u64::MAX, 9)));
        assert_eq!(varint(&[0x81], 0), None);
    }

    #[test]
    fn reads_records_and_columns() {
        // a header of 5 bytes: NULL, int8 7, blob(2), text(1)
        let payload = [5, 0, 1, 16, 15, 7, 0xaa, 0xbb, b'x'];
        assert_eq!(
            record(&payload),
            Some(vec![
                Value::Null,
                Value::Int(7),
                Value::Blob(vec![0xaa, 0xbb]),
                Value::Text(b"x".to_vec())
            ])
        );
        assert_eq!(record(&[2, 1]), None, "A value cut short.");
        assert_eq!(record(&[2, 10]), None, "A reserved serial type.");
        assert_eq!(
            record(&[3, 2, 8, 0xff, 0xfe]),
            Some(vec![Value::Int(-2), Value::Int(0)])
        );
        assert_eq!(
            column(
                "CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT,blob BLOB NOT NULL)",
                "blob"
            ),
            Some(1)
        );
        assert_eq!(
            column("CREATE TABLE x (\"a\" TEXT, [b] TEXT)", "b"),
            Some(1)
        );
        assert_eq!(column("CREATE TABLE x (a TEXT)", "blob"), None);
        assert_eq!(column("nonsense", "a"), None);
    }

    /// A database of 512-byte pages whose schema (page 1) is an interior page pointing to `children`.
    fn interior(children: &[u32]) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend([0x02, 0x00, 1, 1, 0, 64, 32, 32]);
        bytes.resize(512 * 3, 0);
        let header = 100;
        bytes[header] = 0x05;
        let (right, cells) = children.split_last().unwrap();
        bytes[header + 3..header + 5].copy_from_slice(&(cells.len() as u16).to_be_bytes());
        bytes[header + 8..header + 12].copy_from_slice(&right.to_be_bytes());
        for (i, child) in cells.iter().enumerate() {
            let at = 400 + i * 8;
            bytes[header + 12 + i * 2..header + 14 + i * 2]
                .copy_from_slice(&(at as u16).to_be_bytes());
            bytes[at..at + 4].copy_from_slice(&child.to_be_bytes());
        }
        // page 2: an empty leaf
        bytes[512] = 0x0d;
        bytes
    }

    #[test]
    fn reads_every_page_at_most_once() {
        let database = interior(&[2]);
        assert_eq!(Database::open(&database).unwrap().rows(1), Some(vec![]));
        let looped = interior(&[1]);
        assert_eq!(
            Database::open(&looped).unwrap().rows(1),
            None,
            "An interior page pointing to itself."
        );
        let shared = interior(&[2, 2]);
        assert_eq!(
            Database::open(&shared).unwrap().rows(1),
            None,
            "A page reached twice."
        );
        let mut leaf = interior(&[2]);
        // page 2: one cell announcing a payload larger than the file
        leaf[512 + 3..512 + 5].copy_from_slice(&1u16.to_be_bytes());
        leaf[512 + 8..512 + 10].copy_from_slice(&300u16.to_be_bytes());
        leaf[512 + 300..512 + 305].copy_from_slice(&[0x84, 0x80, 0x80, 0x80, 0x00]);
        leaf[512 + 305] = 1;
        assert_eq!(
            Database::open(&leaf).unwrap().rows(1),
            None,
            "A payload larger than the file."
        );
        let mut repeated = interior(&[2]);
        // page 2: 400 cells of 8 bytes, all on the same bytes (3200 > the 1536 of the file)
        repeated[512 + 3..512 + 5].copy_from_slice(&400u16.to_be_bytes());
        for i in 0..400 {
            let at = 512 + 8 + i * 2;
            repeated[at..at + 2].copy_from_slice(&480u16.to_be_bytes());
        }
        repeated[512 + 480] = 8;
        repeated[512 + 481] = 1;
        assert_eq!(
            Database::open(&repeated).unwrap().rows(1),
            None,
            "Cells read more bytes than the file holds."
        );
    }

    #[test]
    fn refuses_a_damaged_file() {
        assert!(Database::open(b"SQLite format 3\0").is_none());
        let mut header = MAGIC.to_vec();
        header.extend([0x03, 0x00, 1, 1, 0, 64, 32, 32]);
        header.resize(1000, 0);
        assert!(Database::open(&header).is_none(), "A page size of 768.");
        header[16..18].copy_from_slice(&[0x02, 0x00]);
        header[20] = 200;
        assert!(
            Database::open(&header).is_none(),
            "Too little usable space."
        );
    }
}
