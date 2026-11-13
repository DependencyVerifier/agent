//! A read-only reader of the values of a Berkeley DB hash database (rpm's `Packages` before RHEL 9): the metadata
//! page (magic, byte order, page size, last page), then every hash page, each value read in place or along its
//! overflow chain. Every offset is checked, every walk bounded.

const HASH_MAGIC: u32 = 0x0006_1561;
const HASH_UNSORTED: u8 = 2;
const HASH: u8 = 13;
const KEY_DATA: u8 = 1;
const OFF_PAGE: u8 = 3;
const PAGE_HEADER: usize = 26;

use std::collections::HashSet;

#[derive(Clone, Copy)]
struct Order(bool);

impl Order {
    fn u16(self, bytes: &[u8], at: usize) -> Option<usize> {
        let b: [u8; 2] = bytes.get(at..at + 2)?.try_into().ok()?;
        Some(usize::from(if self.0 {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        }))
    }

    fn u32(self, bytes: &[u8], at: usize) -> Option<u32> {
        let b: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
        Some(if self.0 {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }
}

struct Database<'a> {
    bytes: &'a [u8],
    order: Order,
    page_size: usize,
    last_page: u32,
}

impl<'a> Database<'a> {
    fn open(bytes: &'a [u8]) -> Option<Self> {
        let order = [Order(false), Order(true)]
            .into_iter()
            .find(|o| o.u32(bytes, 12) == Some(HASH_MAGIC))?;
        let page_size = order.u32(bytes, 20)? as usize;
        if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
            return None;
        }
        Some(Self {
            bytes,
            order,
            page_size,
            last_page: order.u32(bytes, 32)?,
        })
    }

    fn page(&self, number: u32) -> Option<&'a [u8]> {
        let start = (number as usize).checked_mul(self.page_size)?;
        self.bytes.get(start..start.checked_add(self.page_size)?)
    }

    /// A value stored on overflow pages: their data (`hf_offset` bytes each), up to its length. A length larger than
    /// the file, or an overflow page already read (by this value or another one), is a damaged file: no page is read
    /// twice, so the values of a file are never larger than the file.
    fn overflow(&self, mut number: u32, length: usize, seen: &mut HashSet<u32>) -> Option<Vec<u8>> {
        if length > self.bytes.len() {
            return None;
        }
        let mut value = Vec::with_capacity(length);
        loop {
            if !seen.insert(number) {
                return None;
            }
            let page = self.page(number)?;
            let used = self.order.u16(page, 22)?;
            value.extend_from_slice(page.get(PAGE_HEADER..PAGE_HEADER.checked_add(used)?)?);
            number = self.order.u32(page, 16)?;
            if number == 0 || value.len() >= length {
                value.truncate(length);
                return (value.len() == length).then_some(value);
            }
        }
    }

    /// The value of the item at `index` of a hash page (its key is the item before).
    fn value(&self, page: &[u8], index: usize, seen: &mut HashSet<u32>) -> Option<Vec<u8>> {
        let at = self.order.u16(page, PAGE_HEADER + index * 2)?;
        match *page.get(at)? {
            OFF_PAGE => self.overflow(
                self.order.u32(page, at + 4)?,
                self.order.u32(page, at + 8)? as usize,
                seen,
            ),
            KEY_DATA => {
                // Items are laid from the end of the page backwards: this one ends where the previous begins.
                let end = if index == 0 {
                    self.page_size
                } else {
                    self.order.u16(page, PAGE_HEADER + (index - 1) * 2)?
                };
                Some(page.get(at + 1..end)?.to_vec())
            }
            _ => None,
        }
    }
}

/// Every value of the database, in page order.
pub fn values(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let database = Database::open(bytes)?;
    let mut values = Vec::new();
    let mut seen = HashSet::new();
    // Items of a page pointing to the same bytes: never more bytes in all than the file holds.
    let mut total = 0usize;
    for number in 1..=database.last_page {
        let Some(page) = database.page(number) else {
            break;
        };
        if ![HASH, HASH_UNSORTED].contains(page.get(25)?) {
            continue;
        }
        let entries = database.order.u16(page, 20)?;
        for index in (1..entries).step_by(2) {
            if let Some(value) = database.value(page, index, &mut seen) {
                total = total.checked_add(value.len())?;
                if total > bytes.len() {
                    return None;
                }
                values.push(value);
            }
        }
    }
    Some(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn le16(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    /// A database of 512-byte pages: metadata, one hash page with a key and an in-place value, then a key and a
    /// value on two overflow pages.
    fn database() -> Vec<u8> {
        let mut bytes = vec![0u8; 512 * 4];
        le32(&mut bytes, 12, HASH_MAGIC);
        le32(&mut bytes, 20, 512);
        le32(&mut bytes, 32, 3);
        let hash = 512;
        bytes[hash + 25] = HASH;
        le16(&mut bytes, hash + 20, 4);
        // items from the end: key 1 (5 bytes), value "abc" (4), key 2 (5), off-page value (12)
        let (k1, v1, k2, v2) = (507, 503, 498, 486);
        for (i, at) in [k1, v1, k2, v2].iter().enumerate() {
            le16(&mut bytes, hash + PAGE_HEADER + i * 2, *at as u16);
        }
        bytes[hash + k1] = KEY_DATA;
        bytes[hash + v1..hash + v1 + 4].copy_from_slice(&[KEY_DATA, b'a', b'b', b'c']);
        bytes[hash + k2] = KEY_DATA;
        bytes[hash + v2] = OFF_PAGE;
        le32(&mut bytes, hash + v2 + 4, 2);
        le32(&mut bytes, hash + v2 + 8, 600);
        // overflow: page 2 holds 486 bytes then page 3 the rest (114 + junk past the length)
        le16(&mut bytes, 1024 + 22, 486);
        le32(&mut bytes, 1024 + 16, 3);
        bytes[1024 + PAGE_HEADER..1024 + PAGE_HEADER + 486].fill(b'x');
        le16(&mut bytes, 1536 + 22, 120);
        bytes[1536 + PAGE_HEADER..1536 + PAGE_HEADER + 120].fill(b'y');
        bytes
    }

    #[test]
    fn reads_values_in_place_and_on_overflow_pages() {
        let values = values(&database()).unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], b"abc");
        assert_eq!(values[1].len(), 600);
        assert_eq!(&values[1][..486], &[b'x'; 486][..]);
        assert_eq!(&values[1][486..], &[b'y'; 114][..], "Cut at its length.");
    }

    #[test]
    fn reads_either_byte_order_and_refuses_the_rest() {
        let mut big = vec![0u8; 512 * 2];
        big[12..16].copy_from_slice(&HASH_MAGIC.to_be_bytes());
        big[20..24].copy_from_slice(&512u32.to_be_bytes());
        big[32..36].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(
            values(&big),
            Some(vec![]),
            "A big-endian database without hash page."
        );
        assert_eq!(values(&[0u8; 64]), None, "No magic.");
        let mut odd = database();
        le32(&mut odd, 20, 768);
        assert_eq!(values(&odd), None, "Not a power of two.");
        let mut short = database();
        le32(&mut short, 1536 + 16, 0);
        le16(&mut short, 1536 + 22, 50);
        assert_eq!(
            values(&short).unwrap().len(),
            1,
            "A chain shorter than its value: dropped."
        );
        let mut looped = database();
        le32(&mut looped, 1536 + 16, 2);
        le32(&mut looped, 512 + 486 + 8, 100_000);
        assert_eq!(
            values(&looped).unwrap().len(),
            1,
            "A chain looping on itself: dropped."
        );
        let mut huge = database();
        le32(&mut huge, 512 + 486 + 8, u32::MAX);
        assert_eq!(
            values(&huge).unwrap().len(),
            1,
            "A length larger than the file: dropped."
        );
        let mut repeated = database();
        le16(&mut repeated, 512 + 20, 400);
        for i in 0..400 {
            // keys at 511, values from 300 to the key before: 210 bytes each, 200 times
            let at = if i % 2 == 0 { 511 } else { 300 };
            le16(&mut repeated, 512 + PAGE_HEADER + i * 2, at);
        }
        repeated[512 + 300] = KEY_DATA;
        assert_eq!(
            values(&repeated),
            None,
            "Items read more bytes than the file holds."
        );
        let mut cut = database();
        cut.truncate(1536);
        assert_eq!(
            values(&cut).unwrap().len(),
            1,
            "A missing overflow page: dropped."
        );
    }
}
