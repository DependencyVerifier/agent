//! A read-only reader of rpm's ndb database (`Packages.db`, SUSE and openSUSE): a header (`RpmP`, version 0, the
//! number of slot pages), a table of 16-byte slots (`Slot`, package index, first block, block count), then each
//! package's blob (`BlbS`, package index, generation, length) in 16-byte blocks. Every offset is checked: a blob stays
//! within its blocks, no block is read twice, and the blobs of a file are never larger than the file.

use std::collections::HashSet;

pub const MAGIC: &[u8] = b"RpmP";
const SLOT_MAGIC: &[u8] = b"Slot";
const BLOB_MAGIC: &[u8] = b"BlbS";
const PAGE_SIZE: usize = 4096;
const SLOT_SIZE: usize = 16;
const BLOCK_SIZE: usize = 16;
const BLOB_HEADER: usize = 16;
/// The file header takes the first two slots.
const FIRST_SLOT: usize = 32;

fn le32(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?) as usize)
}

/// The blob of every used slot, in slot order.
pub fn blobs(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    if !bytes.starts_with(MAGIC) || le32(bytes, 4)? != 0 {
        return None;
    }
    let slots_end = le32(bytes, 12)?.checked_mul(PAGE_SIZE)?;
    if slots_end > bytes.len() {
        return None;
    }
    let mut blobs = Vec::new();
    let mut seen = HashSet::new();
    let mut total = 0usize;
    for at in (FIRST_SLOT..slots_end).step_by(SLOT_SIZE) {
        if bytes.get(at..at + 4)? != SLOT_MAGIC {
            continue;
        }
        let index = le32(bytes, at + 4)?;
        if index == 0 {
            continue; // a free slot
        }
        let first = le32(bytes, at + 8)?;
        let count = le32(bytes, at + 12)?;
        let start = first.checked_mul(BLOCK_SIZE)?;
        let room = count.checked_mul(BLOCK_SIZE)?;
        if start < slots_end || !seen.insert(first) {
            return None;
        }
        let blob = bytes.get(start..start.checked_add(room)?)?;
        if blob.get(..4)? != BLOB_MAGIC || le32(blob, 4)? != index {
            return None;
        }
        let length = le32(blob, 12)?;
        if BLOB_HEADER.checked_add(length)? > room {
            return None;
        }
        total = total.checked_add(room)?;
        if total > bytes.len() {
            return None;
        }
        blobs.push(blob[BLOB_HEADER..BLOB_HEADER + length].to_vec());
    }
    Some(blobs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One slot page: the header, then slots of `(index, first block, block count)`; a blob of `data` at each.
    fn database(slots: &[(u32, u32, u32)], blobs: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut bytes = vec![0u8; PAGE_SIZE];
        bytes[..4].copy_from_slice(MAGIC);
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        for (i, (index, first, count)) in slots.iter().enumerate() {
            let at = FIRST_SLOT + i * SLOT_SIZE;
            bytes[at..at + 4].copy_from_slice(SLOT_MAGIC);
            for (j, value) in [index, first, count].iter().enumerate() {
                bytes[at + 4 + j * 4..at + 8 + j * 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        for (index, first, data) in blobs {
            let at = *first as usize * BLOCK_SIZE;
            let end = at + BLOB_HEADER + data.len() + 16;
            if bytes.len() < end {
                bytes.resize(end.next_multiple_of(BLOCK_SIZE), 0);
            }
            bytes[at..at + 4].copy_from_slice(BLOB_MAGIC);
            bytes[at + 4..at + 8].copy_from_slice(&index.to_le_bytes());
            bytes[at + 12..at + 16].copy_from_slice(&(data.len() as u32).to_le_bytes());
            bytes[at + BLOB_HEADER..at + BLOB_HEADER + data.len()].copy_from_slice(data);
        }
        bytes
    }

    #[test]
    fn reads_the_blob_of_every_used_slot() {
        let bytes = database(
            &[(1, 256, 3), (0, 0, 0), (2, 260, 2)],
            &[(1, 256, b"first"), (2, 260, b"second")],
        );
        assert_eq!(
            blobs(&bytes),
            Some(vec![b"first".to_vec(), b"second".to_vec()])
        );
    }

    #[test]
    fn refuses_a_damaged_file() {
        assert_eq!(blobs(b"RpmP"), None);
        let mut version = database(&[], &[]);
        version[4] = 1;
        assert_eq!(blobs(&version), None, "An unknown version.");
        let mut pages = database(&[], &[]);
        pages[12..16].copy_from_slice(&100u32.to_le_bytes());
        assert_eq!(blobs(&pages), None, "More slot pages than the file.");
        let shared = database(&[(1, 256, 3), (2, 256, 3)], &[(1, 256, b"first")]);
        assert_eq!(blobs(&shared), None, "Two slots on the same blocks.");
        let inside = database(&[(1, 2, 3)], &[]);
        assert_eq!(blobs(&inside), None, "A blob inside the slot table.");
        let other = database(&[(1, 256, 3)], &[(2, 256, b"first")]);
        assert_eq!(blobs(&other), None, "A blob of another package.");
        let long = database(&[(1, 256, 1)], &[(1, 256, b"longer than one block")]);
        assert_eq!(blobs(&long), None, "A blob longer than its blocks.");
        let huge = database(&[(1, 256, u32::MAX)], &[(1, 256, b"x")]);
        assert_eq!(blobs(&huge), None, "Blocks beyond the file.");
    }
}
