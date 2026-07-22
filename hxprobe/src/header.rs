//! The `HxStore.hxd` file header.
//!
//! Read out of `HxCore.framework`: the initialiser at `0xda5804` allocates a
//! `0x4b0`-byte object, writes `"Nostromo"` at object `+0x10` and a version
//! byte at object `+0x18`, then stamps a `0xdeadbeef` guard pattern at object
//! `+0xac`. The object is persisted with its first `0x10` bytes elided, so
//! `file_offset = object_offset - 0x10`, which the guard confirms: it lands at
//! file `+0x9c`, and that is exactly where `0x24` bytes of repeating
//! `ef be ad de` sit in a real store.
//!
//! ```text
//!   +0x00  char[8]  "Nostromo"
//!   +0x08  u64      version byte ('i' = 0x69 on the macOS build)
//!   +0x38  u64      page size (4096)
//!   +0x9c  u8[0x24] 0xdeadbeef guard
//! ```

/// Magic opening every store.
pub const MAGIC: &[u8; 8] = b"Nostromo";

/// Version bytes this parser will accept.
///
/// `HxCore` carries the literals `NostromoH`, `NostromoH9` and `NostromoI`, so
/// the byte is a compatibility gate rather than a revision counter. The macOS
/// build under test writes `'i'`; Windows Mail samples in the published
/// literature show `'h'`. Both are accepted because the block container they
/// wrap is the same structure, and every block is independently checksummed:
/// if a variant did differ, blocks would fail validation loudly rather than
/// yielding wrong data.
///
/// `'h'` is **untested** here. Accepting it is a considered risk, not a
/// verified claim, which is why [`check`] reports the byte it found.
pub const KNOWN_VERSIONS: [u8; 2] = *b"ih";

/// What the header says about a file.
pub struct Header {
    pub version: u8,
    /// True when the version byte is one this parser has been reasoned about.
    pub known: bool,
    pub page_size: u64,
}

/// Validate the file header.
///
/// Returns `Err` only when the magic is absent, i.e. this is not an HxStore at
/// all. An unrecognised version still parses: the caller is told, and the block
/// checksums remain the real guard.
pub fn check(mm: &[u8]) -> Result<Header, String> {
    if mm.len() < 0x40 {
        return Err("file is too small to hold a header".into());
    }
    if &mm[..8] != MAGIC {
        return Err(format!(
            "not an HxStore: expected magic {:?}, found {:?}",
            String::from_utf8_lossy(MAGIC),
            String::from_utf8_lossy(&mm[..8])
        ));
    }
    let version = mm[8];
    Ok(Header {
        version,
        known: KNOWN_VERSIONS.contains(&version),
        page_size: u64::from_le_bytes(mm[0x38..0x40].try_into().unwrap()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(version: u8) -> Vec<u8> {
        let mut v = vec![0u8; 0x40];
        v[..8].copy_from_slice(MAGIC);
        v[8] = version;
        v[0x38..0x40].copy_from_slice(&4096u64.to_le_bytes());
        v
    }

    #[test]
    fn accepts_the_macos_version() {
        let h = check(&store(b'i')).unwrap();
        assert!(h.known);
        assert_eq!(h.page_size, 4096);
    }

    #[test]
    fn accepts_the_windows_version() {
        assert!(check(&store(b'h')).unwrap().known);
    }

    #[test]
    fn flags_an_unrecognised_version_without_failing() {
        let h = check(&store(b'z')).unwrap();
        assert!(!h.known);
        assert_eq!(h.version, b'z');
    }

    #[test]
    fn rejects_a_file_that_is_not_a_store() {
        assert!(check(&[0u8; 0x40]).is_err());
    }
}
