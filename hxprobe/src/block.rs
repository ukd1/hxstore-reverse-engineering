//! The HxStore block container.
//!
//! Derived from `HxCore.framework` (arm64), not from guesswork:
//!
//!   * the header writer at `0xf44670` stores the magic, then computes
//!     `crc32(block+8, len-8)` into `+0x04` and `crc32(block+4, 0x1c)` into
//!     `+0x00`;
//!   * the validator at `0xf4552c` reloads `[block+0x14]` as the length and
//!     re-checks `+0x04` before the payload is touched.
//!
//! Both checksums verify on 13,107 / 13,116 blocks in a live store, and
//! 13,105 payloads decompress to exactly the length the header declares. That
//! is what makes this a parser rather than a heuristic: a wrong offset fails
//! loudly instead of yielding plausible garbage.
//!
//! ```text
//!   +0x00  u32  crc32(header[4..0x20])
//!   +0x04  u32  crc32(block[8 .. 0x28 + payload_len])
//!   +0x08  u64  magic 0x5d0245643b706a05
//!   +0x10  u32  type            (observed 8 and 16)
//!   +0x14  u32  payload_len     compressed bytes, starting at +0x28
//!   +0x18  u32  inflated_len    exact size of the decompressed payload
//!   +0x1c  u32  4
//!   +0x28  ...  LZ4-compressed payload
//! ```

use crate::lz;

/// Little-endian u64 that opens every block, at offset `+0x08`.
pub const MAGIC: u64 = 0x5d02_4564_3b70_6a05;

/// Fixed distance from the start of a block to its compressed payload.
pub const PAYLOAD: usize = 0x28;

/// A parsed, verified, decompressed block.
pub struct Block {
    pub kind: u32,
    pub data: Vec<u8>,
}

/// Header fields, read but not yet validated.
struct Header {
    crc_header: u32,
    crc_body: u32,
    kind: u32,
    payload_len: usize,
    inflated_len: usize,
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn read_header(mm: &[u8], off: usize) -> Option<Header> {
    if off + PAYLOAD > mm.len() {
        return None;
    }
    let h = &mm[off..off + PAYLOAD];
    Some(Header {
        crc_header: u32_at(h, 0x00),
        crc_body: u32_at(h, 0x04),
        kind: u32_at(h, 0x10),
        payload_len: u32_at(h, 0x14) as usize,
        inflated_len: u32_at(h, 0x18) as usize,
    })
}

/// Parse and fully verify the block at `off`.
///
/// Returns `None` unless the header checksum, the payload checksum and the
/// declared inflated length all agree. Callers can therefore trust the bytes
/// they get back.
pub fn parse(mm: &[u8], off: usize) -> Option<Block> {
    let h = read_header(mm, off)?;

    // Guard against absurd lengths before allocating anything.
    if h.inflated_len == 0
        || h.inflated_len > 32 << 20
        || off + PAYLOAD + h.payload_len > mm.len()
    {
        return None;
    }

    if crc32(&mm[off + 4..off + 0x20]) != h.crc_header {
        return None;
    }
    let end = off + PAYLOAD + h.payload_len;
    if crc32(&mm[off + 8..end]) != h.crc_body {
        return None;
    }

    let data = lz::decode_exact(&mm[off + PAYLOAD..end], h.inflated_len)?;
    Some(Block { kind: h.kind, data })
}

/// Offsets of every block header in the file.
///
/// Blocks are found by their magic rather than by walking a directory: the
/// store keeps free space and stale regions between live blocks, and the two
/// checksums make a scan safe.
pub fn find_all(mm: &[u8]) -> Vec<usize> {
    let magic = MAGIC.to_le_bytes();
    memchr::memmem::find_iter(mm, &magic)
        .filter(|&m| m >= 8)
        .map(|m| m - 8)
        .collect()
}

/// CRC-32 (IEEE, as used by zlib), which is what HxCore calls.
fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    });

    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}
