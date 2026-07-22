//! LZ4 block decoder for HxStore payloads.
//!
//! The payload of every block is LZ4 block format — no frame header, no
//! trailing checksum, just a run of sequences:
//!
//! ```text
//!     [token] [literal-length varint] [literals] [dist_lo] [dist_hi] [match-length varint]
//!
//!     literal_count = token >> 4          (15 = read 255-continuation varint)
//!     match_length  = (token & 0x0F) + 4  (15 = read 255-continuation varint)
//!     distance      = u16 little-endian, counted back from the output end
//! ```
//!
//! The `+4` minimum match and the 255-continuation varints match the length
//! decoder in `HxCore.framework` at x86-64 `0x136c9de`.

/// Decode a block payload, requiring it to inflate to exactly `expected`.
///
/// The container header states the inflated size, so a correct decode lands on
/// it precisely. Anything else — a short read, a back-reference pointing
/// outside the window, trailing input — means the payload was not what we
/// thought, and returning `None` beats returning plausible garbage.
///
/// This strictness is what makes a magic-scan safe. LZ4 has no checksum of its
/// own, so a wrong start still decodes into something; only the length
/// agreement (plus the container's two CRC-32s) rules that out.
pub fn decode_exact(src: &[u8], expected: usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(expected);
    let mut i = 0usize;

    while i < src.len() && out.len() < expected {
        let token = src[i];
        i += 1;

        let mut lit = (token >> 4) as usize;
        if lit == 15 {
            lit = varint(src, &mut i, lit)?;
        }
        if i + lit > src.len() {
            return None;
        }
        out.extend_from_slice(&src[i..i + lit]);
        i += lit;

        // The final sequence of a block is literals only.
        if out.len() >= expected || i + 1 >= src.len() {
            break;
        }

        let dist = u16::from_le_bytes([src[i], src[i + 1]]) as usize;
        i += 2;
        if dist == 0 || dist > out.len() {
            return None;
        }

        let mut len = (token & 0x0F) as usize + 4;
        if (token & 0x0F) == 15 {
            len = varint(src, &mut i, len)?;
        }

        // Overlapping copies are legal and encode run-length expansion, so the
        // copy has to proceed one byte at a time rather than as a block move.
        let start = out.len() - dist;
        for k in 0..len {
            if out.len() >= expected {
                break;
            }
            let b = out[start + k];
            out.push(b);
        }
    }

    (out.len() == expected).then_some(out)
}

/// Read a 255-continuation varint, adding to `base`.
fn varint(src: &[u8], i: &mut usize, base: usize) -> Option<usize> {
    let mut n = base;
    loop {
        let b = *src.get(*i)?;
        *i += 1;
        n += b as usize;
        if b != 0xFF {
            return Some(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_only() {
        // token 0x50 = 5 literals, no match; ends the block.
        assert_eq!(decode_exact(&[0x50, b'h', b'e', b'l', b'l', b'o'], 5).unwrap(), b"hello");
    }

    #[test]
    fn back_reference_repeats() {
        // 4 literals "abcd", then distance 4, match length 4 -> "abcdabcd".
        let src = [0x40, b'a', b'b', b'c', b'd', 0x04, 0x00];
        assert_eq!(decode_exact(&src, 8).unwrap(), b"abcdabcd");
    }

    #[test]
    fn overlapping_copy_expands_a_run() {
        // 1 literal "x", distance 1, match length 4 -> "xxxxx".
        let src = [0x10, b'x', 0x01, 0x00];
        assert_eq!(decode_exact(&src, 5).unwrap(), b"xxxxx");
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert!(decode_exact(&[0x50, b'h', b'e', b'l', b'l', b'o'], 6).is_none());
    }

    #[test]
    fn distance_outside_window_is_rejected() {
        assert!(decode_exact(&[0x10, b'x', 0x99, 0x00], 5).is_none());
    }
}
