//! Snappy block format: a varint of the uncompressed length, then literals and
//! copies.
//!
//! The compressor is the reference one's scheme: 64 KiB blocks, a table of the
//! last position of each hashed four bytes, a match extended as far as it goes.
//! Any decoder of the format reads it.

/// Bytes compressed against one table: an offset fits a `u16`, a copy its
/// two-byte form.
const BLOCK: usize = 1 << 16;
const TABLE_BITS: u32 = 14;
/// Bytes left alone at a block's end, so the search reads whole words without a
/// bound check.
const INPUT_MARGIN: usize = 15;

#[inline]
fn load32(input: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(input[at..at + 4].try_into().unwrap())
}

#[inline]
fn hash(word: u32) -> usize {
    (word.wrapping_mul(0x1e35_a7bd) >> (32 - TABLE_BITS)) as usize
}

/// Bytes `input[a..]` and `input[b..]` share, `a < b`.
#[inline]
fn match_len(input: &[u8], mut a: usize, mut b: usize) -> usize {
    let start = b;
    while b + 8 <= input.len() {
        let x = u64::from_le_bytes(input[a..a + 8].try_into().unwrap());
        let y = u64::from_le_bytes(input[b..b + 8].try_into().unwrap());
        if x != y {
            return b - start + ((x ^ y).trailing_zeros() / 8) as usize;
        }
        a += 8;
        b += 8;
    }
    while b < input.len() && input[a] == input[b] {
        a += 1;
        b += 1;
    }
    b - start
}

/// A literal of at most a block.
fn emit_literal(out: &mut Vec<u8>, literal: &[u8]) {
    let n = literal.len() - 1;
    if n < 60 {
        out.push((n as u8) << 2);
    } else if n < 256 {
        out.extend_from_slice(&[60 << 2, n as u8]);
    } else {
        out.push(61 << 2);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    }
    out.extend_from_slice(literal);
}

/// A copy of `len >= 4` bytes from `offset < 2^16` back, as tags of at most 64
/// bytes each.
fn emit_copy(out: &mut Vec<u8>, offset: usize, mut len: usize) {
    let long = |out: &mut Vec<u8>, len: usize| {
        out.push(2 | ((len - 1) as u8) << 2);
        out.extend_from_slice(&(offset as u16).to_le_bytes());
    };
    // No tag is left shorter than four bytes.
    while len >= 68 {
        long(out, 64);
        len -= 64;
    }
    if len > 64 {
        long(out, 60);
        len -= 60;
    }
    if len >= 12 || offset >= 2048 {
        long(out, len);
    } else {
        out.extend_from_slice(&[
            1 | ((len - 4) as u8) << 2 | ((offset >> 8) as u8) << 5,
            offset as u8,
        ]);
    }
}

fn compress_block(input: &[u8], out: &mut Vec<u8>, table: &mut [u16; 1 << TABLE_BITS]) {
    table.fill(0);
    let mut next_emit = 0;
    if input.len() >= INPUT_MARGIN {
        let limit = input.len() - INPUT_MARGIN;
        let mut ip = 1;
        'block: loop {
            // The next position with a table entry that matches it. Each miss lengthens the
            // step, so data that does not compress is skipped quickly.
            let mut skip = 32;
            let mut candidate;
            loop {
                if ip > limit {
                    break 'block;
                }
                let h = hash(load32(input, ip));
                candidate = table[h] as usize;
                table[h] = ip as u16;
                if load32(input, ip) == load32(input, candidate) {
                    break;
                }
                ip += skip >> 5;
                skip += 1;
            }
            emit_literal(out, &input[next_emit..ip]);
            // Copies back to back, for as long as the position after one matches again.
            loop {
                let len = 4 + match_len(input, candidate + 4, ip + 4);
                emit_copy(out, ip - candidate, len);
                ip += len;
                next_emit = ip;
                if ip >= limit {
                    break 'block;
                }
                table[hash(load32(input, ip - 1))] = (ip - 1) as u16;
                let h = hash(load32(input, ip));
                candidate = table[h] as usize;
                table[h] = ip as u16;
                if load32(input, ip) != load32(input, candidate) {
                    break;
                }
            }
            ip += 1;
        }
    }
    if next_emit < input.len() {
        emit_literal(out, &input[next_emit..]);
    }
}

pub fn compress(input: &[u8]) -> Vec<u8> {
    // The format's bound on a compressed length.
    let mut out = Vec::with_capacity(32 + input.len() + input.len() / 6);
    let mut n = input.len();
    while n >= 0x80 {
        out.push(n as u8 | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
    let mut table = [0u16; 1 << TABLE_BITS];
    for block in input.chunks(BLOCK) {
        compress_block(block, &mut out, &mut table);
    }
    out
}

/// The length `compressed` declares for the bytes it encodes, and where its
/// tags start.
fn header(compressed: &[u8]) -> Option<(usize, usize)> {
    let mut pos = 0;
    let mut len: usize = 0;
    let mut shift = 0;
    loop {
        let b = *compressed.get(pos)?;
        pos += 1;
        len |= ((b & 0x7f) as usize).checked_shl(shift)?;
        if b & 0x80 == 0 {
            return Some((len, pos));
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
}

/// The length `compressed` declares for the bytes it encodes: what
/// [`decompress_into`] writes if it is well formed. A caller reserves that
/// much, having checked it against its own limit.
pub fn decompressed_len(compressed: &[u8]) -> Option<usize> {
    header(compressed).map(|(len, _)| len)
}

/// Writes the bytes `compressed` encodes at the start of `out` and returns how
/// many, if it is well formed and `out` has room for the length it declares. No
/// tag may write past that length.
pub fn decompress_into(compressed: &[u8], out: &mut [u8]) -> Option<usize> {
    let (len, mut pos) = header(compressed)?;
    let out = out.get_mut(..len)?;
    let mut at = 0usize;
    while pos < compressed.len() {
        let tag = compressed[pos];
        pos += 1;
        let (length, offset) = match tag & 0x03 {
            0 => {
                let code = (tag >> 2) as usize;
                let length = if code < 60 {
                    code + 1
                } else {
                    let extra = compressed.get(pos..pos + code - 59)?;
                    pos += extra.len();
                    let n = extra.iter().rev().fold(0usize, |acc, &b| acc << 8 | b as usize);
                    n.checked_add(1)?
                };
                let literal = compressed.get(pos..pos.checked_add(length)?)?;
                out.get_mut(at..at.checked_add(length)?)?.copy_from_slice(literal);
                at += length;
                pos += length;
                continue;
            }
            1 => {
                let low = *compressed.get(pos)? as usize;
                pos += 1;
                (((tag >> 2) & 0x07) as usize + 4, ((tag >> 5) as usize) << 8 | low)
            }
            2 => {
                let bytes = compressed.get(pos..pos + 2)?;
                pos += 2;
                ((tag >> 2) as usize + 1, u16::from_le_bytes(bytes.try_into().unwrap()) as usize)
            }
            _ => {
                let bytes = compressed.get(pos..pos + 4)?;
                pos += 4;
                ((tag >> 2) as usize + 1, u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
            }
        };
        if offset == 0 || offset > at || length > len - at {
            return None;
        }
        // A copy that overlaps its own output repeats the `offset` bytes before it:
        // what is already written doubles each pass.
        let start = at - offset;
        let end = at + length;
        while at < end {
            let take = (end - at).min(at - start);
            out.copy_within(start..start + take, at);
            at += take;
        }
    }
    (at == len).then_some(len)
}

/// The bytes `compressed` encodes, if it is well formed and they are at most
/// `max_len`. The length it declares is checked against `max_len` before
/// anything is allocated.
pub fn decompress(compressed: &[u8], max_len: usize) -> Option<Vec<u8>> {
    let len = decompressed_len(compressed).filter(|&len| len <= max_len)?;
    let mut out = vec![0u8; len];
    decompress_into(compressed, &mut out)?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (state >> 56) as u8
            })
            .collect()
    }

    /// Random bytes with stretches repeated from earlier, at short and long
    /// distances.
    fn repetitive(len: usize, seed: u64) -> Vec<u8> {
        let noise = bytes(len, seed);
        let mut out: Vec<u8> = Vec::with_capacity(len);
        let mut at = 0;
        while out.len() < len {
            let (a, b) = (noise[at % len] as usize, noise[(at + 1) % len] as usize);
            at += 2;
            if a % 3 == 0 || out.len() < 8 {
                out.extend_from_slice(&noise[at % (len - 40)..][..1 + b % 40]);
            } else {
                let back = 1 + (a * 257 + b) % out.len().min(70_000);
                for _ in 0..4 + b {
                    out.push(out[out.len() - back]);
                }
            }
        }
        out.truncate(len);
        out
    }

    #[test]
    fn test_round_trip() {
        let mut inputs: Vec<Vec<u8>> =
            (0..80).map(|len| repetitive(200, 3)[..len].to_vec()).collect();
        inputs.push(vec![0; 300_000]);
        inputs.push(bytes(200_000, 5));
        for len in [65_535, 65_536, 65_537, 131_072, 250_000] {
            inputs.push(repetitive(len, len as u64));
        }
        for input in &inputs {
            let compressed = compress(input);
            assert!(compressed.len() <= 32 + input.len() + input.len() / 6);
            assert_eq!(
                decompress(&compressed, input.len()).as_ref(),
                Some(input),
                "{} bytes",
                input.len()
            );
        }
        assert!(compress(&inputs[80]).len() < 300_000 / 15);
        assert!(compress(&repetitive(250_000, 9)).len() < 150_000);
    }

    #[test]
    fn test_decompress_refuses_malformed() {
        // "abcd", then a copy of 6 from 4 back, which overlaps itself.
        let valid = [10, 3 << 2, b'a', b'b', b'c', b'd', 1 | 2 << 2, 4];
        assert_eq!(decompress(&valid, 10).as_deref(), Some(&b"abcdabcdab"[..]));
        // Declared longer than allowed: refused before allocating.
        assert_eq!(decompress(&valid, 9), None);
        assert_eq!(decompress(&[0xff, 0xff, 0xff, 0xff, 0x0f], 1 << 21), None);
        // A copy past the declared length, one from before the start, a literal cut
        // short, and an output shorter than declared.
        assert_eq!(decompress(&[9, 3 << 2, b'a', b'b', b'c', b'd', 1 | 2 << 2, 4], 100), None);
        assert_eq!(decompress(&[10, 3 << 2, b'a', b'b', b'c', b'd', 1 | 2 << 2, 5], 100), None);
        assert_eq!(decompress(&[10, 3 << 2, b'a', b'b'], 100), None);
        assert_eq!(decompress(&[10, 3 << 2, b'a', b'b', b'c', b'd'], 100), None);
        assert_eq!(decompress(&[], 100), None);
        // Into a buffer: its length is what is declared, and a shorter one is refused.
        let mut out = [0u8; 12];
        assert_eq!(
            (decompressed_len(&valid), decompress_into(&valid, &mut out)),
            (Some(10), Some(10))
        );
        assert_eq!(&out[..10], b"abcdabcdab");
        assert_eq!(decompress_into(&valid, &mut out[..9]), None);
    }
}
