//! SHA-256 of sixteen messages of one length at once, each in a lane of 512-bit
//! vectors.
//!
//! One message at a time, the SHA extensions are faster per byte than these
//! rounds. Sixteen at a time they are not: a Merkle tree's leaves are
//! independent and, but for one, the same length.

use core::arch::x86_64::*;

use seacast_core::Bytes32;

use super::{H0, K, LANES};

/// Block `b` of `prefix || data`, padded as SHA-256 pads it.
fn block(prefix: u8, data: &[u8], b: usize, blocks: usize, out: &mut [u8; 64]) {
    let (message, start) = (data.len() + 1, 64 * b);
    if b >= 1 && start + 64 <= message {
        // Whole and past the prefix: the common case.
        out.copy_from_slice(&data[start - 1..start + 63]);
        return;
    }
    for (i, byte) in out.iter_mut().enumerate() {
        let at = start + i;
        *byte = match at {
            0 => prefix,
            _ if at < message => data[at - 1],
            _ if at == message => 0x80,
            _ => 0,
        };
    }
    if b + 1 == blocks {
        out[56..].copy_from_slice(&(message as u64 * 8).to_be_bytes());
    }
}

/// `sha256(prefix || data[lane])` for sixteen `data` of one length.
#[target_feature(enable = "avx512f,avx512bw")]
pub(crate) fn sha256_prefixed(prefix: u8, data: &[&[u8]; LANES]) -> [Bytes32; LANES] {
    let len = data[0].len();
    assert!(data.iter().all(|d| d.len() == len));
    let blocks = (len + 1 + 9).div_ceil(64);
    // The block in hand of every lane, end to end: one allocation for the gathers
    // to index.
    let mut staged = [[0u8; 64]; LANES];
    let mut words = [[0u32; LANES]; 8];
    // SAFETY: the gathers index `staged`, at most its last word; the stores fill
    // `words`, a row each.
    unsafe {
        let xor3 = |a, b, c| _mm512_ternarylogic_epi32::<0x96>(a, b, c);
        let swap = _mm512_broadcast_i32x4(_mm_set_epi64x(0x0c0d0e0f08090a0b, 0x0405060700010203));
        // Word `j` of lane `l` is at byte `64 l + 4 j` of `staged`.
        let lane_at = _mm512_mullo_epi32(
            _mm512_set_epi32(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
            _mm512_set1_epi32(64),
        );
        let mut state: [__m512i; 8] = H0.map(|h| _mm512_set1_epi32(h as i32));
        for b in 0..blocks {
            for (lane, out) in staged.iter_mut().enumerate() {
                block(prefix, data[lane], b, blocks, out);
            }
            let mut w: [__m512i; 16] = core::array::from_fn(|j| {
                let at = _mm512_add_epi32(lane_at, _mm512_set1_epi32(4 * j as i32));
                _mm512_shuffle_epi8(_mm512_i32gather_epi32::<1>(at, staged.as_ptr().cast()), swap)
            });
            let [mut a, mut b_, mut c, mut d, mut e, mut f, mut g, mut h] = state;
            for i in 0..64 {
                if i >= 16 {
                    let (w15, w2) = (w[(i + 1) & 15], w[(i + 14) & 15]);
                    let s0 = xor3(
                        _mm512_ror_epi32::<7>(w15),
                        _mm512_ror_epi32::<18>(w15),
                        _mm512_srli_epi32::<3>(w15),
                    );
                    let s1 = xor3(
                        _mm512_ror_epi32::<17>(w2),
                        _mm512_ror_epi32::<19>(w2),
                        _mm512_srli_epi32::<10>(w2),
                    );
                    w[i & 15] = _mm512_add_epi32(
                        _mm512_add_epi32(w[i & 15], s0),
                        _mm512_add_epi32(w[(i + 9) & 15], s1),
                    );
                }
                let s1 = xor3(
                    _mm512_ror_epi32::<6>(e),
                    _mm512_ror_epi32::<11>(e),
                    _mm512_ror_epi32::<25>(e),
                );
                let ch = _mm512_ternarylogic_epi32::<0xCA>(e, f, g);
                let wk = _mm512_add_epi32(w[i & 15], _mm512_set1_epi32(K[i] as i32));
                let t1 = _mm512_add_epi32(_mm512_add_epi32(h, s1), _mm512_add_epi32(ch, wk));
                let s0 = xor3(
                    _mm512_ror_epi32::<2>(a),
                    _mm512_ror_epi32::<13>(a),
                    _mm512_ror_epi32::<22>(a),
                );
                let maj = _mm512_ternarylogic_epi32::<0xE8>(a, b_, c);
                h = g;
                g = f;
                f = e;
                e = _mm512_add_epi32(d, t1);
                d = c;
                c = b_;
                b_ = a;
                a = _mm512_add_epi32(t1, _mm512_add_epi32(s0, maj));
            }
            for (sum, add) in state.iter_mut().zip([a, b_, c, d, e, f, g, h]) {
                *sum = _mm512_add_epi32(*sum, add);
            }
        }
        for (row, vector) in words.iter_mut().zip(state) {
            _mm512_storeu_si512(row.as_mut_ptr().cast(), vector);
        }
    }
    core::array::from_fn(|lane| {
        let mut digest = [0u8; 32];
        for (bytes, row) in digest.as_chunks_mut::<4>().0.iter_mut().zip(&words) {
            *bytes = row[lane].to_be_bytes();
        }
        digest
    })
}
