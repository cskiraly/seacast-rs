//! SHA-256 compression with the SHA extensions (SHA-NI).

use core::arch::x86_64::*;

use super::K;

/// Absorb `blocks`, a whole number of 64-byte blocks, into `state`.
#[target_feature(enable = "sha,sse4.1,ssse3")]
pub(crate) fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    let (blocks, rest) = blocks.as_chunks::<64>();
    debug_assert!(rest.is_empty());
    // SAFETY: every load and store is unaligned, inside `state`, `K` or a 64-byte
    // block.
    unsafe {
        let swap = _mm_set_epi64x(0x0c0d0e0f08090a0b, 0x0405060700010203);
        // The rounds want the state as (ABEF, CDGH).
        let dcba = _mm_loadu_si128(state.as_ptr().cast());
        let hgfe = _mm_loadu_si128(state.as_ptr().add(4).cast());
        let cdab = _mm_shuffle_epi32(dcba, 0xB1);
        let efgh = _mm_shuffle_epi32(hgfe, 0x1B);
        let mut abef = _mm_alignr_epi8(cdab, efgh, 8);
        let mut cdgh = _mm_blend_epi16(efgh, cdab, 0xF0);

        for block in blocks {
            let (abef_in, cdgh_in) = (abef, cdgh);
            let mut m: [__m128i; 4] = core::array::from_fn(|i| {
                _mm_shuffle_epi8(_mm_loadu_si128(block.as_ptr().add(16 * i).cast()), swap)
            });
            for i in 0..16 {
                // Four rounds per step: the schedule's next four words from the last sixteen.
                if i >= 4 {
                    let tail = _mm_alignr_epi8(m[3], m[2], 4);
                    let head = _mm_add_epi32(_mm_sha256msg1_epu32(m[0], m[1]), tail);
                    m[0] = _mm_sha256msg2_epu32(head, m[3]);
                }
                let wk = _mm_add_epi32(m[0], _mm_loadu_si128(K.as_ptr().add(4 * i).cast()));
                cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
                abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32(wk, 0x0E));
                // The oldest four words first: by position, so that they stay in registers.
                m = [m[1], m[2], m[3], m[0]];
            }
            abef = _mm_add_epi32(abef, abef_in);
            cdgh = _mm_add_epi32(cdgh, cdgh_in);
        }

        let feba = _mm_shuffle_epi32(abef, 0x1B);
        let dchg = _mm_shuffle_epi32(cdgh, 0xB1);
        _mm_storeu_si128(state.as_mut_ptr().cast(), _mm_blend_epi16(feba, dchg, 0xF0));
        _mm_storeu_si128(state.as_mut_ptr().add(4).cast(), _mm_alignr_epi8(dchg, feba, 8));
    }
}

/// [`compress`] for `S` states at once, each over its own `blocks`, all the
/// same whole number of 64-byte blocks. The rounds of one message wait on each
/// other and those of different messages do not, so several go through in the
/// time of one.
///
/// With `avx` for its three-operand encoding, which spares the copies that more
/// states than registers cost.
#[target_feature(enable = "sha,sse4.1,ssse3,avx")]
fn compress_many<const S: usize>(states: &mut [[u32; 8]; S], blocks: [&[u8]; S]) {
    let count = blocks[0].len() / 64;
    assert!(blocks.iter().all(|b| b.len() == 64 * count));
    // SAFETY: as in `compress`; every block read is inside its slice, checked
    // above.
    unsafe {
        let swap = _mm_set_epi64x(0x0c0d0e0f08090a0b, 0x0405060700010203);
        let mut abef = [_mm_setzero_si128(); S];
        let mut cdgh = [_mm_setzero_si128(); S];
        for (s, state) in states.iter().enumerate() {
            let dcba = _mm_loadu_si128(state.as_ptr().cast());
            let hgfe = _mm_loadu_si128(state.as_ptr().add(4).cast());
            let cdab = _mm_shuffle_epi32(dcba, 0xB1);
            let efgh = _mm_shuffle_epi32(hgfe, 0x1B);
            abef[s] = _mm_alignr_epi8(cdab, efgh, 8);
            cdgh[s] = _mm_blend_epi16(efgh, cdab, 0xF0);
        }
        for b in 0..count {
            let (abef_in, cdgh_in) = (abef, cdgh);
            let mut m: [[__m128i; 4]; S] = core::array::from_fn(|s| {
                let block = blocks[s].as_ptr().add(64 * b);
                core::array::from_fn(|i| {
                    _mm_shuffle_epi8(_mm_loadu_si128(block.add(16 * i).cast()), swap)
                })
            });
            for i in 0..16 {
                let k = _mm_loadu_si128(K.as_ptr().add(4 * i).cast());
                for (s, m) in m.iter_mut().enumerate() {
                    if i >= 4 {
                        let tail = _mm_alignr_epi8(m[(i + 3) % 4], m[(i + 2) % 4], 4);
                        let head =
                            _mm_add_epi32(_mm_sha256msg1_epu32(m[i % 4], m[(i + 1) % 4]), tail);
                        m[i % 4] = _mm_sha256msg2_epu32(head, m[(i + 3) % 4]);
                    }
                    let wk = _mm_add_epi32(m[i % 4], k);
                    cdgh[s] = _mm_sha256rnds2_epu32(cdgh[s], abef[s], wk);
                    abef[s] = _mm_sha256rnds2_epu32(abef[s], cdgh[s], _mm_shuffle_epi32(wk, 0x0E));
                }
            }
            for s in 0..S {
                abef[s] = _mm_add_epi32(abef[s], abef_in[s]);
                cdgh[s] = _mm_add_epi32(cdgh[s], cdgh_in[s]);
            }
        }
        for (s, state) in states.iter_mut().enumerate() {
            let feba = _mm_shuffle_epi32(abef[s], 0x1B);
            let dchg = _mm_shuffle_epi32(cdgh[s], 0xB1);
            _mm_storeu_si128(state.as_mut_ptr().cast(), _mm_blend_epi16(feba, dchg, 0xF0));
            _mm_storeu_si128(state.as_mut_ptr().add(4).cast(), _mm_alignr_epi8(dchg, feba, 8));
        }
    }
}

/// Messages [`compress_many`] is given at once, at most: more gain nothing.
pub(crate) const STREAMS: usize = 4;

/// [`compress`] for each of `states` over its own `blocks`: together, up to
/// [`STREAMS`] of them.
#[target_feature(enable = "sha,sse4.1,ssse3,avx")]
pub(crate) fn compress_streams(states: &mut [[u32; 8]], blocks: &[&[u8]]) {
    assert_eq!(states.len(), blocks.len());
    match states.len() {
        4 => compress_many::<4>(states.try_into().unwrap(), blocks.try_into().unwrap()),
        3 => compress_many::<3>(states.try_into().unwrap(), blocks.try_into().unwrap()),
        2 => compress_many::<2>(states.try_into().unwrap(), blocks.try_into().unwrap()),
        _ => {
            for (state, blocks) in states.iter_mut().zip(blocks) {
                compress(state, blocks);
            }
        }
    }
}
