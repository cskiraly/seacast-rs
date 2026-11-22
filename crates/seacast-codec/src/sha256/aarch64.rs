//! SHA-256 compression with the ARMv8 SHA2 instructions.

use core::arch::aarch64::*;

use super::K;

/// Absorb `blocks`, a whole number of 64-byte blocks, into `state`.
#[target_feature(enable = "sha2")]
pub(crate) fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    let (blocks, rest) = blocks.as_chunks::<64>();
    debug_assert!(rest.is_empty());
    // SAFETY: every load and store is inside `state`, `K` or a 64-byte block.
    unsafe {
        let mut abcd = vld1q_u32(state.as_ptr());
        let mut efgh = vld1q_u32(state.as_ptr().add(4));
        for block in blocks {
            let (abcd_in, efgh_in) = (abcd, efgh);
            let mut m: [uint32x4_t; 4] = core::array::from_fn(|i| {
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(16 * i))))
            });
            for i in 0..16 {
                // Four rounds per step: the schedule's next four words from the last sixteen.
                if i >= 4 {
                    let head = vsha256su0q_u32(m[i % 4], m[(i + 1) % 4]);
                    m[i % 4] = vsha256su1q_u32(head, m[(i + 2) % 4], m[(i + 3) % 4]);
                }
                let wk = vaddq_u32(m[i % 4], vld1q_u32(K.as_ptr().add(4 * i)));
                let abcd_before = abcd;
                abcd = vsha256hq_u32(abcd, efgh, wk);
                efgh = vsha256h2q_u32(efgh, abcd_before, wk);
            }
            abcd = vaddq_u32(abcd, abcd_in);
            efgh = vaddq_u32(efgh, efgh_in);
        }
        vst1q_u32(state.as_mut_ptr(), abcd);
        vst1q_u32(state.as_mut_ptr().add(4), efgh);
    }
}

/// [`compress`] for `S` states at once, each over its own `blocks`, all the
/// same whole number of 64-byte blocks. The rounds of one message wait on each
/// other and those of different messages do not, so several go through in the
/// time of one.
#[target_feature(enable = "sha2")]
fn compress_many<const S: usize>(states: &mut [[u32; 8]; S], blocks: [&[u8]; S]) {
    let count = blocks[0].len() / 64;
    assert!(blocks.iter().all(|b| b.len() == 64 * count));
    // SAFETY: as in `compress`; every block read is inside its slice, checked
    // above.
    unsafe {
        let mut abcd: [uint32x4_t; S] = core::array::from_fn(|s| vld1q_u32(states[s].as_ptr()));
        let mut efgh: [uint32x4_t; S] =
            core::array::from_fn(|s| vld1q_u32(states[s].as_ptr().add(4)));
        for b in 0..count {
            let (abcd_in, efgh_in) = (abcd, efgh);
            let mut m: [[uint32x4_t; 4]; S] = core::array::from_fn(|s| {
                let block = blocks[s].as_ptr().add(64 * b);
                core::array::from_fn(|i| {
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.add(16 * i))))
                })
            });
            for i in 0..16 {
                let k = vld1q_u32(K.as_ptr().add(4 * i));
                for (s, m) in m.iter_mut().enumerate() {
                    if i >= 4 {
                        let head = vsha256su0q_u32(m[i % 4], m[(i + 1) % 4]);
                        m[i % 4] = vsha256su1q_u32(head, m[(i + 2) % 4], m[(i + 3) % 4]);
                    }
                    let wk = vaddq_u32(m[i % 4], k);
                    let abcd_before = abcd[s];
                    abcd[s] = vsha256hq_u32(abcd[s], efgh[s], wk);
                    efgh[s] = vsha256h2q_u32(efgh[s], abcd_before, wk);
                }
            }
            for s in 0..S {
                abcd[s] = vaddq_u32(abcd[s], abcd_in[s]);
                efgh[s] = vaddq_u32(efgh[s], efgh_in[s]);
            }
        }
        for (s, state) in states.iter_mut().enumerate() {
            vst1q_u32(state.as_mut_ptr(), abcd[s]);
            vst1q_u32(state.as_mut_ptr().add(4), efgh[s]);
        }
    }
}

/// Messages [`compress_many`] is given at once, at most.
pub(crate) const STREAMS: usize = 4;

/// [`compress`] for each of `states` over its own `blocks`: together, up to
/// [`STREAMS`] of them.
#[target_feature(enable = "sha2")]
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
