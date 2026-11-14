//! SHA-256 compression with the ARMv8 SHA2 instructions.

use core::arch::aarch64::*;

use super::K;

/// Absorb `blocks`, a whole number of 64-byte blocks, into `state`.
pub(crate) fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    let (blocks, rest) = blocks.as_chunks::<64>();
    debug_assert!(rest.is_empty());
    // SAFETY: the module is compiled only with `sha2` enabled, and every load and
    // store is inside `state`, `K` or a 64-byte block.
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
