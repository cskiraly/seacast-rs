//! `GF(2^8)` row combination with NEON: a product is two 16-entry lookups, one
//! per nibble of the input, each a `TBL`.

use core::arch::aarch64::*;

use super::nibble_tables;

/// A constant's products with the sixteen low nibbles, then with the sixteen
/// high ones.
pub(super) type Coeff = [u8; 32];

/// Bytes a vector holds: `row` handles whole vectors only.
const WIDTH: usize = 16;

#[inline]
pub(super) fn coeff(c: u8) -> Coeff {
    nibble_tables(c)
}

/// `dst[i] = sum_j coeffs[j] * srcs[j][at + i]` over the whole vectors of
/// `dst`. Returns the bytes written, the caller's to finish.
pub(super) fn row(coeffs: &[Coeff], srcs: &[&[u8]], at: usize, dst: &mut [u8]) -> usize {
    let whole = dst.len() / WIDTH * WIDTH;
    assert_eq!(coeffs.len(), srcs.len());
    assert!(srcs.iter().all(|src| src.len() >= at + whole));
    // SAFETY: NEON is baseline on aarch64. Every load is below `at + whole` of a
    // source, checked above, or inside a 32-byte coefficient, and every store
    // below `whole` of `dst`.
    unsafe {
        let nibble = vdupq_n_u8(0x0f);
        let mut off = 0;
        // Four vectors a pass: four independent sums, and each source read in one run.
        while off + 4 * WIDTH <= whole {
            let mut acc = [vdupq_n_u8(0); 4];
            for (c, src) in coeffs.iter().zip(srcs) {
                let (low, high) = (vld1q_u8(c.as_ptr()), vld1q_u8(c.as_ptr().add(16)));
                let p = src.as_ptr().add(at + off);
                for (v, sum) in acc.iter_mut().enumerate() {
                    let x = vld1q_u8(p.add(v * WIDTH));
                    let from_low = vqtbl1q_u8(low, vandq_u8(x, nibble));
                    let from_high = vqtbl1q_u8(high, vshrq_n_u8::<4>(x));
                    *sum = veorq_u8(*sum, veorq_u8(from_low, from_high));
                }
            }
            for (v, sum) in acc.iter().enumerate() {
                vst1q_u8(dst.as_mut_ptr().add(off + v * WIDTH), *sum);
            }
            off += 4 * WIDTH;
        }
        while off < whole {
            let mut sum = vdupq_n_u8(0);
            for (c, src) in coeffs.iter().zip(srcs) {
                let (low, high) = (vld1q_u8(c.as_ptr()), vld1q_u8(c.as_ptr().add(16)));
                let x = vld1q_u8(src.as_ptr().add(at + off));
                let from_low = vqtbl1q_u8(low, vandq_u8(x, nibble));
                let from_high = vqtbl1q_u8(high, vshrq_n_u8::<4>(x));
                sum = veorq_u8(sum, veorq_u8(from_low, from_high));
            }
            vst1q_u8(dst.as_mut_ptr().add(off), sum);
            off += WIDTH;
        }
    }
    whole
}
