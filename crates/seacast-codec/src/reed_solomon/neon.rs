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
                    *sum = xor3(*sum, from_low, from_high);
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
                sum = xor3(sum, from_low, from_high);
            }
            vst1q_u8(dst.as_mut_ptr().add(off), sum);
            off += WIDTH;
        }
    }
    whole
}

/// `a ^ b ^ c`: one instruction where the target has it.
///
/// # Safety
/// Needs NEON, baseline on aarch64.
#[inline(always)]
unsafe fn xor3(a: uint8x16_t, b: uint8x16_t, c: uint8x16_t) -> uint8x16_t {
    unsafe {
        #[cfg(target_feature = "sha3")]
        return veor3q_u8(a, b, c);
        #[cfg(not(target_feature = "sha3"))]
        veorq_u8(a, veorq_u8(b, c))
    }
}

/// `sum ^ c * x`.
///
/// # Safety
/// Needs NEON, baseline on aarch64.
#[inline(always)]
unsafe fn mul_add(low: uint8x16_t, high: uint8x16_t, x: uint8x16_t, sum: uint8x16_t) -> uint8x16_t {
    unsafe {
        let from_low = vqtbl1q_u8(low, vandq_u8(x, vdupq_n_u8(0x0f)));
        xor3(sum, from_low, vqtbl1q_u8(high, vshrq_n_u8::<4>(x)))
    }
}

/// [`row`] for `G` rows at once, row `g` with the coefficients `coeffs[g *
/// cols..][..cols]`, over the whole pairs of vectors of `len` bytes: from
/// `from` of the sources to `at` of the destinations. A source is loaded and
/// split into its nibbles once for all the rows. Returns the bytes written of
/// each.
///
/// `G` is a constant so that the sums stay in registers: up to eight rows.
pub(super) fn rows<const G: usize>(
    coeffs: &[Coeff],
    srcs: &[&[u8]],
    from: usize,
    at: usize,
    len: usize,
    dsts: &mut [&mut [u8]],
) -> usize {
    let (whole, cols) = (len / (2 * WIDTH) * (2 * WIDTH), srcs.len());
    assert!(dsts.len() == G && coeffs.len() == G * cols);
    assert!(srcs.iter().all(|src| src.len() >= from + whole));
    assert!(dsts.iter().all(|dst| dst.len() >= at + whole));
    // SAFETY: NEON is baseline on aarch64. Every load is below `from + whole` of a
    // source or inside a 32-byte coefficient, of which `coeffs` holds one per
    // row and source, and every store below `at + whole` of a destination,
    // checked above.
    unsafe {
        let nibble = vdupq_n_u8(0x0f);
        for off in (0..whole).step_by(2 * WIDTH) {
            let mut acc = [[vdupq_n_u8(0); 2]; G];
            for (j, src) in srcs.iter().enumerate() {
                let p = src.as_ptr().add(from + off);
                let (x0, x1) = (vld1q_u8(p), vld1q_u8(p.add(WIDTH)));
                let (low0, high0) = (vandq_u8(x0, nibble), vshrq_n_u8::<4>(x0));
                let (low1, high1) = (vandq_u8(x1, nibble), vshrq_n_u8::<4>(x1));
                for (g, sum) in acc.iter_mut().enumerate() {
                    let c = coeffs.get_unchecked(g * cols + j).as_ptr();
                    let (low, high) = (vld1q_u8(c), vld1q_u8(c.add(16)));
                    sum[0] = xor3(sum[0], vqtbl1q_u8(low, low0), vqtbl1q_u8(high, high0));
                    sum[1] = xor3(sum[1], vqtbl1q_u8(low, low1), vqtbl1q_u8(high, high1));
                }
            }
            for (dst, sum) in dsts.iter_mut().zip(&acc) {
                let p = dst.as_mut_ptr().add(at + off);
                vst1q_u8(p, sum[0]);
                vst1q_u8(p.add(WIDTH), sum[1]);
            }
        }
    }
    whole
}

/// `g ^= c * h`, then `h ^= g`, over the whole vectors of `g`: both in one pass
/// over the two. Returns the bytes done, the caller's to finish.
pub(super) fn butterfly(c: &Coeff, g: &mut [u8], h: &mut [u8]) -> usize {
    let whole = g.len() / WIDTH * WIDTH;
    assert!(h.len() >= whole);
    // SAFETY: NEON is baseline on aarch64. Every load and store is below `whole`
    // of `g` and `h`, checked above, or inside the 32-byte coefficient.
    unsafe {
        let (low, high) = (vld1q_u8(c.as_ptr()), vld1q_u8(c.as_ptr().add(16)));
        for off in (0..whole).step_by(WIDTH) {
            let (gp, hp) = (g.as_mut_ptr().add(off), h.as_mut_ptr().add(off));
            let y = vld1q_u8(hp);
            let x = mul_add(low, high, y, vld1q_u8(gp));
            vst1q_u8(gp, x);
            vst1q_u8(hp, veorq_u8(x, y));
        }
    }
    whole
}

/// The reverse of [`butterfly`]: `h ^= g`, then `g ^= c * h`.
pub(super) fn butterfly_back(c: &Coeff, g: &mut [u8], h: &mut [u8]) -> usize {
    let whole = g.len() / WIDTH * WIDTH;
    assert!(h.len() >= whole);
    // SAFETY: as in `butterfly`.
    unsafe {
        let (low, high) = (vld1q_u8(c.as_ptr()), vld1q_u8(c.as_ptr().add(16)));
        for off in (0..whole).step_by(WIDTH) {
            let (gp, hp) = (g.as_mut_ptr().add(off), h.as_mut_ptr().add(off));
            let x = vld1q_u8(gp);
            let y = veorq_u8(x, vld1q_u8(hp));
            vst1q_u8(hp, y);
            vst1q_u8(gp, mul_add(low, high, y, x));
        }
    }
    whole
}
