//! `GF(2^8)` row combination with GFNI on 512-bit vectors.
//!
//! Multiplying by a constant is linear over `GF(2)`: one `GF2P8AFFINEQB` with
//! the constant's bit matrix, whatever the field's polynomial.

use core::arch::x86_64::*;

use super::TABLES;

/// The bit matrix of a multiplication, as `GF2P8AFFINEQB` reads it.
pub(super) type Coeff = u64;

/// Bytes a vector holds: `row` handles whole vectors only.
const WIDTH: usize = 64;

const fn matrix(c: u8) -> u64 {
    // Output bit `i` is the parity of the input under byte `7 - i` of the matrix.
    let mut m = 0u64;
    let mut j = 0;
    while j < 8 {
        let product = TABLES.mul(c, 1 << j);
        let mut i = 0;
        while i < 8 {
            if (product >> i) & 1 == 1 {
                m |= 1 << (8 * (7 - i) + j);
            }
            i += 1;
        }
        j += 1;
    }
    m
}

static MATRIX: [u64; 256] = {
    let mut out = [0u64; 256];
    let mut c = 0;
    while c < 256 {
        out[c] = matrix(c as u8);
        c += 1;
    }
    out
};

#[inline]
pub(super) fn coeff(c: u8) -> Coeff {
    MATRIX[c as usize]
}

/// `dst[i] = sum_j coeffs[j] * srcs[j][at + i]` over the whole vectors of
/// `dst`. Returns the bytes written, the caller's to finish.
pub(super) fn row(coeffs: &[Coeff], srcs: &[&[u8]], at: usize, dst: &mut [u8]) -> usize {
    let whole = dst.len() / WIDTH * WIDTH;
    assert_eq!(coeffs.len(), srcs.len());
    assert!(srcs.iter().all(|src| src.len() >= at + whole));
    // SAFETY: the module is compiled only with `gfni` and `avx512f` enabled. Every
    // load is below `at + whole` of a source, checked above, and every store
    // below `whole` of `dst`.
    unsafe {
        let mut off = 0;
        // Four vectors a pass: four independent sums, and each source read in one run.
        while off + 4 * WIDTH <= whole {
            let mut acc = [_mm512_setzero_si512(); 4];
            for (&c, src) in coeffs.iter().zip(srcs) {
                let m = _mm512_set1_epi64(c as i64);
                let p = src.as_ptr().add(at + off);
                for (v, sum) in acc.iter_mut().enumerate() {
                    let x = _mm512_loadu_si512(p.add(v * WIDTH).cast());
                    *sum = _mm512_xor_si512(*sum, _mm512_gf2p8affine_epi64_epi8::<0>(x, m));
                }
            }
            for (v, sum) in acc.iter().enumerate() {
                _mm512_storeu_si512(dst.as_mut_ptr().add(off + v * WIDTH).cast(), *sum);
            }
            off += 4 * WIDTH;
        }
        while off < whole {
            let mut sum = _mm512_setzero_si512();
            for (&c, src) in coeffs.iter().zip(srcs) {
                let x = _mm512_loadu_si512(src.as_ptr().add(at + off).cast());
                sum = _mm512_xor_si512(
                    sum,
                    _mm512_gf2p8affine_epi64_epi8::<0>(x, _mm512_set1_epi64(c as i64)),
                );
            }
            _mm512_storeu_si512(dst.as_mut_ptr().add(off).cast(), sum);
            off += WIDTH;
        }
    }
    whole
}
