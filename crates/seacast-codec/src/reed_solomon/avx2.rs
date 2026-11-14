//! `GF(2^8)` row combination with AVX2: a product is two 16-entry lookups, one
//! per nibble of the input, each a `PSHUFB`.

use core::arch::x86_64::*;

use super::nibble_tables;

/// A constant's products with the sixteen low nibbles, then with the sixteen
/// high ones.
pub(super) type Coeff = [u8; 32];

/// Bytes a vector holds: `row` handles whole vectors only.
const WIDTH: usize = 32;

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
    // SAFETY: the module is compiled only with `avx2` enabled. Every load is below
    // `at + whole` of a source, checked above, or inside a 32-byte coefficient,
    // and every store below `whole` of `dst`.
    unsafe {
        let nibble = _mm256_set1_epi8(0x0f);
        let mut off = 0;
        // Two vectors a pass: two independent sums, and each source read in one run.
        while off + 2 * WIDTH <= whole {
            let mut acc = [_mm256_setzero_si256(); 2];
            for (c, src) in coeffs.iter().zip(srcs) {
                let low = _mm256_broadcastsi128_si256(_mm_loadu_si128(c.as_ptr().cast()));
                let high = _mm256_broadcastsi128_si256(_mm_loadu_si128(c.as_ptr().add(16).cast()));
                let p = src.as_ptr().add(at + off);
                for (v, sum) in acc.iter_mut().enumerate() {
                    let x = _mm256_loadu_si256(p.add(v * WIDTH).cast());
                    let from_low = _mm256_shuffle_epi8(low, _mm256_and_si256(x, nibble));
                    let from_high = _mm256_shuffle_epi8(
                        high,
                        _mm256_and_si256(_mm256_srli_epi64::<4>(x), nibble),
                    );
                    *sum = _mm256_xor_si256(*sum, _mm256_xor_si256(from_low, from_high));
                }
            }
            for (v, sum) in acc.iter().enumerate() {
                _mm256_storeu_si256(dst.as_mut_ptr().add(off + v * WIDTH).cast(), *sum);
            }
            off += 2 * WIDTH;
        }
        while off < whole {
            let mut sum = _mm256_setzero_si256();
            for (c, src) in coeffs.iter().zip(srcs) {
                let low = _mm256_broadcastsi128_si256(_mm_loadu_si128(c.as_ptr().cast()));
                let high = _mm256_broadcastsi128_si256(_mm_loadu_si128(c.as_ptr().add(16).cast()));
                let x = _mm256_loadu_si256(src.as_ptr().add(at + off).cast());
                let from_low = _mm256_shuffle_epi8(low, _mm256_and_si256(x, nibble));
                let from_high =
                    _mm256_shuffle_epi8(high, _mm256_and_si256(_mm256_srli_epi64::<4>(x), nibble));
                sum = _mm256_xor_si256(sum, _mm256_xor_si256(from_low, from_high));
            }
            _mm256_storeu_si256(dst.as_mut_ptr().add(off).cast(), sum);
            off += WIDTH;
        }
    }
    whole
}
