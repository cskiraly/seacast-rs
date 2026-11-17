//! `GF(2^8)` row combination with AVX2: a product is two 16-entry lookups, one
//! per nibble of the input, each a `PSHUFB`.

use core::arch::x86_64::*;

use super::{linear_tables, nibble_tables};

/// A constant's products with the sixteen low nibbles, then with the sixteen
/// high ones.
pub(super) type Coeff = [u8; 32];

/// Bytes a vector holds: `row` handles whole vectors only.
const WIDTH: usize = 32;

#[inline]
pub(super) fn coeff(c: u8) -> Coeff {
    nibble_tables(c)
}

/// The map linear over `GF(2)` that takes bit `j` of a byte to `images[j]`, in
/// place of a product.
#[inline]
pub(super) fn linear(images: [u8; 8]) -> Coeff {
    linear_tables(images)
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

/// `c * x`.
///
/// # Safety
/// Needs `avx2`, which the module is compiled only with.
#[inline(always)]
unsafe fn mul(low: __m256i, high: __m256i, x: __m256i) -> __m256i {
    unsafe {
        let nibble = _mm256_set1_epi8(0x0f);
        let from_low = _mm256_shuffle_epi8(low, _mm256_and_si256(x, nibble));
        let from_high =
            _mm256_shuffle_epi8(high, _mm256_and_si256(_mm256_srli_epi64::<4>(x), nibble));
        _mm256_xor_si256(from_low, from_high)
    }
}

/// `g ^= c * h`, then `h ^= g`, over the whole vectors of `g`: both in one pass
/// over the two. Returns the bytes done, the caller's to finish.
pub(super) fn butterfly(c: &Coeff, g: &mut [u8], h: &mut [u8]) -> usize {
    let whole = g.len() / WIDTH * WIDTH;
    assert!(h.len() >= whole);
    // SAFETY: the module is compiled only with `avx2` enabled. Every load and
    // store is below `whole` of `g` and `h`, checked above, or inside the 32-byte
    // coefficient.
    unsafe {
        let low = _mm256_broadcastsi128_si256(_mm_loadu_si128(c.as_ptr().cast()));
        let high = _mm256_broadcastsi128_si256(_mm_loadu_si128(c.as_ptr().add(16).cast()));
        for off in (0..whole).step_by(WIDTH) {
            let (gp, hp) = (g.as_mut_ptr().add(off), h.as_mut_ptr().add(off));
            let y = _mm256_loadu_si256(hp.cast());
            let x = _mm256_xor_si256(_mm256_loadu_si256(gp.cast()), mul(low, high, y));
            _mm256_storeu_si256(gp.cast(), x);
            _mm256_storeu_si256(hp.cast(), _mm256_xor_si256(x, y));
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
        let low = _mm256_broadcastsi128_si256(_mm_loadu_si128(c.as_ptr().cast()));
        let high = _mm256_broadcastsi128_si256(_mm_loadu_si128(c.as_ptr().add(16).cast()));
        for off in (0..whole).step_by(WIDTH) {
            let (gp, hp) = (g.as_mut_ptr().add(off), h.as_mut_ptr().add(off));
            let x = _mm256_loadu_si256(gp.cast());
            let y = _mm256_xor_si256(x, _mm256_loadu_si256(hp.cast()));
            _mm256_storeu_si256(hp.cast(), y);
            _mm256_storeu_si256(gp.cast(), _mm256_xor_si256(x, mul(low, high, y)));
        }
    }
    whole
}

/// [`butterfly`] over the two planes of `GF(2^16)` symbols, whose product by a
/// constant is `(c[0] h0 + c[1] h1, c[2] h0 + c[3] h1)`, each `c` a [`linear`]
/// map. Returns the
/// bytes done of each plane.
pub(super) fn butterfly2(
    c: &[Coeff; 4],
    g0: &mut [u8],
    g1: &mut [u8],
    h0: &mut [u8],
    h1: &mut [u8],
) -> usize {
    let whole = g0.len() / WIDTH * WIDTH;
    assert!(g1.len() >= whole && h0.len() >= whole && h1.len() >= whole);
    // SAFETY: the module is compiled only with `avx2` enabled. Every load and
    // store is below `whole` of a plane, checked above, or inside a 32-byte
    // coefficient.
    unsafe {
        let low = c.map(|c| _mm256_broadcastsi128_si256(_mm_loadu_si128(c.as_ptr().cast())));
        let high =
            c.map(|c| _mm256_broadcastsi128_si256(_mm_loadu_si128(c.as_ptr().add(16).cast())));
        for off in (0..whole).step_by(WIDTH) {
            let (g0, g1) = (g0.as_mut_ptr().add(off), g1.as_mut_ptr().add(off));
            let (h0, h1) = (h0.as_mut_ptr().add(off), h1.as_mut_ptr().add(off));
            let (y0, y1) = (_mm256_loadu_si256(h0.cast()), _mm256_loadu_si256(h1.cast()));
            let x0 = _mm256_xor_si256(
                _mm256_loadu_si256(g0.cast()),
                _mm256_xor_si256(mul(low[0], high[0], y0), mul(low[1], high[1], y1)),
            );
            let x1 = _mm256_xor_si256(
                _mm256_loadu_si256(g1.cast()),
                _mm256_xor_si256(mul(low[2], high[2], y0), mul(low[3], high[3], y1)),
            );
            _mm256_storeu_si256(g0.cast(), x0);
            _mm256_storeu_si256(g1.cast(), x1);
            _mm256_storeu_si256(h0.cast(), _mm256_xor_si256(x0, y0));
            _mm256_storeu_si256(h1.cast(), _mm256_xor_si256(x1, y1));
        }
    }
    whole
}

/// The reverse of [`butterfly2`].
pub(super) fn butterfly2_back(
    c: &[Coeff; 4],
    g0: &mut [u8],
    g1: &mut [u8],
    h0: &mut [u8],
    h1: &mut [u8],
) -> usize {
    let whole = g0.len() / WIDTH * WIDTH;
    assert!(g1.len() >= whole && h0.len() >= whole && h1.len() >= whole);
    // SAFETY: as in `butterfly2`.
    unsafe {
        let low = c.map(|c| _mm256_broadcastsi128_si256(_mm_loadu_si128(c.as_ptr().cast())));
        let high =
            c.map(|c| _mm256_broadcastsi128_si256(_mm_loadu_si128(c.as_ptr().add(16).cast())));
        for off in (0..whole).step_by(WIDTH) {
            let (g0, g1) = (g0.as_mut_ptr().add(off), g1.as_mut_ptr().add(off));
            let (h0, h1) = (h0.as_mut_ptr().add(off), h1.as_mut_ptr().add(off));
            let (x0, x1) = (_mm256_loadu_si256(g0.cast()), _mm256_loadu_si256(g1.cast()));
            let y0 = _mm256_xor_si256(x0, _mm256_loadu_si256(h0.cast()));
            let y1 = _mm256_xor_si256(x1, _mm256_loadu_si256(h1.cast()));
            _mm256_storeu_si256(h0.cast(), y0);
            _mm256_storeu_si256(h1.cast(), y1);
            let x0 = _mm256_xor_si256(
                x0,
                _mm256_xor_si256(mul(low[0], high[0], y0), mul(low[1], high[1], y1)),
            );
            let x1 = _mm256_xor_si256(
                x1,
                _mm256_xor_si256(mul(low[2], high[2], y0), mul(low[3], high[3], y1)),
            );
            _mm256_storeu_si256(g0.cast(), x0);
            _mm256_storeu_si256(g1.cast(), x1);
        }
    }
    whole
}
