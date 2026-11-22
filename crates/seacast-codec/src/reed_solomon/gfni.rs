//! `GF(2^8)` row combination with GFNI on 512-bit vectors.
//!
//! Multiplying by a constant is linear over `GF(2)`: one `GF2P8AFFINEQB` with
//! the constant's bit matrix, whatever the field's polynomial.

use core::arch::x86_64::*;

use super::{Caches, Kernel, TABLES};

/// The bit matrix of a multiplication, as `GF2P8AFFINEQB` reads it.
type Coeff = u64;

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
fn coeff(c: u8) -> Coeff {
    MATRIX[c as usize]
}

/// The map linear over `GF(2)` that takes bit `j` of a byte to `images[j]`, in
/// place of a product.
#[inline]
fn linear(images: [u8; 8]) -> Coeff {
    // Bit `i` of byte `j` goes to bit `j` of byte `7 - i`: the transpose of the 8
    // by 8 bits, its bytes reversed.
    let mut x = u64::from_le_bytes(images);
    let mut t = (x ^ (x >> 7)) & 0x00aa_00aa_00aa_00aa;
    x ^= t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000_cccc_0000_cccc;
    x ^= t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x0000_0000_f0f0_f0f0;
    x ^= t ^ (t << 28);
    x.swap_bytes()
}

/// `dst[i] = sum_j coeffs[j] * srcs[j][at + i]` over the whole vectors of
/// `dst`. Returns the bytes written, the caller's to finish.
#[inline]
#[target_feature(enable = "gfni,avx512f")]
fn row(coeffs: &[Coeff], srcs: &[&[u8]], at: usize, dst: &mut [u8]) -> usize {
    let whole = dst.len() / WIDTH * WIDTH;
    assert_eq!(coeffs.len(), srcs.len());
    assert!(srcs.iter().all(|src| src.len() >= at + whole));
    // SAFETY: every load is below `at + whole` of a source, checked above, and
    // every store below `whole` of `dst`.
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

/// `g ^= c * h`, then `h ^= g`, over the whole vectors of `g`: both in one pass
/// over the two. Returns the bytes done, the caller's to finish.
#[target_feature(enable = "gfni,avx512f")]
fn butterfly(c: &Coeff, g: &mut [u8], h: &mut [u8]) -> usize {
    let whole = g.len() / WIDTH * WIDTH;
    assert!(h.len() >= whole);
    // SAFETY: every load and store is below `whole` of `g` and `h`, checked above.
    unsafe {
        let m = _mm512_set1_epi64(*c as i64);
        for off in (0..whole).step_by(WIDTH) {
            let (gp, hp) = (g.as_mut_ptr().add(off), h.as_mut_ptr().add(off));
            let y = _mm512_loadu_si512(hp.cast());
            let x = _mm512_xor_si512(
                _mm512_loadu_si512(gp.cast()),
                _mm512_gf2p8affine_epi64_epi8::<0>(y, m),
            );
            _mm512_storeu_si512(gp.cast(), x);
            _mm512_storeu_si512(hp.cast(), _mm512_xor_si512(x, y));
        }
    }
    whole
}

/// The reverse of [`butterfly`]: `h ^= g`, then `g ^= c * h`.
#[target_feature(enable = "gfni,avx512f")]
fn butterfly_back(c: &Coeff, g: &mut [u8], h: &mut [u8]) -> usize {
    let whole = g.len() / WIDTH * WIDTH;
    assert!(h.len() >= whole);
    // SAFETY: as in `butterfly`.
    unsafe {
        let m = _mm512_set1_epi64(*c as i64);
        for off in (0..whole).step_by(WIDTH) {
            let (gp, hp) = (g.as_mut_ptr().add(off), h.as_mut_ptr().add(off));
            let x = _mm512_loadu_si512(gp.cast());
            let y = _mm512_xor_si512(x, _mm512_loadu_si512(hp.cast()));
            _mm512_storeu_si512(hp.cast(), y);
            let x = _mm512_xor_si512(x, _mm512_gf2p8affine_epi64_epi8::<0>(y, m));
            _mm512_storeu_si512(gp.cast(), x);
        }
    }
    whole
}

/// [`butterfly`] over the two planes of `GF(2^16)` symbols, whose product by a
/// constant is `(c[0] h0 + c[1] h1, c[2] h0 + c[3] h1)`, each `c` a [`linear`]
/// map. Returns the
/// bytes done of each plane.
#[target_feature(enable = "gfni,avx512f")]
fn butterfly2(c: &[Coeff; 4], g0: &mut [u8], g1: &mut [u8], h0: &mut [u8], h1: &mut [u8]) -> usize {
    let whole = g0.len() / WIDTH * WIDTH;
    assert!(g1.len() >= whole && h0.len() >= whole && h1.len() >= whole);
    // SAFETY: every load and store is below `whole` of a plane, checked above.
    unsafe {
        let m = c.map(|c| _mm512_set1_epi64(c as i64));
        for off in (0..whole).step_by(WIDTH) {
            let (g0, g1) = (g0.as_mut_ptr().add(off), g1.as_mut_ptr().add(off));
            let (h0, h1) = (h0.as_mut_ptr().add(off), h1.as_mut_ptr().add(off));
            let (y0, y1) = (_mm512_loadu_si512(h0.cast()), _mm512_loadu_si512(h1.cast()));
            let x0 = _mm512_ternarylogic_epi64::<0x96>(
                _mm512_loadu_si512(g0.cast()),
                _mm512_gf2p8affine_epi64_epi8::<0>(y0, m[0]),
                _mm512_gf2p8affine_epi64_epi8::<0>(y1, m[1]),
            );
            let x1 = _mm512_ternarylogic_epi64::<0x96>(
                _mm512_loadu_si512(g1.cast()),
                _mm512_gf2p8affine_epi64_epi8::<0>(y0, m[2]),
                _mm512_gf2p8affine_epi64_epi8::<0>(y1, m[3]),
            );
            _mm512_storeu_si512(g0.cast(), x0);
            _mm512_storeu_si512(g1.cast(), x1);
            _mm512_storeu_si512(h0.cast(), _mm512_xor_si512(x0, y0));
            _mm512_storeu_si512(h1.cast(), _mm512_xor_si512(x1, y1));
        }
    }
    whole
}

/// The reverse of [`butterfly2`].
#[target_feature(enable = "gfni,avx512f")]
fn butterfly2_back(
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
        let m = c.map(|c| _mm512_set1_epi64(c as i64));
        for off in (0..whole).step_by(WIDTH) {
            let (g0, g1) = (g0.as_mut_ptr().add(off), g1.as_mut_ptr().add(off));
            let (h0, h1) = (h0.as_mut_ptr().add(off), h1.as_mut_ptr().add(off));
            let (x0, x1) = (_mm512_loadu_si512(g0.cast()), _mm512_loadu_si512(g1.cast()));
            let y0 = _mm512_xor_si512(x0, _mm512_loadu_si512(h0.cast()));
            let y1 = _mm512_xor_si512(x1, _mm512_loadu_si512(h1.cast()));
            _mm512_storeu_si512(h0.cast(), y0);
            _mm512_storeu_si512(h1.cast(), y1);
            let x0 = _mm512_ternarylogic_epi64::<0x96>(
                x0,
                _mm512_gf2p8affine_epi64_epi8::<0>(y0, m[0]),
                _mm512_gf2p8affine_epi64_epi8::<0>(y1, m[1]),
            );
            let x1 = _mm512_ternarylogic_epi64::<0x96>(
                x1,
                _mm512_gf2p8affine_epi64_epi8::<0>(y0, m[2]),
                _mm512_gf2p8affine_epi64_epi8::<0>(y1, m[3]),
            );
            _mm512_storeu_si512(g0.cast(), x0);
            _mm512_storeu_si512(g1.cast(), x1);
        }
    }
    whole
}

/// [`row`] for `G` rows at once, row `g` with the coefficients `coeffs[g *
/// cols..][..cols]`, over the whole pairs of vectors of `len` bytes: from
/// `from` of the sources to `at` of the destinations. A source is loaded once
/// for all the rows. Returns the bytes written of each.
///
/// `G` is a constant so that the sums stay in registers: up to eight rows.
#[target_feature(enable = "gfni,avx512f")]
fn rows<const G: usize>(
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
    // SAFETY: every load is below `from + whole` of a source and every store
    // below `at + whole` of a destination, checked above; `coeffs` holds an entry
    // per row and source.
    unsafe {
        for off in (0..whole).step_by(2 * WIDTH) {
            let mut acc = [[_mm512_setzero_si512(); 2]; G];
            for (j, src) in srcs.iter().enumerate() {
                let p = src.as_ptr().add(from + off);
                let x0 = _mm512_loadu_si512(p.cast());
                let x1 = _mm512_loadu_si512(p.add(WIDTH).cast());
                for (g, sum) in acc.iter_mut().enumerate() {
                    let m = _mm512_set1_epi64(*coeffs.get_unchecked(g * cols + j) as i64);
                    sum[0] = _mm512_xor_si512(sum[0], _mm512_gf2p8affine_epi64_epi8::<0>(x0, m));
                    sum[1] = _mm512_xor_si512(sum[1], _mm512_gf2p8affine_epi64_epi8::<0>(x1, m));
                }
            }
            for (dst, sum) in dsts.iter_mut().zip(&acc) {
                let p = dst.as_mut_ptr().add(at + off);
                _mm512_storeu_si512(p.cast(), sum[0]);
                _mm512_storeu_si512(p.add(WIDTH).cast(), sum[1]);
            }
        }
    }
    whole
}

/// `h ^= g`.
#[target_feature(enable = "gfni,avx512f")]
fn xor(g: &[u8], h: &mut [u8]) {
    for (h, &g) in h.iter_mut().zip(g) {
        *h ^= g;
    }
}

#[derive(Clone, Copy)]
pub(super) struct Gfni;

static CACHES: Caches<Gfni> = Caches::new();

// SAFETY, every call below: the kernel is used only where `supported` holds.
impl Kernel for Gfni {
    type Coeff = Coeff;

    const FFT_FROM_HALF_ROWS: usize = 8;
    const GATHER: bool = false;

    fn supported() -> bool {
        is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx512f")
    }

    fn caches() -> &'static Caches<Self> {
        &CACHES
    }

    #[inline]
    fn coeff(c: u8) -> Coeff {
        coeff(c)
    }

    #[inline]
    fn linear(images: [u8; 8]) -> Coeff {
        linear(images)
    }

    #[inline]
    fn row(coeffs: &[Coeff], srcs: &[&[u8]], at: usize, dst: &mut [u8]) -> usize {
        unsafe { row(coeffs, srcs, at, dst) }
    }

    #[inline]
    fn rows<const G: usize>(
        coeffs: &[Coeff],
        srcs: &[&[u8]],
        from: usize,
        at: usize,
        len: usize,
        dsts: &mut [&mut [u8]],
    ) -> usize {
        unsafe { rows::<G>(coeffs, srcs, from, at, len, dsts) }
    }

    #[inline]
    fn xor(g: &[u8], h: &mut [u8]) {
        unsafe { xor(g, h) }
    }

    #[inline]
    fn butterfly(c: &Coeff, g: &mut [u8], h: &mut [u8]) -> usize {
        unsafe { butterfly(c, g, h) }
    }

    #[inline]
    fn butterfly_back(c: &Coeff, g: &mut [u8], h: &mut [u8]) -> usize {
        unsafe { butterfly_back(c, g, h) }
    }

    #[inline]
    fn butterfly2(
        c: &[Coeff; 4],
        g0: &mut [u8],
        g1: &mut [u8],
        h0: &mut [u8],
        h1: &mut [u8],
    ) -> usize {
        unsafe { butterfly2(c, g0, g1, h0, h1) }
    }

    #[inline]
    fn butterfly2_back(
        c: &[Coeff; 4],
        g0: &mut [u8],
        g1: &mut [u8],
        h0: &mut [u8],
        h1: &mut [u8],
    ) -> usize {
        unsafe { butterfly2_back(c, g0, g1, h0, h1) }
    }
}
