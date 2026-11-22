//! `GF(2^8)` row combination with no vector instructions: the arm of a target
//! none of the others covers. The products come from the full table, which also
//! finishes every arm's tail.

use super::{Caches, Kernel};

/// The constant itself: its products are a row of the multiplication table.
type Coeff = u8;

#[inline]
fn coeff(c: u8) -> Coeff {
    c
}

/// A map linear over `GF(2)` in place of a product. Nothing reads it: no
/// function here that takes one does any byte.
#[inline]
fn linear(_images: [u8; 8]) -> Coeff {
    0
}

/// `dst[i] = sum_j coeffs[j] * srcs[j][at + i]`. Returns the bytes written: all
/// of them.
fn row(coeffs: &[Coeff], srcs: &[&[u8]], at: usize, dst: &mut [u8]) -> usize {
    super::scalar_row(coeffs, srcs, at, dst);
    dst.len()
}

/// `g ^= c * h`, then `h ^= g`. Returns the bytes done: none, the table
/// finishes them.
fn butterfly(_c: &Coeff, _g: &mut [u8], _h: &mut [u8]) -> usize {
    0
}

/// The reverse of [`butterfly`].
fn butterfly_back(_c: &Coeff, _g: &mut [u8], _h: &mut [u8]) -> usize {
    0
}

/// [`butterfly`] over the two planes of `GF(2^16)` symbols. Returns the bytes
/// done: none, the table finishes them.
fn butterfly2(
    _c: &[Coeff; 4],
    _g0: &mut [u8],
    _g1: &mut [u8],
    _h0: &mut [u8],
    _h1: &mut [u8],
) -> usize {
    0
}

/// The reverse of [`butterfly2`].
fn butterfly2_back(
    _c: &[Coeff; 4],
    _g0: &mut [u8],
    _g1: &mut [u8],
    _h0: &mut [u8],
    _h1: &mut [u8],
) -> usize {
    0
}

/// `h ^= g`.
fn xor(g: &[u8], h: &mut [u8]) {
    for (h, &g) in h.iter_mut().zip(g) {
        *h ^= g;
    }
}

#[derive(Clone, Copy)]
pub(super) struct Portable;

static CACHES: Caches<Portable> = Caches::new();

impl Kernel for Portable {
    type Coeff = Coeff;

    const FFT_FROM_HALF_ROWS: usize = 3;
    const GATHER: bool = true;

    fn supported() -> bool {
        true
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
        row(coeffs, srcs, at, dst)
    }

    #[inline]
    fn xor(g: &[u8], h: &mut [u8]) {
        xor(g, h)
    }

    #[inline]
    fn butterfly(c: &Coeff, g: &mut [u8], h: &mut [u8]) -> usize {
        butterfly(c, g, h)
    }

    #[inline]
    fn butterfly_back(c: &Coeff, g: &mut [u8], h: &mut [u8]) -> usize {
        butterfly_back(c, g, h)
    }

    #[inline]
    fn butterfly2(
        c: &[Coeff; 4],
        g0: &mut [u8],
        g1: &mut [u8],
        h0: &mut [u8],
        h1: &mut [u8],
    ) -> usize {
        butterfly2(c, g0, g1, h0, h1)
    }

    #[inline]
    fn butterfly2_back(
        c: &[Coeff; 4],
        g0: &mut [u8],
        g1: &mut [u8],
        h0: &mut [u8],
        h1: &mut [u8],
    ) -> usize {
        butterfly2_back(c, g0, g1, h0, h1)
    }
}
