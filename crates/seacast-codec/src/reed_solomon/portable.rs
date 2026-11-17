//! `GF(2^8)` row combination with no vector instructions: the arm of a target
//! none of the others covers. The products come from the full table, which also
//! finishes every arm's tail.

/// The constant itself: its products are a row of the multiplication table.
pub(super) type Coeff = u8;

#[inline]
pub(super) fn coeff(c: u8) -> Coeff {
    c
}

/// A map linear over `GF(2)` in place of a product. Nothing reads it: no
/// function here that takes one does any byte.
#[inline]
pub(super) fn linear(_images: [u8; 8]) -> Coeff {
    0
}

/// `dst[i] = sum_j coeffs[j] * srcs[j][at + i]`. Returns the bytes written: all
/// of them.
pub(super) fn row(coeffs: &[Coeff], srcs: &[&[u8]], at: usize, dst: &mut [u8]) -> usize {
    super::scalar_row(coeffs, srcs, at, dst);
    dst.len()
}

/// `g ^= c * h`, then `h ^= g`. Returns the bytes done: none, the table
/// finishes them.
pub(super) fn butterfly(_c: &Coeff, _g: &mut [u8], _h: &mut [u8]) -> usize {
    0
}

/// The reverse of [`butterfly`].
pub(super) fn butterfly_back(_c: &Coeff, _g: &mut [u8], _h: &mut [u8]) -> usize {
    0
}

/// [`butterfly`] over the two planes of `GF(2^16)` symbols. Returns the bytes
/// done: none, the table finishes them.
pub(super) fn butterfly2(
    _c: &[Coeff; 4],
    _g0: &mut [u8],
    _g1: &mut [u8],
    _h0: &mut [u8],
    _h1: &mut [u8],
) -> usize {
    0
}

/// The reverse of [`butterfly2`].
pub(super) fn butterfly2_back(
    _c: &[Coeff; 4],
    _g0: &mut [u8],
    _g1: &mut [u8],
    _h0: &mut [u8],
    _h1: &mut [u8],
) -> usize {
    0
}
