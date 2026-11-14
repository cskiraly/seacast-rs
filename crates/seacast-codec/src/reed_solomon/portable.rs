//! `GF(2^8)` row combination with no vector instructions: the arm of a target
//! none of the others covers. The products come from the full table, which also
//! finishes every arm's tail.

/// The constant itself: its products are a row of the multiplication table.
pub(super) type Coeff = u8;

#[inline]
pub(super) fn coeff(c: u8) -> Coeff {
    c
}

/// `dst[i] = sum_j coeffs[j] * srcs[j][at + i]`. Returns the bytes written: all
/// of them.
pub(super) fn row(coeffs: &[Coeff], srcs: &[&[u8]], at: usize, dst: &mut [u8]) -> usize {
    super::scalar_row(coeffs, srcs, at, dst);
    dst.len()
}
