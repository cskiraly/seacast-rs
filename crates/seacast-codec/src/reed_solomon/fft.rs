//! The parity of the `(K, 2K)` code for `K` a power of two, by the additive FFT
//! of Lin, Chung and Han over the basis `1, 2, 4, ..`: `K log K` products a
//! byte where the matrix takes `K^2`.
//!
//! The points `0..2^i` are the span `V_i` of the first `i` basis elements, and
//! a coset of it is `beta ^ V_i`. With `W_i` the polynomial vanishing on `V_i`,
//! scaled so that `W_i(2^i) = 1`, a polynomial below degree `2^k` is written
//! `f = g + W_(k-1) . h`, both below degree `2^(k-1)`. `W_i` is linear over
//! `GF(2)` and constant on a coset of `V_i`, so on the two halves of `beta ^
//! V_k` it is `w = W_(k-1)(beta)` and `w + 1`: `f = g + w . h` on the low half
//! and that plus `h` on the high one. The data are the values on `V_K`'s
//! points `0..K`, the parity the values on `K ^ (0..K)`.

use super::{MUL, STRIP, TABLES, kernel};

/// `SKEW[i][x]` is `W_i(x)`.
static SKEW: [[u8; 256]; 7] = {
    let mut out = [[0u8; 256]; 7];
    let mut i = 0;
    while i < 7 {
        let mut x = 0;
        while x < 256 {
            // The product of `x - u` over `V_i`, unscaled.
            let mut u = 0;
            let mut w = 1u8;
            while u < 1 << i {
                w = TABLES.mul(w, (x ^ u) as u8);
                u += 1;
            }
            out[i][x] = w;
            x += 1;
        }
        let scale = TABLES.inv(out[i][1 << i]);
        let mut x = 0;
        while x < 256 {
            out[i][x] = TABLES.mul(out[i][x], scale);
            x += 1;
        }
        i += 1;
    }
    out
};

/// `h ^= g`: either butterfly with a zero twiddle, which is where `beta` is in
/// `V_(k-1)`, the leftmost blocks of the data's transform.
#[inline]
fn xor(g: &[u8], h: &mut [u8]) {
    for (h, &g) in h.iter_mut().zip(g) {
        *h ^= g;
    }
}

/// `g ^= w * h`, then `h ^= g`.
#[inline]
fn butterfly(w: u8, g: &mut [u8], h: &mut [u8]) {
    if w == 0 {
        return xor(g, h);
    }
    let done = kernel::butterfly(&kernel::coeff(w), g, h);
    let products = &MUL[w as usize];
    for (g, h) in g[done..].iter_mut().zip(&mut h[done..]) {
        *g ^= products[*h as usize];
        *h ^= *g;
    }
}

/// The reverse of [`butterfly`]: `h ^= g`, then `g ^= w * h`.
#[inline]
fn butterfly_back(w: u8, g: &mut [u8], h: &mut [u8]) {
    if w == 0 {
        return xor(g, h);
    }
    let done = kernel::butterfly_back(&kernel::coeff(w), g, h);
    let products = &MUL[w as usize];
    for (g, h) in g[done..].iter_mut().zip(&mut h[done..]) {
        *h ^= *g;
        *g ^= products[*h as usize];
    }
}

/// The values on `beta ^ V_k`, `block`'s `2^k` slots of `STRIP` bytes, to the
/// coefficients; `len` bytes of each slot are in use.
fn inverse(block: &mut [u8], len: usize, k: u32, beta: usize) {
    if k == 0 {
        return;
    }
    let half = 1usize << (k - 1);
    let (low, high) = block.split_at_mut(half * STRIP);
    inverse(low, len, k - 1, beta);
    inverse(high, len, k - 1, beta ^ half);
    let w = SKEW[k as usize - 1][beta];
    for (g, h) in low.as_chunks_mut::<STRIP>().0.iter_mut().zip(high.as_chunks_mut::<STRIP>().0) {
        butterfly_back(w, &mut g[..len], &mut h[..len]);
    }
}

/// The reverse of [`inverse`].
fn forward(block: &mut [u8], len: usize, k: u32, beta: usize) {
    if k == 0 {
        return;
    }
    let half = 1usize << (k - 1);
    let (low, high) = block.split_at_mut(half * STRIP);
    let w = SKEW[k as usize - 1][beta];
    for (g, h) in low.as_chunks_mut::<STRIP>().0.iter_mut().zip(high.as_chunks_mut::<STRIP>().0) {
        butterfly(w, &mut g[..len], &mut h[..len]);
    }
    forward(low, len, k - 1, beta);
    forward(high, len, k - 1, beta ^ half);
}

/// Writes the chunks `rows` of the `(k, 2k)` code of the data segments `srcs`,
/// `k = srcs.len()` a power of two up to 128, into `dsts`. Every row is in
/// `k..2k` and every segment the same length.
pub(super) fn parity(srcs: &[&[u8]], rows: &[usize], dsts: &mut [&mut [u8]]) {
    let k = srcs.len();
    assert!(k.is_power_of_two() && k <= 128 && rows.len() == dsts.len());
    let size = srcs[0].len();
    assert!(srcs.iter().all(|src| src.len() == size) && dsts.iter().all(|dst| dst.len() == size));
    let bits = k.trailing_zeros();
    // A strip of every segment: the transform of a strip stays in cache.
    let mut work = vec![0u8; k * STRIP];
    for at in (0..size).step_by(STRIP) {
        let len = STRIP.min(size - at);
        for (slot, src) in work.as_chunks_mut::<STRIP>().0.iter_mut().zip(srcs) {
            slot[..len].copy_from_slice(&src[at..at + len]);
        }
        inverse(&mut work, len, bits, 0);
        forward(&mut work, len, bits, k);
        for (&r, dst) in rows.iter().zip(dsts.iter_mut()) {
            dst[at..at + len].copy_from_slice(&work[(r - k) * STRIP..][..len]);
        }
    }
}
