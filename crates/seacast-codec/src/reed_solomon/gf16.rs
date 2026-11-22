//! Reed–Solomon over `GF(2^16)`: the code of a group of more than 256 chunks,
//! which `GF(2^8)` has no points for. Not in the specification.
//!
//! The code and the layout of a chunk are those of Leopard-RS (`leo_encode`
//! with as many recovery shards as original ones), so a chunk is a Leopard
//! shard: original shard `i` is chunk `i`, recovery shard `j` is chunk `k + j`.
//!
//! The field is `GF(2)[x] / POLYNOMIAL`, an element written in the basis
//! `CANTOR`: bit `i` of its `u16` is the coefficient of `CANTOR[i]`. The sum is
//! the XOR in either form. A chunk is blocks of [`BLOCK`] bytes: the low bytes
//! of 32 symbols, then their high bytes.
//!
//! With `m` the power of two from `k` up, the data are the values at the
//! points `m..m + k` of a polynomial below degree `m` that is zero at the
//! points `m + k..2m`, and parity chunk `k + j` is its value at the point `j`.
//! A point is the element its number is as a `u16`. The transform is that of
//! [`super::fft`], over the basis `1, 2, 4, ..`: `CANTOR`.
//!
//! Recovery is by the derivative (Lin, Chung, Han). With `E` the points not
//! known and `P` the polynomial that vanishes on `E`, `f . P` is known at every
//! point of `0..2m`: it is zero on `E`. Its derivative at `e` in `E` is `f(e) .
//! P'(e)`. `W_i` is linear over `GF(2)` with a linear coefficient of one in
//! this basis, so the derivative of the basis polynomial `j` is the sum over
//! the bits `b` of `j` of the basis polynomial `j - 2^b`.

use seacast_core::MAX_BITMAP_BITS;

use super::Kernel;

/// The points of the largest code: twice the power of two from its `k` up.
const POINTS: usize = 2 * (MAX_BITMAP_BITS / 2).next_power_of_two();

/// The levels of a transform over all the points.
const LEVELS: usize = POINTS.trailing_zeros() as usize;

/// The order of the field's multiplicative group.
const ORDER: usize = 65535;

/// `x^16 + x^5 + x^3 + x^2 + 1`.
const POLYNOMIAL: u32 = 0x1002d;

/// The basis an element is written in, each a polynomial in `x`: `CANTOR[i]^2
/// + CANTOR[i] = CANTOR[i - 1]`.
const CANTOR: [u16; 16] = [
    0x0001, 0xacca, 0x3c0e, 0x163e, 0xc582, 0xed2e, 0x914c, 0x4012, 0x6c98, 0x10d8, 0x6a72, 0xb900,
    0xfdb8, 0xfb34, 0xff38, 0x991e,
];

/// Bytes of a block of a chunk: the low bytes of its symbols, then the high.
pub(super) const BLOCK: usize = 64;

/// Bytes of either half of a block.
const HALF: usize = BLOCK / 2;

/// Bytes of a plane of every chunk transformed before moving on. Whole vectors
/// of every kernel, and half of whole blocks.
const PLANE: usize = 512;

/// A strip of a chunk in the work buffer: its two planes.
const SLOT: usize = 2 * PLANE;

/// A constant as the kernels multiply by it: the product with `(x0, x1)` is
/// `(c[0] x0 + c[1] x1, c[2] x0 + c[3] x1)`, each `c` linear over `GF(2)`.
#[derive(Clone, Copy)]
struct Coeff<K: Kernel> {
    log: u16,
    kernel: [K::Coeff; 4],
}

pub(super) struct Tables<K: Kernel> {
    /// The element of every logarithm, and the logarithm of every element but
    /// zero.
    exp: Vec<u16>,
    log: Vec<u16>,
    /// `W_i(beta)` at `beta | (2^i - 1)`, for `beta` a multiple of `2^(i + 1)`:
    /// the constant of the butterflies of a block of `2^(i + 1)` points from
    /// `beta`. `None` is zero.
    twiddle: Vec<Option<Coeff<K>>>,
}

impl<K: Kernel> Tables<K> {
    /// `a * b`, `b` not zero and given by its logarithm.
    #[inline]
    fn mul_log(&self, a: u16, log_b: u16) -> u16 {
        if a == 0 {
            return 0;
        }
        let sum = self.log[a as usize] as usize + log_b as usize;
        self.exp[if sum >= ORDER { sum - ORDER } else { sum }]
    }

    #[inline]
    fn mul(&self, a: u16, b: u16) -> u16 {
        if b == 0 { 0 } else { self.mul_log(a, self.log[b as usize]) }
    }

    /// The constant of logarithm `log`.
    fn coeff(&self, log: u16) -> Coeff<K> {
        // Bit `j` of a symbol is bit `j % 8` of plane `j / 8`.
        let mut images = [[0u8; 8]; 4];
        for j in 0..16 {
            let product = self.mul_log(1 << j, log);
            images[j / 8][j % 8] = product as u8;
            images[2 + j / 8][j % 8] = (product >> 8) as u8;
        }
        Coeff { log, kernel: images.map(K::linear) }
    }

    pub(super) fn new() -> Self {
        let mut plain = vec![0u16; 1 << 16];
        let mut power = 1u32;
        for i in 0..ORDER {
            plain[power as usize] = i as u16;
            power <<= 1;
            if power >> 16 != 0 {
                power ^= POLYNOMIAL;
            }
        }
        let (mut exp, mut log) = (vec![0u16; ORDER], vec![0u16; 1 << 16]);
        for x in 1..=u16::MAX {
            let element = (0..16).filter(|i| x >> i & 1 == 1).fold(0u16, |acc, i| acc ^ CANTOR[i]);
            log[x as usize] = plain[element as usize];
            exp[plain[element as usize] as usize] = x;
        }
        let mut tables = Tables { exp, log, twiddle: vec![None; POINTS] };

        // `s_i`, the product of `x - u` over `V_i`: `s_(i+1)(x) = s_i(x) . (s_i(x) +
        // s_i(2^i))`. In this basis `s_i(2^i)` is one: `s_i` is `W_i`, and its linear
        // coefficient stays one.
        let mut s: Vec<u16> = (0..POINTS as u16).collect();
        for i in 0..LEVELS {
            assert_eq!(s[1 << i], 1);
            for beta in (0..POINTS).step_by(2 << i) {
                let w = s[beta];
                tables.twiddle[beta | ((1 << i) - 1)] =
                    (w != 0).then(|| tables.coeff(tables.log[w as usize]));
            }
            for value in &mut s {
                *value = tables.mul(*value, *value ^ 1);
            }
        }
        tables
    }
}

/// The two planes of a slot, `len` bytes of each.
#[inline]
fn planes(slot: &mut [u8], len: usize) -> (&mut [u8], &mut [u8]) {
    let (low, high) = slot.split_at_mut(PLANE);
    (&mut low[..len], &mut high[..len])
}

/// The whole blocks `src` of a chunk, into the planes of `slot`.
#[inline]
fn load(slot: &mut [u8], src: &[u8]) {
    let (low, high) = slot.split_at_mut(PLANE);
    let halves = low.as_chunks_mut::<HALF>().0.iter_mut().zip(high.as_chunks_mut::<HALF>().0);
    for (block, (low, high)) in src.as_chunks::<BLOCK>().0.iter().zip(halves) {
        low.copy_from_slice(&block[..HALF]);
        high.copy_from_slice(&block[HALF..]);
    }
}

/// The reverse of [`load`].
#[inline]
fn store(slot: &[u8], dst: &mut [u8]) {
    let (low, high) = slot.split_at(PLANE);
    let halves = low.as_chunks::<HALF>().0.iter().zip(high.as_chunks::<HALF>().0);
    for (block, (low, high)) in dst.as_chunks_mut::<BLOCK>().0.iter_mut().zip(halves) {
        block[..HALF].copy_from_slice(low);
        block[HALF..].copy_from_slice(high);
    }
}

/// `g ^= w * h`, then `h ^= g`. No constant is `w = 0`.
#[inline]
fn butterfly<K: Kernel>(
    t: &Tables<K>,
    w: Option<&Coeff<K>>,
    g: &mut [u8],
    h: &mut [u8],
    len: usize,
) {
    let ((g0, g1), (h0, h1)) = (planes(g, len), planes(h, len));
    let Some(w) = w else {
        K::xor(g0, h0);
        return K::xor(g1, h1);
    };
    let done = K::butterfly2(&w.kernel, g0, g1, h0, h1);
    for i in done..len {
        let product = t.mul_log(h0[i] as u16 | (h1[i] as u16) << 8, w.log);
        g0[i] ^= product as u8;
        g1[i] ^= (product >> 8) as u8;
        h0[i] ^= g0[i];
        h1[i] ^= g1[i];
    }
}

/// The reverse of [`butterfly`]: `h ^= g`, then `g ^= w * h`.
#[inline]
fn butterfly_back<K: Kernel>(
    t: &Tables<K>,
    w: Option<&Coeff<K>>,
    g: &mut [u8],
    h: &mut [u8],
    len: usize,
) {
    let ((g0, g1), (h0, h1)) = (planes(g, len), planes(h, len));
    let Some(w) = w else {
        K::xor(g0, h0);
        return K::xor(g1, h1);
    };
    let done = K::butterfly2_back(&w.kernel, g0, g1, h0, h1);
    for i in done..len {
        h0[i] ^= g0[i];
        h1[i] ^= g1[i];
        let product = t.mul_log(h0[i] as u16 | (h1[i] as u16) << 8, w.log);
        g0[i] ^= product as u8;
        g1[i] ^= (product >> 8) as u8;
    }
}

/// `slot *= c`, given `w = c + 1`: a butterfly from a zero `g` leaves `h + w *
/// h` in `h`. `None` is `c = 1`.
#[inline]
fn scale<K: Kernel>(
    t: &Tables<K>,
    w: Option<&Coeff<K>>,
    slot: &mut [u8],
    len: usize,
    zero: &mut [u8; SLOT],
) {
    if w.is_some() {
        let (z0, z1) = planes(zero, len);
        z0.fill(0);
        z1.fill(0);
        butterfly(t, w, zero, slot, len);
    }
}

/// The values on `beta ^ V_k`, `block`'s `2^k` slots, to the coefficients;
/// `len` bytes of each plane are in use.
fn inverse<K: Kernel>(t: &Tables<K>, block: &mut [u8], len: usize, k: u32, beta: usize) {
    if k == 0 {
        return;
    }
    let half = 1usize << (k - 1);
    let (low, high) = block.split_at_mut(half * SLOT);
    inverse(t, low, len, k - 1, beta);
    inverse(t, high, len, k - 1, beta ^ half);
    let w = t.twiddle[beta | (half - 1)].as_ref();
    for (g, h) in
        low.as_chunks_mut::<SLOT>().0.iter_mut().zip(high.as_chunks_mut::<SLOT>().0.iter_mut())
    {
        butterfly_back(t, w, g, h, len);
    }
}

/// The reverse of [`inverse`].
fn forward<K: Kernel>(t: &Tables<K>, block: &mut [u8], len: usize, k: u32, beta: usize) {
    if k == 0 {
        return;
    }
    let half = 1usize << (k - 1);
    let (low, high) = block.split_at_mut(half * SLOT);
    let w = t.twiddle[beta | (half - 1)].as_ref();
    for (g, h) in
        low.as_chunks_mut::<SLOT>().0.iter_mut().zip(high.as_chunks_mut::<SLOT>().0.iter_mut())
    {
        butterfly(t, w, g, h, len);
    }
    forward(t, low, len, k - 1, beta);
    forward(t, high, len, k - 1, beta ^ half);
}

/// The most chunks a code has.
pub(super) const MAX_CHUNKS: usize = MAX_BITMAP_BITS;

/// Whether `(k, n)` with segments of `size` bytes is a code of this field.
pub(super) fn takes(k: usize, n: usize, size: usize) -> bool {
    k >= 1 && k <= n && n <= MAX_CHUNKS && n <= 2 * k && size.is_multiple_of(BLOCK)
}

/// The point of chunk `index` of a code of `k` data segments.
#[inline]
fn point(k: usize, index: usize) -> usize {
    if index < k { k.next_power_of_two() + index } else { index - k }
}

/// Writes the parity chunks `rows` of the data segments `srcs` into `dsts`.
/// Every row is from `srcs.len()` up and every segment the same length, whole
/// blocks.
pub(super) fn parity<K: Kernel>(srcs: &[&[u8]], rows: &[usize], dsts: &mut [&mut [u8]]) {
    let k = srcs.len();
    let size = srcs[0].len();
    assert!(rows.len() == dsts.len() && rows.iter().all(|&r| r >= k && takes(k, r + 1, size)));
    assert!(srcs.iter().all(|src| src.len() == size) && dsts.iter().all(|dst| dst.len() == size));
    let m = k.next_power_of_two();
    let bits = m.trailing_zeros();
    let t = &*K::caches().wide;
    let mut work = vec![0u8; m * SLOT];
    for at in (0..size).step_by(SLOT) {
        let bytes = SLOT.min(size - at);
        for (slot, src) in work.as_chunks_mut::<SLOT>().0.iter_mut().zip(srcs) {
            load(slot, &src[at..at + bytes]);
        }
        // The points `m + k..2m`, where the polynomial is zero.
        work[k * SLOT..].fill(0);
        inverse(t, &mut work, bytes / 2, bits, m);
        forward(t, &mut work, bytes / 2, bits, 0);
        for (&r, dst) in rows.iter().zip(dsts.iter_mut()) {
            store(&work[(r - k) * SLOT..][..SLOT], &mut dst[at..at + bytes]);
        }
    }
}

/// Writes the chunks `wanted` of the code of `k` data segments into `dsts`,
/// from the chunks `known`, each with its index: at least `k` of them, the
/// indices distinct, none of them wanted, every chunk `size` bytes.
///
/// `None`, with nothing written, if `known` or `wanted` is not that.
pub(super) fn restore<K: Kernel>(
    k: usize,
    size: usize,
    known: &[(usize, &[u8])],
    wanted: &[usize],
    dsts: &mut [&mut [u8]],
) -> Option<()> {
    let m = k.next_power_of_two();
    let n = 2 * m;
    let bits = n.trailing_zeros();
    if k == 0 || n > POINTS || !size.is_multiple_of(BLOCK) || wanted.len() != dsts.len() {
        return None;
    }
    // The points `m + k..2m` are known: the polynomial is zero there. The points
    // `k..m` are of no chunk, and never known.
    let mut is_known = [false; POINTS];
    is_known[m + k..n].fill(true);
    for &(index, chunk) in known {
        if index >= 2 * k || chunk.len() != size || is_known[point(k, index)] {
            return None;
        }
        is_known[point(k, index)] = true;
    }
    // A chunk wanted twice would be scaled twice.
    let mut taken = is_known;
    for &index in wanted {
        if index >= 2 * k || std::mem::replace(&mut taken[point(k, index)], true) {
            return None;
        }
    }
    if known.len() < k {
        return None;
    }
    if size == 0 || wanted.is_empty() {
        return Some(());
    }

    // The logarithm of the product of `x - e` over the points not known but `x`:
    // that of `P(x)` at a point known, of `P'(x)` at the others.
    let t = &*K::caches().wide;
    let erased: Vec<usize> = (0..n).filter(|&p| !is_known[p]).collect();
    let log = |x: usize| {
        let sum: usize = erased.iter().filter(|&&e| e != x).map(|&e| t.log[x ^ e] as usize).sum();
        sum % ORDER
    };
    // The constant plus one, as `scale` takes it.
    let scaler = |log: usize| {
        let c = t.exp[log];
        (c != 1).then(|| t.coeff(t.log[(c ^ 1) as usize]))
    };
    let scale_in: Vec<_> = (known.iter())
        .map(|&(index, chunk)| {
            let p = point(k, index);
            (p, chunk, scaler(log(p)))
        })
        .collect();
    let scale_out: Vec<_> = (wanted.iter())
        .map(|&index| {
            let p = point(k, index);
            (p, scaler((ORDER - log(p)) % ORDER))
        })
        .collect();

    let mut work = vec![0u8; n * SLOT];
    let mut zero = [0u8; SLOT];
    for at in (0..size).step_by(SLOT) {
        let bytes = SLOT.min(size - at);
        let len = bytes / 2;
        // `f . P` at every point: zero where `f` is not known, and at `m + k..2m`.
        work.fill(0);
        for (p, chunk, c) in &scale_in {
            let slot = &mut work[p * SLOT..][..SLOT];
            load(slot, &chunk[at..at + bytes]);
            scale(t, c.as_ref(), slot, len, &mut zero);
        }
        inverse(t, &mut work, len, bits, 0);

        // The derivative. A coefficient is the sum of those one bit above it, all
        // still to be replaced when it is.
        for j in 0..n {
            let (below, above) = work.split_at_mut((j + 1) * SLOT);
            let (d0, d1) = planes(&mut below[j * SLOT..], len);
            d0.fill(0);
            d1.fill(0);
            for b in (0..bits).filter(|b| j >> b & 1 == 0) {
                let (s0, s1) = planes(&mut above[((1 << b) - 1) * SLOT..][..SLOT], len);
                K::xor(s0, d0);
                K::xor(s1, d1);
            }
        }

        forward(t, &mut work, len, bits, 0);
        for ((p, c), dst) in scale_out.iter().zip(dsts.iter_mut()) {
            let slot = &mut work[p * SLOT..][..SLOT];
            scale(t, c.as_ref(), slot, len, &mut zero);
            store(slot, &mut dst[at..at + bytes]);
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::{super::portable::Portable, *};

    fn field() -> &'static Tables<Portable> {
        &Portable::caches().wide
    }

    fn bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (state >> 56) as u8
            })
            .collect()
    }

    fn symbol(chunk: &[u8], j: usize) -> u16 {
        let at = j / HALF * BLOCK + j % HALF;
        chunk[at] as u16 | (chunk[at + HALF] as u16) << 8
    }

    fn inv(a: u16) -> u16 {
        field().exp[(ORDER - field().log[a as usize] as usize) % ORDER]
    }

    fn mul(a: u16, b: u16) -> u16 {
        field().mul(a, b)
    }

    #[test]
    fn test_the_field() {
        for a in (1..=u16::MAX).step_by(97) {
            assert_eq!(mul(a, inv(a)), 1);
            for b in (1..=u16::MAX).step_by(4099) {
                assert_eq!(mul(a, b), mul(b, a));
                assert_eq!(mul(a, b ^ 0x1234), mul(a, b) ^ mul(a, 0x1234));
                assert_eq!(mul(mul(a, b), 0x8001), mul(a, mul(b, 0x8001)));
            }
        }
        // Every element but zero has a logarithm, and one is the unit.
        let mut seen = vec![false; 1 << 16];
        assert!(
            field().exp.iter().all(|&x| x != 0 && !std::mem::replace(&mut seen[x as usize], true))
        );
        assert_eq!(mul(1, 0xbeef), 0xbeef);
        // The basis: `CANTOR[i]^2 + CANTOR[i] = CANTOR[i - 1]`.
        for i in 1..16 {
            assert_eq!(mul(1 << i, 1 << i) ^ (1 << i), 1 << (i - 1));
        }
    }

    /// The parity is the polynomial's value at its point: by Lagrange's formula
    /// over the points `m..2m`, the data and the zeros.
    fn parity_is_the_polynomial<K: Kernel>() {
        for k in [129usize, 200, 256, 300] {
            let m = k.next_power_of_two();
            for size in [64, 128, 192, 1024, 1088, 2560] {
                let data: Vec<Vec<u8>> = (0..k).map(|i| bytes(size, (k * 7 + i) as u64)).collect();
                let srcs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
                let rows = [k, k + 1, 2 * k - 1, k + 77];
                let mut out = vec![vec![0x5au8; size]; rows.len()];
                parity::<K>(
                    &srcs,
                    &rows,
                    &mut out.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
                );
                for (&r, chunk) in rows.iter().zip(&out) {
                    let x = (r - k) as u16;
                    // The basis polynomial of the point `c`, at `x`.
                    let basis: Vec<u16> = (m as u16..(m + k) as u16)
                        .map(|c| {
                            (m as u16..2 * m as u16)
                                .filter(|&t| t != c)
                                .fold(1u16, |acc, t| mul(acc, mul(x ^ t, inv(c ^ t))))
                        })
                        .collect();
                    for j in [0, size / 2 - 1, size / 4] {
                        let expected =
                            (0..k).fold(0u16, |acc, c| acc ^ mul(basis[c], symbol(&data[c], j)));
                        assert_eq!(symbol(chunk, j), expected, "k {k} size {size} row {r} at {j}");
                    }
                }
            }
        }
    }

    /// The parity is what `leo_encode` of Leopard-RS gives for the same data: a
    /// hash of all of it and the first bytes, from a build of the reference.
    fn parity_is_leopards<K: Kernel>() {
        let cases: [(usize, usize, u64, [u8; 8]); 6] = [
            (129, 64, 0x38c7ccf495b5e0e0, [0xd6, 0x5f, 0xfe, 0x6f, 0x4e, 0x28, 0xee, 0xc8]),
            (200, 192, 0x5f3e056561c1b1c7, [0xaa, 0x3e, 0x44, 0x67, 0x5f, 0xbc, 0x5c, 0xb2]),
            (256, 2176, 0x242909f1a81ae0c4, [0x4e, 0xaa, 0x5a, 0xf6, 0x93, 0x83, 0xac, 0xae]),
            (300, 128, 0xf81037fc0d9532a7, [0xc2, 0x26, 0xc6, 0xd9, 0x23, 0x84, 0xd4, 0x24]),
            (512, 1088, 0xf0e36ee0994d2218, [0x40, 0x0f, 0xdc, 0xec, 0xa8, 0x55, 0x73, 0x01]),
            (385, 16384, 0x649c38c94961002d, [0x20, 0x74, 0x7f, 0x79, 0x18, 0xd3, 0xc3, 0x94]),
        ];
        for (k, size, hash, first) in cases {
            let data: Vec<Vec<u8>> = (0..k).map(|i| bytes(size, (k * 7 + i) as u64)).collect();
            let srcs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            let rows: Vec<usize> = (k..2 * k).collect();
            let mut out = vec![vec![0u8; size]; k];
            parity::<K>(
                &srcs,
                &rows,
                &mut out.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
            );
            assert_eq!(out[0][..8], first, "k {k} size {size}");
            // FNV-1a.
            let fnv = out
                .iter()
                .flatten()
                .fold(0xcbf29ce484222325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100000001b3));
            assert_eq!(fnv, hash, "k {k} size {size}");
        }
    }

    /// Any `k` chunks give every other chunk back.
    fn restore_from_any_chunks<K: Kernel>() {
        for (k, size) in [(129usize, 64), (257, 128), (300, 1088), (512, 192)] {
            let data: Vec<Vec<u8>> = (0..k).map(|i| bytes(size, (k + i) as u64)).collect();
            let srcs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            let rows: Vec<usize> = (k..2 * k).collect();
            let mut coded = vec![vec![0u8; size]; k];
            parity::<K>(
                &srcs,
                &rows,
                &mut coded.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
            );
            let all: Vec<&[u8]> =
                srcs.iter().copied().chain(coded.iter().map(Vec::as_slice)).collect();
            let picks: [&dyn Fn(usize) -> bool; 4] =
                [&|i| i >= k, &|i| i % 2 == 1, &|i| i % 8 != 0 && i < k + k / 4, &|i| {
                    (i * 2654435761) % 5 < 3
                }];
            for pick in picks {
                let held: Vec<usize> = (0..2 * k).filter(|&i| pick(i)).collect();
                let known: Vec<(usize, &[u8])> = held.iter().map(|&i| (i, all[i])).collect();
                let wanted: Vec<usize> = (0..2 * k).filter(|i| !held.contains(i)).collect();
                let mut out = vec![vec![0xa5u8; size]; wanted.len()];
                let restored = restore::<K>(
                    k,
                    size,
                    &known,
                    &wanted,
                    &mut out.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
                );
                if held.len() < k {
                    assert_eq!(restored, None);
                    continue;
                }
                assert_eq!(restored, Some(()));
                for (&index, chunk) in wanted.iter().zip(&out) {
                    assert!(chunk == all[index], "k {k} size {size} chunk {index}");
                }
            }
        }
    }

    fn restore_refuses_bad_chunks<K: Kernel>() {
        let (k, size) = (130usize, 64);
        let chunk = vec![1u8; size];
        let known: Vec<(usize, &[u8])> = (0..k).map(|i| (i + 5, &chunk[..])).collect();
        let mut out = vec![0u8; size];
        let mut run = |known: &[(usize, &[u8])], wanted: usize| {
            restore::<K>(k, size, known, &[wanted], &mut [&mut out[..]])
        };
        assert_eq!(run(&known, 0), Some(()));
        // A chunk wanted that is known, too few chunks, one twice, one past the code.
        assert_eq!(run(&known, 5), None);
        assert_eq!(
            restore::<K>(k, size, &known, &[0, 0], &mut [&mut [0u8; 64], &mut [0u8; 64]]),
            None
        );
        assert_eq!(run(&known[1..], 0), None);
        let mut twice = known.clone();
        twice[3] = twice[4];
        assert_eq!(run(&twice, 0), None);
        let mut past = known.clone();
        past[0].0 = 2 * k;
        assert_eq!(run(&past, 0), None);
        assert_eq!(restore::<K>(k, 63, &known, &[0], &mut [&mut out[..63]]), None);
    }

    #[test]
    fn test_parity_is_the_polynomial() {
        each_kernel!(parity_is_the_polynomial);
    }

    #[test]
    fn test_parity_is_leopards() {
        each_kernel!(parity_is_leopards);
    }

    #[test]
    fn test_restore_from_any_chunks() {
        each_kernel!(restore_from_any_chunks);
    }

    #[test]
    fn test_restore_refuses_bad_chunks() {
        each_kernel!(restore_refuses_bad_chunks);
    }
}
