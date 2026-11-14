use seacast_core::Bytes32;

pub(crate) const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[cfg(all(target_arch = "aarch64", target_feature = "sha2"))]
mod aarch64;
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "sha",
    target_feature = "sse4.1",
    target_feature = "ssse3"
))]
mod x86;

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f", target_feature = "avx512bw"))]
mod x16;

#[cfg(all(target_arch = "aarch64", target_feature = "sha2"))]
use aarch64::compress;
#[cfg(not(any(
    all(target_arch = "aarch64", target_feature = "sha2"),
    all(
        target_arch = "x86_64",
        target_feature = "sha",
        target_feature = "sse4.1",
        target_feature = "ssse3"
    )
)))]
use portable as compress;
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "sha",
    target_feature = "sse4.1",
    target_feature = "ssse3"
))]
use x86::compress;

/// Absorb `blocks`, a whole number of 64-byte blocks, into `state`. The
/// reference for the hardware arms, and the arm of a target with no SHA
/// instructions.
#[cfg_attr(
    any(
        all(target_arch = "aarch64", target_feature = "sha2"),
        all(
            target_arch = "x86_64",
            target_feature = "sha",
            target_feature = "sse4.1",
            target_feature = "ssse3"
        )
    ),
    allow(dead_code)
)]
pub(crate) fn portable(state: &mut [u32; 8], blocks: &[u8]) {
    let (blocks, rest) = blocks.as_chunks::<64>();
    debug_assert!(rest.is_empty());
    for block in blocks {
        let mut w = [0u32; 64];
        for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (word, add) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = word.wrapping_add(add);
        }
    }
}

fn digest(state: &[u32; 8]) -> Bytes32 {
    let mut out = [0u8; 32];
    for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *bytes = word.to_be_bytes();
    }
    out
}

/// `sha256(prefix || left || right)`: the 65 bytes and their padding are two
/// blocks, laid out here with no buffering.
#[inline]
pub(crate) fn sha256_pair(prefix: u8, left: &Bytes32, right: &Bytes32) -> Bytes32 {
    let mut blocks = [0u8; 128];
    blocks[0] = prefix;
    blocks[1..33].copy_from_slice(left);
    blocks[33..65].copy_from_slice(right);
    blocks[65] = 0x80;
    blocks[120..].copy_from_slice(&(65u64 * 8).to_be_bytes());
    let mut state = H0;
    compress(&mut state, &blocks);
    digest(&state)
}

/// `out[i] = sha256(prefix || inputs[i])`. Where a target hashes several
/// messages at once, runs of equal-length inputs go through it.
pub(crate) fn sha256_prefixed_many<T: AsRef<[u8]>>(prefix: u8, inputs: &[T], out: &mut [Bytes32]) {
    assert_eq!(inputs.len(), out.len());
    #[allow(unused_mut)]
    let mut at = 0;
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f", target_feature = "avx512bw"))]
    while at + x16::LANES <= inputs.len() {
        let batch: [&[u8]; x16::LANES] = std::array::from_fn(|lane| inputs[at + lane].as_ref());
        if batch.iter().any(|input| input.len() != batch[0].len()) {
            break;
        }
        out[at..at + x16::LANES].copy_from_slice(&x16::sha256_prefixed(prefix, &batch));
        at += x16::LANES;
    }
    for (input, digest) in inputs[at..].iter().zip(&mut out[at..]) {
        let mut h = Sha256::new();
        h.update(&[prefix]);
        h.update(input.as_ref());
        *digest = h.finalize();
    }
}

/// Streaming FIPS 180-4 SHA-256 hasher.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    #[inline]
    pub const fn new() -> Self {
        Self { state: H0, buf: [0u8; 64], buf_len: 0, total_len: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return;
            }
            compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        // Whole blocks straight from the input, in one call.
        let (whole, rest) = data.split_at(data.len() & !63);
        compress(&mut self.state, whole);
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub fn finalize(mut self) -> Bytes32 {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut self.state, &self.buf);
        digest(&self.state)
    }
}

/// Computes the SHA-256 digest of `data` (`sha256` in `protocol.md` §1).
#[inline]
pub fn sha256(data: &[u8]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Batches of equal lengths, a short input in the middle of them, and a
    /// tail, against one message at a time.
    #[test]
    fn test_sha256_prefixed_many_matches_one_at_a_time() {
        let byte = |i: usize| (i.wrapping_mul(2654435761) >> 13) as u8;
        for len in [0, 1, 54, 55, 56, 62, 63, 64, 65, 118, 119, 120, 127, 128, 129, 1000] {
            let mut inputs: Vec<Vec<u8>> =
                (0..53).map(|i| (0..len).map(|j| byte(i * 1009 + j)).collect()).collect();
            inputs[20].push(7);
            let mut out = vec![[0u8; 32]; inputs.len()];
            sha256_prefixed_many(0x00, &inputs, &mut out);
            for (input, digest) in inputs.iter().zip(&out) {
                let mut message = vec![0x00];
                message.extend_from_slice(input);
                assert_eq!(*digest, sha256(&message), "length {len}");
            }
        }
    }

    /// Every length across three blocks, split at every third position: the arm
    /// in use against the portable one, through the buffering.
    #[test]
    fn test_sha256_matches_portable() {
        let data: Vec<u8> = (0..200u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
        for len in 0..=data.len() {
            let mut padded = data[..len].to_vec();
            padded.push(0x80);
            padded.resize((len + 9).next_multiple_of(64) - 8, 0);
            padded.extend_from_slice(&(len as u64 * 8).to_be_bytes());
            let mut state = H0;
            portable(&mut state, &padded);
            let expected = digest(&state);
            assert_eq!(sha256(&data[..len]), expected, "length {len}");
            for split in (0..len).step_by(3) {
                let mut h = Sha256::new();
                h.update(&data[..split]);
                h.update(&data[split..len]);
                assert_eq!(h.finalize(), expected, "length {len} split {split}");
            }
        }
        let (left, right) = (sha256(b"l"), sha256(b"r"));
        let mut h = Sha256::new();
        h.update(&[0x01]);
        h.update(&left);
        h.update(&right);
        assert_eq!(sha256_pair(0x01, &left, &right), h.finalize());
    }

    #[test]
    fn test_sha256_vectors() {
        let empty = sha256(b"");
        assert_eq!(empty, [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55
        ]);
        let abc = sha256(b"abc");
        assert_eq!(abc, [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]);
    }
}
