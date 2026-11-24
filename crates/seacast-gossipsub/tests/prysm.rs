//! Groups built by Prysm (`seacast-devnet`, `container/segments` and
//! `p2p.MsgID`), read here: the frame, the ids, level 1, and level 2
//! rebuilding Prysm's frames byte for byte.
//!
//! A file holds the topic, the group id, and a line a segment: its message id
//! and its SSZ. The body is 40000 bytes, `body[i] = (i / 7) % 251`, snappy
//! compressed by Prysm. `prysm_segments.txt` is a coded group, read from its
//! parity alone; `prysm_plain_segments.txt` is the same body uncoded, cut at
//! 1000 bytes.

use seacast_codec::{VecBufferPool, snappy};
use seacast_core::{ChunkMsg, PreallocVec, TypeCodec, ValidationResult};
use seacast_gossipsub::{PayloadCodec, message_id_of, payload_group, split_chunk};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn a_coded_group_built_by_prysm() {
    group(include_str!("prysm_segments.txt"), (2, 6, 3));
}

#[test]
fn a_plain_group_built_by_prysm() {
    group(include_str!("prysm_plain_segments.txt"), (1, 3, 3));
}

/// `shape`: the descriptor's version, count and `k`.
fn group(file: &str, shape: (u8, u32, u32)) {
    let (version, n, k) = shape;
    let mut lines = file.lines();
    let topic = lines.next().unwrap().strip_prefix("topic ").unwrap();
    let gid = unhex(lines.next().unwrap().strip_prefix("gid ").unwrap());
    let segments: Vec<(Vec<u8>, Vec<u8>)> = lines
        .map(|line| {
            let mut parts = line.strip_prefix("seg ").unwrap().split(' ');
            (unhex(parts.next().unwrap()), unhex(parts.next().unwrap()))
        })
        .collect();
    assert_eq!(segments.len(), n as usize);

    let mut codec = PayloadCodec::<VecBufferPool, Vec<u8>>::new(VecBufferPool, topic.as_bytes());
    let decompress = |data: &[u8], len: usize| {
        let mut out = vec![0u8; len];
        snappy::decompress_into(data, &mut out).map(|n| {
            out.truncate(n);
            out
        })
    };
    let chunks: Vec<ChunkMsg<Vec<u8>>> = segments
        .iter()
        .enumerate()
        .map(|(index, (id, frame))| {
            let chunk = codec.read_message(&snappy::compress(frame), decompress).unwrap();
            let d = split_chunk(frame).unwrap().descriptor;
            assert_eq!((d.version, d.encoding, d.count, d.k()), (version, 1, n, k));
            assert_eq!(chunk.group, payload_group(d.root));
            assert_eq!(chunk.index as usize, index);
            assert_eq!(message_id_of(&chunk.cached_id)[..], id[..]);
            assert_eq!(codec.header_id(&chunk)[..], gid[..]);
            assert!(codec.check(&chunk));
            assert_eq!(PayloadCodec::check_proof(&codec, &chunk), ValidationResult::Accept);
            chunk
        })
        .collect();

    let shape = codec.shape(&chunks[0]).unwrap();
    let mut rebuilt = PreallocVec::with_capacity(shape.n as usize);
    let held = &chunks[(n - k) as usize..];
    let body = codec.decode(&chunks[0].group, held, &shape, &mut rebuilt).unwrap();
    let expected: Vec<u8> = (0..40_000).map(|i| ((i / 7) % 251) as u8).collect();
    assert!(body == expected);
    assert_eq!(rebuilt.len(), n as usize);
    for (made, chunk) in rebuilt.as_slice().iter().zip(&chunks) {
        assert_eq!(made.cached_id, chunk.cached_id);
        assert!(made.frame == chunk.frame);
    }
}
