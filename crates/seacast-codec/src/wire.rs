use std::ops::Range;

use seacast_core::{
    Bitmap, Bytes32, ChunkBuffer, ChunkId, ChunkMsg, Direction, Duty, Evidence, Graft, Have,
    InlineVec, InterestKind, Join, MAX_ENTRY_CONTROL, MAX_HAVE_BYTES, Prune, Rpc, TypeId, Want,
};

use crate::{
    buffer::{BufferPool, ChunkBytes},
    segment::chunk_id,
};

/// Magic prefix for standalone SEACAST v2 RPC frames (`"SEAC\x02"`).
pub const SEACAST_V2_MAGIC: [u8; 5] = *b"SEAC\x02";

/// Encodes a standalone SEACAST v2 `Rpc` but for the bytes of its evidence body
/// and of its chunk, which close the frame in that order (`protocol-v2.md` §2,
/// §7): the frame is what this appends to `out`, then the body, then the data.
/// A writer that gathers sends the three as they lie, with no copy of a chunk.
/// Returns the two handles.
pub fn encode_rpc_framing<'a, B>(rpc: &'a Rpc<B>, out: &mut Vec<u8>) -> [Option<&'a B>; 2]
where
    B: ChunkBuffer,
{
    out.clear();
    out.extend_from_slice(&SEACAST_V2_MAGIC);

    // 1. Joins
    put_u16(out, rpc.joins.len() as u16);
    for j in &rpc.joins {
        put_u16(out, j.object_type.0);
        out.push(match j.interest {
            InterestKind::All => 0,
            InterestKind::Derived => 1,
            InterestKind::Declared => 2,
        });
        put_u64(out, j.custody_count);
        out.push(match j.duty {
            Duty::Forward => 0,
            Duty::None => 1,
        });
        put_u16(out, j.colours);
    }

    let mut wire_bits_buf = [0u8; MAX_HAVE_BYTES];

    // 3. Haves (Holdings & Offers)
    put_u16(out, rpc.haves.len() as u16);
    for h in &rpc.haves {
        let mut flags = 0u8;
        if h.offer {
            flags |= 0x01;
        }
        if h.claim_all {
            flags |= 0x02;
        }
        if h.complete {
            flags |= 0x04;
        }
        out.push(flags);
        out.extend_from_slice(&h.group);
        let wire_len = h.bits.encode_to_slice(&mut wire_bits_buf);
        put_u16(out, wire_len as u16);
        out.extend_from_slice(&wire_bits_buf[..wire_len]);
    }

    // 4. Wants
    put_u16(out, rpc.wants.len() as u16);
    for w in &rpc.wants {
        out.push(u8::from(w.track_promise));
        out.extend_from_slice(&w.group);
        let wire_len = w.bits.encode_to_slice(&mut wire_bits_buf);
        put_u16(out, wire_len as u16);
        out.extend_from_slice(&wire_bits_buf[..wire_len]);
    }

    // 5. Grafts
    put_u16(out, rpc.grafts.len() as u16);
    for g in &rpc.grafts {
        put_u16(out, g.object_type.0);
        put_u32(out, g.family);
        put_u16(out, g.colour);
        out.push(encode_dir(g.direction));
    }

    // 6. Prunes
    put_u16(out, rpc.prunes.len() as u16);
    for p in &rpc.prunes {
        put_u16(out, p.object_type.0);
        put_u32(out, p.family);
        put_u16(out, p.colour);
        out.push(encode_dir(p.direction));
    }

    // 7. Evidence (at most 1 per RPC frame): its group and its body's length
    if let Some(ref ev) = rpc.evidence {
        put_u16(out, 1);
        out.extend_from_slice(&ev.group);
        put_u32(out, ev.body.len() as u32);
    } else {
        put_u16(out, 0);
    }

    // 8. Chunk (at most 1 per RPC frame): its type, group and index. Its frame is
    //    the last
    // thing sent and has no length: its type and its header give every length in
    // it.
    if let Some(ref ch) = rpc.chunk {
        put_u16(out, 1);
        put_u16(out, ch.type_id.0);
        out.extend_from_slice(&ch.group);
        put_u32(out, ch.index);
    } else {
        put_u16(out, 0);
    }
    [rpc.evidence.as_ref().map(|ev| &ev.body), rpc.chunk.as_ref().map(|ch| &ch.frame)]
}

/// Encodes a standalone SEACAST v2 `Rpc` into a caller-supplied byte buffer
/// (`protocol-v2.md` §2, §7). If `out` is preallocated with sufficient
/// capacity, performs zero heap allocations.
pub fn encode_rpc_into<B>(rpc: &Rpc<B>, out: &mut Vec<u8>)
where
    B: ChunkBytes,
{
    for trailing in encode_rpc_framing(rpc, out).into_iter().flatten() {
        out.extend_from_slice(trailing.as_bytes());
    }
}

/// Encodes a standalone SEACAST v2 `Rpc` into bytes (`protocol-v2.md` §2, §7).
pub fn encode_rpc<B>(rpc: &Rpc<B>) -> Vec<u8>
where
    B: ChunkBytes,
{
    let mut out = Vec::new();
    encode_rpc_into(rpc, &mut out);
    out
}

/// A decoded chunk's fields, for the function that gives it its id.
pub struct ChunkParts<'a> {
    pub type_id: TypeId,
    pub group: &'a Bytes32,
    pub index: u32,
    pub frame: &'a [u8],
}

/// The id function of chunks that are all on `topic`, for [`decode_rpc`] and
/// [`decode_rpc_with`]. A host with several types gives a function that picks
/// the topic of `type_id`.
pub fn chunk_id_on(topic: &[u8]) -> impl Fn(ChunkParts<'_>) -> ChunkId + '_ {
    move |c| chunk_id(topic, c.type_id, c.group, c.index, c.frame)
}

/// Decodes a standalone SEACAST v2 `Rpc`, copying its chunk's data and its
/// evidence body into buffers of `pool`.
pub fn decode_rpc<B, Pool>(
    input: &[u8],
    pool: &mut Pool,
    chunk_id: impl FnMut(ChunkParts<'_>) -> ChunkId,
) -> Option<Rpc<B>>
where
    B: ChunkBuffer,
    Pool: BufferPool<B>,
{
    decode_rpc_with(input, |range| pool.alloc_from_slice(&input[range]), chunk_id)
}

/// Decodes a standalone SEACAST v2 `Rpc`. `buffer` makes the handle for a range
/// of `input`, the chunk's data or the evidence body: a host that keeps `input`
/// where it arrived hands back a reference to that range, and nothing is
/// copied.
pub fn decode_rpc_with<B>(
    input: &[u8],
    mut buffer: impl FnMut(Range<usize>) -> B,
    mut chunk_id: impl FnMut(ChunkParts<'_>) -> ChunkId,
) -> Option<Rpc<B>>
where
    B: ChunkBuffer,
{
    if input.len() < SEACAST_V2_MAGIC.len() || input[0..5] != SEACAST_V2_MAGIC {
        return None;
    }
    let mut pos = 5;

    // 1. Joins
    let joins_len = get_u16(input, &mut pos)? as usize;
    if joins_len > 4 {
        return None;
    }
    let mut joins: InlineVec<Join, 4> = InlineVec::new();
    for _ in 0..joins_len {
        let object_type = TypeId(get_u16(input, &mut pos)?);
        let interest = match get_u8(input, &mut pos)? {
            0 => InterestKind::All,
            1 => InterestKind::Derived,
            2 => InterestKind::Declared,
            _ => return None,
        };
        let custody_count = get_u64(input, &mut pos)?;
        let duty = match get_u8(input, &mut pos)? {
            0 => Duty::Forward,
            1 => Duty::None,
            _ => return None,
        };
        let colours = get_u16(input, &mut pos)?;
        let _ = joins.push(Join { object_type, interest, custody_count, duty, colours });
    }

    // 3. Haves
    let haves_len = get_u16(input, &mut pos)? as usize;
    if haves_len > MAX_ENTRY_CONTROL {
        return None;
    }
    let mut haves: InlineVec<Have, MAX_ENTRY_CONTROL> = InlineVec::new();
    for _ in 0..haves_len {
        let flags = get_u8(input, &mut pos)?;
        let group = get_bytes32(input, &mut pos)?;
        let bits_len = get_u16(input, &mut pos)? as usize;
        if bits_len > MAX_HAVE_BYTES || pos + bits_len > input.len() {
            return None;
        }
        let bits = Bitmap::from_wire_bytes(&input[pos..pos + bits_len])?;
        pos += bits_len;
        let _ = haves.push(Have {
            group,
            bits,
            offer: (flags & 0x01) != 0,
            claim_all: (flags & 0x02) != 0,
            complete: (flags & 0x04) != 0,
        });
    }

    // 4. Wants
    let wants_len = get_u16(input, &mut pos)? as usize;
    if wants_len > MAX_ENTRY_CONTROL {
        return None;
    }
    let mut wants: InlineVec<Want, MAX_ENTRY_CONTROL> = InlineVec::new();
    for _ in 0..wants_len {
        let track_promise = get_u8(input, &mut pos)? != 0;
        let group = get_bytes32(input, &mut pos)?;
        let bits_len = get_u16(input, &mut pos)? as usize;
        if bits_len > MAX_HAVE_BYTES || pos + bits_len > input.len() {
            return None;
        }
        let bits = Bitmap::from_wire_bytes(&input[pos..pos + bits_len])?;
        pos += bits_len;
        let _ = wants.push(Want { group, bits, track_promise });
    }

    // 5. Grafts
    let grafts_len = get_u16(input, &mut pos)? as usize;
    if grafts_len > MAX_ENTRY_CONTROL {
        return None;
    }
    let mut grafts: InlineVec<Graft, MAX_ENTRY_CONTROL> = InlineVec::new();
    for _ in 0..grafts_len {
        let object_type = TypeId(get_u16(input, &mut pos)?);
        let family = get_u32(input, &mut pos)?;
        let colour = get_u16(input, &mut pos)?;
        let direction = decode_dir(get_u8(input, &mut pos)?)?;
        let _ = grafts.push(Graft { object_type, family, colour, direction });
    }

    // 6. Prunes
    let prunes_len = get_u16(input, &mut pos)? as usize;
    if prunes_len > MAX_ENTRY_CONTROL {
        return None;
    }
    let mut prunes: InlineVec<Prune, MAX_ENTRY_CONTROL> = InlineVec::new();
    for _ in 0..prunes_len {
        let object_type = TypeId(get_u16(input, &mut pos)?);
        let family = get_u32(input, &mut pos)?;
        let colour = get_u16(input, &mut pos)?;
        let direction = decode_dir(get_u8(input, &mut pos)?)?;
        let _ = prunes.push(Prune { object_type, family, colour, direction });
    }

    // 7. Evidence: its group and its body's length
    let ev_len = get_u16(input, &mut pos)? as usize;
    if ev_len > 1 {
        return None;
    }
    let evidence_head = if ev_len == 1 {
        Some((get_bytes32(input, &mut pos)?, get_u32(input, &mut pos)? as usize))
    } else {
        None
    };

    // 8. Chunk: everything but its data
    let chunks_len = get_u16(input, &mut pos)? as usize;
    if chunks_len > 1 {
        return None;
    }
    let chunk_head = if chunks_len == 1 {
        let type_id = TypeId(get_u16(input, &mut pos)?);
        let group = get_bytes32(input, &mut pos)?;
        let index = get_u32(input, &mut pos)?;
        Some((type_id, group, index))
    } else {
        None
    };

    // The evidence body, then the chunk's frame: all that is left.
    let mut take = |len: usize| {
        let range = pos..pos.checked_add(len)?;
        input.get(range.clone())?;
        pos = range.end;
        Some(range)
    };
    let evidence = match evidence_head {
        Some((group, body_len)) => {
            let body = buffer(take(body_len)?);
            Some(Evidence { group, body })
        }
        None => None,
    };
    let chunk = match chunk_head {
        Some((type_id, group, index)) => {
            let range = pos..input.len();
            pos = input.len();
            let cached_id = chunk_id(ChunkParts {
                type_id,
                group: &group,
                index,
                frame: &input[range.clone()],
            });
            Some(ChunkMsg { type_id, group, index, frame: buffer(range), cached_id, memo: [0; 32] })
        }
        None => None,
    };
    if pos != input.len() {
        return None;
    }

    Some(Rpc { joins, chunk, haves, wants, grafts, prunes, evidence })
}

fn encode_dir(d: Direction) -> u8 {
    match d {
        Direction::Out => 0,
        Direction::In => 1,
        Direction::Both => 2,
    }
}

#[inline]
fn decode_dir(b: u8) -> Option<Direction> {
    match b {
        0 => Some(Direction::Out),
        1 => Some(Direction::In),
        2 => Some(Direction::Both),
        _ => None,
    }
}

#[inline]
fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn get_u8(input: &[u8], pos: &mut usize) -> Option<u8> {
    let b = *input.get(*pos)?;
    *pos += 1;
    Some(b)
}

#[inline]
fn get_u16(input: &[u8], pos: &mut usize) -> Option<u16> {
    if *pos + 2 > input.len() {
        return None;
    }
    let v = u16::from_le_bytes([input[*pos], input[*pos + 1]]);
    *pos += 2;
    Some(v)
}

#[inline]
fn get_u32(input: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 4 > input.len() {
        return None;
    }
    let v = u32::from_le_bytes(input[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Some(v)
}

#[inline]
fn get_u64(input: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos + 8 > input.len() {
        return None;
    }
    let v = u64::from_le_bytes(input[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Some(v)
}

#[inline]
fn get_bytes32(input: &[u8], pos: &mut usize) -> Option<Bytes32> {
    if *pos + 32 > input.len() {
        return None;
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&input[*pos..*pos + 32]);
    *pos += 32;
    Some(b)
}

#[cfg(test)]
mod tests {
    use seacast_core::Ask;

    use super::*;
    use crate::buffer::VecBufferPool;

    #[test]
    fn test_wire_rpc_roundtrip() {
        let mut pool = VecBufferPool;
        let group = [0x11; 32];
        let frame = vec![1u8, 2, 3, 4, 5];
        let cid = chunk_id(b"topic", TypeId(0), &group, 2, &frame);

        let rpc: Rpc<Vec<u8>> = Rpc {
            joins: InlineVec::singleton(Join {
                object_type: TypeId(0),
                interest: InterestKind::All,
                custody_count: 0,
                duty: Duty::Forward,
                colours: 1,
            }),
            chunk: Some(ChunkMsg {
                type_id: TypeId(0),
                group,
                index: 2,
                frame,
                cached_id: cid,
                memo: [0; 32],
            }),
            haves: InlineVec::from_slice(&[
                Have::holding(group, Bitmap::all_bits(8), true, true),
                Have::offer(group, Bitmap::singleton(3)),
            ]),
            wants: InlineVec::singleton(Want::pull_ask(Ask::new(group, 5))),
            grafts: InlineVec::singleton(Graft {
                object_type: TypeId(0),
                family: 0,
                colour: 0,
                direction: Direction::Both,
            }),
            prunes: InlineVec::singleton(Prune {
                object_type: TypeId(1),
                family: 7,
                colour: 0,
                direction: Direction::In,
            }),
            evidence: Some(Evidence { group, body: vec![9, 8, 7] }),
        };

        let bytes = encode_rpc(&rpc);
        let decoded = decode_rpc(&bytes, &mut pool, chunk_id_on(b"topic")).expect("decode rpc");
        assert_eq!(decoded, rpc);
    }
}
