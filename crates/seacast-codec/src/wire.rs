use std::ops::Range;

use seacast_core::{
    Bitmap, Bytes32, ChunkBuffer, Direction, Duty, Evidence, Graft, GroupId, Have, InlineVec,
    InterestKind, Join, MAX_ENTRY_CONTROL, MAX_HAVE_BYTES, Prune, Rpc, TypeId, Want,
};

use crate::buffer::{BufferPool, ChunkBytes};

/// The type a control message is sent with, where a chunk has its object
/// type: no object type has this id.
pub const CONTROL_TYPE: TypeId = TypeId(0xffff);

/// The most bytes of an encoded control message before its evidence body,
/// which has no bound here. Nothing in the encoding delimits a message: the
/// transport does.
pub const MAX_CONTROL_BYTES: usize = 2 +
    (2 + MAX_ENTRY_CONTROL * (2 + 1 + 8 + 1 + 2)) +
    2 * (2 + MAX_ENTRY_CONTROL * (1 + 2 + 32 + 2 + MAX_HAVE_BYTES)) +
    2 * (2 + MAX_ENTRY_CONTROL * (2 + 4 + 2 + 1)) +
    (2 + 32 + 4);

/// What a chunk is sent with before its frame: `type | group | index`. A
/// message is either this and a frame, or a control message; both start with
/// a type, so a reader knows from the first two bytes which it has, and for a
/// chunk how its frame is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHead {
    pub type_id: TypeId,
    pub group: GroupId,
    pub index: u32,
}

impl ChunkHead {
    pub const BYTES: usize = 2 + 32 + 4;

    pub fn encode(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[..2].copy_from_slice(&self.type_id.0.to_le_bytes());
        out[2..34].copy_from_slice(&self.group);
        out[34..].copy_from_slice(&self.index.to_le_bytes());
        out
    }

    pub fn parse(bytes: &[u8; Self::BYTES]) -> Self {
        let mut group = [0u8; 32];
        group.copy_from_slice(&bytes[2..34]);
        Self {
            type_id: TypeId(u16::from_le_bytes([bytes[0], bytes[1]])),
            group,
            index: u32::from_le_bytes([bytes[34], bytes[35], bytes[36], bytes[37]]),
        }
    }
}

/// Encodes the control messages of `rpc` but for the bytes of its evidence
/// body, which close the message: the message is what this writes to `out`,
/// then the body. A chunk of `rpc` is not written: it is a message of its own
/// ([`ChunkHead`], then its frame). Returns the body's handle.
pub fn encode_control_framing<'a, B>(rpc: &'a Rpc<B>, out: &mut Vec<u8>) -> Option<&'a B>
where
    B: ChunkBuffer,
{
    out.clear();
    put_u16(out, CONTROL_TYPE.0);

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
        put_u16(out, h.object_type.0);
        out.extend_from_slice(&h.group);
        let wire_len = h.bits.encode_to_slice(&mut wire_bits_buf);
        put_u16(out, wire_len as u16);
        out.extend_from_slice(&wire_bits_buf[..wire_len]);
    }

    // 4. Wants
    put_u16(out, rpc.wants.len() as u16);
    for w in &rpc.wants {
        out.push(u8::from(w.track_promise));
        put_u16(out, w.object_type.0);
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

    rpc.evidence.as_ref().map(|ev| &ev.body)
}

/// [`encode_control_framing`] and the evidence body, appended.
pub fn encode_control_into<B>(rpc: &Rpc<B>, out: &mut Vec<u8>)
where
    B: ChunkBytes,
{
    if let Some(body) = encode_control_framing(rpc, out) {
        out.extend_from_slice(body.as_bytes());
    }
}

pub fn encode_control<B>(rpc: &Rpc<B>) -> Vec<u8>
where
    B: ChunkBytes,
{
    let mut out = Vec::new();
    encode_control_into(rpc, &mut out);
    out
}

/// Decodes a control message, copying its evidence body into a buffer of
/// `pool`.
pub fn decode_control<B, Pool>(input: &[u8], pool: &mut Pool) -> Option<Rpc<B>>
where
    B: ChunkBuffer,
    Pool: BufferPool<B>,
{
    decode_control_with(input, |range| pool.alloc_from_slice(&input[range]))
}

/// Decodes a control message: an `Rpc` with no chunk. `buffer` makes the
/// handle for the range of `input` that is the evidence body: a host that
/// keeps `input` where it arrived hands back a reference to that range, and
/// nothing is copied.
pub fn decode_control_with<B>(
    input: &[u8],
    mut buffer: impl FnMut(Range<usize>) -> B,
) -> Option<Rpc<B>>
where
    B: ChunkBuffer,
{
    let mut pos = 0;
    if TypeId(get_u16(input, &mut pos)?) != CONTROL_TYPE {
        return None;
    }

    // 1. Joins
    let joins_len = get_u16(input, &mut pos)? as usize;
    if joins_len > MAX_ENTRY_CONTROL {
        return None;
    }
    let mut joins: InlineVec<Join, MAX_ENTRY_CONTROL> = InlineVec::new();
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
        let object_type = TypeId(get_u16(input, &mut pos)?);
        let group = get_bytes32(input, &mut pos)?;
        let bits_len = get_u16(input, &mut pos)? as usize;
        if bits_len > MAX_HAVE_BYTES || pos + bits_len > input.len() {
            return None;
        }
        let bits = Bitmap::from_wire_bytes(&input[pos..pos + bits_len])?;
        pos += bits_len;
        let _ = haves.push(Have {
            object_type,
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
        let object_type = TypeId(get_u16(input, &mut pos)?);
        let group = get_bytes32(input, &mut pos)?;
        let bits_len = get_u16(input, &mut pos)? as usize;
        if bits_len > MAX_HAVE_BYTES || pos + bits_len > input.len() {
            return None;
        }
        let bits = Bitmap::from_wire_bytes(&input[pos..pos + bits_len])?;
        pos += bits_len;
        let _ = wants.push(Want { object_type, group, bits, track_promise });
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

    // The evidence body: all that is left.
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
    if pos != input.len() {
        return None;
    }

    Some(Rpc { joins, chunk: None, haves, wants, grafts, prunes, evidence })
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
    use seacast_core::{Ask, MAX_BITMAP_BITS};

    use super::*;
    use crate::buffer::VecBufferPool;

    #[test]
    fn test_control_roundtrip() {
        let group = [0x11; 32];
        let rpc: Rpc<Vec<u8>> = Rpc {
            joins: InlineVec::singleton(Join {
                object_type: TypeId(0),
                interest: InterestKind::All,
                custody_count: 0,
                duty: Duty::Forward,
                colours: 1,
            }),
            chunk: None,
            haves: InlineVec::from_slice(&[
                Have::holding(TypeId(0), group, Bitmap::all_bits(8), true, true),
                Have::offer(TypeId(3), group, Bitmap::singleton(3)),
            ]),
            wants: InlineVec::singleton(Want::pull_ask(TypeId(4), Ask::new(group, 5))),
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

        let bytes = encode_control(&rpc);
        assert_eq!(bytes[..2], CONTROL_TYPE.0.to_le_bytes());
        assert_eq!(decode_control(&bytes, &mut VecBufferPool), Some(rpc));

        // A chunk's head is not a control message, and a message is decoded whole.
        let head = ChunkHead { type_id: TypeId(7), group, index: 2 }.encode();
        assert_eq!(decode_control::<Vec<u8>, _>(&head, &mut VecBufferPool), None);
        assert_eq!(
            decode_control::<Vec<u8>, _>(&bytes[..bytes.len() - 1], &mut VecBufferPool),
            None
        );
    }

    #[test]
    fn test_chunk_head_roundtrip() {
        let head = ChunkHead { type_id: TypeId(0x0301), group: [0xab; 32], index: 0x0102_0304 };
        assert_eq!(ChunkHead::parse(&head.encode()), head);
        assert_eq!(head.encode()[..2], [0x01, 0x03]);
    }

    #[test]
    fn test_control_bound() {
        let every = Bitmap::all_bits(MAX_BITMAP_BITS as u32);
        let group = [0xff; 32];
        let mut rpc: Rpc<Vec<u8>> = Rpc::default();
        for t in 0..MAX_ENTRY_CONTROL as u16 {
            let _ = rpc.joins.push(Join { object_type: TypeId(t), ..Join::default() });
            let _ = rpc.haves.push(Have::offer(TypeId(1), group, every));
            let _ = rpc.wants.push(Want::standing(TypeId(1), group, every));
            let _ = rpc.grafts.push(Graft::default());
            let _ = rpc.prunes.push(Prune::default());
        }
        rpc.evidence = Some(Evidence { group, body: Vec::new() });
        assert_eq!(encode_control(&rpc).len(), MAX_CONTROL_BYTES);
    }
}
