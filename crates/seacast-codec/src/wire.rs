//! The standalone binding (`protocol-v2-bindings.md` §1): a frame is
//! `uvarint(len(kind || body)) || kind || body`, one message a frame, the body
//! the message's SSZ.
//!
//! Kind `0x06` is any object's chunk, not the payload's: its body is the object
//! header ([`ChunkHead`]: group and index), then the type's frame compressed
//! with snappy. The type's codec gives the frame's layout. The binding has a
//! kind per chunk layout instead (`0x06` the payload's `Chunk`, `0x07` a cell).

use seacast_core::{
    Bitmap, Bytes32, ChunkBuffer, ChunkMsg, Control, Direction, Duty, Graft, GroupId, Have,
    InterestKind, Join, MAX_HAVE_BYTES, Prune, QueueEntry, Rpc, TypeId, Want,
};

use crate::{buffer::ChunkBytes, layout::ChunkLayout, snappy};

/// The binding's protocol id (§1.1).
pub const PROTOCOL_ID: &str = "/seacast/2.0.0";

pub const KIND_JOIN: u8 = 0x01;
pub const KIND_GRAFT: u8 = 0x02;
pub const KIND_PRUNE: u8 = 0x03;
pub const KIND_HAVE: u8 = 0x04;
pub const KIND_WANT: u8 = 0x05;
pub const KIND_CHUNK: u8 = 0x06;
/// Reserved: none is sent, and one received is skipped as of an unknown kind.
pub const KIND_EVIDENCE: u8 = 0x08;

/// The bitmap's bound on the wire (`MAX_HAVE_BYTES` of §1.3). A bitmap past
/// what a node's own bitmaps hold ([`MAX_HAVE_BYTES`]) names a group beyond
/// its limits: the message is ignored.
pub const MAX_BITMAP_BYTES: usize = 1024;

/// A `GroupId` on the wire: type, key, index.
pub const GROUP_BYTES: usize = 1 + 32 + 2;

pub const JOIN_BYTES: usize = 1 + 4 + 1 + 8 + 1 + 2;
pub const GRAFT_BYTES: usize = 1 + 2 + 2 + 1 + 1;
pub const PRUNE_BYTES: usize = 1 + 2 + 2 + 1;
/// A HAVE's fixed part: group, flags, the bitmap's offset.
const HAVE_FIXED: usize = GROUP_BYTES + 1 + 4;
/// A WANT's fixed part: group, flags, hops, the bitmap's offset.
const WANT_FIXED: usize = GROUP_BYTES + 1 + 1 + 4;

/// Longest uvarint of a frame's length: every frame a bound allows fits it
/// (§1.5).
const MAX_LEN_BYTES: usize = 3;

/// A frame the peer is penalised for, and its stream closed (§1.2): a body
/// that does not decode, or one over its kind's bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Violation;

/// The object header of a chunk: its group and index, in the clear before its
/// compressed frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHead {
    pub group: GroupId,
    pub index: u32,
}

impl ChunkHead {
    pub const BYTES: usize = GROUP_BYTES + 4;

    pub fn of<B>(chunk: &ChunkMsg<B>) -> Self {
        Self { group: chunk.group, index: chunk.index }
    }

    pub fn encode(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        put_group(&mut out[..GROUP_BYTES], &self.group);
        out[GROUP_BYTES..].copy_from_slice(&self.index.to_le_bytes());
        out
    }

    pub fn parse(bytes: &[u8; Self::BYTES]) -> Self {
        Self {
            group: get_group(&bytes[..GROUP_BYTES]),
            index: u32::from_le_bytes(bytes[GROUP_BYTES..].try_into().unwrap()),
        }
    }
}

/// The bound on a chunk's body for frames of at most `max_frame` bytes
/// decompressed: the header, then snappy's worst case (§1.6).
pub const fn chunk_body_bound(max_frame: usize) -> usize {
    ChunkHead::BYTES + 32 + max_frame + max_frame / 6
}

/// The bound on a body of `kind` (§1.6). A kind not known here is held to the
/// largest known kind's.
pub const fn body_bound(kind: u8, max_frame: usize) -> usize {
    match kind {
        KIND_JOIN => JOIN_BYTES,
        KIND_GRAFT => GRAFT_BYTES,
        KIND_PRUNE => PRUNE_BYTES,
        KIND_HAVE => HAVE_FIXED + MAX_BITMAP_BYTES,
        KIND_WANT => WANT_FIXED + MAX_BITMAP_BYTES,
        _ => {
            let chunk = chunk_body_bound(max_frame);
            if chunk > WANT_FIXED + MAX_BITMAP_BYTES {
                chunk
            } else {
                WANT_FIXED + MAX_BITMAP_BYTES
            }
        }
    }
}

/// A frame read off the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireFrame<'a> {
    pub kind: u8,
    pub body: &'a [u8],
    /// The bytes the frame takes, its length included.
    pub len: usize,
}

/// The first frame of `input`: its kind, its body and the bytes it takes.
/// `Ok(None)` until the frame is all there. A frame over its kind's bound is
/// refused from its length and kind, before its body is read. `max_frame` is
/// the longest decompressed frame of any type the node runs.
pub fn next_frame(input: &[u8], max_frame: usize) -> Result<Option<WireFrame<'_>>, Violation> {
    let mut len = 0usize;
    let mut at = 0usize;
    loop {
        let Some(&b) = input.get(at) else {
            return Ok(None);
        };
        len |= ((b & 0x7f) as usize) << (7 * at);
        at += 1;
        if b & 0x80 == 0 {
            // Minimal encoding: no trailing zero group.
            if b == 0 && at > 1 {
                return Err(Violation);
            }
            break;
        }
        if at == MAX_LEN_BYTES {
            return Err(Violation);
        }
    }
    if len == 0 {
        return Err(Violation);
    }
    let Some(&kind) = input.get(at) else {
        return Ok(None);
    };
    if len - 1 > body_bound(kind, max_frame) {
        return Err(Violation);
    }
    let end = at + len;
    match input.get(at + 1..end) {
        Some(body) => Ok(Some(WireFrame { kind, body, len: end })),
        None => Ok(None),
    }
}

/// Decodes the body of a message that is not a chunk. `Ok(None)`: skipped
/// without penalty, as of a kind not known here or a group beyond the node's
/// limits.
pub fn decode_control(kind: u8, body: &[u8]) -> Result<Option<Control>, Violation> {
    let fixed = |len: usize| if body.len() == len { Ok(()) } else { Err(Violation) };
    let control = match kind {
        KIND_JOIN => {
            fixed(JOIN_BYTES)?;
            Control::Join(Join {
                object_type: TypeId(body[0]),
                fork_digest: body[1..5].try_into().unwrap(),
                interest: match body[5] {
                    0 => InterestKind::All,
                    1 => InterestKind::Derived,
                    2 => InterestKind::Declared,
                    _ => return Err(Violation),
                },
                custody_count: u64::from_le_bytes(body[6..14].try_into().unwrap()),
                duty: match body[14] {
                    0 => Duty::None,
                    1 => Duty::Forward,
                    _ => return Err(Violation),
                },
                colours: u16::from_le_bytes([body[15], body[16]]),
            })
        }
        KIND_GRAFT => {
            fixed(GRAFT_BYTES)?;
            Control::Graft(Graft {
                object_type: TypeId(body[0]),
                family: u16::from_le_bytes([body[1], body[2]]),
                colour: u16::from_le_bytes([body[3], body[4]]),
                direction: get_direction(body[5])?,
                answer: match body[6] {
                    0 => false,
                    1 => true,
                    _ => return Err(Violation),
                },
            })
        }
        KIND_PRUNE => {
            fixed(PRUNE_BYTES)?;
            Control::Prune(Prune {
                object_type: TypeId(body[0]),
                family: u16::from_le_bytes([body[1], body[2]]),
                colour: u16::from_le_bytes([body[3], body[4]]),
                direction: get_direction(body[5])?,
            })
        }
        KIND_HAVE => {
            let Some(bits) = get_bitmap(body, HAVE_FIXED)? else {
                return Ok(None);
            };
            let flags = body[GROUP_BYTES];
            Control::Have(Have {
                group: get_group(body),
                bits,
                offer: flags & 0x01 != 0,
                claim_all: flags & 0x02 != 0,
                complete: flags & 0x04 != 0,
            })
        }
        KIND_WANT => {
            let Some(bits) = get_bitmap(body, WANT_FIXED)? else {
                return Ok(None);
            };
            let flags = body[GROUP_BYTES];
            Control::Want(Want {
                group: get_group(body),
                bits,
                standing: flags & 0x01 != 0,
                hops: body[GROUP_BYTES + 1],
                probe: flags & 0x02 != 0,
                track_promise: false,
            })
        }
        _ => return Ok(None),
    };
    Ok(Some(control))
}

/// Decodes the body of a chunk (kind [`KIND_CHUNK`]). `layout` gives a type's
/// frame layout, `None` for a type the node does not run, whose chunk is
/// skipped. `decompress` writes the frame, of the length given, from the
/// compressed bytes into a buffer of the host's
/// ([`snappy::decompress_into`]). The chunk's id and `memo` are set here
/// ([`ChunkLayout::identify`]).
pub fn decode_chunk<B: ChunkBytes>(
    body: &[u8],
    layout: impl FnOnce(TypeId) -> Option<ChunkLayout>,
    decompress: impl FnOnce(&[u8], usize) -> Option<B>,
) -> Result<Option<ChunkMsg<B>>, Violation> {
    let (head, compressed) = body.split_at_checked(ChunkHead::BYTES).ok_or(Violation)?;
    let head = ChunkHead::parse(head.try_into().unwrap());
    let Some(layout) = layout(head.group.type_id) else {
        return Ok(None);
    };
    let len = snappy::decompressed_len(compressed).ok_or(Violation)?;
    if len > layout.max_frame_len() {
        return Err(Violation);
    }
    let frame = decompress(compressed, len).ok_or(Violation)?;
    if frame.len() != len {
        return Err(Violation);
    }
    let mut chunk =
        ChunkMsg { group: head.group, index: head.index, cached_id: [0; 59], frame, memo: [0; 32] };
    layout.identify(&mut chunk);
    Ok(Some(chunk))
}

/// An `Rpc` of one message, as the node takes a frame.
pub fn rpc_of<B>(control: Control) -> Rpc<B> {
    let mut rpc = Rpc::default();
    let _ = match control {
        Control::Join(j) => rpc.joins.push(j),
        Control::Have(h) => rpc.haves.push(h),
        Control::Want(w) => rpc.wants.push(w),
        Control::Graft(g) => rpc.grafts.push(g),
        Control::Prune(p) => rpc.prunes.push(p),
    };
    rpc
}

/// Appends the frame of a control message to `out`.
pub fn encode_control(control: &Control, out: &mut Vec<u8>) {
    let mut body = [0u8; WANT_FIXED + MAX_HAVE_BYTES];
    let (kind, len) = match control {
        Control::Join(j) => {
            body[0] = j.object_type.0;
            body[1..5].copy_from_slice(&j.fork_digest);
            body[5] = match j.interest {
                InterestKind::All => 0,
                InterestKind::Derived => 1,
                InterestKind::Declared => 2,
            };
            body[6..14].copy_from_slice(&j.custody_count.to_le_bytes());
            body[14] = match j.duty {
                Duty::None => 0,
                Duty::Forward => 1,
            };
            body[15..17].copy_from_slice(&j.colours.to_le_bytes());
            (KIND_JOIN, JOIN_BYTES)
        }
        Control::Graft(g) => {
            body[0] = g.object_type.0;
            body[1..3].copy_from_slice(&g.family.to_le_bytes());
            body[3..5].copy_from_slice(&g.colour.to_le_bytes());
            body[5] = put_direction(g.direction);
            body[6] = u8::from(g.answer);
            (KIND_GRAFT, GRAFT_BYTES)
        }
        Control::Prune(p) => {
            body[0] = p.object_type.0;
            body[1..3].copy_from_slice(&p.family.to_le_bytes());
            body[3..5].copy_from_slice(&p.colour.to_le_bytes());
            body[5] = put_direction(p.direction);
            (KIND_PRUNE, PRUNE_BYTES)
        }
        Control::Have(h) => {
            put_group(&mut body, &h.group);
            body[GROUP_BYTES] =
                u8::from(h.offer) | u8::from(h.claim_all) << 1 | u8::from(h.complete) << 2;
            (KIND_HAVE, put_bitmap(&mut body, HAVE_FIXED, &h.bits))
        }
        Control::Want(w) => {
            put_group(&mut body, &w.group);
            body[GROUP_BYTES] = u8::from(w.standing) | u8::from(w.probe) << 1;
            body[GROUP_BYTES + 1] = w.hops;
            (KIND_WANT, put_bitmap(&mut body, WANT_FIXED, &w.bits))
        }
    };
    put_frame_head(out, kind, len);
    out.extend_from_slice(&body[..len]);
}

/// Appends the frame of a chunk whose frame is `compressed`
/// ([`snappy::compress`] of it): a host may compress a chunk once and keep the
/// result for every peer it is sent to.
pub fn encode_chunk(head: &ChunkHead, compressed: &[u8], out: &mut Vec<u8>) {
    put_frame_head(out, KIND_CHUNK, ChunkHead::BYTES + compressed.len());
    out.extend_from_slice(&head.encode());
    out.extend_from_slice(compressed);
}

/// Appends the frames of `entry`: its chunk, compressed here, then its control
/// messages. Evidence is not sent (§1.2). Where the chunk is the first of its
/// group to the peer (`QueueEntry::first_of_group`), `extend_first` appends
/// what its type sends with it to a copy of its frame, as a cell its header.
pub fn encode_entry<B: ChunkBytes>(
    entry: &QueueEntry<B>,
    out: &mut Vec<u8>,
    extend_first: impl FnOnce(&ChunkMsg<B>, &mut Vec<u8>),
) {
    if let Some(chunk) = &entry.chunk {
        let compressed = if entry.first_of_group {
            let mut frame = chunk.frame.as_bytes().to_vec();
            extend_first(chunk, &mut frame);
            snappy::compress(&frame)
        } else {
            snappy::compress(chunk.frame.as_bytes())
        };
        encode_chunk(&ChunkHead::of(chunk), &compressed, out);
    }
    let controls = entry
        .joins
        .iter()
        .map(|&j| Control::Join(j))
        .chain(entry.haves.iter().map(|&h| Control::Have(h)))
        .chain(entry.wants.iter().map(|&w| Control::Want(w)))
        .chain(entry.grafts.iter().map(|&g| Control::Graft(g)))
        .chain(entry.prunes.iter().map(|&p| Control::Prune(p)));
    for control in controls {
        encode_control(&control, out);
    }
}

/// The bytes a chunk takes on the stream, its frame counted uncompressed
/// (§1.7).
pub fn chunk_wire_size<B: ChunkBuffer>(chunk: &ChunkMsg<B>) -> usize {
    let len = 1 + ChunkHead::BYTES + chunk.frame.len();
    uvarint_len(len) + len
}

fn put_frame_head(out: &mut Vec<u8>, kind: u8, body_len: usize) {
    let mut len = body_len + 1;
    while len >= 0x80 {
        out.push(len as u8 | 0x80);
        len >>= 7;
    }
    out.push(len as u8);
    out.push(kind);
}

const fn uvarint_len(mut v: usize) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

fn put_group(out: &mut [u8], group: &GroupId) {
    out[0] = group.type_id.0;
    out[1..33].copy_from_slice(&group.key);
    out[33..35].copy_from_slice(&group.index.to_le_bytes());
}

fn get_group(bytes: &[u8]) -> GroupId {
    let key: Bytes32 = bytes[1..33].try_into().unwrap();
    GroupId::new(TypeId(bytes[0]), key, u16::from_le_bytes([bytes[33], bytes[34]]))
}

/// Writes the bitmap's offset at the end of the fixed part and its bytes after
/// it; gives the body's length.
fn put_bitmap(body: &mut [u8], fixed: usize, bits: &Bitmap) -> usize {
    body[fixed - 4..fixed].copy_from_slice(&(fixed as u32).to_le_bytes());
    let bytes: &mut [u8; MAX_HAVE_BYTES] =
        (&mut body[fixed..fixed + MAX_HAVE_BYTES]).try_into().unwrap();
    fixed + bits.encode_to_slice(bytes)
}

/// The bitmap of a body whose fixed part is `fixed` bytes, its offset the last
/// four. `Ok(None)`: longer than the node's bitmaps.
fn get_bitmap(body: &[u8], fixed: usize) -> Result<Option<Bitmap>, Violation> {
    if body.len() < fixed || body.len() > fixed + MAX_BITMAP_BYTES {
        return Err(Violation);
    }
    if u32::from_le_bytes(body[fixed - 4..fixed].try_into().unwrap()) as usize != fixed {
        return Err(Violation);
    }
    let bytes = &body[fixed..];
    if bytes.len() > MAX_HAVE_BYTES {
        return Ok(None);
    }
    Ok(Bitmap::from_wire_bytes(bytes))
}

fn put_direction(d: Direction) -> u8 {
    match d {
        Direction::Out => 0,
        Direction::In => 1,
        Direction::Both => 2,
    }
}

fn get_direction(b: u8) -> Result<Direction, Violation> {
    match b {
        0 => Ok(Direction::Out),
        1 => Ok(Direction::In),
        2 => Ok(Direction::Both),
        _ => Err(Violation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_FRAME: usize = 40_000;

    fn group() -> GroupId {
        GroupId::new(TypeId(3), [0x11; 32], 0x0102)
    }

    /// Every frame's size on the stream is §1.7's, and it decodes to what was
    /// encoded.
    fn roundtrip(control: Control, size: usize) {
        let mut out = Vec::new();
        encode_control(&control, &mut out);
        assert_eq!(out.len(), size, "{control:?}");
        let WireFrame { kind, body, len: used } = next_frame(&out, MAX_FRAME).unwrap().unwrap();
        assert_eq!(used, out.len());
        let back = decode_control(kind, body).unwrap().unwrap();
        assert_eq!(format!("{back:?}"), format!("{control:?}"));
        // Not all there yet.
        assert_eq!(next_frame(&out[..out.len() - 1], MAX_FRAME), Ok(None));
    }

    #[test]
    fn test_control_sizes() {
        let join = Join {
            object_type: TypeId(2),
            fork_digest: [1, 2, 3, 4],
            interest: InterestKind::Declared,
            custody_count: 7,
            duty: Duty::None,
            colours: 2,
        };
        roundtrip(Control::Join(join), 19);
        let graft = Graft {
            object_type: TypeId(1),
            family: 77,
            colour: 1,
            direction: Direction::In,
            answer: true,
        };
        roundtrip(Control::Graft(graft), 9);
        let prune =
            Prune { object_type: TypeId(1), family: 77, colour: 1, direction: Direction::Both };
        roundtrip(Control::Prune(prune), 8);

        // HAVE: 42 + b, 43 + b from b = 87. Bitmaps hold at most 128 bytes here.
        for (bits, b) in
            [(Bitmap::new(), 0), (Bitmap::all_bits(8), 1), (Bitmap::all_bits(1024), 128)]
        {
            let size = if b >= 87 { 43 + b } else { 42 + b };
            roundtrip(Control::Have(Have::holding(group(), bits, true, false)), size);
            roundtrip(Control::Have(Have::offer(group(), bits)), size);
        }
        // WANT of one index i: 44 + i / 8, 45 + i / 8 from i = 680.
        for i in [0u32, 9, 679, 680, 1023] {
            let size = if i >= 680 { 45 + i / 8 } else { 44 + i / 8 };
            let want =
                Want { hops: 2, probe: true, ..Want::standing(group(), Bitmap::singleton(i)) };
            roundtrip(Control::Want(want), size as usize);
        }
    }

    #[test]
    fn test_chunk_roundtrip() {
        let frame: Vec<u8> = (0..5000u32).map(|i| (i % 7) as u8).collect();
        let layout = ChunkLayout::Standalone { context_len: 0, max_data: frame.len() };
        let mut chunk =
            ChunkMsg { group: group(), index: 9, cached_id: [0; 59], frame, memo: [0; 32] };
        layout.identify(&mut chunk);
        let mut out = Vec::new();
        let no_extension = |_: &ChunkMsg<Vec<u8>>, _: &mut Vec<u8>| panic!("not a first push");
        encode_entry(&QueueEntry::from_chunk(chunk.clone(), false), &mut out, no_extension);
        let WireFrame { kind, body, len: used } = next_frame(&out, MAX_FRAME).unwrap().unwrap();
        assert_eq!((kind, used), (KIND_CHUNK, out.len()));
        let decompress = |c: &[u8], len: usize| snappy::decompress(c, len);
        let back = decode_chunk(body, |_| Some(layout), decompress).unwrap().unwrap();
        assert_eq!(back, chunk);
        assert_eq!(back.cached_id[..ChunkHead::BYTES], ChunkHead::of(&chunk).encode());

        // A type not run is skipped; a frame past the type's bound is a violation.
        assert_eq!(decode_chunk(body, |_| None, decompress), Ok(None));
        let short = ChunkLayout::Standalone { context_len: 0, max_data: chunk.frame.len() - 1 };
        assert_eq!(decode_chunk(body, |_| Some(short), decompress), Err(Violation));

        // The first of its group to the peer carries what its type appends.
        let first =
            QueueEntry { first_of_group: true, ..QueueEntry::from_chunk(chunk.clone(), false) };
        let mut out = Vec::new();
        encode_entry(&first, &mut out, |_, frame| frame.extend_from_slice(b"head"));
        let WireFrame { body, .. } = next_frame(&out, MAX_FRAME).unwrap().unwrap();
        let wide = ChunkLayout::Standalone { context_len: 0, max_data: chunk.frame.len() + 4 };
        let back = decode_chunk(body, |_| Some(wide), decompress).unwrap().unwrap();
        assert_eq!(back.frame[..chunk.frame.len()], chunk.frame[..]);
        assert_eq!(&back.frame[chunk.frame.len()..], b"head");
    }

    #[test]
    fn test_violations() {
        // A length over the kind's bound, before the body is there.
        let mut out = Vec::new();
        put_frame_head(&mut out, KIND_JOIN, JOIN_BYTES + 1);
        assert_eq!(next_frame(&out, MAX_FRAME), Err(Violation));
        // An unknown kind is held to the largest bound, and skipped.
        let mut out = Vec::new();
        put_frame_head(&mut out, 0x42, body_bound(0x42, MAX_FRAME) + 1);
        assert_eq!(next_frame(&out, MAX_FRAME), Err(Violation));
        assert_eq!(decode_control(0x42, &[1, 2, 3]), Ok(None));
        assert_eq!(decode_control(KIND_EVIDENCE, &[1, 2, 3]), Ok(None));
        // A length past three bytes, or not minimal.
        assert_eq!(next_frame(&[0x80, 0x80, 0x80, 0x01], MAX_FRAME), Err(Violation));
        assert_eq!(next_frame(&[0x81, 0x00, KIND_JOIN], MAX_FRAME), Err(Violation));
        // Enums out of range, a fixed body of another length, a bad offset.
        let mut out = Vec::new();
        encode_control(&Control::Join(Join::default()), &mut out);
        let WireFrame { kind, body, .. } = next_frame(&out, MAX_FRAME).unwrap().unwrap();
        let mut bad = body.to_vec();
        bad[14] = 2;
        assert_eq!(decode_control(kind, &bad), Err(Violation));
        assert_eq!(decode_control(kind, &body[1..]), Err(Violation));
        let mut out = Vec::new();
        encode_control(&Control::Have(Have::offer(group(), Bitmap::singleton(3))), &mut out);
        let WireFrame { kind, body, .. } = next_frame(&out, MAX_FRAME).unwrap().unwrap();
        let mut bad = body.to_vec();
        bad[HAVE_FIXED - 4] += 1;
        assert_eq!(decode_control(kind, &bad), Err(Violation));
        // A bitmap past this node's bitmaps is ignored.
        let mut long = body[..HAVE_FIXED].to_vec();
        long.resize(HAVE_FIXED + MAX_HAVE_BYTES + 1, 0xff);
        assert_eq!(decode_control(kind, &long), Ok(None));
    }
}
