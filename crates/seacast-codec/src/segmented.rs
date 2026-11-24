//! The codec of a segmented type as a node's [`TypeCodec`]: a chunk's frame is
//! `descriptor | context | proof | data`, its group id binds the type, the
//! descriptor and the context, and its proof is a Merkle path to the
//! descriptor's root. Nothing here knows what a context holds, only how long it
//! is.

use std::marker::PhantomData;

use seacast_core::{Bytes32, ChunkMsg, GroupId, PreallocVec, Shape, TypeCodec, ValidationResult};

use crate::{
    buffer::{BufferPool, ChunkBytes},
    layout::ChunkLayout,
    segment::{
        DESCRIPTOR_BYTES, SnappyBlockCompressor, check_frame, check_frame_leaf, chunk_wire_size,
        decode_and_reencode, frame_leaf_hash, group_id, split_frame,
    },
};

type Chunk<B> = ChunkMsg<B>;

pub struct SegmentedCodec<Pool, B> {
    pub pool: Pool,
    /// The bytes of a chunk's context, which the domain defines.
    pub context_len: usize,
    _buffer: PhantomData<B>,
}

impl<Pool, B> SegmentedCodec<Pool, B> {
    pub fn new(pool: Pool, context_len: usize) -> Self {
        Self { pool, context_len, _buffer: PhantomData }
    }

    /// Sets a received chunk's id, and its `memo` to its data's leaf digest,
    /// the proof not checked ([`ChunkLayout::identify`]).
    pub fn identify(&self, chunk: &mut Chunk<B>)
    where
        B: ChunkBytes,
    {
        ChunkLayout::Segmented { context_len: self.context_len }.identify(chunk);
    }

    /// The rest of level 1 for a chunk [`TypeCodec::check_proof`] answered
    /// `Pending` for: its Merkle proof. The host runs it wherever it sees
    /// fit before it calls `on_validated`. The proof is checked from the leaf
    /// digest in `memo` where [`identify`](Self::identify) left one, and the
    /// data is not hashed again; otherwise the leaf is computed and left there.
    /// Level 2 takes it from `memo`.
    pub fn check_proof(&self, chunk: &mut Chunk<B>) -> ValidationResult
    where
        B: ChunkBytes,
    {
        let frame = chunk.frame.as_bytes();
        let ok = if chunk.memo != Bytes32::default() {
            check_frame_leaf(chunk.index, frame, self.context_len, &chunk.memo)
        } else {
            match frame_leaf_hash(chunk.index, frame, self.context_len) {
                Some(leaf) => {
                    chunk.memo = leaf;
                    true
                }
                None => false,
            }
        };
        if ok { ValidationResult::Accept } else { ValidationResult::Reject }
    }
}

impl<Pool, B> TypeCodec<B> for SegmentedCodec<Pool, B>
where
    Pool: BufferPool<B>,
    B: ChunkBytes,
{
    fn shape(&self, chunk: &Chunk<B>) -> Option<Shape> {
        let frame = split_frame(chunk.frame.as_bytes(), self.context_len)?;
        Some(Shape { n: frame.descriptor.count, k: frame.descriptor.k() })
    }

    fn check(&self, chunk: &Chunk<B>) -> bool {
        check_frame(
            chunk.group.type_id,
            &chunk.group,
            chunk.index,
            chunk.frame.as_bytes(),
            self.context_len,
        )
    }

    fn check_proof(&mut self, _chunk: &Chunk<B>) -> ValidationResult {
        ValidationResult::Pending
    }

    fn header_id(&self, chunk: &Chunk<B>) -> Bytes32 {
        split_frame(chunk.frame.as_bytes(), self.context_len)
            .map(|frame| group_id(&frame.descriptor))
            .unwrap_or_default()
    }

    fn context<'a>(&self, chunk: &'a Chunk<B>) -> &'a [u8] {
        chunk
            .frame
            .as_bytes()
            .get(DESCRIPTOR_BYTES..DESCRIPTOR_BYTES + self.context_len)
            .unwrap_or(&[])
    }

    fn decode(
        &mut self,
        _group: &GroupId,
        available: &[Chunk<B>],
        _shape: &Shape,
        out_rebuilt: &mut PreallocVec<Chunk<B>>,
    ) -> Option<B> {
        decode_and_reencode(
            available,
            self.context_len,
            &mut self.pool,
            &SnappyBlockCompressor,
            out_rebuilt,
        )
    }

    fn wire_size(&self, chunk: &Chunk<B>, _first_of_group: bool) -> usize {
        chunk_wire_size(chunk)
    }
}
