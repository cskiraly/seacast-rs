//! The codec of a segmented type as a node's [`TypeCodec`]: a chunk's frame is
//! `descriptor | context | proof | data`, its group id binds the type, the
//! descriptor and the context, and its proof is a Merkle path to the
//! descriptor's root. Nothing here knows what a context holds, only how long it
//! is.

use std::marker::PhantomData;

#[cfg(feature = "data_only_root")]
use seacast_core::Bitmap;
use seacast_core::{
    Bytes32, ChunkMsg, GroupId, PreallocVec, Shape, TypeCodec, TypeId, ValidationResult,
};

use crate::{
    buffer::{BufferPool, ChunkBytes},
    segment::{
        DESCRIPTOR_BYTES, SnappyBlockCompressor, check_frame, decode_and_reencode, frame_leaf_hash,
        group_id, split_frame,
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

    /// The rest of level 1 for a chunk [`TypeCodec::check_proof`] answered
    /// `Pending` for: its Merkle proof. The host runs it wherever it sees
    /// fit before it calls `on_validated`. The leaf digest it proved is left in
    /// the chunk's `memo`, for level 2 not to hash the chunk again.
    pub fn check_proof(&self, chunk: &mut Chunk<B>) -> ValidationResult
    where
        B: ChunkBytes,
    {
        match frame_leaf_hash(chunk.index, chunk.frame.as_bytes(), self.context_len) {
            Some(leaf) => {
                chunk.memo = leaf;
                ValidationResult::Accept
            }
            None => ValidationResult::Reject,
        }
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
            chunk.type_id,
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
        _t: TypeId,
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

    /// No parity is computed: the data chunks, and the chunks held.
    #[cfg(feature = "data_only_root")]
    fn producible(&self, _t: TypeId, shape: &Shape, held: &Bitmap) -> Bitmap {
        Bitmap::all_bits(shape.k) | held
    }

    /// The chunk as it is sent: its type, group and index, then its frame.
    fn wire_size(&self, chunk: &Chunk<B>) -> usize {
        2 + 32 + 4 + chunk.frame.len()
    }
}
