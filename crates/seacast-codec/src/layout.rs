//! How a type's chunk frame is laid out, and level 1 in the two steps a reader
//! of a stream takes: the part before the proof as soon as it has arrived,
//! and the rest over the whole frame.

use seacast_core::{Bytes32, GroupId, TypeId};

use crate::{
    merkle::MAX_PROOF_DEPTH,
    segment::{
        DESCRIPTOR_BYTES, MAX_PLAIN_CHUNKS, MAX_SEGMENT_SIZE, SegmentDescriptor, frame_leaf_hash,
        group_id, group_key,
    },
    standalone::standalone_group,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkLayout {
    /// `context | data`, one chunk a group.
    Standalone { context_len: usize, max_data: usize },
    /// `descriptor | context | proof | data`.
    Segmented { context_len: usize },
}

impl ChunkLayout {
    /// The bytes of a frame before its proof: every length in the frame is
    /// given by the type and these.
    pub const fn head_len(&self) -> usize {
        match *self {
            Self::Standalone { context_len, .. } => context_len,
            Self::Segmented { context_len } => DESCRIPTOR_BYTES + context_len,
        }
    }

    /// The longest frame of the type.
    pub const fn max_frame_len(&self) -> usize {
        match *self {
            Self::Standalone { context_len, max_data } => context_len + max_data,
            Self::Segmented { context_len } => {
                DESCRIPTOR_BYTES + context_len + 32 * MAX_PROOF_DEPTH + MAX_SEGMENT_SIZE as usize
            }
        }
    }

    /// The part of level 1 that reads neither proof nor data, on a frame's
    /// first [`head_len`](Self::head_len) bytes and the count of those that
    /// follow. For a segmented chunk: the descriptor is valid, `group` is the
    /// id of `type_id`, the descriptor and the context, `index` is one the
    /// descriptor has, and the proof and the data have the lengths it gives.
    /// For a standalone chunk only the index and the data's bound: its group
    /// id is over the whole frame. Gives the proof's length in bytes.
    pub fn check_head(
        &self,
        type_id: TypeId,
        group: &GroupId,
        index: u32,
        head: &[u8],
        rest_len: usize,
    ) -> Option<usize> {
        if head.len() != self.head_len() {
            return None;
        }
        match *self {
            Self::Standalone { max_data, .. } => (index == 0 && rest_len <= max_data).then_some(0),
            Self::Segmented { .. } => {
                let (descriptor, context) = head.split_at(DESCRIPTOR_BYTES);
                let descriptor = SegmentDescriptor::deserialize(descriptor)?;
                let proof_len = 32 * descriptor.proof_len();
                (descriptor.is_valid() &&
                    descriptor.count as usize <= MAX_PLAIN_CHUNKS &&
                    index < descriptor.count &&
                    group_key(type_id, &group_id(&descriptor), context) == *group &&
                    rest_len == proof_len + descriptor.segment_length(index))
                .then_some(proof_len)
            }
        }
    }

    /// The rest of level 1, on a whole frame whose head passed
    /// [`check_head`](Self::check_head): a segmented chunk's data is the leaf
    /// its proof leads from to the descriptor's root, a standalone chunk's
    /// frame is what `group` is the id of. Gives the content of the chunk's
    /// id ([`chunk_id`](crate::chunk_id)): the leaf's digest, or the group id.
    pub fn check_body(
        &self,
        type_id: TypeId,
        group: &GroupId,
        index: u32,
        frame: &[u8],
    ) -> Option<Bytes32> {
        match *self {
            Self::Standalone { .. } => {
                (standalone_group(type_id, frame) == *group).then_some(*group)
            }
            Self::Segmented { context_len } => frame_leaf_hash(index, frame, context_len),
        }
    }

    /// Both steps, on a frame that is all there.
    pub fn check(
        &self,
        type_id: TypeId,
        group: &GroupId,
        index: u32,
        frame: &[u8],
    ) -> Option<Bytes32> {
        let (head, rest) = frame.split_at_checked(self.head_len())?;
        self.check_head(type_id, group, index, head, rest.len())?;
        self.check_body(type_id, group, index, frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        buffer::VecBufferPool,
        segment::{SnappyBlockCompressor, build_chunks, build_group, chunk_id},
    };

    #[test]
    fn test_segmented_layout() {
        let context = [5u8; 40];
        let layout = ChunkLayout::Segmented { context_len: context.len() };
        let body: Vec<u8> = (0..100_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let (descriptor, shards) =
            build_group::<Vec<u8>, _, _>(&body, &mut VecBufferPool, &SnappyBlockCompressor);
        let t = TypeId(3);
        for chunk in build_chunks(t, &context, &descriptor, &shards, &mut VecBufferPool) {
            let (group, index, frame) = (&chunk.group, chunk.index, &chunk.frame);
            assert!(frame.len() <= layout.max_frame_len());
            let (head, rest) = frame.split_at(layout.head_len());
            let proof_len = layout.check_head(t, group, index, head, rest.len()).unwrap();
            assert_eq!(proof_len, 32 * descriptor.proof_len());
            let leaf = layout.check_body(t, group, index, frame).unwrap();
            assert_eq!(chunk.cached_id, chunk_id(group, index, &leaf));
            assert_eq!(layout.check(t, group, index, frame), Some(leaf));

            // The head alone refuses another type, group or index, and a frame of
            // another length.
            assert_eq!(layout.check_head(TypeId(4), group, index, head, rest.len()), None);
            assert_eq!(layout.check_head(t, &[0; 32], index, head, rest.len()), None);
            assert_eq!(layout.check_head(t, group, descriptor.count, head, rest.len()), None);
            assert_eq!(layout.check_head(t, group, index, head, rest.len() + 1), None);
            // The body refuses other data.
            let mut bad = frame.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert_eq!(layout.check_body(t, group, index, &bad), None);
        }
    }

    #[test]
    fn test_standalone_layout() {
        let layout = ChunkLayout::Standalone { context_len: 2, max_data: 8 };
        let t = TypeId(9);
        let frame = b"cx12345678";
        let group = standalone_group(t, frame);
        assert_eq!(layout.check(t, &group, 0, frame), Some(group));
        assert_eq!(layout.check(t, &group, 1, frame), None);
        assert_eq!(layout.check(TypeId(8), &group, 0, frame), None);
        assert_eq!(layout.check(t, &group, 0, b"cx123456789"), None);
        assert_eq!(layout.check(t, &group, 0, b"c"), None);
    }
}
