//! How a type's chunk frame is laid out, and level 1 in the two steps a reader
//! of a stream takes: the part before the proof as soon as it has arrived,
//! and the rest over the whole frame, from the digest its id is computed with.

use seacast_core::{Bytes32, ChunkMsg, GroupId};

use crate::{
    buffer::ChunkBytes,
    merkle::MAX_PROOF_DEPTH,
    segment::{
        DESCRIPTOR_BYTES, MAX_PLAIN_CHUNKS, MAX_SEGMENT_SIZE, SegmentDescriptor, check_frame_leaf,
        chunk_id, frame_identity, group_id, group_key,
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
    /// one of its type, the descriptor and the context, `index` is one the
    /// descriptor has, and the proof and the data have the lengths it gives.
    /// For a standalone chunk only the index and the data's bound: its group
    /// is over the whole frame. Gives the proof's length in bytes.
    pub fn check_head(
        &self,
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
                    group_key(group.type_id, &group_id(&descriptor), context) == *group &&
                    rest_len == proof_len + descriptor.segment_length(index))
                .then_some(proof_len)
            }
        }
    }

    /// What a reader computes of a whole frame before level 1: the content of
    /// its id and the digest level 1 then checks, the leaf of a segmented
    /// chunk's data or a standalone chunk's key. Each byte of the frame is
    /// hashed once.
    pub fn identity(&self, group: &GroupId, frame: &[u8]) -> (Bytes32, Bytes32) {
        match *self {
            Self::Standalone { .. } => {
                let key = standalone_group(group.type_id, frame).key;
                (key, key)
            }
            Self::Segmented { context_len } => {
                let (content, leaf) = frame_identity(frame, context_len);
                (content, leaf.unwrap_or_default())
            }
        }
    }

    /// Sets `chunk`'s id and `memo` from [`identity`](Self::identity): the
    /// digest level 1 checks, which a segmented chunk keeps for level 2 once
    /// its proof has passed.
    pub fn identify<B: ChunkBytes>(&self, chunk: &mut ChunkMsg<B>) {
        let (content, digest) = self.identity(&chunk.group, chunk.frame.as_bytes());
        chunk.cached_id = chunk_id(&chunk.group, chunk.index, &content);
        chunk.memo = digest;
    }

    /// The rest of level 1, on a whole frame whose head passed
    /// [`check_head`](Self::check_head), with the digest
    /// [`identity`](Self::identity) gave: a segmented chunk's proof leads from
    /// the leaf to the descriptor's root, a standalone chunk's frame is what
    /// `group`'s key is the hash of.
    pub fn check_body(&self, group: &GroupId, index: u32, frame: &[u8], digest: &Bytes32) -> bool {
        match *self {
            Self::Standalone { .. } => *digest == group.key,
            Self::Segmented { context_len } => check_frame_leaf(index, frame, context_len, digest),
        }
    }

    /// Both steps, on a frame that is all there. Gives the digest level 1
    /// checked.
    pub fn check(&self, group: &GroupId, index: u32, frame: &[u8]) -> Option<Bytes32> {
        let (head, rest) = frame.split_at_checked(self.head_len())?;
        self.check_head(group, index, head, rest.len())?;
        let (_, digest) = self.identity(group, frame);
        self.check_body(group, index, frame, &digest).then_some(digest)
    }
}

#[cfg(test)]
mod tests {
    use seacast_core::TypeId;

    use super::*;
    use crate::{
        buffer::VecBufferPool,
        merkle::leaf_hash,
        segment::{SnappyBlockCompressor, build_chunks, build_group, split_frame},
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
            let proof_len = layout.check_head(group, index, head, rest.len()).unwrap();
            assert_eq!(proof_len, 32 * descriptor.proof_len());
            // A reader's id is the publisher's, and its digest the data's leaf.
            let mut read = chunk.clone();
            read.cached_id = [0; 59];
            layout.identify(&mut read);
            assert_eq!(read.cached_id, chunk.cached_id);
            let leaf = leaf_hash(split_frame(frame, context.len()).unwrap().data);
            assert_eq!(read.memo, leaf);
            assert!(layout.check_body(group, index, frame, &leaf));
            assert_eq!(layout.check(group, index, frame), Some(leaf));

            // The head alone refuses another type, group or index, and a frame of
            // another length.
            let other_type = GroupId { type_id: TypeId(4), ..*group };
            assert_eq!(layout.check_head(&other_type, index, head, rest.len()), None);
            let other = GroupId { key: [0; 32], ..*group };
            assert_eq!(layout.check_head(&other, index, head, rest.len()), None);
            assert_eq!(layout.check_head(group, descriptor.count, head, rest.len()), None);
            assert_eq!(layout.check_head(group, index, head, rest.len() + 1), None);
            // Another byte anywhere is another id, and level 1 refuses it: a header
            // or context byte at the head, a proof or data byte at the body.
            for at in [0, head.len(), frame.len() - 1] {
                let mut bad = chunk.clone();
                bad.frame[at] ^= 1;
                layout.identify(&mut bad);
                assert_ne!(bad.cached_id, chunk.cached_id);
                assert_eq!(layout.check(group, index, &bad.frame), None);
            }
        }
    }

    #[test]
    fn test_standalone_layout() {
        let layout = ChunkLayout::Standalone { context_len: 2, max_data: 8 };
        let t = TypeId(9);
        let frame = b"cx12345678";
        let group = standalone_group(t, frame);
        assert_eq!(layout.check(&group, 0, frame), Some(group.key));
        assert_eq!(layout.check(&group, 1, frame), None);
        assert_eq!(layout.check(&GroupId { type_id: TypeId(8), ..group }, 0, frame), None);
        assert_eq!(layout.check(&group, 0, b"cx123456789"), None);
        assert_eq!(layout.check(&group, 0, b"c"), None);
        // A forged frame under the group has an id of its own.
        let (forged, _) = layout.identity(&group, b"cx12345679");
        assert_ne!(forged, group.key);
    }
}
