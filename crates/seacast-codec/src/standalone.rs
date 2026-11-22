//! A standalone type: one chunk a group (`N = K = 1`), with no header and no
//! proof. Its frame is `context | data`, and its group id is the hash of its
//! type and that frame, so the id alone authenticates the content. The context
//! may be empty.

use seacast_core::{
    Bytes32, ChunkMsg, GroupId, PreallocVec, Shape, TypeCodec, TypeId, ValidationResult,
};

use crate::{buffer::ChunkBytes, sha256::Sha256, wire::chunk_wire_size};

/// The group of a standalone chunk: index 0 under the key `sha256(0x04 || type
/// || frame)`.
pub fn standalone_group(type_id: TypeId, frame: &[u8]) -> GroupId {
    let mut h = Sha256::new();
    h.update(&[0x04, type_id.0]);
    h.update(frame);
    GroupId::new(type_id, h.finalize(), 0)
}

/// Level 1 of a standalone chunk, all of it: it is index 0, its frame holds a
/// context and no more than `max_data` bytes of data, and `group` is the id of
/// that frame.
pub fn check_standalone(
    type_id: TypeId,
    group: &GroupId,
    index: u32,
    frame: &[u8],
    context_len: usize,
    max_data: usize,
) -> bool {
    index == 0 &&
        frame.len() >= context_len &&
        frame.len() - context_len <= max_data &&
        standalone_group(type_id, frame) == *group
}

/// The codec of a standalone type as a node's [`TypeCodec`]. The group id
/// commits the whole frame, so there is no header: the domain is given the
/// group id in its place.
#[derive(Debug, Clone, Copy)]
pub struct StandaloneCodec {
    pub context_len: usize,
    pub max_data: usize,
}

impl<B: ChunkBytes> TypeCodec<B> for StandaloneCodec {
    fn shape(&self, _chunk: &ChunkMsg<B>) -> Option<Shape> {
        Some(Shape { n: 1, k: 1 })
    }

    fn check(&self, chunk: &ChunkMsg<B>) -> bool {
        check_standalone(
            chunk.group.type_id,
            &chunk.group,
            chunk.index,
            chunk.frame.as_bytes(),
            self.context_len,
            self.max_data,
        )
    }

    fn check_proof(&mut self, _chunk: &ChunkMsg<B>) -> ValidationResult {
        ValidationResult::Accept
    }

    fn header_id(&self, chunk: &ChunkMsg<B>) -> Bytes32 {
        chunk.group.key
    }

    fn context<'a>(&self, chunk: &'a ChunkMsg<B>) -> &'a [u8] {
        chunk.frame.as_bytes().get(..self.context_len).unwrap_or(&[])
    }

    /// The object is the one chunk's frame, context included.
    fn decode(
        &mut self,
        _group: &GroupId,
        available: &[ChunkMsg<B>],
        _shape: &Shape,
        out_rebuilt: &mut PreallocVec<ChunkMsg<B>>,
    ) -> Option<B> {
        let chunk = available.first()?;
        let _ = out_rebuilt.push(chunk.clone());
        Some(chunk.frame.clone())
    }

    fn wire_size(&self, chunk: &ChunkMsg<B>, _first_of_group: bool) -> usize {
        chunk_wire_size(chunk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standalone_chunk() {
        let t = TypeId(7);
        let frame = b"a small message";
        let group = standalone_group(t, frame);
        assert!(check_standalone(t, &group, 0, frame, 0, 64));
        // Another index, type or byte, or more data than the type allows, is refused.
        assert!(!check_standalone(t, &group, 1, frame, 0, 64));
        assert!(!check_standalone(TypeId(8), &group, 0, frame, 0, 64));
        assert!(!check_standalone(t, &group, 0, &frame[1..], 0, 64));
        assert!(!check_standalone(t, &group, 0, frame, 0, 4));
        assert!(!check_standalone(t, &group, 0, frame, 32, 64));
    }

    #[test]
    fn test_standalone_codec() {
        let t = TypeId(7);
        let frame = b"ctx:a small message".to_vec();
        let chunk = ChunkMsg {
            group: standalone_group(t, &frame),
            index: 0,
            frame: frame.clone(),
            cached_id: [0; 59],
            memo: [0; 32],
            wire_len: 0,
        };
        let mut codec = StandaloneCodec { context_len: 4, max_data: 64 };
        assert!(codec.check(&chunk));
        assert_eq!(TypeCodec::<Vec<u8>>::context(&codec, &chunk), b"ctx:");
        assert_eq!(codec.shape(&chunk), Some(Shape { n: 1, k: 1 }));
        let mut rebuilt = PreallocVec::with_capacity(1);
        let shape = Shape { n: 1, k: 1 };
        let object = codec.decode(&chunk.group, std::slice::from_ref(&chunk), &shape, &mut rebuilt);
        assert_eq!(object, Some(frame));
        assert_eq!(rebuilt.len(), 1);
    }
}
