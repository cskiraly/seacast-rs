//! A standalone type: one chunk a group (`N = K = 1`), with no header and no
//! proof. Its frame is `context | data`, and its group id is the hash of its
//! type and that frame, so the id alone authenticates the content. The context
//! may be empty.

use seacast_core::{GroupId, TypeId};

use crate::sha256::Sha256;

/// The id of the group of a standalone chunk: `sha256(0x04 || uint16_le(type)
/// || frame)`.
pub fn standalone_group(type_id: TypeId, frame: &[u8]) -> GroupId {
    let mut h = Sha256::new();
    h.update(&[0x04]);
    h.update(&type_id.0.to_le_bytes());
    h.update(frame);
    h.finalize()
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
}
