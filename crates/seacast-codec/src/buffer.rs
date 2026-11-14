//! Buffers whose bytes are at hand, for hosts that keep each chunk in memory of
//! its own.
//!
//! The state machine asks a buffer handle only for its length
//! (`seacast_core::ChunkBuffer`). The functions of this crate that take or make
//! whole chunks need more: the bytes behind a handle ([`ChunkBytes`]), and a
//! handle for bytes they produced ([`BufferPool`]). A host whose chunks sit
//! in a store it writes in place uses the slice-level functions instead
//! (`segment::decode_in_place`, `wire::encode_rpc_framing`,
//! `wire::decode_rpc_with`), and needs neither.

use seacast_core::ChunkBuffer;

/// A handle that can show its bytes without anything else in hand.
pub trait ChunkBytes: ChunkBuffer {
    fn as_bytes(&self) -> &[u8];
}

impl ChunkBytes for Vec<u8> {
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        self
    }
}

impl ChunkBytes for std::sync::Arc<[u8]> {
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        self
    }
}

/// Makes a buffer of its own for bytes that were produced elsewhere: a copy.
pub trait BufferPool<B: ChunkBuffer> {
    fn alloc_from_slice(&mut self, data: &[u8]) -> B;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct VecBufferPool;

impl BufferPool<Vec<u8>> for VecBufferPool {
    #[inline]
    fn alloc_from_slice(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ArcBufferPool;

impl BufferPool<std::sync::Arc<[u8]>> for ArcBufferPool {
    #[inline]
    fn alloc_from_slice(&mut self, data: &[u8]) -> std::sync::Arc<[u8]> {
        std::sync::Arc::from(data)
    }
}
