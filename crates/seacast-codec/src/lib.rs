//! # `seacast-codec`
//!
//! Cryptographic, erasure-coding, segmentation, and standalone wire
//! serialization implementations for **SEACAST v2**.

pub mod buffer;
pub mod merkle;
pub mod reed_solomon;
pub mod segment;
pub mod segmented;
pub mod sha256;
pub mod snappy;
pub mod standalone;
pub mod wire;

pub use buffer::{ArcBufferPool, BufferPool, ChunkBytes, VecBufferPool};
pub use merkle::{
    MAX_MERKLE_LEAVES, MAX_PROOF_DEPTH, MerkleProof, MerkleTree, build_merkle_layers, leaf_hash,
    merkle_proof, merkle_proof_from_layers, merkle_root, node_hash, tree_width,
    verify_merkle_proof,
};
pub use reed_solomon::{
    GF256, Gf256Tables, build_systematic_matrix, rs_complete_in_place, rs_parity, rs_parity_rows,
    rs_reconstruct_data, rs_reconstruct_into,
};
pub use segment::{
    Compressor, DESCRIPTOR_BYTES, Frame, MAX_CHUNKS, MAX_CODED_BODY, MAX_PLAIN_CHUNKS,
    MAX_SEGMENT_SIZE, SegmentDescriptor, Shard, SnappyBlockCompressor, UNIT, body_into, body_len,
    build_chunks, build_frame, build_group, check_frame, check_frame_proof, chunk_id,
    complete_in_place, decode_and_reencode, group_id, group_key, proof_len, split_frame,
};
pub use segmented::SegmentedCodec;
pub use sha256::{Sha256, sha256};
pub use standalone::{check_standalone, standalone_group};
pub use wire::{
    ChunkParts, SEACAST_V2_MAGIC, chunk_id_on, decode_rpc, decode_rpc_with, encode_rpc,
    encode_rpc_framing, encode_rpc_into,
};
