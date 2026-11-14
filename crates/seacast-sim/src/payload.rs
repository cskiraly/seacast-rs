//! The payload object type (`protocol-v2.md` §1.1, the column "payload (v0.3)")
//! as the catalog a `SeacastNode` is driven with: the codec is
//! [`SegmentedCodec`], the [`Domain`] is the host's ([`PayloadHost`]: whether a
//! context commits a descriptor), and the [`Policy`] is one type
//! joined on every link.

use seacast_codec::{BufferPool, ChunkBytes, SegmentedCodec, Sha256};
use seacast_core::{
    Bytes32, ChunkId, ChunkMsg, Domain, GroupId, InlineVec, Join, NodeId, PeerId, Policy,
    PreallocVec, Shape, Timestamp, TypeCodec, TypeId, TypeParams, ValidationResult,
};

use crate::PAYLOAD;

/// What the payload type asks of the domain.
pub trait PayloadHost {
    /// Whether `context` commits the descriptor whose id is `header_id` for
    /// `group` (`Domain::authenticate`). For the payload under consensus,
    /// `context` names a block and the answer is `Defer` until that block
    /// is validated and applied locally, then whether
    /// its bid's `execution_payload_segment_group_id` is `header_id`.
    fn authenticate(
        &mut self,
        group: &GroupId,
        header_id: &Bytes32,
        context: &[u8],
    ) -> ValidationResult;

    /// Whether the domain commits `group` already (`Domain::authenticable`).
    fn authenticable(&self, group: &GroupId) -> bool;

    /// When `context`'s slot leaves the live window (`Domain::deadline`).
    fn deadline(&self, _group: &GroupId, _context: &[u8]) -> Option<Timestamp> {
        None
    }

    fn node_id(&self, peer: PeerId) -> NodeId;
}

type Chunk<B> = ChunkMsg<B>;

pub struct PayloadCatalog<Host, Pool, B> {
    pub host: Host,
    pub codec: SegmentedCodec<Pool, B>,
    pub params: TypeParams,
    /// What this node declares for the payload type on every link.
    pub join: Join,
}

impl<Host: PayloadHost, Pool, B> PayloadCatalog<Host, Pool, B> {
    pub fn new(host: Host, codec: SegmentedCodec<Pool, B>, params: TypeParams, join: Join) -> Self {
        Self { host, codec, params, join }
    }
}

impl<Host, Pool, B> TypeCodec<B> for PayloadCatalog<Host, Pool, B>
where
    Host: PayloadHost,
    Pool: BufferPool<B>,
    B: ChunkBytes,
{
    fn shape(&self, chunk: &Chunk<B>) -> Option<Shape> {
        self.codec.shape(chunk)
    }

    fn check(&self, chunk: &Chunk<B>) -> bool {
        self.codec.check(chunk)
    }

    fn check_proof(&mut self, chunk: &Chunk<B>) -> ValidationResult {
        TypeCodec::check_proof(&mut self.codec, chunk)
    }

    fn header_id(&self, chunk: &Chunk<B>) -> Bytes32 {
        self.codec.header_id(chunk)
    }

    fn context<'a>(&self, chunk: &'a Chunk<B>) -> &'a [u8] {
        self.codec.context(chunk)
    }

    fn decode(
        &mut self,
        t: TypeId,
        group: &GroupId,
        available: &[Chunk<B>],
        shape: &Shape,
        out_rebuilt: &mut PreallocVec<Chunk<B>>,
    ) -> Option<B> {
        self.codec.decode(t, group, available, shape, out_rebuilt)
    }

    fn wire_size(&self, chunk: &Chunk<B>) -> usize {
        self.codec.wire_size(chunk)
    }
}

impl<Host: PayloadHost, Pool, B> Domain for PayloadCatalog<Host, Pool, B> {
    fn authenticate(
        &mut self,
        _t: TypeId,
        group: &GroupId,
        header_id: &Bytes32,
        context: &[u8],
    ) -> ValidationResult {
        self.host.authenticate(group, header_id, context)
    }

    fn authenticable(&self, _t: TypeId, group: &GroupId) -> bool {
        self.host.authenticable(group)
    }

    fn deadline(&self, _t: TypeId, group: &GroupId, context: &[u8]) -> Option<Timestamp> {
        self.host.deadline(group, context)
    }
}

impl<Host: PayloadHost, Pool, B> Policy for PayloadCatalog<Host, Pool, B> {
    fn type_of_group(&self, _group: &GroupId) -> TypeId {
        PAYLOAD
    }

    fn params(&self, _t: TypeId) -> &TypeParams {
        &self.params
    }

    fn our_join(&self, _t: TypeId) -> Join {
        self.join
    }

    fn joined_types(&self) -> InlineVec<TypeId, 8> {
        InlineVec::singleton(PAYLOAD)
    }

    /// A hash of the chunk and the peer, the same at every node (`tiebreak(f,
    /// p)`, `protocol.md` §5.3).
    fn tiebreak(&self, chunk_id: &ChunkId, peer: PeerId) -> u64 {
        let mut h = Sha256::new();
        h.update(chunk_id);
        h.update(&self.host.node_id(peer));
        u64::from_be_bytes(h.finalize()[..8].try_into().unwrap())
    }

    fn node_id(&self, peer: PeerId) -> NodeId {
        self.host.node_id(peer)
    }
}
