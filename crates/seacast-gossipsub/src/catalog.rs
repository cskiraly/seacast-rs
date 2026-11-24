//! The payload as the catalog a `SeacastNode` is driven with on the gossipsub
//! binding: the codec is [`PayloadCodec`], the [`Domain`] is the host's
//! ([`PayloadHost`]: whether a block's bid commits a descriptor), and the
//! [`Policy`] is one type, joined on every link, whose relations the host
//! keeps.

use seacast_codec::Sha256;
use seacast_core::{
    Bytes32, ChunkBuffer, ChunkId, ChunkMsg, Domain, Duty, ForkDigest, GroupId, InlineVec,
    InterestKind, Join, MAX_JOINED_TYPES, NodeId, PeerId, Policy, PreallocVec, Shape, Timestamp,
    TypeCodec, TypeId, TypeParams, ValidationResult,
};

use crate::payload::PAYLOAD;

/// What the payload asks of the domain. A chunk names its group alone, so
/// the domain is given no context.
pub trait PayloadHost {
    /// Whether the descriptor whose group id is `header_id` is committed
    /// (`Domain::authenticate`): `Defer` while the host cannot tell.
    fn authenticate(&mut self, group: &GroupId, header_id: &Bytes32) -> ValidationResult;

    /// Whether `group` is one the host has accepted (`Domain::authenticable`).
    fn authenticable(&self, group: &GroupId) -> bool;

    /// When `group` leaves the live window (`Domain::deadline`).
    fn deadline(&self, _group: &GroupId) -> Option<Timestamp> {
        None
    }

    fn node_id(&self, peer: PeerId) -> NodeId;
}

/// The payload's parameters on this binding: one colour, one relation both
/// ways, kept by the host as its topic's mesh. The rest are the defaults.
pub fn payload_params() -> TypeParams {
    TypeParams { m: 1, symmetric: true, host_relations: true, ..TypeParams::default() }
}

/// The JOIN a subscription to the payload's topic stands for, ours and a
/// peer's (`seacast-bindings.md` §0): every chunk, with duty.
pub const fn payload_join(fork_digest: ForkDigest) -> Join {
    Join {
        object_type: PAYLOAD,
        fork_digest,
        interest: InterestKind::All,
        custody_count: 0,
        duty: Duty::Forward,
        colours: 1,
    }
}

/// `C` is the payload's codec: [`PayloadCodec`], or a host's own over it where
/// the host keeps a group's chunks in place and runs level 2 there.
pub struct PayloadCatalog<Host, C> {
    pub host: Host,
    pub codec: C,
    pub params: TypeParams,
    pub join: Join,
}

impl<Host: PayloadHost, C> PayloadCatalog<Host, C> {
    /// The catalog with [`payload_params`] and [`payload_join`].
    pub fn new(host: Host, codec: C, fork_digest: ForkDigest) -> Self {
        Self { host, codec, params: payload_params(), join: payload_join(fork_digest) }
    }
}

impl<Host, C, B> TypeCodec<B> for PayloadCatalog<Host, C>
where
    Host: PayloadHost,
    C: TypeCodec<B>,
    B: ChunkBuffer,
{
    fn shape(&self, chunk: &ChunkMsg<B>) -> Option<Shape> {
        self.codec.shape(chunk)
    }

    fn check(&self, chunk: &ChunkMsg<B>) -> bool {
        self.codec.check(chunk)
    }

    fn check_proof(&mut self, chunk: &ChunkMsg<B>) -> ValidationResult {
        self.codec.check_proof(chunk)
    }

    fn header_id(&self, chunk: &ChunkMsg<B>) -> Bytes32 {
        self.codec.header_id(chunk)
    }

    fn context<'a>(&self, chunk: &'a ChunkMsg<B>) -> &'a [u8] {
        self.codec.context(chunk)
    }

    fn decode(
        &mut self,
        group: &GroupId,
        available: &[ChunkMsg<B>],
        shape: &Shape,
        out_rebuilt: &mut PreallocVec<ChunkMsg<B>>,
    ) -> Option<B> {
        self.codec.decode(group, available, shape, out_rebuilt)
    }

    fn wire_size(&self, chunk: &ChunkMsg<B>, first_of_group: bool) -> usize {
        self.codec.wire_size(chunk, first_of_group)
    }
}

impl<Host: PayloadHost, C> Domain for PayloadCatalog<Host, C> {
    fn authenticate(
        &mut self,
        group: &GroupId,
        header_id: &Bytes32,
        _context: &[u8],
    ) -> ValidationResult {
        self.host.authenticate(group, header_id)
    }

    fn authenticable(&self, group: &GroupId) -> bool {
        self.host.authenticable(group)
    }

    fn deadline(&self, group: &GroupId, _context: &[u8]) -> Option<Timestamp> {
        self.host.deadline(group)
    }
}

impl<Host: PayloadHost, C> Policy for PayloadCatalog<Host, C> {
    fn params(&self, _t: TypeId) -> &TypeParams {
        &self.params
    }

    fn our_join(&self, _t: TypeId) -> Join {
        self.join
    }

    fn joined_types(&self) -> InlineVec<TypeId, MAX_JOINED_TYPES> {
        InlineVec::singleton(PAYLOAD)
    }

    /// A hash of the chunk and the peer, the same at every node (`tiebreak(f,
    /// p)`, `seacast-lite.md` §5.3).
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
