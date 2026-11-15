//! What a peer sends cannot crash a node or grow its state past its limits, and
//! nothing it is owed or has asked for is left behind (`protocol.md` §8.1,
//! §8.2; `protocol-v2.md` §2, §3, §6.3).

use seacast_core::{
    Ask, Bitmap, BoundedDeferredStore, ChunkId, ChunkMsg, Direction, DispatchOutcome, Domain, Duty,
    Graft, GroupId, GroupState, Have, InlineVec, InterestKind, Join, MAX_JOINED_TYPES, NodeConfig,
    NodeId, PeerId, PenaltyReason, Policy, PreallocVec, Rpc, RuntimeEnv, SeacastNode, Shape,
    SplitMix64, TimerEvent, Timestamp, TypeCodec, TypeId, TypeParams, ValidationResult, Want,
};

type Chunk = ChunkMsg<Vec<u8>>;
const TYPE: TypeId = TypeId(0);
type BlockRoot = [u8; 32];
type Node = SeacastNode<Vec<u8>>;

struct Env {
    now: Timestamp,
    delivered: usize,
    /// `RetryOffer` timers armed, and penalties reported.
    retries: usize,
    penalties: usize,
}

impl RuntimeEnv<Vec<u8>> for Env {
    fn now(&self) -> Timestamp {
        self.now
    }
    fn schedule_after(&mut self, _delay: f64, event: TimerEvent) {
        if matches!(event, TimerEvent::RetryOffer(_)) {
            self.retries += 1;
        }
    }
    fn send(&mut self, _peer: PeerId, _item: seacast_core::Queued, _urgent: bool) -> bool {
        false
    }
    fn start_decode(&mut self, _group: GroupId) {}
    fn deliver(&mut self, _group: GroupId, _object: Vec<u8>) {
        self.delivered += 1;
    }
    fn penalise(&mut self, _peer: PeerId, _reason: PenaltyReason) {
        self.penalties += 1;
    }
}

/// One type of `n` indices, complete at `k`. A header is the chunk's own;
/// `interest` is what the node itself wants, `declared` whether it joins as a
/// sampler does.
struct Catalog {
    params: TypeParams,
    n: u32,
    k: u32,
    interest: Bitmap,
    declared: bool,
    /// The one block root taken as installed, if set: a chunk naming another is
    /// deferred.
    installed: Option<BlockRoot>,
    /// Whether the proof is checked off the chunk path: the inline check then
    /// answers `Pending`.
    deferred_proof: bool,
    /// Groups whose gate is a header, and whether that header is validated:
    /// their chunks need no installed block once it is.
    cells: Vec<GroupId>,
    header_validated: bool,
    /// The domain does not take groups yet: their chunks are ignored.
    too_early: bool,
    /// When the domain's window closes on every group, if it has one.
    deadline: Option<Timestamp>,
    /// A second index every chunk is said to fill, as a faulty `project` would.
    stray_index: Option<u32>,
}

impl Catalog {
    fn new(n: u32, k: u32) -> Self {
        Self {
            params: TypeParams::default(),
            n,
            k,
            interest: Bitmap::EVERY_INDEX,
            declared: false,
            installed: None,
            deferred_proof: false,
            cells: Vec::new(),
            header_validated: false,
            too_early: false,
            deadline: None,
            stray_index: None,
        }
    }
}

impl TypeCodec<Vec<u8>> for Catalog {
    fn shape(&self, _chunk: &Chunk) -> Option<Shape> {
        Some(Shape { n: self.n, k: self.k })
    }
    fn check(&self, chunk: &Chunk) -> bool {
        chunk.index < self.n
    }
    fn check_proof(&mut self, _chunk: &Chunk) -> ValidationResult {
        if self.deferred_proof { ValidationResult::Pending } else { ValidationResult::Accept }
    }
    fn header_id(&self, _chunk: &Chunk) -> [u8; 32] {
        [0; 32]
    }
    /// The block root a chunk names.
    fn context<'a>(&self, chunk: &'a Chunk) -> &'a [u8] {
        &chunk.frame[..32]
    }
    fn decode(
        &mut self,
        _t: TypeId,
        group: &GroupId,
        available: &[Chunk],
        _shape: &Shape,
        out_rebuilt: &mut PreallocVec<Chunk>,
    ) -> Option<Vec<u8>> {
        if available.len() < self.k as usize {
            return None;
        }
        let root: BlockRoot = available[0].frame[..32].try_into().unwrap();
        for i in 0..self.n {
            let _ = out_rebuilt.push(chunk(*group, i, root));
        }
        Some(vec![0xAA; 16])
    }
    fn project(
        &self,
        _t: TypeId,
        chunk: &Chunk,
    ) -> InlineVec<(GroupId, u32), { seacast_core::MAX_PROJECTED }> {
        let mut filled = InlineVec::singleton((chunk.group, chunk.index));
        if let Some(index) = self.stray_index {
            let _ = filled.push((chunk.group, index));
        }
        filled
    }
}

impl Domain for Catalog {
    fn authenticate(
        &mut self,
        _t: TypeId,
        group: &GroupId,
        _header_id: &[u8; 32],
        context: &[u8],
    ) -> ValidationResult {
        let by_header = self.header_validated && self.cells.contains(group);
        if self.too_early {
            ValidationResult::Ignore
        } else if by_header || self.installed.is_none_or(|root| root[..] == *context) {
            ValidationResult::Accept
        } else {
            ValidationResult::Defer
        }
    }
    fn deadline(&self, _t: TypeId, _group: &GroupId, _context: &[u8]) -> Option<Timestamp> {
        self.deadline
    }

    fn authenticable(&self, _t: TypeId, _group: &GroupId) -> bool {
        true
    }
}

impl Policy for Catalog {
    fn type_of_group(&self, _group: &GroupId) -> TypeId {
        TYPE
    }
    fn params(&self, t: TypeId) -> &TypeParams {
        assert_eq!(t, TYPE, "asked for a type this node does not run");
        &self.params
    }
    fn own_interest(&self, _t: TypeId, _group: &GroupId) -> Bitmap {
        self.interest
    }
    fn decode_at_k(&self, _t: TypeId, _group: &GroupId) -> bool {
        // A sampler rebuilds nothing.
        !self.declared
    }
    fn our_join(&self, t: TypeId) -> Join {
        assert_eq!(t, TYPE, "asked for a type this node does not run");
        Join {
            object_type: t,
            interest: if self.declared { InterestKind::Declared } else { InterestKind::All },
            custody_count: 0,
            duty: if self.declared { Duty::None } else { Duty::Forward },
            colours: 1,
        }
    }
    fn joined_types(&self) -> InlineVec<TypeId, MAX_JOINED_TYPES> {
        InlineVec::singleton(TYPE)
    }
    fn tiebreak(&self, chunk_id: &ChunkId, peer: PeerId) -> u64 {
        (chunk_id[0] as u64).wrapping_add(peer)
    }
    fn node_id(&self, peer: PeerId) -> NodeId {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&peer.to_le_bytes());
        id
    }
}

fn group(tag: u32) -> GroupId {
    let mut g = [0u8; 32];
    g[..4].copy_from_slice(&tag.to_le_bytes());
    g[31] = 1;
    g
}

fn chunk(group: GroupId, index: u32, root: BlockRoot) -> Chunk {
    let mut cached_id = [0u8; 56];
    cached_id[..32].copy_from_slice(&group);
    cached_id[32..36].copy_from_slice(&index.to_le_bytes());
    cached_id[36] = root[0];
    let mut frame = root.to_vec();
    frame.extend_from_slice(&[index as u8; 8]);
    ChunkMsg { type_id: TYPE, group, index, frame, cached_id, memo: [0; 32] }
}

fn peer_join(interest: InterestKind) -> Join {
    Join { object_type: TYPE, interest, custody_count: 0, duty: Duty::Forward, colours: 1 }
}

struct World {
    node: Node,
    env: seacast_core::WithQueues<Env>,
    catalog: Catalog,
    rng: SplitMix64,
    store: BoundedDeferredStore,
}

impl World {
    /// A node with `peers` connected, each joined to the type with `interest`.
    fn new(catalog: Catalog, peers: u64, interest: InterestKind) -> Self {
        Self::with_config(NodeConfig::default(), catalog, peers, interest)
    }

    fn with_config(
        config: NodeConfig,
        catalog: Catalog,
        peers: u64,
        interest: InterestKind,
    ) -> Self {
        let mut world = Self {
            node: SeacastNode::new(config.clone()),
            env: seacast_core::WithQueues::new(config, Env {
                now: 1.0,
                delivered: 0,
                retries: 0,
                penalties: 0,
            }),
            catalog,
            rng: SplitMix64::new(7),
            store: BoundedDeferredStore::default(),
        };
        for peer in 1..=peers {
            world.env.queues.connect(peer);
            world.node.connect_peer(peer, true, &mut world.env, &world.catalog);
            let mut rpc = Rpc::default();
            let _ = rpc.joins.push(peer_join(interest));
            world.rpc(peer, rpc);
            world.drain(peer);
        }
        world
    }

    fn rpc(&mut self, peer: PeerId, rpc: Rpc<Vec<u8>>) {
        self.node.on_rpc(
            peer,
            rpc,
            &mut self.env,
            &mut self.catalog,
            &mut self.rng,
            &mut self.store,
        );
    }

    fn heartbeat(&mut self) {
        self.node.on_timer(
            TimerEvent::Heartbeat,
            &mut self.env,
            &mut self.catalog,
            &mut self.rng,
            &mut self.store,
        );
    }

    /// Everything the writer to `peer` sends until its queue is empty.
    fn drain(&mut self, peer: PeerId) -> Vec<seacast_core::QueueEntry<Vec<u8>>> {
        let mut sent = Vec::new();
        while let DispatchOutcome::Send(entry) =
            self.env.next_to_send(&mut self.node, peer, &self.catalog)
        {
            sent.push(entry);
        }
        sent
    }
}

fn chunk_rpc(chunk: Chunk) -> Rpc<Vec<u8>> {
    Rpc { chunk: Some(chunk), ..Rpc::default() }
}

/// More grafts, offers, holdings, asks and chunks than any table has room for,
/// from one linked peer: nothing panics, and what the peer made the node keep
/// stays within the per-peer limits.
#[test]
fn a_peer_cannot_overflow_the_tables() {
    let mut world = World::new(Catalog::new(400, 400), 1, InterestKind::Declared);
    let limit = world.node.config.max_pending_groups;
    let per_link = world.node.config.max_relations_per_link;

    // Grafts in both directions for every family, and for colours the type does not
    // have.
    for family in 0..6000u32 {
        let mut rpc = Rpc::default();
        for colour in [0u16, 1, 7] {
            let _ = rpc.grafts.push(Graft {
                object_type: TYPE,
                family,
                colour,
                direction: Direction::Both,
            });
        }
        world.rpc(1, rpc);
    }
    assert!(world.node.push_in.len() <= per_link && world.node.push_out.len() <= per_link);
    assert!(world.node.push_in.iter().all(|&(_, _, _, colour)| colour == 0));

    // Offers, holdings and asks of every index for thousands of groups nobody has a
    // header for.
    let every = Bitmap::all_bits(400);
    for tag in 0..3000 {
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::offer(TYPE, group(tag), every));
        let _ = rpc.haves.push(Have::holding(TYPE, group(tag + 10_000), every, true, true));
        let _ = rpc.wants.push(Want::standing(TYPE, group(tag + 20_000), every));
        // An offer of nothing, and one of indices this node does not want, keep
        // nothing.
        let _ = rpc.haves.push(Have::offer(TYPE, group(tag + 30_000), Bitmap::new()));
        world.rpc(1, rpc);
        world.drain(1);
    }
    let named = |groups: Vec<GroupId>| {
        let mut distinct = groups;
        distinct.sort_unstable();
        distinct.dedup();
        distinct.len()
    };
    assert!(named(world.node.pairs.keys().map(|&(_, g)| g).collect()) <= limit);
    assert!(named(world.node.pairs.keys().map(|&(_, g)| g).collect()) <= limit);
    assert!(named(world.node.pairs.keys().map(|&(_, g)| g).collect()) <= limit);
    assert!(world.node.groups.len() <= 2 * limit);
    // Holders are counted for groups the node has open, and it has opened none.
    assert_eq!(world.node.holders.len(), 0);

    // Junk chunks: every one rejected at level 1, each with an id of its own.
    for tag in 0..10_000u32 {
        world.rpc(1, chunk_rpc(chunk(group(40_000 + tag), 400, [0; 32])));
    }
    // Chunks of more groups than the node tracks.
    for tag in 0..600u32 {
        world.rpc(1, chunk_rpc(chunk(group(60_000 + tag), 0, [0; 32])));
        world.drain(1);
    }
    assert!(world.node.groups.open_count() <= world.node.config.capacities.max_groups);
    assert_eq!(world.node.chunks.len(), world.node.groups.open_count());
}

/// A group's state goes `GROUP_TTL` after its last chunk, leaving a tombstone
/// that keeps the group from being taken up again, and the tombstone goes in
/// its turn.
#[test]
fn a_group_expires_and_leaves_a_tombstone() {
    let mut world = World::new(Catalog::new(8, 8), 2, InterestKind::All);
    let g = group(1);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(TYPE, g, Bitmap::all_bits(8)));
    let _ = rpc.haves.push(Have::holding(TYPE, g, Bitmap::singleton(3), false, false));
    world.rpc(2, rpc);
    assert_eq!(world.node.group_state(&g), Some(GroupState::Collecting));
    assert!(!world.node.offers.is_empty() && !world.node.seen_ids.is_empty());

    // Short of the lifetime: still there.
    world.env.now += world.node.config.group_ttl - 1.0;
    world.heartbeat();
    assert_eq!(world.node.group_state(&g), Some(GroupState::Collecting));

    world.env.now += 2.0;
    world.heartbeat();
    assert!(world.node.expired(&g));
    assert_eq!(world.node.group_state(&g), None);
    let node = &world.node;
    assert!(node.chunks.is_empty() && node.known_id.is_empty() && node.groups.is_empty());
    assert!(node.offers.is_empty() && node.pairs.is_empty() && node.tried.is_empty());
    assert!(node.asked_at.is_empty() && node.promises.is_empty() && node.seen_ids.is_empty());
    assert!(node.holders.is_empty());
    assert!(node.listed_count.iter().all(|(_, &listed)| listed == 0));

    // Expired for good: a chunk, an offer and a holding of it are ignored.
    world.rpc(1, chunk_rpc(chunk(g, 1, [0; 32])));
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(TYPE, g, Bitmap::all_bits(8)));
    world.rpc(2, rpc);
    assert!(
        world.node.chunks.is_empty() &&
            world.node.offers.is_empty() &&
            world.node.groups.is_empty()
    );

    world.env.now += world.node.config.tombstone_ttl + 1.0;
    world.heartbeat();
    assert!(!world.node.expired(&g) && world.node.tombstones.is_empty());
}

/// A domain whose window a group has left ends it: the group and the chunks
/// still waiting for it go, and it leaves a tombstone. A chunk waiting for a
/// group nothing ends goes `GROUP_TTL` after it arrived.
#[test]
fn the_domain_ends_a_group_and_its_deferred_chunks() {
    let mut catalog = Catalog::new(8, 8);
    catalog.installed = Some([9; 32]);
    let mut world = World::new(catalog, 1, InterestKind::All);
    let (held, waiting, other) = (group(1), group(2), group(3));
    world.rpc(1, chunk_rpc(chunk(held, 0, [9; 32])));
    world.rpc(1, chunk_rpc(chunk(waiting, 0, [5; 32])));
    world.rpc(1, chunk_rpc(chunk(other, 0, [5; 32])));
    assert_eq!((world.node.pending.len(), world.node.pending_ids.len()), (2, 2));

    for g in [held, waiting] {
        world.node.end_group(g, &mut world.env, &mut world.store);
    }
    assert_eq!(world.node.group_state(&held), None);
    assert_eq!((world.node.pending.len(), world.node.pending_ids.len()), (1, 1));
    assert!(world.node.expired(&held) && world.node.expired(&waiting));

    world.env.now += world.node.config.group_ttl + 1.0;
    world.heartbeat();
    assert!(world.node.pending.is_empty() && world.node.pending_ids.is_empty());
}

/// A group the domain gave a deadline goes at it, sooner than `GROUP_TTL`, with
/// its deferred chunks; one ended before the deadline is kept out until it,
/// longer than `tombstone_ttl`.
#[test]
fn a_deadline_ends_a_group_and_bounds_its_tombstone() {
    let mut catalog = Catalog::new(8, 8);
    catalog.installed = Some([9; 32]);
    let mut world = World::new(catalog, 1, InterestKind::All);
    let ttl = world.node.config.group_ttl;
    assert!(world.node.config.tombstone_ttl <= ttl);
    world.catalog.deadline = Some(world.env.now + 4.0 * ttl);
    let (ended, waiting) = (group(1), group(2));
    world.rpc(1, chunk_rpc(chunk(ended, 0, [9; 32])));
    world.node.end_group(ended, &mut world.env, &mut world.store);
    world.env.now += 2.0 * ttl;
    world.heartbeat();
    assert!(world.node.expired(&ended));

    world.catalog.deadline = Some(world.env.now + 2.0);
    let held = group(3);
    world.rpc(1, chunk_rpc(chunk(held, 0, [9; 32])));
    world.rpc(1, chunk_rpc(chunk(waiting, 0, [5; 32])));
    assert_eq!(world.node.group_state(&held), Some(GroupState::Collecting));
    assert_eq!(world.node.pending.len(), 1);

    world.env.now += 3.0;
    world.heartbeat();
    assert_eq!(world.node.group_state(&held), None);
    assert!(world.node.chunks.is_empty() && world.node.pending.is_empty());
    assert!(world.node.pending_ids.is_empty());
    // Past its deadline a group needs no tombstone: the domain ignores it.
    assert!(!world.node.expired(&held) && world.node.expired(&ended));

    world.env.now += 2.0 * ttl;
    world.heartbeat();
    assert!(world.node.tombstones.is_empty());
}

/// Every index an offer makes the node ask for leaves in a WANT, however many
/// there are.
#[test]
fn every_ask_of_an_offer_is_sent() {
    let mut world = World::new(Catalog::new(300, 300), 1, InterestKind::All);
    let mut rpc = Rpc::default();
    for tag in 0..3 {
        let _ = rpc.haves.push(Have::offer(TYPE, group(tag), Bitmap::all_bits(300)));
    }
    world.rpc(1, rpc);
    let asked: usize = world.node.asked_at.len();
    assert_eq!(asked, 900);
    let mut sent = 0;
    for entry in world.drain(1) {
        for want in entry.wants.iter() {
            assert!(want.track_promise);
            sent += want.bits.popcount() as usize;
        }
    }
    assert_eq!(sent, asked);
    // A promise runs for each of them from the write.
    assert_eq!(world.node.promises.len(), asked);
}

/// Offers owed in more groups than one entry carries all leave, over as many
/// entries as it takes.
#[test]
fn owed_offers_are_never_dropped() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    for tag in 0..50 {
        world.node.owe(1, group(tag), Bitmap::singleton(tag % 8), &mut world.env);
    }
    let mut offered = Vec::new();
    for entry in world.drain(1) {
        offered.extend(entry.haves.iter().filter(|h| h.offer).map(|h| h.group));
    }
    offered.sort_unstable();
    assert_eq!(offered, (0..50).map(group).collect::<Vec<_>>());
    assert!(world.env.queues.queue.get(&1).is_some_and(|q| q.owed.is_empty()));
}

/// A chunk that waited for its block from a peer that then left can still
/// arrive from another.
#[test]
fn a_departed_peer_does_not_block_its_deferred_chunks() {
    let mut catalog = Catalog::new(8, 8);
    catalog.installed = Some([9; 32]);
    let mut world = World::new(catalog, 2, InterestKind::All);
    let g = group(1);
    let waiting = chunk(g, 0, [5; 32]);
    world.rpc(1, chunk_rpc(waiting.clone()));
    assert_eq!(world.node.pending_ids.len(), 1);
    world.node.disconnect_peer(1, &mut world.env, &mut world.store);
    world.env.queues.disconnect(1, &mut world.env.env);
    assert!(world.node.pending.is_empty() && world.node.pending_ids.is_empty());

    // The block installs, and the same chunk comes from the other peer.
    world.catalog.installed = None;
    world.rpc(2, chunk_rpc(waiting));
    assert!(world.node.chunks.contains_key(&(g, 0)));
}

/// What a sampler declared before a group opened is still its interest once a
/// chunk opens it, so it completes when its indices have arrived.
#[test]
fn a_sampler_completes_on_its_declared_indices() {
    let mut catalog = Catalog::new(8, 8);
    catalog.interest = Bitmap::new();
    catalog.declared = true;
    let mut world = World::new(catalog, 1, InterestKind::All);
    let g = group(1);
    let mut wanted = Bitmap::new();
    wanted.set(2);
    wanted.set(5);
    world.node.sample(g, wanted, &mut world.env, &world.catalog, &mut world.rng);
    world.rpc(1, chunk_rpc(chunk(g, 2, [0; 32])));
    assert_eq!(world.node.group_state(&g), Some(GroupState::Collecting));
    assert_eq!(world.node.groups.get(&g).and_then(|rec| rec.interest), Some(wanted));
    world.rpc(1, chunk_rpc(chunk(g, 5, [0; 32])));
    assert_eq!(world.node.group_state(&g), Some(GroupState::Complete));
}

/// Nothing of a peer that has not joined the type on its link is handled: no
/// state, no answer.
#[test]
fn messages_of_an_unjoined_type_are_ignored() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    world.node.connect_peer(2, false, &mut world.env, &world.catalog);
    world.env.queues.connect(2);
    let g = group(1);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    world.drain(1);

    let mut rpc = chunk_rpc(chunk(g, 1, [0; 32]));
    let _ = rpc.haves.push(Have::offer(TYPE, g, Bitmap::all_bits(8)));
    let _ = rpc.haves.push(Have::holding(TYPE, g, Bitmap::singleton(4), false, false));
    let _ = rpc.wants.push(Want::pull_ask(TYPE, Ask { group: g, index: 0 }));
    world.rpc(2, rpc);
    assert!(!world.node.chunks.contains_key(&(g, 1)));
    assert!(world.node.pairs.is_empty());
    assert!(world.drain(2).is_empty());
}

/// A chunk whose proof is checked off the chunk path is held by the host until
/// its verdict: nothing is stored, claimed or forwarded before, a second copy
/// is not verified again, and the static checks still reject at once.
#[test]
fn a_chunk_waits_for_its_verdict() {
    let mut catalog = Catalog::new(8, 8);
    catalog.deferred_proof = true;
    let mut world = World::new(catalog, 2, InterestKind::All);
    let g = group(1);
    let (good, forged) = (chunk(g, 0, [0; 32]), chunk(g, 1, [0; 32]));

    world.rpc(1, chunk_rpc(good.clone()));
    world.rpc(2, chunk_rpc(good.clone()));
    world.rpc(1, chunk_rpc(forged.clone()));
    // An index outside the group fails the inline check: never handed out.
    world.rpc(1, chunk_rpc(chunk(g, 8, [0; 32])));
    // The group is known to be authentic and nothing more: it is not open.
    assert!(world.node.chunks.is_empty() && world.node.group_state(&g).is_none());
    assert!(world.drain(1).is_empty() && world.drain(2).is_empty());

    let (from, first) = world.node.pop_unverified().expect("the first copy");
    let (_, second) = world.node.pop_unverified().expect("the other chunk");
    assert_eq!((from, first.index, second.index), (1, 0, 1));
    assert!(world.node.pop_unverified().is_none());

    let (env, catalog, rng, store) =
        (&mut world.env, &mut world.catalog, &mut world.rng, &mut world.store);
    world.node.on_validated(1, first, ValidationResult::Accept, env, catalog, rng, store);
    world.node.on_validated(1, second, ValidationResult::Reject, env, catalog, rng, store);
    assert!(world.node.chunks.contains_key(&(g, 0)) && !world.node.chunks.contains_key(&(g, 1)));
    assert!(world.node.verifying.is_empty());
    // The accepted chunk is claimed to its sender; the rejected one is seen, so
    // another copy of it is not verified again.
    assert!(
        world.drain(1).iter().any(|entry| entry.haves.iter().any(|h| !h.offer && h.bits.has(0)))
    );
    world.rpc(2, chunk_rpc(forged));
    assert!(world.node.pop_unverified().is_none());
}

/// Groups that peers only name have their own room: however many there are, a
/// group whose chunk arrives can still be opened.
#[test]
fn named_groups_do_not_crowd_out_open_ones() {
    let mut world = World::new(Catalog::new(8, 8), 6, InterestKind::All);
    let max_groups = world.node.config.capacities.max_groups;
    for peer in 1..=6u64 {
        for tag in 0..64 {
            let mut rpc = Rpc::default();
            let _ = rpc.haves.push(Have::offer(
                TYPE,
                group(peer as u32 * 1000 + tag),
                Bitmap::all_bits(8),
            ));
            world.rpc(peer, rpc);
        }
    }
    assert_eq!((world.node.groups.len(), world.node.groups.open_count()), (max_groups, 0));
    for tag in 0..10 {
        world.rpc(1, chunk_rpc(chunk(group(900_000 + tag), 0, [0; 32])));
    }
    assert_eq!(world.node.groups.open_count(), 10);
    assert_eq!(world.node.chunks.len(), 10);
}

/// A chunk of a group the domain does not take yet is ignored, and taken once
/// it does.
#[test]
fn a_chunk_the_domain_ignores_leaves_nothing() {
    let mut catalog = Catalog::new(8, 8);
    catalog.too_early = true;
    let mut world = World::new(catalog, 1, InterestKind::All);
    world.rpc(1, chunk_rpc(chunk(group(1), 0, [0; 32])));
    assert!(world.node.chunks.is_empty() && world.node.seen_ids.is_empty());
    assert_eq!(world.env.penalties, 0);
    world.catalog.too_early = false;
    world.rpc(1, chunk_rpc(chunk(group(1), 0, [0; 32])));
    assert_eq!(world.node.chunks.len(), 1);
}

/// Cells that arrive before their header wait for it, not for the block: when
/// the header is validated they are taken up, and those of another group of the
/// root keep waiting.
#[test]
fn a_validated_header_resumes_its_deferred_chunks() {
    let (cell, other) = (group(1), group(2));
    let mut catalog = Catalog::new(8, 8);
    catalog.installed = Some([9; 32]);
    catalog.cells = vec![cell];
    let mut world = World::new(catalog, 1, InterestKind::All);
    world.rpc(1, chunk_rpc(chunk(cell, 0, [5; 32])));
    world.rpc(1, chunk_rpc(chunk(other, 0, [5; 32])));
    assert_eq!((world.node.pending.len(), world.node.chunks.len()), (2, 0));

    world.catalog.header_validated = true;
    let (env, catalog, rng, store) =
        (&mut world.env, &mut world.catalog, &mut world.rng, &mut world.store);
    world.node.on_groups_authenticated(&[cell], env, catalog, rng, store);
    assert!(world.node.chunks.contains_key(&(cell, 0)));
    assert_eq!((world.node.pending.len(), world.node.pending_ids.len()), (1, 1));
    assert!(!world.node.tied_to_root(1, Ask { group: cell, index: 0 }));
    assert!(world.node.tied_to_root(1, Ask { group: other, index: 0 }));
}

/// A JOIN for a type this node does not run asks nothing of the catalog and
/// leaves no state.
#[test]
fn a_join_of_an_unknown_type_is_ignored() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    let joined = world.node.join_recv.len();
    for t in 1..=2000u16 {
        let mut rpc = Rpc::default();
        let _ = rpc.joins.push(Join { object_type: TypeId(t), ..peer_join(InterestKind::All) });
        world.rpc(1, rpc);
    }
    assert_eq!(world.node.join_recv.len(), joined);
    assert!(world.drain(1).is_empty());
}

/// Past the IHAVE limits an offer arms no timer and makes no ask; the next
/// heartbeat takes it up.
#[test]
fn offers_over_the_limits_arm_no_timer() {
    let mut world = World::new(Catalog::new(1024, 1024), 1, InterestKind::All);
    let offer = |world: &mut World, tag: u32| {
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::offer(TYPE, group(tag), Bitmap::all_bits(1024)));
        world.rpc(1, rpc);
    };
    let mut tag = 0;
    while !world.node.over_ihave_limits(1) {
        offer(&mut world, tag);
        tag += 1;
    }
    let (retries, asked) = (world.env.retries, world.node.asked_at.len());
    assert_eq!(retries, asked);
    for _ in 0..4 {
        offer(&mut world, tag);
        tag += 1;
    }
    // The same offers again cost nothing either.
    for again in 0..tag {
        offer(&mut world, again);
    }
    assert_eq!((world.env.retries, world.node.asked_at.len()), (retries, asked));

    world.drain(1);
    world.env.now += 0.7;
    world.heartbeat();
    let asks = world.drain(1).iter().flat_map(|entry| entry.wants.iter()).count();
    assert!(asks > 0);
}

/// An ask the table has no room for is not made, so its timer is not armed
/// either.
#[test]
fn an_unrecorded_ask_is_not_made() {
    let mut config = NodeConfig::default();
    config.capacities.max_asks = 16;
    let mut world = World::with_config(config, Catalog::new(300, 300), 1, InterestKind::All);
    for round in 0..8 {
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::offer(TYPE, group(1), Bitmap::all_bits(300)));
        world.rpc(1, rpc);
        assert_eq!(world.node.asked_at.len(), 16);
        assert!(world.env.retries <= 16 * (round + 1));
        world.env.now += 1.0;
    }
}

/// An offer naming an index past the group's count is refused whole and counts
/// against its sender.
#[test]
fn an_offer_past_the_index_count_is_refused() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    let g = group(1);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    let penalties = world.env.penalties;
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(TYPE, g, Bitmap::all_bits(300)));
    world.rpc(1, rpc);
    assert_eq!(world.env.penalties, penalties + 1);
    assert!(world.node.asked_at.is_empty() && world.node.pairs.is_empty());
    assert_eq!(world.env.retries, 0);
}

/// An index `project` returns that no bitmap can name is dropped, not indexed
/// with.
#[test]
fn a_projected_index_past_the_bitmap_is_dropped() {
    let mut catalog = Catalog::new(8, 8);
    catalog.stray_index = Some(5000);
    let mut world = World::new(catalog, 2, InterestKind::All);
    let g = group(1);
    for index in 0..8 {
        world.rpc(1, chunk_rpc(chunk(g, index, [0; 32])));
    }
    assert_eq!(world.node.group_state(&g), Some(GroupState::Decoding));
    assert!(!world.node.chunks.contains_key(&(g, 5000)));
}

/// An ask for an index this node neither holds nor has in its interest counts
/// against the asker and leaves no standing request; one inside its interest is
/// in order.
#[test]
fn an_ask_outside_offer_and_interest_is_refused() {
    let mut catalog = Catalog::new(8, 8);
    catalog.declared = true;
    catalog.interest = Bitmap::all_bits(4);
    let mut world = World::new(catalog, 1, InterestKind::Declared);
    let g = group(1);
    let ask = |world: &mut World, index: u32| {
        let mut rpc = Rpc::default();
        let _ = rpc.wants.push(Want::pull_ask(TYPE, Ask { group: g, index }));
        world.rpc(1, rpc);
    };
    ask(&mut world, 2);
    assert_eq!(world.env.penalties, 0);
    assert!(world.node.standing.contains_key(&(g, 2)));
    ask(&mut world, 6);
    assert_eq!(world.env.penalties, 1);
    assert!(!world.node.standing.contains_key(&(g, 6)));
}

/// However many chunks a peer asks for, it is served a bounded number of them a
/// heartbeat.
#[test]
fn asks_are_served_within_the_heartbeat_budget() {
    let config = NodeConfig { max_served_per_heartbeat: 4, ..Default::default() };
    let mut world = World::with_config(config, Catalog::new(16, 16), 2, InterestKind::All);
    let g = group(1);
    for index in 0..8 {
        world.rpc(1, chunk_rpc(chunk(g, index, [0; 32])));
    }
    world.drain(2);
    let served = |world: &mut World| {
        let mut rpc = Rpc::default();
        let _ = rpc.wants.push(Want::standing(TYPE, g, Bitmap::all_bits(8)));
        world.rpc(2, rpc);
        let sent = world.drain(2);
        sent.iter().filter(|entry| entry.chunk.is_some()).count()
    };
    assert_eq!(served(&mut world), 4);
    assert_eq!(served(&mut world), 0);
    world.heartbeat();
    world.drain(2);
    assert_eq!(served(&mut world), 4);
}

/// A pair keeps indices past its narrow bitmaps in a pool block; with the pool
/// empty they are not kept, and a pair that goes gives its block back.
#[test]
fn a_pair_keeps_wide_bitmaps_while_the_pool_has_room() {
    let mut pairs = seacast_core::Pairs::with_capacity(4, 1);
    let (first, second) = ((1, group(1)), (2, group(1)));
    let wide = Bitmap::from_indices([3, 127, 128, 1000]);
    pairs.set_offered(first, Bitmap::singleton(5));
    pairs.set_want_p(first, wide);
    assert_eq!(pairs.offered(&first), Some(Bitmap::singleton(5)));
    assert_eq!(pairs.want_p(&first), Some(wide));
    assert_eq!(pairs.sent_to(&first), None);

    pairs.set_offered(second, wide);
    assert_eq!(pairs.offered(&second), Some(Bitmap::from_indices([3, 127])));
    pairs.retain(|key| *key != first);
    pairs.set_offered(second, wide);
    assert_eq!(pairs.offered(&second), Some(wide));

    // A complemented bitmap keeps its meaning.
    let mut all_but = Bitmap::EVERY_INDEX;
    all_but.clear(7);
    pairs.set_sent_to(second, all_but);
    assert_eq!(pairs.sent_to(&second), Some(all_but));
}

/// A host with a send path of its own: it is handed what to send, told when a
/// chunk waiting to be sent is no longer needed, and turns an item into its
/// frame as it writes it.
#[test]
fn a_host_without_the_reference_queue_is_handed_its_sends() {
    #[derive(Default)]
    struct Host {
        outbox: Vec<(PeerId, seacast_core::Queued)>,
        cancelled: Vec<(PeerId, GroupId, u32)>,
    }
    impl RuntimeEnv<Vec<u8>> for Host {
        fn now(&self) -> Timestamp {
            1.0
        }
        fn schedule_after(&mut self, _delay: f64, _event: TimerEvent) {}
        fn send(&mut self, peer: PeerId, item: seacast_core::Queued, _urgent: bool) -> bool {
            self.outbox.push((peer, item));
            true
        }
        fn cancel_chunk(&mut self, peer: PeerId, group: GroupId, index: u32) {
            self.cancelled.push((peer, group, index));
        }
        fn start_decode(&mut self, _group: GroupId) {}
        fn deliver(&mut self, _group: GroupId, _object: Vec<u8>) {}
        fn penalise(&mut self, _peer: PeerId, _reason: PenaltyReason) {}
    }

    let mut node = Node::new(NodeConfig::default());
    let (mut host, mut catalog) = (Host::default(), Catalog::new(8, 8));
    let (mut rng, mut store) = (SplitMix64::new(7), BoundedDeferredStore::default());
    let g = group(1);
    for peer in [1, 2] {
        node.connect_peer(peer, true, &mut host, &catalog);
        let mut rpc = Rpc::default();
        let _ = rpc.joins.push(peer_join(InterestKind::All));
        node.on_rpc(peer, rpc, &mut host, &mut catalog, &mut rng, &mut store);
    }
    let rpc = chunk_rpc(chunk(g, 0, [0; 32]));
    node.on_rpc(1, rpc, &mut host, &mut catalog, &mut rng, &mut store);
    host.outbox.clear();

    // Peer 2 asks for the chunk: the host is handed the answer, by reference.
    let mut rpc = Rpc::default();
    let _ = rpc.wants.push(Want::pull_ask(TYPE, Ask { group: g, index: 0 }));
    node.on_rpc(2, rpc, &mut host, &mut catalog, &mut rng, &mut store);
    let answer = host
        .outbox
        .iter()
        .find(|(peer, item)| *peer == 2 && item.is_chunk())
        .map(|&(_, item)| item)
        .expect("the answer is handed to the host");

    // It then says it holds the chunk: the host is told, and the item is no longer
    // written.
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::holding(TYPE, g, Bitmap::singleton(0), false, false));
    node.on_rpc(2, rpc, &mut host, &mut catalog, &mut rng, &mut store);
    assert_eq!(host.cancelled, vec![(2, g, 0)]);
    assert!(node.on_write(2, answer, &mut host, &catalog).is_none());

    // To a peer that does not hold it, the same item is the chunk's frame.
    let frame = node.on_write(1, answer, &mut host, &catalog);
    assert!(frame.is_some_and(|entry| entry.chunk.is_some()));
}

/// A holding, offer or ask names its group's type: one of a type not joined on
/// the link is ignored, and the type is kept for a group that is not open.
#[test]
fn a_group_is_of_the_type_it_is_named_with() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    let (named, other) = (group(1), group(2));

    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(TypeId(9), other, Bitmap::all_bits(8)));
    world.rpc(1, rpc);
    assert!(world.node.groups.get(&other).is_none() && world.node.asked_at.is_empty());

    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(TYPE, named, Bitmap::all_bits(8)));
    world.rpc(1, rpc);
    assert_eq!(world.node.groups.get(&named).and_then(|r| r.named_t), Some(TYPE));
    assert_eq!(world.node.type_of(&named, &world.catalog), TYPE);
    assert_eq!(world.node.asked_at.len(), 8);

    // Named again as another type, the group keeps the first.
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(TypeId(9), named, Bitmap::all_bits(8)));
    world.rpc(1, rpc);
    assert_eq!(world.node.type_of(&named, &world.catalog), TYPE);
}

/// A host that writes elsewhere reports each write: a chunk is recorded as
/// sent, and an ask's promise runs from the time of the write, unless the
/// chunk arrived before the report.
#[test]
fn a_reported_write_has_the_effects_of_a_write() {
    let mut world = World::new(Catalog::new(8, 8), 2, InterestKind::All);
    let g = group(1);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));

    let pushed = seacast_core::Queued::Chunk { group: g, index: 0, solicited: false };
    world.node.on_written(2, &pushed, world.env.now(), &mut world.env, &world.catalog);
    assert!(world.node.pairs.sent_to(&(2, g)).is_some_and(|sent| sent.has(0)));

    let written_at = world.env.now() - 0.1;
    let ask =
        |index| seacast_core::Queued::from_want(Want::pull_ask(TYPE, Ask { group: g, index }));
    world.node.on_written(2, &ask(3), written_at, &mut world.env, &world.catalog);
    assert_eq!(world.node.promises.len(), 1);
    assert!(world.node.promises.contains(Ask { group: g, index: 3 }, 2));

    // Index 0 is held: its ask starts no promise.
    world.node.on_written(2, &ask(0), written_at, &mut world.env, &world.catalog);
    assert_eq!(world.node.promises.len(), 1);
}
