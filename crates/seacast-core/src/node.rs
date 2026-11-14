use crate::{
    bitmap::{Bitmap, MAX_BITMAP_BITS},
    collections::{
        InlineVec, MAX_ENTRY_CONTROL, MAX_INLINE_OFFERS, MAX_INLINE_PEERS, PreallocDeque,
        PreallocMap, PreallocSet, PreallocVec,
    },
    message::{ChunkMsg, Join, Prune, Queued, Rpc, Want},
    state::{AskPeers, GossipHistory, Groups, MAX_GOSSIP_GROUPS, Pairs},
    traits::{ChunkBuffer, DeferredStore, ObjectCatalog, RngSource, RuntimeEnv, TimerEvent},
    types::{
        Ask, ChunkId, Colour, FamilyId, GroupId, GroupState, NodeConfig, PeerId, Timestamp, TypeId,
    },
};

/// A paced gossip send: the peer, the groups and indices, and when it is due.
pub type PacedGossip = (PeerId, InlineVec<(GroupId, Bitmap), MAX_GOSSIP_GROUPS>, Timestamp);

/// Standalone `sans-io` state machine for a SEACAST v2 node (`protocol-v2.md` +
/// `protocol.md` v0.8).
///
/// All state tables are preallocated with fixed capacities in
/// [`SeacastNode::new`]. Protocol execution performs **no heap allocation**;
/// all external resources (I/O, timers, randomness, buffer allocation, deferred
/// chunk storage, and object verification) are injected via traits.
pub struct SeacastNode<B> {
    pub config: NodeConfig,

    // Connected peers in deterministic registration order
    pub peers: PreallocVec<PeerId>,

    // Per link and object type (`protocol-v2.md` §3)
    pub join_recv: PreallocMap<(PeerId, TypeId), Join>,
    pub join_sent: PreallocMap<(PeerId, TypeId), Join>,
    pub push_out: PreallocSet<(PeerId, TypeId, FamilyId, Colour)>,
    pub push_in: PreallocSet<(PeerId, TypeId, FamilyId, Colour)>,
    /// The relations of each link in `push_in` and in `push_out`, for the
    /// per-link limit.
    pub(crate) relation_count: PreallocMap<(PeerId, TypeId), (usize, usize)>,

    // Per group state (`protocol-v2.md` §3, `protocol.md` §8.1)
    /// Per group state (`protocol-v2.md` §3, `protocol.md` §8.1), a record a
    /// group.
    pub groups: Groups,
    pub chunks: PreallocMap<(GroupId, u32), ChunkMsg<B>>,
    pub known_id: PreallocMap<(GroupId, u32), ChunkId>,
    /// Until when each expired group is kept out.
    pub tombstones: PreallocMap<GroupId, Timestamp>,

    // Per peer and group diffusion state (`protocol-v2.md` §3)
    /// `peer_has`, `pushed`, `sent_to`, `served`, `want_p`, `offered` and
    /// `park`, a record a pair.
    pub pairs: Pairs,
    pub holders: PreallocMap<(GroupId, u32), InlineVec<PeerId, MAX_INLINE_PEERS>>,
    pub serve_count: PreallocMap<(PeerId, ChunkId), usize>,
    pub unwanted: PreallocSet<(PeerId, ChunkId)>,
    pub standing: PreallocMap<(GroupId, u32), InlineVec<PeerId, MAX_INLINE_PEERS>>,

    // Pull discipline, offer ledger, promises, and parking (`protocol.md` §6.1, §8.1)
    pub offers: PreallocMap<Ask, InlineVec<PeerId, MAX_INLINE_OFFERS>>,
    pub listed_count: PreallocMap<PeerId, usize>,
    pub tried: AskPeers<Timestamp>,
    pub asked_at: PreallocMap<Ask, Timestamp>,
    pub promises: AskPeers<u64>,
    pub asked_parked: PreallocMap<(GroupId, u32), InlineVec<PeerId, MAX_INLINE_PEERS>>,
    pub last_resort_armed: PreallocSet<(GroupId, u32)>,
    pub retry_armed: PreallocSet<Ask>,
    pub ihave_rpcs: PreallocMap<PeerId, usize>,
    pub ihave_asked: PreallocMap<PeerId, usize>,
    /// Chunks served to each peer's asks this heartbeat.
    pub(crate) served_now: PreallocMap<PeerId, usize>,
    pub held_back: PreallocMap<(GroupId, u32), Ask>,
    /// Groups with offers taken in over the IHAVE limits: their asks are the
    /// next heartbeat's.
    pub(crate) held_groups: PreallocSet<GroupId>,
    /// The groups one heartbeat ends, while their state is removed in one pass
    /// a table.
    pub(crate) expiring: PreallocSet<GroupId>,

    // Claims, deferral, probe, and IncrementalDAS repair sampling (`protocol-v2.md` §3, §4.6)
    pub probe_asks: PreallocSet<Ask>,
    pub rsample_asked: PreallocSet<(GroupId, u32, PeerId)>,

    // Gate deferral & equivocation ties (`protocol.md` §4.2)
    pub seen_ids: PreallocSet<ChunkId>,
    /// Chunks waiting for the domain's word on their group, with when each
    /// is dropped.
    pub pending: PreallocVec<(Timestamp, PeerId, ChunkMsg<B>)>,
    pub pending_ids: PreallocSet<ChunkId>,
    /// Chunks that passed the inline checks, for the host to verify, and their
    /// ids until the verdict is in: a second copy meanwhile is not verified
    /// again.
    pub(crate) unverified: PreallocDeque<(PeerId, ChunkMsg<B>)>,
    pub verifying: PreallocSet<ChunkId>,
    pub tied: PreallocMap<(PeerId, GroupId), Bitmap>,
    /// `tied` by peer and group, over every root, and the number of ties of
    /// each peer: what the per-index and per-chunk checks read.
    pub(crate) tied_bits: PreallocMap<(PeerId, GroupId), Bitmap>,
    pub(crate) tie_count: PreallocMap<PeerId, usize>,
    /// Groups without a header that a peer has named, with the heartbeats each
    /// has left, and their number per peer (`MAX_PENDING_GROUPS`,
    /// `protocol.md` §8.2).
    pub(crate) named: PreallocMap<(PeerId, GroupId), u32>,
    pub(crate) named_count: PreallocMap<PeerId, usize>,

    pub gossip_history: GossipHistory,
    pub pace_queue: PreallocDeque<PacedGossip>,
    pub pace_timer_active: bool,

    // Preallocated scratch buffers for Level 2 decode (`decode_group`)
    pub(crate) decode_in_scratch: PreallocVec<ChunkMsg<B>>,
    pub(crate) decode_out_scratch: PreallocVec<ChunkMsg<B>>,
}

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Creates a new SEACAST v2 node state machine and preallocates all
    /// fixed-capacity state tables.
    pub fn new(config: NodeConfig) -> Self {
        let cap = &config.capacities;
        let peer_types = cap.max_peers * cap.max_types;
        let peer_asks = cap.max_peers * 64;

        Self {
            peers: PreallocVec::with_capacity(cap.max_peers),
            join_recv: PreallocMap::with_capacity(peer_types),
            join_sent: PreallocMap::with_capacity(peer_types),
            push_out: PreallocSet::with_capacity(cap.max_relations),
            push_in: PreallocSet::with_capacity(cap.max_relations),
            relation_count: PreallocMap::with_capacity(peer_types),
            groups: Groups::with_capacity(cap.max_groups),
            chunks: PreallocMap::with_capacity(cap.max_stored_chunks),
            known_id: PreallocMap::with_capacity(cap.max_stored_chunks),
            tombstones: PreallocMap::with_capacity(cap.max_groups),
            pairs: Pairs::with_capacity(cap.max_pairs, cap.max_wide_pairs),
            holders: PreallocMap::with_capacity(cap.max_stored_chunks),
            serve_count: PreallocMap::with_capacity(cap.max_seen_ids),
            unwanted: PreallocSet::with_capacity(cap.max_seen_ids),
            standing: PreallocMap::with_capacity(cap.max_asks),
            offers: PreallocMap::with_capacity(cap.max_asks),
            listed_count: PreallocMap::with_capacity(cap.max_peers),
            tried: AskPeers::with_capacity(cap.max_asks),
            asked_at: PreallocMap::with_capacity(cap.max_asks),
            promises: AskPeers::with_capacity(cap.max_asks),
            asked_parked: PreallocMap::with_capacity(cap.max_asks),
            last_resort_armed: PreallocSet::with_capacity(cap.max_asks),
            retry_armed: PreallocSet::with_capacity(cap.max_asks),
            ihave_rpcs: PreallocMap::with_capacity(cap.max_peers),
            ihave_asked: PreallocMap::with_capacity(cap.max_peers),
            served_now: PreallocMap::with_capacity(cap.max_peers),
            held_back: PreallocMap::with_capacity(cap.max_asks),
            held_groups: PreallocSet::with_capacity(2 * cap.max_groups),
            expiring: PreallocSet::with_capacity(2 * cap.max_groups),
            probe_asks: PreallocSet::with_capacity(cap.max_groups),
            rsample_asked: PreallocSet::with_capacity(peer_asks),
            seen_ids: PreallocSet::with_capacity(cap.max_seen_ids),
            pending: PreallocVec::with_capacity(cap.max_deferred_chunks),
            pending_ids: PreallocSet::with_capacity(cap.max_deferred_chunks),
            unverified: PreallocDeque::with_capacity(cap.max_deferred_chunks),
            verifying: PreallocSet::with_capacity(cap.max_deferred_chunks),
            tied: PreallocMap::with_capacity(cap.max_deferred_chunks),
            tied_bits: PreallocMap::with_capacity(cap.max_deferred_chunks),
            tie_count: PreallocMap::with_capacity(cap.max_peers),
            named: PreallocMap::with_capacity(cap.max_peers * config.max_pending_groups),
            named_count: PreallocMap::with_capacity(cap.max_peers),
            gossip_history: GossipHistory::with_capacity(6, 3, cap.max_groups),
            pace_queue: PreallocDeque::with_capacity(cap.max_peers * 4),
            pace_timer_active: false,
            decode_in_scratch: PreallocVec::with_capacity(MAX_BITMAP_BITS),
            decode_out_scratch: PreallocVec::with_capacity(MAX_BITMAP_BITS),
            config,
        }
    }

    // =========================================================================
    // Connection & Link Management (§1.3, §4.1, §8.1)
    // =========================================================================

    /// Registers a newly connected peer and optionally sends our initial `Join`
    /// declarations.
    pub fn connect_peer<E, C>(&mut self, peer: PeerId, send_joins: bool, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        // Past `max_peers` a connection gets no state: nothing is sent to it or kept of
        // it.
        if !self.peers.contains(&peer) && !self.peers.push(peer) {
            return;
        }
        if send_joins {
            for t in catalog.joined_types() {
                let j = catalog.our_join(t);
                // Recorded only once queued: a JOIN a full queue refused is sent with the
                // peer's.
                if self.enqueue(peer, Queued::from_join(j), true, env) {
                    self.join_sent.insert((peer, t), j);
                }
            }
        }
    }

    /// Cleans up all per-connection state when a peer disconnects
    /// (`protocol.md` §8.1). Note: `park` is kept across reconnections as
    /// scores are (`protocol.md` §8.1).
    pub fn disconnect_peer<E, D>(&mut self, peer: PeerId, _env: &mut E, deferred_store: &mut D)
    where
        E: RuntimeEnv<B>,
        D: DeferredStore<B>,
    {
        self.peers.retain(|&q| q != peer);
        self.join_recv.retain(|&(q, _), _| q != peer);
        self.join_sent.retain(|&(q, _), _| q != peer);
        self.push_out.retain(|&(q, _, _, _)| q != peer);
        self.push_in.retain(|&(q, _, _, _)| q != peer);
        self.relation_count.retain(|&(q, _), _| q != peer);

        // Remove peer from live holders when its `peer_has` goes
        self.pairs.retain(|&(q, _)| q != peer);
        for (_, set) in self.holders.iter_mut() {
            set.remove_item(&peer);
        }

        self.serve_count.retain(|&(q, _), _| q != peer);
        self.unwanted.retain(|&(q, _)| q != peer);
        self.ihave_rpcs.remove(&peer);
        self.ihave_asked.remove(&peer);
        self.served_now.remove(&peer);

        for (_, peers) in self.standing.iter_mut() {
            peers.remove_item(&peer);
        }

        // Remove peer from ordered offer lists and decrement listed_count
        self.listed_count.remove(&peer);
        self.offers.retain(|_, list| {
            list.remove_item(&peer);
            !list.is_empty()
        });

        // Close promises and tried records for this peer
        self.tried.retain(|_, q, _| q != peer);
        self.promises.retain(|_, q, _| q != peer);
        for (_, set) in self.asked_parked.iter_mut() {
            set.remove_item(&peer);
        }

        // Release deferred chunks and ties from this peer
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].1 == peer {
                let (_, _, chunk) = self.pending.remove(i);
                self.pending_ids.remove(&chunk.cached_id);
                deferred_store.release(peer, &chunk);
            } else {
                i += 1;
            }
        }
        self.tied.retain(|&(q, _), _| q != peer);
        self.reindex_ties();
        self.named.retain(|&(q, _), _| q != peer);
        self.named_count.remove(&peer);

        // A claim is a connection's: a gone claimant is neither probed nor counted.
        for (_, rec) in self.groups.iter_mut() {
            if let Some(claimants) = &mut rec.claims {
                claimants.remove_item(&peer);
                if claimants.is_empty() {
                    rec.claims = None;
                }
            }
            if rec.probed == Some(peer) {
                rec.probed = None;
            }
        }
        self.rsample_asked.retain(|&(_, _, q)| q != peer);
    }

    // =========================================================================
    // §4. Events: Top-Level RPC & Timer Dispatch
    // =========================================================================

    /// Handles an incoming standalone `Rpc` from `peer` (`protocol-v2.md` §4
    /// `on_rpc`).
    pub fn on_rpc<E, C, R, D>(
        &mut self,
        peer: PeerId,
        rpc: Rpc<B>,
        env: &mut E,
        catalog: &mut C,
        rng: &mut R,
        deferred_store: &mut D,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
        D: DeferredStore<B>,
    {
        for j in rpc.joins {
            self.on_join(peer, j, env, catalog);
        }
        // A message for an object type not joined on this link is ignored, without
        // penalty (`protocol-v2.md` §2).
        if let Some(f) = rpc.chunk {
            if self.is_linked(peer, f.type_id) {
                self.on_chunk(peer, f, env, catalog, rng, deferred_store);
            }
        }
        // One WANT per group: an offer's asks are bits of one bitmap, so none is left
        // behind.
        let mut asks: InlineVec<Want, MAX_ENTRY_CONTROL> = InlineVec::new();
        let mut offered = false;
        for h in &rpc.haves {
            if h.offer && self.linked_for(peer, &h.group, catalog) {
                if !offered && !h.bits.is_empty() {
                    offered = true;
                    *self.ihave_rpcs.entry_or_default(peer) += 1;
                }
                for a in self.on_offer(peer, h, env, catalog, rng) {
                    match asks.iter_mut().find(|w| w.group == a.group) {
                        Some(w) => w.bits.set(a.index),
                        None => {
                            let _ = asks.push(Want::pull_ask(a));
                        }
                    }
                }
            }
        }
        let mut wants: InlineVec<Want, MAX_ENTRY_CONTROL> = InlineVec::new();
        for w in &rpc.wants {
            if self.linked_for(peer, &w.group, catalog) {
                let _ = wants.push(*w);
            }
        }
        let answers = self.on_want(peer, &wants, env, catalog);
        let mut prunes: InlineVec<Prune, MAX_ENTRY_CONTROL> = InlineVec::new();
        for gr in rpc.grafts {
            let batch = self.on_graft(peer, gr, env, catalog);
            prunes.extend_from_slice(&batch);
        }
        for pr in rpc.prunes {
            self.on_prune(peer, pr);
        }
        for h in rpc.haves {
            if !h.offer && self.linked_for(peer, &h.group, catalog) {
                self.on_holding(peer, h, env, catalog, rng);
            }
        }
        self.respond(peer, &asks, &answers, &prunes, env);
    }

    /// Whether `peer` and this node have both joined `group`'s object type on
    /// their link.
    fn linked_for<C>(&self, peer: PeerId, group: &GroupId, catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        let t = self
            .groups
            .get(group)
            .and_then(|r| r.t_of.as_ref())
            .copied()
            .unwrap_or_else(|| catalog.type_of_group(group));
        self.is_linked(peer, t)
    }

    /// Sends one combined response per RPC handled (`protocol.md` §4.1
    /// `respond`).
    pub fn respond<E>(
        &mut self,
        peer: PeerId,
        asks: &[Want],
        answers: &[(GroupId, u32)],
        prunes: &[Prune],
        env: &mut E,
    ) where
        E: RuntimeEnv<B>,
    {
        // The control goes ahead of the answers; the writer sends what is control at
        // the head of a lane as one RPC.
        for &want in asks {
            self.enqueue(peer, Queued::from_want(want), false, env);
        }
        for &prune in prunes {
            self.enqueue(peer, Queued::from_prune(prune), false, env);
        }
        for &(group, index) in answers {
            if self.resolve_chunk(&group, index).is_none() {
                continue;
            }
            let entry = Queued::Chunk { group, index, solicited: true };
            if !self.enqueue(peer, entry, false, env) {
                env.owe_answer(peer, group, index);
            }
        }
    }

    /// Dispatches a scheduled `TimerEvent` (`protocol-v2.md` §4).
    pub fn on_timer<E, C, R, D>(
        &mut self,
        event: TimerEvent,
        env: &mut E,
        catalog: &mut C,
        rng: &mut R,
        deferred_store: &mut D,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
        D: DeferredStore<B>,
    {
        match event {
            TimerEvent::RetryOffer(ask) => {
                self.retry_armed.remove(&ask);
                self.retry_offer(ask, env, catalog);
            }
            TimerEvent::PromiseDue { ask, peer, at_bits } => {
                self.promise_due(ask, peer, at_bits, env);
            }
            TimerEvent::AskParked(ask) => {
                self.ask_parked(ask, env, catalog);
            }
            TimerEvent::WindowTimeout { peer, group, index, at_bits } => {
                // The send path's: a host with one gives it this event.
                let _ = (peer, group, index, at_bits);
            }
            TimerEvent::Reconsider { group, at_bits } => {
                self.reconsider(group, at_bits, env, catalog, rng);
            }
            TimerEvent::Resample { group, bits, peer } => {
                self.resample(group, bits, peer, env, catalog, rng);
            }
            TimerEvent::PaceTick => {
                self.on_pace_tick(env, catalog);
            }
            TimerEvent::Heartbeat => {
                self.on_heartbeat(env, catalog, rng, deferred_store);
            }
        }
    }

    // =========================================================================
    // Shared State Queries
    // =========================================================================

    #[inline]
    pub fn accepted(&self, group: &GroupId, index: u32) -> bool {
        self.groups.get(group).and_then(|r| r.state.as_ref()) != Some(&GroupState::Invalid) &&
            self.chunks.contains_key(&(*group, index))
    }

    /// The next chunk whose level 1 check the host is to finish, with the peer
    /// it came from. The verdict goes to [`Self::on_validated`].
    pub fn pop_unverified(&mut self) -> Option<(PeerId, ChunkMsg<B>)> {
        self.unverified.pop_front()
    }

    /// Whether the chunk stored at `(group, index)` is the one with id `mid`
    /// (`accepted(mid)`).
    #[inline]
    pub fn accepted_id(&self, mid: &ChunkId, group: &GroupId, index: u32) -> bool {
        self.groups.get(group).and_then(|r| r.state.as_ref()) != Some(&GroupState::Invalid) &&
            self.known_id.get(&(*group, index)) == Some(mid)
    }

    #[inline]
    pub fn resolve_chunk(&self, group: &GroupId, index: u32) -> Option<ChunkMsg<B>> {
        if self.groups.get(group).and_then(|r| r.state.as_ref()) == Some(&GroupState::Invalid) {
            return None;
        }
        self.chunks.get(&(*group, index)).cloned()
    }

    #[inline]
    pub fn held(&self, ask: Ask) -> bool {
        self.groups
            .get(&ask.group)
            .and_then(|r| r.mine.as_ref())
            .map(|b| b.has(ask.index))
            .unwrap_or(false)
    }

    #[inline]
    pub fn gated(&self, ask: Ask) -> bool {
        self.groups.get(&ask.group).and_then(|r| r.stop_pull.as_ref()).copied().unwrap_or(false) &&
            !self.probe_asks.contains(&ask)
    }

    #[inline]
    pub fn expired(&self, group: &GroupId) -> bool {
        self.tombstones.contains_key(group)
    }

    #[inline]
    pub fn holder_count(&self, group: &GroupId, index: u32) -> usize {
        self.holders.get(&(*group, index)).map(|s| s.len()).unwrap_or(0)
    }

    /// Every `(group, index)` a chunk fills (`T.project(f)`), but for an index
    /// no bitmap can name: what follows indexes bitmaps with them.
    pub(crate) fn projections<C>(
        catalog: &C,
        t: TypeId,
        chunk: &ChunkMsg<B>,
    ) -> InlineVec<(GroupId, u32), { crate::collections::MAX_PROJECTED }>
    where
        C: ObjectCatalog<B>,
    {
        let mut projected = catalog.project(t, chunk);
        projected.retain(|&(_, index)| (index as usize) < MAX_BITMAP_BITS);
        projected
    }

    /// Takes one relation of `peer`'s link off its count; `out` for `push_out`.
    /// A relation the host wrote into the sets directly was never counted,
    /// so the count saturates.
    pub(crate) fn uncount_relation(&mut self, peer: PeerId, t: TypeId, out: bool) {
        if let Some(count) = self.relation_count.get_mut(&(peer, t)) {
            let side = if out { &mut count.1 } else { &mut count.0 };
            *side = side.saturating_sub(1);
        }
    }

    #[inline]
    pub fn over_ihave_limits(&self, peer: PeerId) -> bool {
        let rpcs = self.ihave_rpcs.get(&peer).copied().unwrap_or(0);
        let asked = self.ihave_asked.get(&peer).copied().unwrap_or(0);
        rpcs > self.config.max_ihave_messages || asked >= self.config.max_ihave_length
    }

    pub fn valid_have<C>(&self, h: &crate::message::Have, _catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        if h.bits.wire_byte_len() > crate::bitmap::MAX_HAVE_BYTES {
            return false;
        }
        if let Some(hdr) = self.groups.get(&h.group).and_then(|r| r.hdr.as_ref()) {
            let n = hdr.n;
            if !h.bits.all_below(n) {
                return false;
            }
        }
        true
    }

    /// Whether `peer` may have state kept for `group`: always for a group with
    /// a header, else as one of the `MAX_PENDING_GROUPS` it has named
    /// lately (`admitted_group(p, g)`). Naming a group again keeps its
    /// place.
    pub fn admit_group(&mut self, peer: PeerId, group: &GroupId) -> bool {
        if self.groups.get(group).is_some_and(|r| r.hdr.is_some()) {
            return true;
        }
        // As long as the group's own state would live without a chunk of it.
        let heartbeats = (self.config.group_ttl / self.config.heartbeat).ceil().max(1.0) as u32;
        if let Some(left) = self.named.get_mut(&(peer, *group)) {
            *left = heartbeats;
            return true;
        }
        let count = self.named_count.get(&peer).copied().unwrap_or(0);
        if count >= self.config.max_pending_groups || self.named.is_full() {
            return false;
        }
        self.named.insert((peer, *group), heartbeats);
        self.named_count.insert(peer, count + 1);
        true
    }

    #[inline]
    pub fn tie_room<C>(&self, peer: PeerId, chunk: &ChunkMsg<B>, _catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        if (chunk.index as usize) >= crate::bitmap::MAX_BITMAP_BITS {
            return false;
        }
        let shape = self.groups.get(&chunk.group).and_then(|r| r.hdr.as_ref());
        if shape.is_some_and(|shape| chunk.index >= shape.n) {
            return false;
        }
        self.tied.contains_key(&(peer, chunk.group)) ||
            self.tie_count.get(&peer).copied().unwrap_or(0) < self.config.max_pending_groups
    }

    /// Rebuilds the per-peer views of `tied` after ties were removed.
    pub(crate) fn reindex_ties(&mut self) {
        self.tied_bits.clear();
        self.tie_count.clear();
        for (&(peer, group), bits) in self.tied.iter() {
            *self.tied_bits.entry_or_default((peer, group)) |= bits;
            *self.tie_count.entry_or_default(peer) += 1;
        }
    }

    /// Returns the current lifecycle state of `group` (`Pending` or
    /// `Complete`), if open.
    #[inline]
    pub fn group_state(&self, group: &GroupId) -> Option<GroupState> {
        self.groups.get(group).and_then(|r| r.state.as_ref()).copied()
    }
}
