use crate::{
    bitmap::{Bitmap, MAX_BITMAP_BITS, MAX_CHUNKS},
    collections::{InlineVec, MAX_INLINE_PEERS},
    message::ChunkMsg,
    node::SeacastNode,
    traits::{
        ChunkBuffer, DeferredStore, ObjectCatalog, PenaltyReason, RngSource, RuntimeEnv, TimerEvent,
    },
    types::{Ask, Duty, GroupId, GroupState, PeerId, Timestamp, ValidationResult},
};

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Handles an arriving chunk from `peer` (`protocol-v2.md` §4.2 `on_chunk`,
    /// `protocol.md` §4.2).
    pub fn on_chunk<E, C, R, D>(
        &mut self,
        peer: PeerId,
        chunk: ChunkMsg<B>,
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
        // An index no bitmap can name belongs to no group this node can hold.
        if chunk.index as usize >= MAX_BITMAP_BITS {
            return;
        }
        let mid = chunk.cached_id;
        let known = self.seen_ids.contains(&mid) || self.pending_ids.contains(&mid);
        if known || self.verifying.contains(&mid) {
            if self.accepted_id(&mid, &chunk.group, chunk.index) {
                self.send_have(peer, chunk.group, env, catalog);
            } else if self.pending_ids.contains(&mid) {
                self.tie(peer, &chunk, catalog);
            }
            return;
        }
        if self.expired(&chunk.group) {
            return;
        }
        let res = self.level1(&chunk, catalog);
        self.route(peer, chunk, res, env, catalog, rng, deferred_store);
    }

    /// Level 1 of a chunk, in the order of its cost: the codec's checks that
    /// read no data, the domain's word on the group, which is asked once a
    /// group, then the proof.
    fn level1<C>(&mut self, chunk: &ChunkMsg<B>, catalog: &mut C) -> ValidationResult
    where
        C: ObjectCatalog<B>,
    {
        let rec = self.groups.get(&chunk.group);
        if rec.is_some_and(|r| r.t_of.is_some_and(|t| t != chunk.type_id)) || !catalog.check(chunk)
        {
            return ValidationResult::Reject;
        }
        if !rec.is_some_and(|r| r.authentic) {
            let header_id = catalog.header_id(chunk);
            let context = catalog.context(chunk);
            let verdict = catalog.authenticate(chunk.type_id, &chunk.group, &header_id, context);
            if verdict != ValidationResult::Accept {
                // A domain's `Pending` is no verdict: the chunk is not taken.
                return if verdict == ValidationResult::Pending {
                    ValidationResult::Ignore
                } else {
                    verdict
                };
            }
            let deadline = catalog.deadline(chunk.type_id, &chunk.group, context);
            let rec = self.groups.rec(chunk.group);
            rec.authentic = true;
            rec.deadline = deadline;
        }
        catalog.check_proof(chunk)
    }

    /// Takes a chunk on from its inline check: to the host if the rest of level
    /// 1 is still to do, else on as validated.
    #[allow(clippy::too_many_arguments)]
    fn route<E, C, R, D>(
        &mut self,
        peer: PeerId,
        chunk: ChunkMsg<B>,
        result: ValidationResult,
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
        if result != ValidationResult::Pending {
            return self.on_validated(peer, chunk, result, env, catalog, rng, deferred_store);
        }
        // With no room the chunk is dropped unseen: a later copy is taken up again.
        if !self.unverified.is_full() && self.verifying.insert(chunk.cached_id) {
            let _ = self.unverified.push_back((peer, chunk));
        }
    }

    /// Continues chunk processing once Level 1 validation returns
    /// (`on_validated(p, f, result)`): from the inline check, or from the
    /// host with the verdict on a chunk it took from `pop_unverified`.
    #[allow(clippy::too_many_arguments)]
    pub fn on_validated<E, C, R, D>(
        &mut self,
        peer: PeerId,
        chunk: ChunkMsg<B>,
        result: ValidationResult,
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
        self.verifying.remove(&chunk.cached_id);
        if self.expired(&chunk.group) {
            return;
        }
        if result == ValidationResult::Defer {
            self.defer(peer, chunk, env, catalog, deferred_store);
            return;
        }
        // A verdict is `Accept`, `Reject`, `Defer` or `Ignore`.
        if result == ValidationResult::Pending || result == ValidationResult::Ignore {
            return;
        }
        self.seen_ids.insert(chunk.cached_id);
        if result == ValidationResult::Reject {
            env.penalise(peer, PenaltyReason::InvalidChunkLevel1);
            return;
        }
        let t = chunk.type_id;
        let projected = Self::projections(catalog, t, &chunk);
        for &(g, i) in &projected {
            self.fill(g, i, &chunk, Some(peer), env, catalog);
        }
        if projected.iter().any(|&(g, _)| {
            let tg = self.type_of(&g, catalog);
            catalog.duty_for(tg, &g) == Duty::Forward
        }) {
            self.forward(&chunk, peer, env, catalog, rng);
        }
        for (g, _) in projected {
            self.check_completion(g, env, catalog, rng);
        }
    }

    /// Fills `(group, index)` with a verified or rebuilt chunk
    /// (`protocol-v2.md` §4.2 `fill`).
    pub fn fill<E, C>(
        &mut self,
        group: GroupId,
        index: u32,
        chunk: &ChunkMsg<B>,
        sender: Option<PeerId>,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if self.expired(&group) {
            return;
        }
        if index as usize >= MAX_BITMAP_BITS {
            return;
        }
        if self.groups.get(&group).is_none_or(|r| r.t_of.is_none()) {
            self.open_group(group, chunk, env.now(), catalog);
        }
        // Not opened: the group tables are full, or its header names more indices than
        // a bitmap has.
        if self.groups.get(&group).is_none_or(|r| r.t_of.is_none()) ||
            self.groups.get(&group).and_then(|r| r.state.as_ref()) == Some(&GroupState::Invalid)
        {
            return;
        }
        let already_held = self
            .groups
            .get(&group)
            .and_then(|r| r.received.as_ref())
            .map(|b| b.has(index))
            .unwrap_or(false) ||
            self.groups
                .get(&group)
                .and_then(|r| r.rebuilt.as_ref())
                .map(|b| b.has(index))
                .unwrap_or(false);
        if already_held {
            if let Some(p) = sender {
                self.send_have(p, group, env, catalog);
            }
            return;
        }
        self.store_chunk(group, index, chunk.clone(), env.now());
        if sender.is_some() {
            self.groups.rec(group).received.get_or_insert_with(Default::default).set(index);
        } else {
            self.groups.rec(group).rebuilt.get_or_insert_with(Default::default).set(index);
        }
        self.close_promises(group, index, None);
        self.serve_standing(group, index, env, catalog);

        let mine_entry = self.groups.rec(group).mine.get_or_insert_with(Default::default);
        let claim = !mine_entry.has(index);
        if claim {
            mine_entry.set(index);
        }
        let mut recipients: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
        if claim {
            for q in self.suppression_scope(&group, catalog) {
                recipients.insert_unique(q);
            }
        }
        if let Some(p) = sender {
            recipients.insert_unique(p);
        }
        for q in recipients {
            self.send_have(q, group, env, catalog);
        }
    }

    pub(crate) fn open_group<C>(
        &mut self,
        group: GroupId,
        chunk: &ChunkMsg<B>,
        now: Timestamp,
        catalog: &C,
    ) where
        C: ObjectCatalog<B>,
    {
        // A chunk opens its own group as its type; one it only projects onto, as that
        // group's.
        let t = if chunk.group == group { chunk.type_id } else { catalog.type_of_group(&group) };
        let header = catalog
            .shape_by_group(&group)
            .or_else(|| (chunk.group == group).then(|| catalog.shape(chunk)).flatten());
        if let Some(h) = &header {
            if h.n as usize > MAX_BITMAP_BITS {
                return;
            }
        }
        if !self.groups.open(group, t) {
            return;
        }
        let rec = self.groups.rec(group);
        if header.is_some() {
            rec.hdr = header;
        }
        rec.state = Some(GroupState::Collecting);
        // What a sampler declared, or an offer recorded, before the group opened is
        // kept.
        *rec.interest.get_or_insert_with(Default::default) |= &catalog.own_interest(t, &group);
        rec.known_at.get_or_insert(now);
        rec.last_activity = Some(now);
        // Holdings that arrived before the group opened count from now on.
        for &p in self.peers.iter() {
            let Some(entry) = self.pairs.peer_has(&(p, group)) else {
                continue;
            };
            for i in entry.bits.iter() {
                self.holders.entry_or_default((group, i)).insert_unique(p);
            }
            if entry.claim_all {
                self.groups.rec(group).claims.get_or_insert_with(Default::default).insert_unique(p);
            }
        }
    }

    pub(crate) fn store_chunk(
        &mut self,
        group: GroupId,
        index: u32,
        chunk: ChunkMsg<B>,
        now: Timestamp,
    ) {
        self.known_id.insert((group, index), chunk.cached_id);
        self.chunks.insert((group, index), chunk);
        self.groups.rec(group).last_activity.replace(now);
    }

    /// Defers a chunk whose group the domain cannot tell of yet (`protocol.md`
    /// §4.2 `defer`).
    pub fn defer<E, C, D>(
        &mut self,
        peer: PeerId,
        chunk: ChunkMsg<B>,
        env: &mut E,
        catalog: &mut C,
        deferred_store: &mut D,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        D: DeferredStore<B>,
    {
        self.tie(peer, &chunk, catalog);
        if self.pending.is_full() || self.pending_ids.len() >= self.pending_ids.capacity() {
            return;
        }
        if deferred_store.reserve(peer, &chunk) {
            self.pending_ids.insert(chunk.cached_id);
            let until = catalog
                .deadline(chunk.type_id, &chunk.group, catalog.context(&chunk))
                .unwrap_or(env.now() + self.config.group_ttl);
            let _ = self.pending.push((until, peer, chunk));
        }
    }

    /// Ties a sender to the group its deferred chunk is of (`protocol.md` §4.2
    /// `tie`).
    pub fn tie<C>(&mut self, peer: PeerId, chunk: &ChunkMsg<B>, catalog: &C)
    where
        C: ObjectCatalog<B>,
    {
        if self.expired(&chunk.group) {
            return;
        }
        if !self.admit_group(peer, &chunk.group) || !self.tie_room(peer, chunk, catalog) {
            return;
        }
        let key = (peer, chunk.group);
        if !self.tied.contains_key(&key) && self.tied.is_full() {
            return;
        }
        if !self.tied.contains_key(&key) {
            *self.tie_count.entry_or_default(peer) += 1;
        }
        self.tied.entry_or_default(key).set(chunk.index);
        self.tied_bits.entry_or_default((peer, chunk.group)).set(chunk.index);
        self.close_promises(chunk.group, chunk.index, Some(peer));
    }

    /// Returns `true` if `peer` has a copy of `ask` waiting for the domain's
    /// word on its group (`tied_to_root(p, a)`).
    pub fn tied_to_root(&self, peer: PeerId, ask: Ask) -> bool {
        self.tied_bits.get(&(peer, ask.group)).is_some_and(|bits| bits.has(ask.index))
    }

    /// The domain can now tell of `groups` (`protocol.md` §4.2
    /// `on_block_installed`, `protocol-v2.md` §4.2 `on_header_validated`):
    /// the chunks of them that waited are taken up again, each once; the
    /// senders tied to one it commits become announcers of what they
    /// sent, a tie on one it does not commit is dropped; and what was offered
    /// is asked for.
    pub fn on_groups_authenticated<E, C, R, D>(
        &mut self,
        groups: &[GroupId],
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
        let (mut idx, mut left) = (0, self.pending.len());
        while left > 0 {
            left -= 1;
            if !groups.contains(&self.pending[idx].2.group) {
                idx += 1;
                continue;
            }
            let (_, p, f) = self.pending.remove(idx);
            self.pending_ids.remove(&f.cached_id);
            deferred_store.release(p, &f);
            let res = self.level1(&f, catalog);
            self.route(p, f, res, env, catalog, rng, deferred_store);
        }
        self.release_ties(groups, env, catalog);
        for g in groups {
            let asks = self.ledger(g);
            for a in asks {
                self.retry_offer(a, env, catalog);
            }
        }
    }

    /// Releases the ties on `groups`: the senders of a group the domain commits
    /// are unparked and become announcers of what they sent; a tie on any
    /// other is dropped.
    fn release_ties<E, C>(&mut self, groups: &[GroupId], env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let now = env.now();
        // The ties, in peer and group order.
        let mut released: InlineVec<(PeerId, GroupId), MAX_BITMAP_BITS> = InlineVec::new();
        loop {
            released.clear();
            for &(p, g) in self.tied.keys() {
                if groups.contains(&g) && !released.push((p, g)) {
                    break;
                }
            }
            if released.is_empty() {
                break;
            }
            released.as_mut_slice().sort_unstable();
            for &(p, g) in released.iter() {
                let Some(bits) = self.tied.remove(&(p, g)) else {
                    continue;
                };
                if self.expired(&g) {
                    continue;
                }
                let t = self.type_of(&g, catalog);
                if !catalog.authenticable(t, &g) {
                    self.drop_tie(p, g, &bits, env, catalog);
                    continue;
                }
                self.pairs.clear_park(&(p, g));
                for i in bits.iter() {
                    if let Some(set) = self.asked_parked.get_mut(&(g, i)) {
                        set.remove_item(&p);
                    }
                    let held = self
                        .groups
                        .get(&g)
                        .and_then(|r| r.mine.as_ref())
                        .map(|b| b.has(i))
                        .unwrap_or(false);
                    if !held {
                        self.add_offer(Ask::new(g, i), p, now);
                    }
                }
            }
        }
        self.reindex_ties();
    }

    /// Drops a tie on a group the domain does not commit (`drop_tie`).
    pub fn drop_tie<E, C>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        bits: &Bitmap,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let t = self.type_of(&group, catalog);
        let auth = catalog.authenticable(t, &group);
        for i in bits.iter() {
            self.drop_offer(group, i, peer, env);
            if auth {
                self.retry_offer(Ask::new(group, i), env, catalog);
            }
        }
    }

    /// Checks whether our interest in `group` is satisfied and triggers
    /// completion/decode (`protocol-v2.md` §4.6 `check_completion`).
    pub fn check_completion<E, C, R>(
        &mut self,
        group: GroupId,
        env: &mut E,
        catalog: &mut C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if self.groups.get(&group).and_then(|r| r.state.as_ref()) != Some(&GroupState::Collecting) {
            return;
        }
        let Some(interest) = self.groups.get(&group).and_then(|r| r.interest.as_ref()) else {
            return;
        };
        if interest.is_empty() || !self.interest_satisfied(&group, catalog) {
            return;
        }
        self.groups.rec(group).stop_pull.replace(true);
        let t = self.type_of(&group, catalog);
        if catalog.decode_at_k(t, &group) {
            self.groups.rec(group).state.replace(GroupState::Decoding);
            if let Some(h) = self.groups.get(&group).and_then(|r| r.hdr.as_ref()).copied() {
                let rec = self.groups.rec(group);
                let held = rec.mine.unwrap_or(Bitmap::EMPTY);
                rec.mine.replace(catalog.producible(t, &h, &held));
            }
        } else {
            self.groups.rec(group).state.replace(GroupState::Complete);
            if let Some(later) = catalog.decode_later(t, &group, rng) {
                let known_at = self
                    .groups
                    .get(&group)
                    .and_then(|r| r.known_at.as_ref())
                    .copied()
                    .unwrap_or_else(|| env.now());
                self.arm(group, known_at + later, env);
            }
        }
        for q in self.suppression_scope(&group, catalog) {
            self.send_have(q, group, env, catalog);
        }
        self.close_promises_of_group(&group);
        if self.groups.get(&group).and_then(|r| r.state.as_ref()) == Some(&GroupState::Decoding) {
            env.start_decode(group);
        }
    }

    /// Returns `true` if our interest in `group` is satisfied
    /// (`interest_satisfied(g)`).
    pub fn interest_satisfied<C>(&self, group: &GroupId, _catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        let Some(h) = self.groups.get(group).and_then(|r| r.hdr.as_ref()) else {
            return false;
        };
        let recv =
            self.groups.get(group).and_then(|r| r.received.as_ref()).unwrap_or(Bitmap::empty_ref());
        let reb =
            self.groups.get(group).and_then(|r| r.rebuilt.as_ref()).unwrap_or(Bitmap::empty_ref());
        let have = recv | reb;
        let want =
            self.groups.get(group).and_then(|r| r.interest.as_ref()).unwrap_or(Bitmap::empty_ref());
        if want.is_unbounded() { have.popcount() >= h.k } else { want.and_not(&have).is_empty() }
    }

    /// Arms a delayed decode duty for `group` at timestamp `at` (`arm(g, at)`).
    pub fn arm<E>(&mut self, group: GroupId, at: Timestamp, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        let at_bits = at.to_bits();
        self.groups.rec(group).reconsider_at.replace(at_bits);
        let delay = (at - env.now()).max(0.0);
        env.schedule_after(delay, TimerEvent::Reconsider { group, at_bits });
    }

    /// Executes Level 2 group decoding, cross-group filling, repair pushes, and
    /// Level 3 delivery (`protocol-v2.md` §4.6 `decode_group`) using
    /// preallocated scratch buffers (zero heap allocation).
    pub fn decode_group<E, C, R>(
        &mut self,
        group: GroupId,
        env: &mut E,
        catalog: &mut C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if self.expired(&group) {
            return;
        }
        let Some(h) = self.groups.get(&group).and_then(|r| r.hdr.as_ref()).cloned() else {
            return;
        };
        self.decode_in_scratch.clear();
        // The chunks held, in index order: one lookup an index, not a pass over every
        // group's.
        let held =
            self.groups.get(&group).and_then(|r| r.mine.as_ref()).copied().unwrap_or(Bitmap::EMPTY);
        let mut given = Bitmap::EMPTY;
        for i in held.iter() {
            if let Some(ch) = self.chunks.get(&(group, i)) {
                let _ = self.decode_in_scratch.push(ch.clone());
                given.set(i);
            }
        }
        if self.decode_in_scratch.is_empty() {
            return;
        }
        let t = self.type_of(&group, catalog);
        self.decode_out_scratch.clear();
        let decoded =
            catalog.decode(t, &group, &self.decode_in_scratch, &h, &mut self.decode_out_scratch);
        if self.expired(&group) {
            return;
        }
        let Some(object) = decoded else {
            self.drop_group(group, env);
            return;
        };
        let recv = self
            .groups
            .get(&group)
            .and_then(|r| r.received.as_ref())
            .copied()
            .unwrap_or(Bitmap::EMPTY);
        let mut new_indices: InlineVec<u32, MAX_BITMAP_BITS> = InlineVec::new();
        let mut filled_groups: InlineVec<GroupId, MAX_CHUNKS> = InlineVec::new();
        let now = env.now();

        // A chunk's place in the group is its place in `producible`, not its own index:
        // a chunk of two groups keeps the index of its first (`R4`).
        let mut places = catalog.producible(t, &h, &given).iter();
        for idx in 0..self.decode_out_scratch.len() {
            let ch = self.decode_out_scratch[idx].clone();
            let Some(i) = places.next() else {
                break;
            };
            if !recv.has(i) {
                let _ = new_indices.push(i);
                self.store_chunk(group, i, ch.clone(), now);
                self.groups.rec(group).rebuilt.get_or_insert_with(Default::default).set(i);
                for (g2, i2) in Self::projections(catalog, t, &ch) {
                    if g2 == group {
                        continue;
                    }
                    self.fill(g2, i2, &ch, None, env, catalog);
                    filled_groups.insert_unique(g2);
                }
            }
        }
        self.groups.rec(group).state.replace(GroupState::Complete);
        self.groups.rec(group).last_activity.replace(now);
        self.push_rebuilt(group, &new_indices, env, catalog, rng);
        for g2 in filled_groups {
            self.check_completion(g2, env, catalog, rng);
        }
        env.deliver(group, object);
    }

    /// Drops a group when Level 2 or Level 3 validation fails (`protocol.md`
    /// §4.6 `drop_group`).
    pub fn drop_group<E>(&mut self, group: GroupId, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        self.groups.rec(group).state.replace(GroupState::Invalid);
        self.groups.rec(group).stop_pull.replace(true);
        env.cancel_group(&group);
        self.gossip_history.remove_group(&group);
        self.discard_paced(&group);
        self.close_promises_of_group(&group);
    }

    /// Ends `group` now, as the end of its lifetime would, for a domain whose
    /// window the group has left: its chunks still waiting go with it, and
    /// it leaves a tombstone.
    pub fn end_group<E, D>(&mut self, group: GroupId, env: &mut E, deferred_store: &mut D)
    where
        E: RuntimeEnv<B>,
        D: DeferredStore<B>,
    {
        let mut at = 0;
        while at < self.pending.len() {
            if self.pending[at].2.group == group {
                let (_, peer, chunk) = self.pending.remove(at);
                self.pending_ids.remove(&chunk.cached_id);
                deferred_store.release(peer, &chunk);
            } else {
                at += 1;
            }
        }
        self.expiring.insert(group);
        self.expire_due(env.now(), env);
    }

    /// Ends the active lifetime of every group past it (`protocol.md` §8.1): a
    /// group `GROUP_TTL` after its last chunk or its completion leaves a
    /// tombstone and nothing else; a deferred chunk goes `GROUP_TTL` after
    /// it arrived; a tombstone goes after its own time. A group the domain
    /// gave a deadline goes at it if that is sooner, as do its deferred
    /// chunks, and its tombstone is kept until it.
    pub(crate) fn expire_groups<E, D>(&mut self, env: &mut E, deferred_store: &mut D)
    where
        E: RuntimeEnv<B>,
        D: DeferredStore<B>,
    {
        let now = env.now();
        let ttl = self.config.group_ttl;
        let mut at = 0;
        while at < self.pending.len() {
            if now > self.pending[at].0 {
                let (_, peer, chunk) = self.pending.remove(at);
                self.pending_ids.remove(&chunk.cached_id);
                deferred_store.release(peer, &chunk);
            } else {
                at += 1;
            }
        }

        // A record nothing has stamped yet counts from now.
        for (_, rec) in self.groups.iter_mut() {
            if rec.known_at.is_none() && rec.last_activity.is_none() {
                rec.known_at = Some(now);
            }
        }
        // Every group due is ended together: each table is walked once a heartbeat, not
        // once a group.
        loop {
            for (&group, rec) in self.groups.iter() {
                let active = rec.last_activity.or(rec.known_at).unwrap_or(now);
                if now - active > ttl || rec.deadline.is_some_and(|at| now > at) {
                    self.expiring.insert(group);
                }
            }
            if self.expiring.is_empty() {
                break;
            }
            self.expire_due(now, env);
        }

        self.tombstones.retain(|_, &mut until| now <= until);
    }

    /// Removes everything kept of the groups in `expiring` but their
    /// tombstones.
    fn expire_due<E>(&mut self, now: Timestamp, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        let dead = core::mem::replace(&mut self.expiring, crate::PreallocSet::with_capacity(0));
        for &group in dead.iter() {
            let deadline = self.groups.remove(&group).and_then(|rec| rec.deadline);
            self.tombstones.insert(group, deadline.unwrap_or(now + self.config.tombstone_ttl));
        }
        let gone = |of: &GroupId| dead.contains(of);
        let gone_id =
            |id: &crate::ChunkId| dead.contains(GroupId::try_from(&id[..32]).as_ref().unwrap());

        self.chunks.retain(|(of, _), _| !gone(of));
        self.known_id.retain(|(of, _), _| !gone(of));
        // A chunk id opens with its group's id.
        self.seen_ids.retain(|id| !gone_id(id));
        self.verifying.retain(|id| !gone_id(id));
        self.serve_count.retain(|(_, id), _| !gone_id(id));
        self.unwanted.retain(|(_, id)| !gone_id(id));

        self.pairs.retain(|(_, of)| !gone(of));
        self.holders.retain(|(of, _), _| !gone(of));
        self.standing.retain(|(of, _), _| !gone(of));

        // The pull state: offers with their announcers' counts, then what hangs off an
        // ask.
        let listed_count = &mut self.listed_count;
        self.offers.retain(|ask, announcers| {
            if !gone(&ask.group) {
                return true;
            }
            for p in announcers.iter() {
                if let Some(count) = listed_count.get_mut(p) {
                    *count = count.saturating_sub(1);
                }
            }
            false
        });
        self.tried.retain(|ask, _, _| !gone(&ask.group));
        self.asked_at.retain(|ask, _| !gone(&ask.group));
        self.promises.retain(|ask, _, _| !gone(&ask.group));
        self.asked_parked.retain(|(of, _), _| !gone(of));
        self.last_resort_armed.retain(|(of, _)| !gone(of));
        self.retry_armed.retain(|ask| !gone(&ask.group));
        self.held_back.retain(|(of, _), _| !gone(of));
        self.tied.retain(|(_, of), _| !gone(of));
        self.reindex_ties();
        let named_count = &mut self.named_count;
        self.named.retain(|(peer, of), _| {
            if gone(of) {
                if let Some(count) = named_count.get_mut(peer) {
                    *count = count.saturating_sub(1);
                }
            }
            !gone(of)
        });

        self.probe_asks.retain(|ask| !gone(&ask.group));
        self.rsample_asked.retain(|(of, _, _)| !gone(of));

        // Queued chunks, offers and asks of them, and what is owed; their holdings
        // still leave.
        for g in dead.iter() {
            env.cancel_group(g);
            self.gossip_history.remove_group(g);
            self.discard_paced(g);
        }
        let mut dead = dead;
        dead.clear();
        self.expiring = dead;
    }

    pub(crate) fn discard_paced(&mut self, group: &GroupId) {
        for idx in 0..self.pace_queue.len() {
            if let Some((_, items, _)) = self.pace_queue.get_mut(idx) {
                items.retain(|(g, _)| g != group);
            }
        }
    }
}
