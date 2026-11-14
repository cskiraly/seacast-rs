use crate::{
    bitmap::{Bitmap, MAX_BITMAP_BITS},
    collections::{InlineVec, MAX_INLINE_PEERS},
    message::{ChunkMsg, Have, Queued},
    node::SeacastNode,
    traits::{ChunkBuffer, ObjectCatalog, RngSource, RuntimeEnv},
    types::{AnnounceWidth, Duty, GroupId, GroupState, PeerId, Shape, Timestamp},
};

/// Peers one chunk of a published group is planned for: its budget `R`, with
/// room above it.
const MAX_PLAN_TARGETS: usize = 8;

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Returns the suppression scope of `group`: peers that may push this
    /// family to us (`protocol-v2.md` §4.2 `suppression_scope`).
    pub fn suppression_scope<C>(
        &self,
        group: &GroupId,
        catalog: &C,
    ) -> InlineVec<PeerId, MAX_INLINE_PEERS>
    where
        C: ObjectCatalog<B>,
    {
        let t = self
            .groups
            .get(group)
            .and_then(|r| r.t_of.as_ref())
            .copied()
            .unwrap_or_else(|| catalog.type_of_group(group));
        let fam = catalog.family(t, group);
        let mut out = InlineVec::new();
        for q in self.links(t) {
            if self.has_push_in_any_colour(q, t, fam) {
                let _ = out.push(q);
            }
        }
        out
    }

    /// Sends a holding (`Have` with `offer = false`) on the urgent lane
    /// (`send_have(p, g)`).
    pub fn send_have<E, C>(&mut self, peer: PeerId, group: GroupId, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let bits = self.have_bits(&group);
        let h = self.holding_of(group, bits, catalog);
        if h.claim_all {
            self.groups.rec(group).claimed_all = true;
        }
        if self.groups.get(&group).is_some_and(|r| r.origin.is_some()) &&
            self.config.merge_holdings &&
            env.merge_holding(peer, &h)
        {
            return;
        }
        self.enqueue(peer, Queued::from_have(h), true, env);
    }

    /// Builds a holding `Have` message with `claim_all` and `complete` flags
    /// (`holding_of(g, bits)`).
    pub fn holding_of<C>(&self, group: GroupId, bits: Bitmap, catalog: &C) -> Have
    where
        C: ObjectCatalog<B>,
    {
        let n = self
            .groups
            .get(&group)
            .and_then(|r| r.hdr.as_ref())
            .map(|h| h.n)
            .or_else(|| catalog.shape_by_group(&group).map(|h| h.n))
            .unwrap_or(0);
        let (whole, done) = if self.groups.get(&group).is_some_and(|r| r.origin.is_some()) {
            let all_sent = n > 0 && bits.popcount() >= n;
            (all_sent, all_sent)
        } else {
            let is_decoding = self.groups.get(&group).and_then(|r| r.state.as_ref()) ==
                Some(&GroupState::Decoding);
            let mine_count = self
                .groups
                .get(&group)
                .and_then(|r| r.mine.as_ref())
                .map(|b| b.popcount())
                .unwrap_or(0);
            let whole = is_decoding || (n > 0 && mine_count >= n);
            let done = self
                .groups
                .get(&group)
                .and_then(|r| r.stop_pull.as_ref())
                .copied()
                .unwrap_or(false);
            (whole, done)
        };
        Have::holding(group, bits, whole, done)
    }

    /// Returns what our holding says of `group` (`have_bits(g)` in
    /// `protocol.md` §4.2 `[P4]`).
    #[inline]
    pub fn have_bits(&self, group: &GroupId) -> Bitmap {
        if let Some(orig) = self.groups.get(group).and_then(|r| r.origin.as_ref()) {
            *orig
        } else {
            self.groups.get(group).and_then(|r| r.mine.as_ref()).copied().unwrap_or(Bitmap::EMPTY)
        }
    }

    /// Forwards a verified chunk along each projected `(group, index)` axis
    /// where we have `FORWARD` duty (`protocol-v2.md` §4.4 `forward`).
    pub fn forward<E, C, R>(
        &mut self,
        chunk: &ChunkMsg<B>,
        from_peer: PeerId,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let t_chunk = catalog.type_of_group(&chunk.group);
        for (g, i) in Self::projections(catalog, t_chunk, chunk) {
            if self.expired(&g) {
                continue;
            }
            let t = self
                .groups
                .get(&g)
                .and_then(|r| r.t_of.as_ref())
                .copied()
                .unwrap_or_else(|| catalog.type_of_group(&g));
            if catalog.duty_for(t, &g) != Duty::Forward {
                continue;
            }
            let fam = catalog.family(t, &g);
            let m = catalog.params(t).m.max(1) as u32;
            let c = (i % m) as u16;
            let pushers = self.out_pushees(t, fam, c);
            let mut holding: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
            let mut cands: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
            for &q in &pushers {
                let has_i = self.pairs.peer_has(&(q, g)).map(|e| e.has(i)).unwrap_or(false);
                if has_i {
                    let _ = holding.push(q);
                } else if q != from_peer &&
                    self.interest_of_peer(q, &g, catalog).has(i) &&
                    !self.pairs.peer_has(&(q, g)).map(|e| e.complete).unwrap_or(false)
                {
                    let _ = cands.push(q);
                }
            }
            let budget = if catalog.params(t).eager {
                self.config.r_node().saturating_sub(holding.len())
            } else {
                0
            };
            let targets =
                self.choose_push(chunk, &g, &cands, budget, false, env.now(), catalog, rng);
            for &q in &targets {
                let entry = Queued::Chunk { group: g, index: i, solicited: false };
                if self.enqueue(q, entry, false, env) {
                    self.note_push(q, g, i, env.now());
                } else {
                    self.owe(q, g, Bitmap::singleton(i), env);
                }
            }
            for &q in &cands {
                if !targets.contains(&q) {
                    self.announce(q, g, Bitmap::singleton(i), env, catalog);
                }
            }
            for q in self.announce_extra(&g, i, catalog) {
                self.announce(q, g, Bitmap::singleton(i), env, catalog);
            }
        }
        self.put_gossip(chunk, catalog);
    }

    /// Chooses up to `budget` push targets from `cands` (`protocol.md` §5.3
    /// `choose_push`, `[c16]`) with zero heap allocation.
    #[allow(clippy::too_many_arguments)]
    pub fn choose_push<C, R>(
        &self,
        chunk: &ChunkMsg<B>,
        group: &GroupId,
        cands: &[PeerId],
        budget: usize,
        at_source: bool,
        now: Timestamp,
        catalog: &C,
        rng: &mut R,
    ) -> InlineVec<PeerId, MAX_INLINE_PEERS>
    where
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if budget >= cands.len() {
            return InlineVec::from_slice(cands);
        }
        if budget == 0 {
            return InlineVec::new();
        }
        let mut order = InlineVec::<PeerId, MAX_INLINE_PEERS>::from_slice(cands);
        order.as_mut_slice().sort_by(|&a, &b| {
            let ta = (catalog.tiebreak(&chunk.cached_id, a), catalog.node_id(a));
            let tb = (catalog.tiebreak(&chunk.cached_id, b), catalog.node_id(b));
            tb.cmp(&ta)
        });

        if !self.config.card16_enabled {
            order.truncate(budget);
            return order;
        }

        let peer_metrics = |p: PeerId| -> (bool, u32) {
            let has_bits = &self.pairs.has_bits(&(p, *group));
            let pushed_bits = &self.pairs.pushed_bits(&(p, *group));
            let known = (has_bits | pushed_bits).popcount();
            let unproven = self.guard_fails(p, group, now);
            (unproven, known)
        };

        order.as_mut_slice().sort_by_key(|&p| peer_metrics(p));

        if !at_source {
            let mut ok: InlineVec<(PeerId, u32), MAX_INLINE_PEERS> = InlineVec::new();
            for &p in order.iter() {
                let (unproven, known) = peer_metrics(p);
                if !unproven {
                    let _ = ok.push((p, known));
                }
            }
            if !ok.is_empty() {
                let median = ok[(ok.len() - 1) / 2].1;
                let mut pool: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
                for &(p, known) in ok.iter() {
                    if known <= median {
                        let _ = pool.push(p);
                    }
                }
                let draw_len = budget.min(pool.len());
                let drawn: InlineVec<PeerId, MAX_INLINE_PEERS> =
                    rng.sample_without_replacement(&pool, draw_len);
                let mut new_order = drawn;
                for &p in order.iter() {
                    if !new_order.contains(&p) {
                        let _ = new_order.push(p);
                    }
                }
                order = new_order;
            }
        }
        order.truncate(budget);
        order
    }

    /// Proof guard (`protocol.md` §5.3 `guard_fails(p, g)` `[c16]`):
    /// Demotes a peer that has been pushed at least `R_NODE` chunks of `group`,
    /// the first more than `GUARD_GRACE` ago, without sending any `Have`
    /// holding for `group`.
    pub fn guard_fails(&self, peer: PeerId, group: &GroupId, now: Timestamp) -> bool {
        let Some(e) = self.pairs.pushed(&(peer, *group)) else {
            return false;
        };
        let Some(first_push) = e.first_push else {
            return false;
        };
        let has_any_have = self.pairs.peer_has(&(peer, *group)).is_some();
        (e.popcount() as usize) >= self.config.r_node() &&
            (now - first_push) > self.config.guard_grace &&
            !has_any_have
    }

    /// Records a chosen push to `peer` (`protocol.md` §5.2 `note_push`).
    pub fn note_push(&mut self, peer: PeerId, group: GroupId, index: u32, now: Timestamp) {
        let push_ttl = self.config.push_ttl;
        let mut e = self.pairs.pushed(&(peer, group)).unwrap_or_default();
        if e.is_empty() {
            e.first_push = Some(now);
        }
        e.set(index);
        e.ttl = push_ttl;
        self.pairs.set_pushed((peer, group), e);
    }

    /// Sends an offer `Have(offer = true)` to `peer` for indices in `bits`
    /// (`protocol-v2.md` §4.4 `announce`).
    pub fn announce<E, C>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        bits: Bitmap,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let pushed_bits = &self.pairs.pushed_bits(&(peer, group));
        let peer_has_bits = &self.pairs.has_bits(&(peer, group));
        let interest = self.interest_of_peer(peer, &group, catalog);
        let b = (bits.and_not(pushed_bits).and_not(peer_has_bits)) & interest;
        if b.is_empty() {
            return;
        }
        let offer = Have::offer(group, b);
        if !self.enqueue(peer, Queued::from_have(offer), false, env) {
            self.owe(peer, group, b, env);
        }
    }

    /// Extra peers outside the relation to announce to immediately
    /// (`announce_extra(g, i)`, `[D5]`).
    pub fn announce_extra<C>(
        &self,
        group: &GroupId,
        index: u32,
        catalog: &C,
    ) -> InlineVec<PeerId, MAX_INLINE_PEERS>
    where
        C: ObjectCatalog<B>,
    {
        let mut out = InlineVec::new();
        let t = self
            .groups
            .get(group)
            .and_then(|r| r.t_of.as_ref())
            .copied()
            .unwrap_or_else(|| catalog.type_of_group(group));
        if catalog.params(t).announce_extra != AnnounceWidth::AllJoined {
            return out;
        }
        let fam = catalog.family(t, group);
        for q in self.links(t) {
            let in_out = self.has_push_out_any_colour(q, t, fam);
            let in_in = self.has_push_in_any_colour(q, t, fam);
            if !in_out && !in_in && self.wants_from_me(q, group, catalog).has(index) {
                let _ = out.push(q);
            }
        }
        out
    }

    /// Converts a skipped or refused push into an owed offer if `peer` is in
    /// the push relation (`unpush`).
    pub fn unpush<E, C>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        index: u32,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if let Some(mut e) = self.pairs.pushed(&(peer, group)) {
            e.clear(index);
            self.pairs.set_pushed((peer, group), e);
        }
        let t = self
            .groups
            .get(&group)
            .and_then(|r| r.t_of.as_ref())
            .copied()
            .unwrap_or_else(|| catalog.type_of_group(&group));
        let fam = catalog.family(t, &group);
        let m = catalog.params(t).m.max(1) as u32;
        let c = (index % m) as u16;
        if self.push_out.contains(&(peer, t, fam, c)) {
            self.owe(peer, group, Bitmap::singleton(index), env);
        }
    }

    /// Marks `bits` of `group` as owed to `peer` for the next write (`owe(p, g,
    /// bits)`).
    pub fn owe<E>(&mut self, peer: PeerId, group: GroupId, bits: Bitmap, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        env.owe_offer(peer, group, bits);
    }

    /// Publishes a group as its source (`protocol-v2.md` §4.7 `publish`, `[c2,
    /// c13, P4]`) with zero heap allocation.
    pub fn publish<E, C, R>(
        &mut self,
        group: GroupId,
        shape: Shape,
        shards: &[ChunkMsg<B>],
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if self.expired(&group) {
            return;
        }
        let now = env.now();
        let t = catalog.type_of_group(&group);
        let n = shape.n;
        if !self.groups.open(group, t) {
            return;
        }
        let deadline = shards.first().and_then(|f| catalog.deadline(t, &group, catalog.context(f)));
        let rec = self.groups.rec(group);
        rec.hdr = Some(shape);
        rec.authentic = true;
        rec.deadline = deadline;
        rec.interest = Some(catalog.own_interest(t, &group));
        rec.known_at.get_or_insert(now);

        for f in shards {
            self.seen_ids.insert(f.cached_id);
            self.put_gossip(f, catalog);
            self.store_chunk(group, f.index, f.clone(), now);
        }
        self.groups.rec(group).mine.replace(Bitmap::all_bits(n));
        self.groups.rec(group).state.replace(GroupState::Complete);
        self.groups.rec(group).stop_pull.replace(true);
        self.groups.rec(group).origin.replace(Bitmap::new());

        let r = self.config.r;
        // A chunk's targets are at most its budget. A chunk the plan has no room for is
        // pushed to nobody, and so stays in what the relation peers are offered
        // below.
        let mut plan: InlineVec<(u32, InlineVec<PeerId, MAX_PLAN_TARGETS>), MAX_BITMAP_BITS> =
            InlineVec::new();
        for i in 0..n {
            let Some(f) = self.chunks.get(&(group, i)).cloned() else {
                continue;
            };
            let cands = self.candidates_for_source(&f, catalog);
            let chosen = self.choose_push(&f, &group, &cands, r, true, now, catalog, rng);
            let targets = InlineVec::<PeerId, MAX_PLAN_TARGETS>::from_slice(&chosen);
            if !plan.push((i, targets)) {
                break;
            }
            for &p in &targets {
                self.note_push(p, group, i, now);
            }
        }

        let mut led: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
        for copy in 0..r {
            for &(i, ref targets) in plan.iter() {
                if copy < targets.len() {
                    let p = targets[copy];
                    let Some(f) = self.chunks.get(&(group, i)).cloned() else {
                        continue;
                    };
                    if led.insert_unique(p) {
                        let bits = self
                            .groups
                            .get(&group)
                            .and_then(|r| r.origin.as_ref())
                            .copied()
                            .unwrap_or(Bitmap::EMPTY) |
                            Bitmap::singleton(i);
                        let holding = self.holding_of(group, bits, catalog);
                        if holding.claim_all {
                            self.groups.rec(group).claimed_all = true;
                        }
                        self.enqueue(p, Queued::from_have(holding), true, env);
                    }
                    if !self.enqueue(p, Queued::from_chunk(&f, false), false, env) {
                        self.unpush(p, group, i, env, catalog);
                    }
                }
            }
        }

        let fam = catalog.family(t, &group);
        let m = catalog.params(t).m.max(1) as u32;
        for i in 0..n {
            let c = (i % m) as u16;
            let rel_peers = self.out_pushees(t, fam, c);
            for p in rel_peers {
                self.announce(p, group, Bitmap::singleton(i), env, catalog);
            }
        }
    }

    /// Keeps `chunk` for the heartbeat's gossip, if its type is gossiped at
    /// all: the history is bounded, and a type announced to every joined
    /// peer would crowd the others out of it.
    fn put_gossip<C>(&mut self, chunk: &ChunkMsg<B>, catalog: &C)
    where
        C: ObjectCatalog<B>,
    {
        let t = self
            .groups
            .get(&chunk.group)
            .and_then(|r| r.t_of.as_ref())
            .copied()
            .unwrap_or_else(|| catalog.type_of_group(&chunk.group));
        if catalog.params(t).announce_extra == AnnounceWidth::Sample {
            self.gossip_history.put(chunk);
        }
    }

    /// Updates our paced source holding when a chunk of a group we published
    /// leaves for the first time (`protocol-v2.md` §4.7 `origin_sent(f)`,
    /// `[P4]`).
    pub fn origin_sent<E, C>(&mut self, group: GroupId, index: u32, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let Some(orig) = self.groups.get_mut(&group).and_then(|r| r.origin.as_mut()) else {
            return;
        };
        if orig.has(index) {
            return;
        }
        orig.set(index);
        for q in self.suppression_scope(&group, catalog) {
            self.send_have(q, group, env, catalog);
        }
    }

    /// Returns candidate peers for source pushes (`protocol-v2.md` §4.7
    /// `candidates_for_source`).
    pub fn candidates_for_source<C>(
        &self,
        chunk: &ChunkMsg<B>,
        catalog: &C,
    ) -> InlineVec<PeerId, MAX_INLINE_PEERS>
    where
        C: ObjectCatalog<B>,
    {
        let g = chunk.group;
        let t = self
            .groups
            .get(&g)
            .and_then(|r| r.t_of.as_ref())
            .copied()
            .unwrap_or_else(|| catalog.type_of_group(&g));
        let fam = catalog.family(t, &g);
        let m = catalog.params(t).m.max(1) as u32;
        let c = (chunk.index % m) as u16;

        let pool = if self.config.card13_enabled &&
            self.config.uplink_bps >= self.config.stripe_uplink_bps
        {
            self.links(t)
        } else {
            self.out_pushees(t, fam, c)
        };
        let mut out = InlineVec::new();
        for q in pool {
            if self.wants_from_me(q, &g, catalog).has(chunk.index) {
                let _ = out.push(q);
            }
        }
        out
    }

    /// Returns `true` if `peer` is projected to reach `K` for `group` without
    /// further unsolicited pushes (`protocol-v2.md` §4.9 `projected(p, g)`,
    /// `[c12]`).
    pub fn projected<C>(&self, peer: PeerId, group: &GroupId, _catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        let Some(h) = self.groups.get(group).and_then(|r| r.hdr.as_ref()) else {
            return false;
        };
        let k = h.k;
        let n = h.n;
        if k == n {
            return false;
        }
        let has = &self.pairs.has_bits(&(peer, *group));
        let sent = self.pairs.sent_to(&(peer, *group)).unwrap_or_default();
        let unconfirmed = sent.and_not(has).popcount();
        has.popcount() + self.config.fan_in * unconfirmed >= k
    }
}
