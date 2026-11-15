use crate::{
    bitmap::{Bitmap, MAX_BITMAP_BITS},
    collections::{InlineVec, MAX_INLINE_PEERS},
    message::{Have, Queued, Want},
    node::SeacastNode,
    traits::{ChunkBuffer, ObjectCatalog, PenaltyReason, RngSource, RuntimeEnv, TimerEvent},
    types::{Ask, GroupId, GroupState, InterestKind, PeerId, RepairVerdict, TypeId},
};

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Handles an arriving holding (`Have` with `offer = false`,
    /// `protocol-v2.md` §4.3 `on_holding`).
    pub fn on_holding<E, C, R>(
        &mut self,
        peer: PeerId,
        h: Have,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if self.expired(&h.group) {
            return;
        }
        if !self.valid_have(&h, catalog) {
            env.penalise(peer, PenaltyReason::InvalidHaveBitmap);
            return;
        }
        if !self.admit_group(peer, &h.group) {
            return;
        }
        let have_ttl = self.config.have_ttl;
        let mut e = self.pairs.peer_has(&(peer, h.group)).unwrap_or_default();
        let newly = h.bits.and_not(&e.bits);
        e.bits |= &h.bits;
        e.ttl = have_ttl;
        e.claim_all = e.claim_all || h.claim_all;
        e.complete = e.complete || h.complete;
        self.pairs.set_peer_has((peer, h.group), e);

        // A group this node has not opened has no claim to act on and no holders to
        // count: both are taken from `peer_has` when it opens (`open_group`).
        let open = self.groups.get(&h.group).is_some_and(|r| r.t_of.is_some());
        if h.claim_all && open {
            self.note_claim(peer, h.group, env, catalog, rng);
        }
        for i in newly.iter() {
            if open {
                self.holders.entry_or_default((h.group, i)).insert_unique(peer);
            }
            env.cancel_chunk(peer, h.group, i);
        }
    }

    /// Returns the union of our holdings and our un-claimed relation peers'
    /// holdings (`known_in_scope(g)`).
    pub fn known_in_scope<C>(&self, group: &GroupId, catalog: &C) -> Bitmap
    where
        C: ObjectCatalog<B>,
    {
        let mut known =
            self.groups.get(group).and_then(|r| r.mine.as_ref()).copied().unwrap_or(Bitmap::EMPTY);
        let claimants = self.groups.get(group).and_then(|r| r.claims.as_ref());
        for q in self.suppression_scope(group, catalog) {
            if claimants.map(|s| s.contains(&q)).unwrap_or(false) {
                continue;
            }
            if let Some(e) = self.pairs.peer_has(&(q, *group)) {
                known |= &e.bits;
            }
        }
        known
    }

    /// Returns what our relation peers on the cross axis hold of `group`
    /// (`known_across(g)`, `R4`).
    pub fn known_across<C>(&self, group: &GroupId, catalog: &C) -> Bitmap
    where
        C: ObjectCatalog<B>,
    {
        let mut known =
            self.groups.get(group).and_then(|r| r.mine.as_ref()).copied().unwrap_or(Bitmap::EMPTY);
        let Some(h) = self.groups.get(group).and_then(|r| r.hdr.as_ref()) else {
            return known;
        };
        let t = self.type_of(group, catalog);
        let n = h.n;
        for i in 0..n {
            if known.has(i) {
                continue;
            }
            for (g2, i2) in catalog.cross(t, group, i) {
                let scope2 = self.suppression_scope(&g2, catalog);
                if scope2
                    .iter()
                    .any(|&q| self.pairs.peer_has(&(q, g2)).map(|e| e.has(i2)).unwrap_or(false))
                {
                    known.set(i);
                    break;
                }
            }
        }
        known
    }

    /// Member check (`protocol-v2.md` §4.6 `owed_missing(g)`, `R5`):
    /// Returns `true` if a chunk of `group` that belongs to our own interest on
    /// the cross axis is still missing from our holdings.
    pub fn owed_missing<C>(&self, group: &GroupId, catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        let Some(h) = self.groups.get(group).and_then(|r| r.hdr.as_ref()) else {
            return false;
        };
        let t = self.type_of(group, catalog);
        let n = h.n;
        let recv =
            self.groups.get(group).and_then(|r| r.received.as_ref()).unwrap_or(Bitmap::empty_ref());
        let reb =
            self.groups.get(group).and_then(|r| r.rebuilt.as_ref()).unwrap_or(Bitmap::empty_ref());
        for i in 0..n {
            if recv.has(i) || reb.has(i) {
                continue;
            }
            for (g2, i2) in catalog.cross(t, group, i) {
                let t2 = self.type_of(&g2, catalog);
                let interest2 = self
                    .groups
                    .get(&g2)
                    .and_then(|r| r.interest.as_ref())
                    .copied()
                    .unwrap_or_else(|| catalog.own_interest(t2, &g2));
                if interest2.has(i2) {
                    return true;
                }
            }
        }
        false
    }

    /// IncrementalDAS sampling verdict on a claimant's repair
    /// (`repair_verdict(g)`, `R5`).
    pub fn repair_verdict<E, C, R>(
        &mut self,
        group: GroupId,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) -> RepairVerdict
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let t = self.type_of(&group, catalog);
        let Some(ref steps_ref) = catalog.params(t).repair_sample else {
            return RepairVerdict::Repaired;
        };
        let steps = InlineVec::<(usize, usize), 8>::from_slice(steps_ref);
        let repair_reask = catalog.params(t).repair_reask;
        let k = self.groups.get(&group).and_then(|r| r.rsample_step.as_ref()).copied().unwrap_or(0);
        if k > 0 {
            let recv = self
                .groups
                .get(&group)
                .and_then(|r| r.received.as_ref())
                .copied()
                .unwrap_or(Bitmap::EMPTY);
            let reb = self
                .groups
                .get(&group)
                .and_then(|r| r.rebuilt.as_ref())
                .copied()
                .unwrap_or(Bitmap::EMPTY);
            let sampled = self
                .groups
                .get(&group)
                .and_then(|r| r.rsample.as_ref())
                .copied()
                .unwrap_or_default();
            let mut lost: InlineVec<u32, MAX_BITMAP_BITS> = InlineVec::new();
            for i in sampled {
                if !recv.has(i) && !reb.has(i) {
                    let _ = lost.push(i);
                }
            }
            if lost.len() <= steps[k - 1].1 {
                return RepairVerdict::Repaired;
            }
            if k == steps.len() &&
                self.groups
                    .get(&group)
                    .and_then(|r| r.rsample_final.as_ref())
                    .copied()
                    .unwrap_or(false)
            {
                return RepairVerdict::NotRepaired;
            }
            let mut reasked_any = false;
            if repair_reask {
                for &i in &lost {
                    if self.ask_custodian(group, i, env, catalog, rng) {
                        reasked_any = true;
                    }
                }
            }
            if k == steps.len() {
                if !reasked_any {
                    return RepairVerdict::NotRepaired;
                }
                self.groups.rec(group).rsample_final.replace(true);
                return RepairVerdict::Asked;
            }
        }

        let current_len =
            self.groups.get(&group).and_then(|r| r.rsample.as_ref()).map(|v| v.len()).unwrap_or(0);
        let mut want = steps[k].0.saturating_sub(current_len);
        let n = self.groups.get(&group).and_then(|r| r.hdr.as_ref()).map(|h| h.n).unwrap_or(0);
        let recv = self
            .groups
            .get(&group)
            .and_then(|r| r.received.as_ref())
            .copied()
            .unwrap_or(Bitmap::EMPTY);
        let reb = self
            .groups
            .get(&group)
            .and_then(|r| r.rebuilt.as_ref())
            .copied()
            .unwrap_or(Bitmap::EMPTY);
        let existing =
            self.groups.get(&group).and_then(|r| r.rsample.as_ref()).copied().unwrap_or_default();
        let mut pool: InlineVec<u32, MAX_BITMAP_BITS> = InlineVec::new();
        for i in 0..n {
            if !recv.has(i) && !reb.has(i) && !existing.contains(&i) {
                let _ = pool.push(i);
            }
        }
        rng.shuffle(pool.as_mut_slice());
        for i in pool {
            if want == 0 {
                break;
            }
            if self.ask_custodian(group, i, env, catalog, rng) {
                let _ = self.groups.rec(group).rsample.get_or_insert_with(Default::default).push(i);
                want -= 1;
            }
        }
        self.groups.rec(group).rsample_step.replace(k + 1);
        if self
            .groups
            .get(&group)
            .and_then(|r| r.rsample.as_ref())
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
            RepairVerdict::Asked
        } else {
            RepairVerdict::Repaired
        }
    }

    /// Asks a custodian of family `i` for cell `i` of `group`
    /// (`ask_custodian(g, i)`).
    pub fn ask_custodian<E, C, R>(
        &mut self,
        group: GroupId,
        index: u32,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) -> bool
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let t = self.type_of(&group, catalog);
        let cross = catalog.cross(t, &group, index);
        let Some(&(g2, i2)) = cross.first() else {
            return false;
        };
        if self.expired(&g2) {
            return false;
        }
        let t2 = self.type_of(&g2, catalog);
        let claimants = self.groups.get(&group).and_then(|r| r.claims.as_ref());
        let mut qs: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
        for q in self.links(t2) {
            let claimed = claimants.map(|s| s.contains(&q)).unwrap_or(false);
            let already = self.rsample_asked.contains(&(group, index, q));
            if self.interest_of_peer(q, &g2, catalog).has(i2) && !claimed && !already {
                let _ = qs.push(q);
            }
        }
        let Some(&q) = rng.choice(&qs) else {
            return false;
        };
        self.rsample_asked.insert((group, index, q));
        let want = Want::standing(self.type_of(&g2, catalog), g2, Bitmap::singleton(i2));
        self.enqueue(q, Queued::from_want(want), false, env);
        true
    }

    /// Evaluates a delayed decode duty when its timer fires (`protocol-v2.md`
    /// §4.6 `reconsider`).
    pub fn reconsider<E, C, R>(
        &mut self,
        group: GroupId,
        at_bits: u64,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if self.groups.get(&group).and_then(|r| r.reconsider_at.as_ref()).copied() != Some(at_bits) ||
            self.groups.get(&group).and_then(|r| r.state.as_ref()) != Some(&GroupState::Complete)
        {
            return;
        }
        self.groups.get_mut(&group).and_then(|r| r.reconsider_at.take());
        let Some(h) = self.groups.get(&group).and_then(|r| r.hdr.as_ref()).cloned() else {
            return;
        };
        let t = self.type_of(&group, catalog);
        let n = h.n;
        if self.known_in_scope(&group, catalog).popcount() >= n {
            return;
        }
        let is_deferred =
            self.groups.get(&group).and_then(|r| r.deferred.as_ref()).copied().unwrap_or(false);
        let probe_received = self
            .groups
            .get(&group)
            .and_then(|r| r.probe.as_ref())
            .map(|&p_idx| {
                self.groups
                    .get(&group)
                    .and_then(|r| r.received.as_ref())
                    .map(|b| b.has(p_idx))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        let fam = catalog.family(t, &group);

        if is_deferred &&
            probe_received &&
            catalog.wants_family(t, fam) &&
            !self.owed_missing(&group, catalog)
        {
            if catalog.params(t).repair_sample.is_none() {
                return;
            }
            let sample_wait = catalog.params(t).sample_wait;
            match self.repair_verdict(group, env, catalog, rng) {
                RepairVerdict::Repaired => return,
                RepairVerdict::Asked => {
                    self.arm(group, env.now() + sample_wait, env);
                    return;
                }
                RepairVerdict::NotRepaired => {}
            }
        }

        let is_waited =
            self.groups.get(&group).and_then(|r| r.waited.as_ref()).copied().unwrap_or(false);
        if !is_waited && !is_deferred {
            let combined =
                self.known_in_scope(&group, catalog) | self.known_across(&group, catalog);
            if combined.popcount() >= n {
                self.groups.rec(group).waited.replace(true);
                let defer_win = catalog.params(t).defer_window;
                self.arm(group, env.now() + defer_win, env);
                return;
            }
        }

        let has_claims = self
            .groups
            .get(&group)
            .and_then(|r| r.claims.as_ref())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if has_claims && !is_deferred {
            self.defer_on_claim(group, env, catalog, rng);
            return;
        }

        if is_deferred && !probe_received {
            if let Some(&probed_peer) = self.groups.get(&group).and_then(|r| r.probed.as_ref()) {
                env.penalise(probed_peer, PenaltyReason::UnansweredClaimProbe);
            }
        }

        self.groups.rec(group).state.replace(GroupState::Decoding);
        let rec = self.groups.rec(group);
        let held = rec.mine.unwrap_or(Bitmap::EMPTY);
        rec.mine.replace(catalog.producible(t, &h, &held));
        for q in self.suppression_scope(&group, catalog) {
            self.send_have(q, group, env, catalog);
        }
        env.start_decode(group);
    }

    /// Records a peer's `claim_all` and defers our own pending decode if armed
    /// (`note_claim(p, g)`).
    pub fn note_claim<E, C, R>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        self.groups.rec(group).claims.get_or_insert_with(Default::default).insert_unique(peer);
        let is_deferred =
            self.groups.get(&group).and_then(|r| r.deferred.as_ref()).copied().unwrap_or(false);
        if self.groups.get(&group).is_some_and(|r| r.reconsider_at.is_some()) &&
            self.groups.get(&group).and_then(|r| r.state.as_ref()) == Some(&GroupState::Complete) &&
            !is_deferred
        {
            if let Some(h) = self.groups.get(&group).and_then(|r| r.hdr.as_ref()) {
                let n = h.n;
                let mine_count = self
                    .groups
                    .get(&group)
                    .and_then(|r| r.mine.as_ref())
                    .map(|b| b.popcount())
                    .unwrap_or(0);
                if mine_count < n {
                    self.defer_on_claim(group, env, catalog, rng);
                }
            }
        }
    }

    /// Defers a decode once on a peer's `claim_all` and sends a verification
    /// probe ask (`defer_on_claim(g)`).
    pub fn defer_on_claim<E, C, R>(&mut self, group: GroupId, env: &mut E, catalog: &C, rng: &mut R)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let Some(h) = self.groups.get(&group).and_then(|r| r.hdr.as_ref()) else {
            return;
        };
        let t = self.type_of(&group, catalog);
        let n = h.n;
        let mine =
            self.groups.get(&group).and_then(|r| r.mine.as_ref()).unwrap_or(Bitmap::empty_ref());
        let Some(probe_idx) = (0..n).find(|&i| !mine.has(i)) else {
            return;
        };
        let claimants =
            self.groups.get(&group).and_then(|r| r.claims.as_ref()).copied().unwrap_or_default();
        let Some(&q) = rng.choice(&claimants) else {
            return;
        };
        let now = env.now();
        let defer_win = catalog.params(t).defer_window;
        self.groups.rec(group).deferred.replace(true);
        self.groups.rec(group).probe.replace(probe_idx);
        self.groups.rec(group).probed.replace(q);

        let a = Ask::new(group, probe_idx);
        self.add_offer(a, q, now);
        self.tried.insert(a, q, now);
        self.probe_asks.insert(a);

        let now_bits = now.to_bits();
        self.promises.insert(a, q, now_bits);
        env.schedule_after(defer_win, TimerEvent::PromiseDue {
            ask: a,
            peer: q,
            at_bits: now_bits,
        });
        let want = Want::standing(t, group, Bitmap::singleton(probe_idx));
        self.enqueue(q, Queued::from_want(want), false, env);

        let current_reconsider = self
            .groups
            .get(&group)
            .and_then(|r| r.reconsider_at.as_ref())
            .map(|&bits| f64::from_bits(bits))
            .unwrap_or(now);
        let arm_at = current_reconsider.max(now + defer_win);
        self.arm(group, arm_at, env);
    }

    /// Pushes or offers rebuilt chunks across each group they fill
    /// (`protocol-v2.md` §4.6 `push_rebuilt`) with zero heap allocation.
    pub fn push_rebuilt<E, C, R>(
        &mut self,
        group: GroupId,
        new_indices: &[u32],
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let t = self.type_of(&group, catalog);

        // Collect unique target groups g2 and their (i2, source_index) pairs on the
        // stack
        let mut group_order: InlineVec<GroupId, MAX_BITMAP_BITS> = InlineVec::new();
        let mut projected_items: InlineVec<(GroupId, u32, u32), { 2 * MAX_BITMAP_BITS }> =
            InlineVec::new();

        for &i in new_indices {
            if let Some(ch) = self.chunks.get(&(group, i)) {
                for (g2, i2) in Self::projections(catalog, t, ch) {
                    group_order.insert_unique(g2);
                    let _ = projected_items.push((g2, i2, i));
                }
            }
        }

        for g2 in group_order {
            if self.expired(&g2) {
                continue;
            }
            let mut items: InlineVec<(u32, u32), MAX_BITMAP_BITS> = InlineVec::new();
            for &(ref pg, i2, src_i) in projected_items.iter() {
                if *pg == g2 {
                    let _ = items.push((i2, src_i));
                }
            }
            if items.is_empty() {
                continue;
            }

            let t2 = self.type_of(&g2, catalog);
            let Some(h2) = self
                .groups
                .get(&g2)
                .and_then(|r| r.hdr.as_ref())
                .cloned()
                .or_else(|| catalog.shape_by_group(&g2))
            else {
                continue;
            };
            let k = h2.k;
            let prm2 = catalog.params(t2);
            let repair_budget = prm2.repair_budget;
            let eager = prm2.eager;

            if repair_budget && eager {
                self.push_rebuilt_as_source(group, g2, t2, &items, env, catalog, rng);
                continue;
            }

            let mut repair_peers = self.repair_candidates(t2, &g2, catalog);
            rng.shuffle(repair_peers.as_mut_slice());

            for q in repair_peers {
                let complete = self.pairs.peer_has(&(q, g2)).map(|e| e.complete).unwrap_or(false);
                if complete {
                    continue;
                }
                let has_bits = &self.pairs.has_bits(&(q, g2));
                let pushed_bits = &self.pairs.pushed_bits(&(q, g2));
                let known = has_bits | pushed_bits;
                let known_count = known.popcount();
                if known_count >= k {
                    continue;
                }
                let short = (k - known_count) as usize;
                let want = self.interest_of_peer(q, &g2, catalog);
                let mut lacks: InlineVec<(u32, u32), MAX_BITMAP_BITS> = InlineVec::new();
                for &(i2, src_i) in items.iter() {
                    if !known.has(i2) && want.has(i2) {
                        let _ = lacks.push((i2, src_i));
                    }
                }
                rng.shuffle(lacks.as_mut_slice());

                for &(i2, src_i) in lacks.iter().take(short) {
                    if !eager {
                        self.announce(q, g2, Bitmap::singleton(i2), env, catalog);
                        continue;
                    }
                    if !self.chunks.contains_key(&(group, src_i)) {
                        continue;
                    }
                    let entry = Queued::Chunk { group, index: src_i, solicited: false };
                    if self.enqueue(q, entry, false, env) {
                        self.note_push(q, g2, i2, env.now());
                    } else {
                        self.owe(q, g2, Bitmap::singleton(i2), env);
                    }
                }
            }
        }
    }

    /// Pushes each rebuilt chunk to `R_NODE` peers lacking it and offers it to
    /// the rest (`protocol-v2.md` §4.6 `push_rebuilt_as_source`,
    /// `REPAIR_BUDGET`).
    #[allow(clippy::too_many_arguments)]
    fn push_rebuilt_as_source<E, C, R>(
        &mut self,
        src_group: GroupId,
        g2: GroupId,
        t2: TypeId,
        items: &[(u32, u32)],
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let r_node = self.config.r_node();
        let base_peers = self.repair_candidates(t2, &g2, catalog);
        for &(i2, src_i) in items {
            if !self.chunks.contains_key(&(src_group, src_i)) {
                continue;
            }
            let entry = Queued::Chunk { group: src_group, index: src_i, solicited: false };
            let mut shuffled_peers = base_peers;
            rng.shuffle(shuffled_peers.as_mut_slice());
            let mut cands: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
            for q in shuffled_peers {
                let complete = self.pairs.peer_has(&(q, g2)).map(|e| e.complete).unwrap_or(false);
                let has_bits = &self.pairs.has_bits(&(q, g2));
                let pushed_bits = &self.pairs.pushed_bits(&(q, g2));
                if !complete &&
                    !(has_bits | pushed_bits).has(i2) &&
                    self.interest_of_peer(q, &g2, catalog).has(i2)
                {
                    let _ = cands.push(q);
                }
            }
            for &q in cands.iter().take(r_node) {
                if self.enqueue(q, entry, false, env) {
                    self.note_push(q, g2, i2, env.now());
                } else {
                    self.owe(q, g2, Bitmap::singleton(i2), env);
                }
            }
            for &q in cands.iter().skip(r_node) {
                self.announce(q, g2, Bitmap::singleton(i2), env, catalog);
            }
        }
    }

    pub(crate) fn repair_candidates<C>(
        &self,
        t: TypeId,
        group: &GroupId,
        catalog: &C,
    ) -> InlineVec<PeerId, MAX_INLINE_PEERS>
    where
        C: ObjectCatalog<B>,
    {
        if let Some(custom) = catalog.repair_to(t, group) {
            return custom;
        }
        let fam = catalog.family(t, group);
        let mut out = InlineVec::new();
        for &q in self.peers.iter() {
            let in_rel = self.has_push_out_any_colour(q, t, fam);
            if in_rel || !self.interest_of_peer(q, group, catalog).is_empty() {
                let _ = out.push(q);
            }
        }
        out
    }

    /// Declares sample interest in `bits` of `group` to a single custodian/full
    /// link (`protocol-v2.md` §4.10 `sample(g, bits)`).
    pub fn sample<E, C, R>(
        &mut self,
        group: GroupId,
        bits: Bitmap,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if self.expired(&group) || bits.is_empty() {
            return;
        }
        let t = self.type_of(&group, catalog);
        let now = env.now();
        let mut cands: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
        for q in self.links(t) {
            let not_declared = self
                .join_recv
                .get(&(q, t))
                .map(|j| j.interest != InterestKind::Declared)
                .unwrap_or(false);
            let not_parked = !self.parked(q, &group, now);
            let covers_bits = (self.interest_of_peer(q, &group, catalog) & bits) == bits;
            if not_declared && not_parked && covers_bits {
                let _ = cands.push(q);
            }
        }
        let Some(&q) = rng.choice(&cands) else {
            env.unreachable(group, bits);
            return;
        };
        *self.groups.rec(group).interest.get_or_insert_with(Default::default) |= bits;
        self.groups.rec(group).known_at.get_or_insert(now);
        let want = Want::standing(t, group, bits);
        self.enqueue(q, Queued::from_want(want), false, env);
        let sample_retry = catalog.params(t).sample_retry;
        env.schedule_after(sample_retry, TimerEvent::Resample { group, bits, peer: q });
    }

    /// Retries a sample on another link if `peer` did not deliver within
    /// `SAMPLE_RETRY` (`protocol-v2.md` §4.10 `resample(g, bits, q)`).
    pub fn resample<E, C, R>(
        &mut self,
        group: GroupId,
        bits: Bitmap,
        peer: PeerId,
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
        let mine =
            self.groups.get(&group).and_then(|r| r.mine.as_ref()).unwrap_or(Bitmap::empty_ref());
        let missing = bits.and_not(mine);
        if missing.is_empty() {
            return;
        }
        let now = env.now();
        self.pairs.set_park((peer, group), now + self.config.park_ttl);
        self.sample(group, missing, env, catalog, rng);
    }
}
