use crate::{
    bitmap::{Bitmap, MAX_BITMAP_BITS},
    collections::{InlineVec, MAX_INLINE_PEERS},
    message::{Have, Queued, Want},
    node::SeacastNode,
    traits::{ChunkBuffer, ObjectCatalog, PenaltyReason, RngSource, RuntimeEnv, TimerEvent},
    types::{Ask, ChunkId, GroupId, InterestKind, PeerId, Timestamp},
};

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Handles an arriving offer (`Have` with `offer = true`, `protocol-v2.md`
    /// §4.3 `on_offer` + `protocol.md` §4.4).
    pub fn on_offer<E, C, R>(
        &mut self,
        peer: PeerId,
        h: &Have,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) -> InlineVec<Ask, MAX_BITMAP_BITS>
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let g = h.group;
        if self.expired(&g) {
            return InlineVec::new();
        }
        // An offer is a HAVE bitmap: one naming an index the group does not have is
        // ignored and counts against its sender (`protocol.md` §8.2).
        if !self.valid_have(h, catalog) {
            env.penalise(peer, PenaltyReason::InvalidHaveBitmap);
            return InlineVec::new();
        }
        if !self.admit_group(peer, &g) {
            return InlineVec::new();
        }

        let t = self.type_of(&g, catalog);
        let now = env.now();
        let interest = match self.groups.get(&g).and_then(|r| r.interest.as_ref()) {
            Some(interest) => *interest,
            None => catalog.own_interest(t, &g),
        };
        // Nothing is kept of an offer that names nothing this node wants: state for a
        // group starts with an offer the admission above counts (`offered`, by
        // `add_offer`).
        if (h.bits & interest)
            .and_not(
                self.groups.get(&g).and_then(|r| r.mine.as_ref()).unwrap_or(Bitmap::empty_ref()),
            )
            .is_empty()
        {
            return InlineVec::new();
        }
        let known_at = *self.groups.rec(g).known_at.get_or_insert(now);

        // Over the IHAVE limits the offer is recorded and nothing is done per index:
        // what it lets the node ask for is the next heartbeat's (`protocol.md`
        // §4.4).
        if self.over_ihave_limits(peer) {
            let mine = self.groups.get(&g).and_then(|r| r.mine.as_ref());
            let wanted = (h.bits & interest).and_not(mine.unwrap_or(Bitmap::empty_ref()));
            let held = self.pairs.offered(&(peer, g)).unwrap_or_default();
            self.pairs.set_offered((peer, g), held | wanted);
            self.pairs.set_offer_at((peer, g), now);
            self.held_groups.insert(g);
            return InlineVec::new();
        }

        let start_delay = catalog.params(t).start_delay;
        if now - known_at < start_delay {
            return self.deferred_offers(peer, h, &interest, known_at, start_delay, env);
        }

        let mine =
            self.groups.get(&g).and_then(|r| r.mine.as_ref()).copied().unwrap_or(Bitmap::EMPTY);
        let wanted = (h.bits & interest).and_not(&mine);
        let auth = catalog.authenticable(t, &g);

        let mut candidates: InlineVec<Ask, MAX_BITMAP_BITS> = InlineVec::new();
        for i in wanted.iter() {
            let a = Ask::new(g, i);
            self.add_offer(a, peer, now);
            if self.gated(a) || !auth {
                continue;
            }
            if self.tied_to_root(peer, a) {
                continue;
            }
            if self.parked(peer, &g, now) {
                self.last_resort(a, env, catalog);
                continue;
            }
            if self.outstanding(peer, a, env) {
                continue;
            }
            let _ = candidates.push(a);
        }

        rng.shuffle(candidates.as_mut_slice());
        let mut asks = InlineVec::new();
        for a in candidates {
            if self.over_ihave_limits(peer) {
                self.held_back.insert((a.group, a.index), a);
            } else if self.may_ask(a, peer, env) {
                let _ = asks.push(a);
                *self.ihave_asked.entry_or_default(peer) += 1;
            }
        }
        asks
    }

    /// Records offers arriving before `START_DELAY` and schedules their first
    /// retry after the delay (`protocol-v2.md` §4.3 `deferred_offers`,
    /// `[D8]`).
    fn deferred_offers<E>(
        &mut self,
        peer: PeerId,
        h: &Have,
        interest: &Bitmap,
        known_at: Timestamp,
        start_delay: f64,
        env: &mut E,
    ) -> InlineVec<Ask, MAX_BITMAP_BITS>
    where
        E: RuntimeEnv<B>,
    {
        let g = h.group;
        let now = env.now();
        let due = (known_at + start_delay - now).max(0.0) + 1e-6;
        let mine =
            self.groups.get(&g).and_then(|r| r.mine.as_ref()).copied().unwrap_or(Bitmap::EMPTY);
        let wanted = (h.bits & interest).and_not(&mine);
        for i in wanted.iter() {
            let a = Ask::new(g, i);
            self.add_offer(a, peer, now);
            if self.retry_armed.insert(a) {
                env.schedule_after(due, TimerEvent::RetryOffer(a));
            }
        }
        InlineVec::new()
    }

    /// Handles incoming `Want` asks from `peer` (`protocol-v2.md` §4.5
    /// `on_want`), returning deduplicated `(group, index)` answers with
    /// zero heap allocation.
    pub fn on_want<E, C>(
        &mut self,
        peer: PeerId,
        wants: &[Want],
        env: &mut E,
        catalog: &C,
    ) -> InlineVec<(GroupId, u32), MAX_BITMAP_BITS>
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let mut answers: InlineVec<(GroupId, u32), MAX_BITMAP_BITS> = InlineVec::new();
        let mut seen_mids: InlineVec<ChunkId, MAX_BITMAP_BITS> = InlineVec::new();

        for w in wants {
            let g = w.group;
            if self.expired(&g) {
                continue;
            }
            let t = self.type_of(&g, catalog);
            let declared = self
                .join_recv
                .get(&(peer, t))
                .map(|j| j.interest == InterestKind::Declared)
                .unwrap_or(false);
            let serve_limit = catalog.params(t).serve_limit;

            // A declared interest is state for a group this peer names: admitted like any
            // other, and stamped so that it goes with the group (`GROUP_TTL`).
            let declared = declared && self.admit_group(peer, &g);
            if declared && !w.bits.is_empty() {
                let now = env.now();
                self.groups.rec(g).known_at.get_or_insert(now);
            }
            let count = self.groups.get(&g).and_then(|r| r.hdr.as_ref()).map(|h| h.n);
            // What this node could have offered is what it holds, and its interest as
            // `peer` sees it is every index for an `ALL` join, else its own
            // interest with what it has declared by its WANTs; a `claim_all`
            // invites any index. An ask outside all of these was never invited.
            let ours = self.join_sent.get(&(peer, t)).map(|j| j.interest);
            let claimed_all = self.groups.get(&g).is_some_and(|r| r.claimed_all);
            let invited = if claimed_all || ours == Some(InterestKind::All) {
                Bitmap::EVERY_INDEX
            } else {
                let wanted = self.groups.get(&g).and_then(|r| r.interest.as_ref());
                catalog.own_interest(t, &g) | wanted.unwrap_or(Bitmap::empty_ref())
            };
            let budget = self.config.max_served_per_heartbeat;

            for idx in w.bits.iter() {
                if count.is_some_and(|n| idx >= n) {
                    continue;
                }
                if declared {
                    let mut wanted = self.pairs.want_p(&(peer, g)).unwrap_or_default();
                    wanted.set(idx);
                    self.pairs.set_want_p((peer, g), wanted);
                }
                if !invited.has(idx) && !self.known_id.contains_key(&(g, idx)) {
                    env.penalise(peer, PenaltyReason::AskOutsideOfferOrInterest);
                    continue;
                }
                let claimed_by_peer =
                    self.pairs.peer_has(&(peer, g)).map(|e| e.has(idx)).unwrap_or(false);
                if claimed_by_peer {
                    env.penalise(peer, PenaltyReason::AskedForClaimedChunk);
                    continue;
                }
                let served_so_far = self.pairs.served(&(peer, g));
                if served_so_far >= serve_limit {
                    continue;
                }
                let Some(&mid) = self.known_id.get(&(g, idx)) else {
                    if declared {
                        self.standing.entry_or_default((g, idx)).insert_unique(peer);
                    }
                    continue;
                };
                if self.groups.get(&g).and_then(|r| r.state.as_ref()) ==
                    Some(&crate::types::GroupState::Invalid)
                {
                    continue;
                }
                if self.unwanted.contains(&(peer, mid)) {
                    continue;
                }
                let count = self.serve_count.entry_or_default((peer, mid));
                *count += 1;
                if *count > self.config.gossip_retransmission {
                    continue;
                }
                if self.served_now.get(&peer).copied().unwrap_or(0) >= budget {
                    continue;
                }
                *self.served_now.entry_or_default(peer) += 1;
                self.pairs.add_served((peer, g));
                if seen_mids.insert_unique(mid) {
                    let _ = answers.push((g, idx));
                }
            }
        }
        answers
    }

    /// Serves standing `Want` requests that preceded the arrival of `(group,
    /// index)` (`serve_standing`).
    pub fn serve_standing<E, C>(&mut self, group: GroupId, index: u32, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let Some(waiting_peers) = self.standing.remove(&(group, index)) else {
            return;
        };
        if self.resolve_chunk(&group, index).is_none() {
            return;
        }
        let t = self.type_of(&group, catalog);
        let serve_limit = catalog.params(t).serve_limit;
        let now = env.now();

        for q in waiting_peers {
            let peer_already_has =
                self.pairs.peer_has(&(q, group)).map(|e| e.has(index)).unwrap_or(false);
            let served_so_far = self.pairs.served(&(q, group));
            let over = self.served_now.get(&q).copied().unwrap_or(0) >=
                self.config.max_served_per_heartbeat;
            if peer_already_has || served_so_far >= serve_limit || over {
                continue;
            }
            *self.served_now.entry_or_default(q) += 1;
            self.pairs.add_served((q, group));
            let entry = Queued::Chunk { group, index, solicited: true };
            if !self.enqueue(q, entry, false, env) {
                env.owe_answer(q, group, index);
            }
            self.note_push(q, group, index, now);
        }
    }

    /// Returns `true` if `peer` may legitimately be asked for `(group, index)`
    /// (`may_be_asked(p, g, i)`).
    pub fn may_be_asked<C>(&self, peer: PeerId, group: &GroupId, index: u32, catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        let offered_us = self.pairs.offered(&(peer, *group)).map(|b| b.has(index)).unwrap_or(false);
        let in_interest = self.interest_of_peer(peer, group, catalog).has(index);
        let claimed_all =
            self.pairs.peer_has(&(peer, *group)).map(|e| e.claim_all).unwrap_or(false);
        offered_us || in_interest || claimed_all
    }

    /// Checks if an ask for `a` may be sent now (`protocol.md` §6.1 `may_ask(a,
    /// p)` `[c5]`).
    pub fn may_ask<E>(&mut self, ask: Ask, peer: PeerId, env: &mut E) -> bool
    where
        E: RuntimeEnv<B>,
    {
        let now = env.now();
        let iwant_win = self.config.scaled_iwant_window();
        match self.asked_at.get(&ask) {
            Some(&at) if now - at < iwant_win => return false,
            Some(_) => {}
            // An ask that cannot be recorded is not made: nothing would stop its repeat. The
            // next heartbeat takes its group up again.
            None if self.asked_at.is_full() => {
                self.held_groups.insert(ask.group);
                return false;
            }
            None => {}
        }
        self.asked_at.insert(ask, now);
        self.tried.insert(ask, peer, now);
        env.schedule_after(iwant_win + self.config.retry_slack, TimerEvent::RetryOffer(ask));
        true
    }

    /// Retries an ask after `IWANT_WINDOW` closes (`protocol.md` §6.1
    /// `retry_offer(a)`).
    pub fn retry_offer<E, C>(&mut self, ask: Ask, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if self.held(ask) ||
            self.groups
                .get(&ask.group)
                .and_then(|r| r.stop_pull.as_ref())
                .copied()
                .unwrap_or(false) ||
            self.expired(&ask.group)
        {
            return;
        }
        // Nothing is asked for before it can be authenticated (`protocol-v2.md` §4.2):
        // the offers wait in the ledger, and the gate's opening retries them.
        let t = self.type_of(&ask.group, catalog);
        if !catalog.authenticable(t, &ask.group) {
            return;
        }
        let now = env.now();
        let iwant_win = self.config.scaled_iwant_window();
        if let Some(&at) = self.asked_at.get(&ask) {
            if now - at < iwant_win {
                return;
            }
        }
        let mut cands: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
        for q in self.announcers(ask) {
            if !self.parked(q, &ask.group, now) && !self.tied_to_root(q, ask) {
                let _ = cands.push(q);
            }
        }
        if cands.is_empty() {
            self.last_resort(ask, env, catalog);
            return;
        }
        let mut free: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
        for q in cands {
            if !self.outstanding(q, ask, env) {
                let _ = free.push(q);
            }
        }
        if free.is_empty() {
            env.schedule_after(iwant_win + self.config.retry_slack, TimerEvent::RetryOffer(ask));
            return;
        }
        let pick =
            self.untried(&free, ask).unwrap_or_else(|| self.least_recently_tried(&free, ask));
        if self.may_ask(ask, pick, env) {
            let want = Want::pull_ask(self.type_of(&ask.group, catalog), ask);
            self.enqueue(pick, Queued::from_want(want), false, env);
        }
    }

    /// Returns `true` if an ask for `ask` to `peer` is currently promised or
    /// queued (`outstanding(q, a)`).
    pub fn outstanding<E>(&self, peer: PeerId, ask: Ask, env: &E) -> bool
    where
        E: RuntimeEnv<B>,
    {
        self.promises.contains(ask, peer) || env.ask_waiting(peer, ask)
    }

    /// Records `peer`'s offer of `ask` (`protocol.md` §6.1 `add_offer(a, p)`).
    pub fn add_offer(&mut self, ask: Ask, peer: PeerId, now: Timestamp) {
        let key = (peer, ask.group);
        let mut offered = self.pairs.offered(&key).unwrap_or_default();
        offered.set(ask.index);
        self.pairs.set_offered(key, offered);
        self.pairs.set_offer_at(key, now);

        let max_offers = self.config.max_offers_per_ask;
        let max_listed = self.config.max_listed_per_peer;
        let listed = self.listed_count.get(&peer).copied().unwrap_or(0);
        let list = self.offers.entry_or_default(ask);
        if !list.contains(&peer) && list.len() < max_offers && listed < max_listed {
            if list.push(peer) {
                *self.listed_count.entry_or_default(peer) += 1;
            }
        }
    }

    /// Drops `peer`'s offers and queued/promised asks of `(group, index)`
    /// (`drop_offer` in `protocol.md` §6.1).
    pub fn drop_offer<E>(&mut self, group: GroupId, index: u32, peer: PeerId, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        self.drop_offers(group, &Bitmap::singleton(index), peer, env);
    }

    /// [`Self::drop_offer`] for every index of `bits`, with one pass over the
    /// peer's queue.
    pub fn drop_offers<E>(&mut self, group: GroupId, bits: &Bitmap, peer: PeerId, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        if let Some(offered) = self.pairs.offered(&(peer, group)) {
            self.pairs.set_offered((peer, group), offered.and_not(bits));
        }
        for index in bits.iter() {
            let ask = Ask::new(group, index);
            let mut remove_ask = false;
            if let Some(list) = self.offers.get_mut(&ask) {
                if list.remove_item(&peer) {
                    if let Some(c) = self.listed_count.get_mut(&peer) {
                        *c = c.saturating_sub(1);
                    }
                }
                remove_ask = list.is_empty();
            }
            if remove_ask {
                self.offers.remove(&ask);
            }
            self.promises.remove(ask, peer);
        }
        env.cancel_asks(peer, group, bits);
    }

    /// Returns all connected peers that offered `ask`, ordered by `offers[ask]`
    /// first (`announcers(a)`).
    pub fn announcers(&self, ask: Ask) -> InlineVec<PeerId, MAX_INLINE_PEERS> {
        let mut out = InlineVec::new();
        if let Some(list) = self.offers.get(&ask) {
            for &p in list {
                let _ = out.push(p);
            }
        }
        for &q in self.peers.iter() {
            if !out.contains(&q) {
                let has_offered =
                    self.pairs.offered(&(q, ask.group)).map(|b| b.has(ask.index)).unwrap_or(false);
                if has_offered {
                    let _ = out.push(q);
                }
            }
        }
        out
    }

    /// Returns all offered and not-yet-held asks of `group` (`protocol.md` §6.1
    /// `ledger(g)`).
    pub fn ledger(&self, group: &GroupId) -> InlineVec<Ask, MAX_BITMAP_BITS> {
        let mut bits = Bitmap::new();
        for &q in self.peers.iter() {
            if let Some(b) = self.pairs.offered(&(q, *group)) {
                bits |= b;
            }
        }
        let mine =
            self.groups.get(group).and_then(|r| r.mine.as_ref()).unwrap_or(Bitmap::empty_ref());
        let mut out = InlineVec::new();
        for i in bits.and_not(mine).iter() {
            let _ = out.push(Ask::new(*group, i));
        }
        out
    }

    fn untried(&self, cands: &[PeerId], ask: Ask) -> Option<PeerId> {
        cands.iter().copied().find(|&q| !self.tried.contains(ask, q))
    }

    fn least_recently_tried(&self, cands: &[PeerId], ask: Ask) -> PeerId {
        cands
            .iter()
            .copied()
            .min_by(|&a, &b| {
                let ta = self.tried.get(ask, a).unwrap_or(f64::NEG_INFINITY);
                let tb = self.tried.get(ask, b).unwrap_or(f64::NEG_INFINITY);
                ta.partial_cmp(&tb).unwrap_or(std::cmp::Ordering::Equal)
            })
            .expect("cands non-empty")
    }

    /// Parks `peer` for `ask.group` when its promise expires unanswered
    /// (`promise_due(a, p, at)`).
    pub fn promise_due<E>(&mut self, ask: Ask, peer: PeerId, at_bits: u64, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        if self.promises.get(ask, peer) != Some(at_bits) {
            return;
        }
        self.promises.remove(ask, peer);
        let now = env.now();
        self.pairs.set_park((peer, ask.group), now + self.config.park_ttl);
    }

    /// Returns `true` if `peer` is currently parked for `group` (`parked(p,
    /// a)`).
    #[inline]
    pub fn parked(&self, peer: PeerId, group: &GroupId, now: Timestamp) -> bool {
        self.pairs.park(&(peer, *group)).map(|until| now < until).unwrap_or(false)
    }

    /// Arms a doubling backoff retry when every announcer of `ask` is parked
    /// (`last_resort(a)`).
    pub fn last_resort<E, C>(&mut self, ask: Ask, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let k = (ask.group, ask.index);
        let now = env.now();
        let mut untied: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
        for q in self.announcers(ask) {
            if !self.tied_to_root(q, ask) {
                let _ = untied.push(q);
            }
        }
        if self.last_resort_armed.contains(&k) ||
            untied.iter().any(|&q| !self.parked(q, &ask.group, now))
        {
            return;
        }
        let done_len = self.asked_parked.get(&k).map(|s| s.len()).unwrap_or(0);
        let all_done = untied
            .iter()
            .all(|&q| self.asked_parked.get(&k).map(|s| s.contains(&q)).unwrap_or(false));
        if all_done {
            return;
        }
        self.last_resort_armed.insert(k);
        let factor = 1u64.checked_shl(done_len as u32).unwrap_or(u64::MAX);
        let t = self.type_of(&ask.group, catalog);
        let delay = catalog.params(t).promise * (factor as f64);
        env.schedule_after(delay, TimerEvent::AskParked(ask));
    }

    /// Asks a parked announcer once more when `last_resort`'s timer fires
    /// (`ask_parked(a)`).
    pub fn ask_parked<E, C>(&mut self, ask: Ask, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let _ = catalog;
        let k = (ask.group, ask.index);
        self.last_resort_armed.remove(&k);
        if self.held(ask) ||
            self.groups
                .get(&ask.group)
                .and_then(|r| r.stop_pull.as_ref())
                .copied()
                .unwrap_or(false) ||
            self.expired(&ask.group)
        {
            return;
        }
        let now = env.now();
        let iwant_win = self.config.scaled_iwant_window();
        if let Some(&at) = self.asked_at.get(&ask) {
            if now - at < iwant_win {
                return;
            }
        }
        let mut untied: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
        for q in self.announcers(ask) {
            if !self.tied_to_root(q, ask) {
                let _ = untied.push(q);
            }
        }
        let mut cands: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
        for &q in &untied {
            if !self.parked(q, &ask.group, now) {
                let _ = cands.push(q);
            }
        }
        if cands.is_empty() {
            for &q in &untied {
                let already = self.asked_parked.get(&k).map(|s| s.contains(&q)).unwrap_or(false);
                if !already {
                    let _ = cands.push(q);
                }
            }
            if cands.is_empty() {
                return;
            }
        }
        let mut free: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
        for q in cands {
            if !self.outstanding(q, ask, env) {
                let _ = free.push(q);
            }
        }
        if free.is_empty() {
            self.last_resort_armed.insert(k);
            env.schedule_after(iwant_win + self.config.retry_slack, TimerEvent::AskParked(ask));
            return;
        }
        let pick =
            self.untried(&free, ask).unwrap_or_else(|| self.least_recently_tried(&free, ask));
        let want = Want::pull_ask(self.type_of(&ask.group, catalog), ask);
        if self.may_ask(ask, pick, env) && self.enqueue(pick, Queued::from_want(want), false, env) {
            if self.parked(pick, &ask.group, now) {
                self.asked_parked.entry_or_default(k).insert_unique(pick);
            }
        }
    }

    pub(crate) fn close_promises(&mut self, group: GroupId, index: u32, of_peer: Option<PeerId>) {
        let ask = Ask::new(group, index);
        if let Some(peer) = of_peer {
            self.promises.remove(ask, peer);
            return;
        }
        self.tried.remove_ask(ask);
        self.promises.remove_ask(ask);
        if let Some(list) = self.offers.remove(&ask) {
            for p in list {
                if let Some(c) = self.listed_count.get_mut(&p) {
                    *c = c.saturating_sub(1);
                }
            }
        }
        self.asked_at.remove(&ask);
        self.asked_parked.remove(&(group, index));
        for idx in 0..self.peers.len() {
            let key = (self.peers[idx], group);
            if let Some(mut bits) = self.pairs.offered(&key) {
                bits.clear(index);
                self.pairs.set_offered(key, bits);
            }
        }
    }

    pub(crate) fn close_promises_of_group(&mut self, group: &GroupId) {
        self.promises.retain(|a, _, _| &a.group != group);
    }
}
