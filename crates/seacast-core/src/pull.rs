use crate::{
    bitmap::{Bitmap, MAX_BITMAP_BITS},
    collections::{InlineVec, PreallocVec},
    message::{Have, Queued, Want},
    node::SeacastNode,
    state::{GroupBits, PeerSet},
    traits::{ChunkBuffer, ObjectCatalog, PenaltyReason, RngSource, RuntimeEnv, TimerEvent},
    types::{Ask, ChunkId, Duty, GroupId, InterestKind, PeerId, Timestamp, TypeId},
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

        let t = g.type_id;
        let now = env.now();
        let interest = match self.groups.bits(&g, GroupBits::Interest) {
            Some(interest) => interest,
            None => catalog.own_interest(&g),
        };
        // Nothing is kept of an offer that names nothing this node wants: state for a
        // group starts with an offer the admission above counts (`offered`, by
        // `add_offer`).
        if (h.bits & interest)
            .and_not(&self.groups.bits(&g, GroupBits::Mine).unwrap_or(Bitmap::EMPTY))
            .is_empty()
        {
            return InlineVec::new();
        }
        let known_at = *self.groups.rec(g).known_at.get_or_insert(now);

        // Over the IHAVE limits the offer is recorded and nothing is done per index:
        // what it lets the node ask for is the next heartbeat's (`protocol.md`
        // §4.4).
        if self.over_ihave_limits(peer) {
            let mine = self.groups.bits(&g, GroupBits::Mine);
            let wanted = (h.bits & interest).and_not(&mine.unwrap_or(Bitmap::EMPTY));
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

        let mine = self.groups.bits(&g, GroupBits::Mine).unwrap_or(Bitmap::EMPTY);
        let wanted = (h.bits & interest).and_not(&mine);
        let auth = catalog.authenticable(&g);

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
            if self.outstanding(peer, a) {
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
                if let Some(slot) = self.slots.get_mut(peer) {
                    slot.ihave_asked += 1;
                }
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
        let mine = self.groups.bits(&g, GroupBits::Mine).unwrap_or(Bitmap::EMPTY);
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
            let t = g.type_id;
            let declared =
                self.join_recv(peer, t).is_some_and(|j| j.interest == InterestKind::Declared);
            let serve_limit = catalog.params(t).serve_limit;

            // A declared interest is state for a group this peer names: admitted like any
            // other, and stamped so that it goes with the group (`GROUP_TTL`).
            // So is a standing request.
            let admitted = (declared || w.standing) && self.admit_group(peer, &g);
            let declared = declared && admitted;
            let standing = admitted;
            if declared && !w.bits.is_empty() {
                let now = env.now();
                self.groups.rec(g).known_at.get_or_insert(now);
            }
            let count = self.groups.get(&g).and_then(|r| r.hdr.as_ref()).map(|h| h.n);
            // What this node could have offered is what it holds, and its interest as
            // `peer` sees it is every index for an `ALL` join, else its own
            // interest with what it has declared by its WANTs; a `claim_all`
            // invites any index. An ask outside all of these was never invited.
            let ours = self.join_sent(peer, t).map(|j| j.interest);
            let claimed_all = self.groups.get(&g).is_some_and(|r| r.claimed_all);
            let invited = if claimed_all || ours == Some(InterestKind::All) {
                Bitmap::EVERY_INDEX
            } else {
                let wanted = self.groups.bits(&g, GroupBits::Interest);
                catalog.own_interest(&g) | wanted.unwrap_or(Bitmap::EMPTY)
            };
            let budget = self.config.max_served_per_heartbeat;
            // A routed sample request may come to a node with duty that neither holds
            // the index nor has it in its interest (§4.5, `[D12]`). Its answer goes back
            // by the standing request, so it is passed on only where that is kept.
            let routed = w.hops > 0 &&
                standing &&
                self.join_sent(peer, t).is_some_and(|j| j.duty == Duty::Forward);

            for idx in w.bits.iter() {
                if count.is_some_and(|n| idx >= n) {
                    continue;
                }
                if declared {
                    let mut wanted = self.pairs.want_p(&(peer, g)).unwrap_or_default();
                    wanted.set(idx);
                    self.pairs.set_want_p((peer, g), wanted);
                }
                if !invited.has(idx) && !self.known_id.contains_key(&(g, idx)) && !routed {
                    env.penalise(peer, PenaltyReason::AskOutsideOfferOrInterest);
                    continue;
                }
                // The peer's probe of our claim: answered whatever it holds, once
                // for the group (`protocol-v2.md` §4.6 `probe_of_claim`).
                // While its probe of another index is kept, it is a plain ask.
                let claimed = self.groups.bits(&g, GroupBits::Mine);
                let waiting = self.probe_waiting_of.get(&(peer, g)).copied();
                let flagged = w.probe &&
                    claimed.is_some_and(|mine| mine.has(idx)) &&
                    !self.pairs.probe_served(&(peer, g)) &&
                    waiting.is_none_or(|j| j == idx);
                let claimed_by_peer =
                    self.pairs.peer_has(&(peer, g)).map(|e| e.has(idx)).unwrap_or(false);
                if claimed_by_peer && !flagged {
                    env.penalise(peer, PenaltyReason::AskedForClaimedChunk);
                    continue;
                }
                let served_so_far = self.pairs.served(&(peer, g));
                if served_so_far >= serve_limit {
                    continue;
                }
                let Some(&mid) = self.known_id.get(&(g, idx)) else {
                    // Claimed, not stored: we are decoding. The first probe per asker and
                    // group is kept and answered once, when the chunk is stored, in place
                    // of a standing WANT of that index from the asker (§4.6).
                    if flagged && waiting.is_none() {
                        if !self.probe_waiting_of.is_full() &&
                            self.probe_waiting.insert((g, idx), peer)
                        {
                            self.probe_waiting_of.insert((peer, g), idx);
                            self.standing.remove(&(g, idx), peer);
                        }
                    } else if standing && waiting != Some(idx) {
                        self.standing.insert((g, idx), peer);
                    }
                    if routed {
                        self.route_want(peer, t, g, idx, w.hops, env, catalog);
                    }
                    continue;
                };
                if self.groups.get(&g).and_then(|r| r.state.as_ref()) ==
                    Some(&crate::types::GroupState::Invalid)
                {
                    continue;
                }
                if self.unwanted.contains(&(peer, mid)) && !flagged {
                    continue;
                }
                let count = self.serve_count.entry_or_default((peer, mid));
                *count += 1;
                if *count > self.config.gossip_retransmission {
                    continue;
                }
                match self.slots.get_mut(peer) {
                    Some(slot) if slot.served_now < budget => slot.served_now += 1,
                    _ => continue,
                }
                self.pairs.add_served((peer, g));
                if flagged {
                    // The cap is taken, and the answer passes the write's filter once,
                    // under the chunk's own group and index (`serve_probe`).
                    self.pairs.set_probe_served((peer, g));
                    if let Some(of) = self.resolve_chunk(&g, idx).map(|f| (peer, f.group, f.index))
                    {
                        self.probe_answers.insert(of);
                    }
                }
                if seen_mids.insert_unique(mid) {
                    let _ = answers.push((g, idx));
                }
            }
        }
        answers
    }

    /// Passes a routed sample request this node cannot answer one step on: to
    /// a link that serves the index, or, where none does and steps are left,
    /// to a forwarding link (`protocol-v2.md` §4.5 `route_want`). At the limit
    /// or without a route it says nothing: the sampler's wait moves it on. The
    /// link is the one of the largest keyed hash, as in `announcers`.
    #[allow(clippy::too_many_arguments)]
    fn route_want<E, C>(
        &mut self,
        peer: PeerId,
        t: TypeId,
        group: GroupId,
        index: u32,
        hops: u8,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        // By node: a connection's end does not reset the count.
        let Some(id) = self.slots.get(peer).map(|s| s.node_id) else {
            return;
        };
        let passed = match self.forwarded.get(&id) {
            Some(&n) => n,
            // No room for a count: the limit could not be held.
            None if self.forwarded.is_full() => return,
            None => 0,
        };
        if passed >= catalog.params(t).forward_limit {
            return;
        }
        let now = env.now();
        // Of those that serve the index, else of those that pass it on, the one a
        // hash under the node's secret puts first.
        let key = self.config.order_key;
        let order = |q: &PeerId| fxhash::hash64(&(key, group, index, *q));
        let serves = |q: &PeerId| {
            self.join_recv(*q, t).is_some_and(|j| j.interest != InterestKind::Declared) &&
                self.interest_of_peer(*q, &group, catalog).has(index) &&
                !self.parked(*q, &group, now)
        };
        let others = || self.peers_of(self.links(t)).filter(|&q| q != peer);
        let mut left = 0;
        let mut pick = others().filter(serves).max_by_key(order);
        if pick.is_none() && hops > 1 {
            let passes =
                |q: &PeerId| self.join_recv(*q, t).is_some_and(|j| j.duty == Duty::Forward);
            pick = others().filter(passes).max_by_key(order);
            left = hops - 1;
        }
        let Some(q) = pick else {
            return;
        };
        *self.forwarded.entry_or_default(id) += 1;
        let want = Want { hops: left, ..Want::standing(group, Bitmap::singleton(index)) };
        self.enqueue(q, Queued::from_want(want), false, env);
    }

    /// Serves standing `Want` requests that preceded the arrival of `(group,
    /// index)` (`serve_standing`).
    pub fn serve_standing<E, C>(&mut self, group: GroupId, index: u32, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if !self.standing.contains_key(&(group, index)) {
            return;
        }
        if self.resolve_chunk(&group, index).is_none() {
            self.standing.remove_key(&(group, index));
            return;
        }
        let t = group.type_id;
        let serve_limit = catalog.params(t).serve_limit;
        let now = env.now();

        self.for_each(PeerSet::Standing(group, index), |node, q| {
            let peer_already_has =
                node.pairs.peer_has(&(q, group)).map(|e| e.has(index)).unwrap_or(false);
            let served_so_far = node.pairs.served(&(q, group));
            let over = node
                .slots
                .get(q)
                .is_none_or(|s| s.served_now >= node.config.max_served_per_heartbeat);
            if peer_already_has || served_so_far >= serve_limit || over {
                return;
            }
            if let Some(slot) = node.slots.get_mut(q) {
                slot.served_now += 1;
            }
            node.pairs.add_served((q, group));
            let entry = Queued::Chunk { group, index, solicited: true };
            if !node.enqueue(q, entry, false, env) {
                let single = node.single_chunk(&group);
                node.sends.owe_answer(q, group, index, single);
            }
            node.note_push(q, group, index, now, catalog);
        });
        self.standing.remove_key(&(group, index));
    }

    /// Answers the probes kept for `(group, index)`, now stored, received or
    /// rebuilt, as `on_want` answers a probe, with its one exemption
    /// (`protocol-v2.md` §4.6 `serve_waiting_probe`).
    pub fn serve_waiting_probe<E, C>(
        &mut self,
        group: GroupId,
        index: u32,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if !self.probe_waiting.contains_key(&(group, index)) {
            return;
        }
        let Some(of) = self.resolve_chunk(&group, index).map(|f| (f.group, f.index)) else {
            return;
        };
        let t = group.type_id;
        let serve_limit = catalog.params(t).serve_limit;
        let now = env.now();
        self.for_each(PeerSet::ProbeWaiting(group, index), |node, q| {
            node.probe_waiting_of.remove(&(q, group));
            if node.pairs.probe_served(&(q, group)) || node.pairs.served(&(q, group)) >= serve_limit
            {
                return;
            }
            node.pairs.add_served((q, group));
            node.pairs.set_probe_served((q, group));
            node.probe_answers.insert((q, of.0, of.1));
            let entry = Queued::Chunk { group, index, solicited: true };
            if !node.enqueue(q, entry, false, env) {
                let single = node.single_chunk(&group);
                node.sends.owe_answer(q, group, index, single);
            }
            node.note_push(q, group, index, now, catalog);
        });
        self.probe_waiting.remove_key(&(group, index));
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
        // The same for an ask over the peer's bound or the table's.
        if !self.tried.has_room(ask, peer) {
            self.held_groups.insert(ask.group);
            return false;
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
        if !catalog.authenticable(&ask.group) {
            return;
        }
        let now = env.now();
        let iwant_win = self.config.scaled_iwant_window();
        if let Some(&at) = self.asked_at.get(&ask) {
            if now - at < iwant_win {
                return;
            }
        }
        let cand = |q: PeerId| !self.parked(q, &ask.group, now) && !self.tied_to_root(q, ask);
        if !self.announcers(ask).any(cand) {
            self.last_resort(ask, env, catalog);
            return;
        }
        let Some(pick) = self.pick_announcer(ask, |q| cand(q) && !self.outstanding(q, ask)) else {
            env.schedule_after(iwant_win + self.config.retry_slack, TimerEvent::RetryOffer(ask));
            return;
        };
        if self.may_ask(ask, pick, env) {
            let want = Want::pull_ask(ask);
            self.enqueue(pick, Queued::from_want(want), false, env);
        }
    }

    /// Returns `true` if an ask for `ask` to `peer` is currently promised or
    /// queued (`outstanding(q, a)`).
    pub fn outstanding(&self, peer: PeerId, ask: Ask) -> bool {
        self.promises.contains(ask, peer) || self.sends.ask_waiting(peer, ask)
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
        let Some(slot) = self.slots.get_mut(peer) else {
            return;
        };
        let list = self.offers.entry_or_default(ask);
        if !list.contains(&peer) && list.len() < max_offers && slot.listed_count < max_listed {
            if list.push(peer) {
                slot.listed_count += 1;
            }
        }
    }

    /// Drops `peer`'s offers and queued/promised asks of `(group, index)`
    /// (`drop_offer` in `protocol.md` §6.1).
    pub fn drop_offer(&mut self, group: GroupId, index: u32, peer: PeerId) {
        self.drop_offers(group, &Bitmap::singleton(index), peer);
    }

    /// [`Self::drop_offer`] for every index of `bits`, with one pass over the
    /// peer's queue.
    pub fn drop_offers(&mut self, group: GroupId, bits: &Bitmap, peer: PeerId) {
        if let Some(offered) = self.pairs.offered(&(peer, group)) {
            self.pairs.set_offered((peer, group), offered.and_not(bits));
        }
        for index in bits.iter() {
            let ask = Ask::new(group, index);
            let mut remove_ask = false;
            if let Some(list) = self.offers.get_mut(&ask) {
                if list.remove_item(&peer) {
                    if let Some(slot) = self.slots.get_mut(peer) {
                        slot.listed_count = slot.listed_count.saturating_sub(1);
                    }
                }
                remove_ask = list.is_empty();
            }
            if remove_ask {
                self.offers.remove(&ask);
            }
            self.promises.remove(ask, peer);
        }
        self.sends.cancel_asks(peer, group, bits);
    }

    /// The peers that offered `ask`: its offer list, then every other peer
    /// whose offers of the group name the index (`announcers(a)`). Their order
    /// is [`Self::announcer_rank`].
    pub fn announcers(&self, ask: Ask) -> impl Iterator<Item = PeerId> + '_ {
        let listed = self.offers.get(&ask).map(|list| list.as_slice()).unwrap_or(&[]);
        let others = self.pairs.offering(&ask.group).filter(move |q| {
            !listed.contains(q) &&
                self.pairs.offered(&(*q, ask.group)).is_some_and(|b| b.has(ask.index))
        });
        listed.iter().copied().chain(others)
    }

    /// Where `q` stands among the announcers of `ask`, smaller first: the offer
    /// list in its order, then the others in an order no peer can arrange, by a
    /// hash of the ask and the peer under the node's secret, larger first
    /// (`protocol.md` §6.1).
    fn announcer_rank(&self, ask: Ask, q: PeerId) -> (u64, u64, u64) {
        let listed = self.offers.get(&ask).and_then(|list| list.iter().position(|&p| p == q));
        match listed {
            Some(at) => (0, at as u64, 0),
            None => {
                let key = self.config.order_key;
                (1, !fxhash::hash64(&(key, ask.group, ask.index, q)), !q)
            }
        }
    }

    /// The announcer of `ask` to ask among those `free` takes: one not tried
    /// yet, else the one tried longest ago; of several, the first in the
    /// announcers' order.
    fn pick_announcer(&self, ask: Ask, free: impl Fn(PeerId) -> bool) -> Option<PeerId> {
        let free = || self.announcers(ask).filter(|&q| free(q));
        let untried = free()
            .filter(|&q| !self.tried.contains(ask, q))
            .min_by_key(|&q| self.announcer_rank(ask, q));
        untried.or_else(|| {
            free().min_by(|&a, &b| {
                let ta = self.tried.get(ask, a).unwrap_or(f64::NEG_INFINITY);
                let tb = self.tried.get(ask, b).unwrap_or(f64::NEG_INFINITY);
                ta.partial_cmp(&tb)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| self.announcer_rank(ask, a).cmp(&self.announcer_rank(ask, b)))
            })
        })
    }

    /// Returns all offered and not-yet-held asks of `group` (`protocol.md` §6.1
    /// `ledger(g)`).
    pub fn ledger(&self, group: &GroupId) -> InlineVec<Ask, MAX_BITMAP_BITS> {
        let mut bits = Bitmap::new();
        for q in self.pairs.offering(group) {
            if let Some(b) = self.pairs.offered(&(q, *group)) {
                bits |= b;
            }
        }
        let mine = self.groups.bits(group, GroupBits::Mine).unwrap_or(Bitmap::EMPTY);
        let mut out = InlineVec::new();
        for i in bits.and_not(&mine).iter() {
            let _ = out.push(Ask::new(*group, i));
        }
        out
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
        let untied = |q: &PeerId| !self.tied_to_root(*q, ask);
        if self.last_resort_armed.contains(&k) ||
            self.announcers(ask).filter(untied).any(|q| !self.parked(q, &ask.group, now))
        {
            return;
        }
        let done_len = self.asked_parked.count(&k);
        let all_done =
            self.announcers(ask).filter(untied).all(|q| self.asked_parked.contains(&k, q));
        if all_done {
            return;
        }
        self.last_resort_armed.insert(k);
        let factor = 1u64.checked_shl(done_len as u32).unwrap_or(u64::MAX);
        let t = ask.group.type_id;
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
        // An announcer unparked meanwhile first, else one not asked while parked.
        let untied = |q: PeerId| !self.tied_to_root(q, ask);
        let unparked = |q: PeerId| untied(q) && !self.parked(q, &ask.group, now);
        let unasked = |q: PeerId| untied(q) && !self.asked_parked.contains(&k, q);
        let any_unparked = self.announcers(ask).any(unparked);
        if !any_unparked && !self.announcers(ask).any(unasked) {
            return;
        }
        let cand = |q: PeerId| if any_unparked { unparked(q) } else { unasked(q) };
        let Some(pick) = self.pick_announcer(ask, |q| cand(q) && !self.outstanding(q, ask)) else {
            self.last_resort_armed.insert(k);
            env.schedule_after(iwant_win + self.config.retry_slack, TimerEvent::AskParked(ask));
            return;
        };
        let want = Want::pull_ask(ask);
        if self.may_ask(ask, pick, env) && self.enqueue(pick, Queued::from_want(want), false, env) {
            if self.parked(pick, &ask.group, now) {
                self.asked_parked.insert(k, pick);
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
                if let Some(slot) = self.slots.get_mut(p) {
                    slot.listed_count = slot.listed_count.saturating_sub(1);
                }
            }
        }
        self.asked_at.remove(&ask);
        self.asked_parked.remove_key(&(group, index));
        self.pairs.clear_offered(&group, index);
    }

    /// `group`'s count is known now: the offers, asks, tries and promises of
    /// an index it has not go (`drop_beyond`, `protocol.md` §4.2, §8.2). Every
    /// ask is of an offered index, so the offers name them all. A tie past the
    /// count went at its release, before the group could open.
    pub(crate) fn drop_beyond(&mut self, group: GroupId, n: u32) {
        let mut beyond = Bitmap::new();
        for q in self.pairs.offering(&group) {
            if let Some(bits) = self.pairs.offered(&(q, group)) {
                beyond |= &bits;
            }
        }
        let beyond = beyond.and_not(&Bitmap::all_bits(n));
        if beyond.is_empty() {
            return;
        }
        let mut offering = std::mem::replace(&mut self.peer_scratch, PreallocVec::with_capacity(0));
        offering.clear();
        for q in self.pairs.offering(&group) {
            let _ = offering.push(q);
        }
        for &q in offering.iter() {
            self.drop_offers(group, &beyond, q);
        }
        self.peer_scratch = offering;
        for i in beyond.iter() {
            self.close_promises(group, i, None);
        }
    }

    pub(crate) fn close_promises_of_group(&mut self, group: &GroupId) {
        self.promises.retain(|a, _, _| &a.group != group);
    }
}
