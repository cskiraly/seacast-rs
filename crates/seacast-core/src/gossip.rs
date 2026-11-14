use crate::{
    bitmap::{Bitmap, MAX_CHUNKS},
    collections::{InlineVec, MAX_INLINE_PEERS, PreallocMap},
    node::SeacastNode,
    traits::{ChunkBuffer, DeferredStore, ObjectCatalog, RngSource, RuntimeEnv, TimerEvent},
    types::{AnnounceWidth, Ask, GroupId, PeerId, Timestamp},
};

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Runs heartbeat maintenance (`protocol-v2.md` §4.8 `on_heartbeat`,
    /// `protocol.md` §6.4) with zero heap allocation.
    pub fn on_heartbeat<E, C, R, D>(
        &mut self,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
        deferred_store: &mut D,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
        D: DeferredStore<B>,
    {
        self.ihave_rpcs.clear();
        self.ihave_asked.clear();
        self.served_now.clear();
        // Every ask held back is retried, a batch at a time. A retry that is held back
        // again waits for the next heartbeat: at most as many are taken as were
        // waiting.
        let mut waiting = self.held_back.len();
        while waiting > 0 {
            let mut batch: InlineVec<Ask, MAX_CHUNKS> = InlineVec::new();
            for (_, &a) in self.held_back.iter().take(waiting.min(MAX_CHUNKS)) {
                let _ = batch.push(a);
            }
            waiting -= batch.len();
            for a in &batch {
                self.held_back.remove(&(a.group, a.index));
            }
            for a in batch {
                self.retry_offer(a, env, catalog);
            }
        }

        // Offers taken in over the limits: what they name is asked for now, a group at
        // a time. A group held again by a retry waits for the next heartbeat.
        for _ in 0..self.held_groups.len() {
            let next = self.held_groups.iter().next().copied();
            let Some(g) = next else { break };
            self.held_groups.remove(&g);
            for a in self.ledger(&g) {
                self.retry_offer(a, env, catalog);
            }
        }

        let now = env.now();
        self.expire_groups(env, deferred_store);
        self.expire_heartbeat_ttls(now, env);
        let group_bits = self.gossip_history.gossip_group_bits();
        self.gossip_history.shift();

        for t in catalog.joined_types() {
            self.maintain_relations(t, env, catalog);
        }

        if group_bits.is_empty() {
            return;
        }

        let mut eligible: InlineVec<PeerId, MAX_INLINE_PEERS> = InlineVec::new();
        // Peers that joined some object type on their link and hold no relation with
        // this node.
        for &q in self.peers.iter() {
            let joined = self.join_recv.keys().any(|&(p, _)| p == q);
            if joined && !self.is_related(q) {
                let _ = eligible.push(q);
            }
        }
        let factor_n = ((self.config.gossip_factor * (eligible.len() as f64)).floor()) as usize;
        let n = eligible.len().min(self.config.d_lazy.max(factor_n));
        let sampled: InlineVec<PeerId, MAX_INLINE_PEERS> =
            rng.sample_without_replacement(&eligible, n);

        for q in sampled {
            if self.config.paced_gossip {
                let was_empty = self.pace_queue.is_empty();
                let _ = self.pace_queue.push_back((q, group_bits, now));
                if was_empty && !self.pace_timer_active {
                    self.pace_timer_active = true;
                    env.schedule_after(self.config.heartbeat / 16.0, TimerEvent::PaceTick);
                }
            } else {
                self.send_gossip(q, &group_bits, env, catalog);
            }
        }
    }

    /// Sends one peer's paced gossip per tick (`protocol.md` §6.4
    /// `on_pace_tick`).
    pub fn on_pace_tick<E, C>(&mut self, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        self.pace_timer_active = false;
        let now = env.now();
        while let Some((q, group_bits, at)) = self.pace_queue.pop_front() {
            if now - at >= self.config.heartbeat || !self.peers.contains(&q) {
                continue;
            }
            self.send_gossip(q, &group_bits, env, catalog);
            break;
        }
        if !self.pace_queue.is_empty() && !self.pace_timer_active {
            self.pace_timer_active = true;
            env.schedule_after(self.config.heartbeat / 16.0, TimerEvent::PaceTick);
        }
    }

    /// Announces gossip bitmaps to `peer` for `SAMPLE` object types
    /// (`send_gossip(q, ids)`).
    pub fn send_gossip<E, C>(
        &mut self,
        peer: PeerId,
        group_bits: &[(GroupId, Bitmap)],
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        for (g, bits) in group_bits {
            if self.expired(g) {
                continue;
            }
            let t = self
                .groups
                .get(g)
                .and_then(|r| r.t_of.as_ref())
                .copied()
                .unwrap_or_else(|| catalog.type_of_group(g));
            if catalog.params(t).announce_extra == AnnounceWidth::Sample {
                self.announce(peer, *g, *bits, env, catalog);
            }
        }
    }

    pub(crate) fn expire_heartbeat_ttls<E>(&mut self, now: Timestamp, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        // Expire HAVE_TTL (counted in heartbeats); what was sent to the peer goes with
        // its claims, and the peer leaves the holders of what it claimed.
        let holders = &mut self.holders;
        self.pairs.heartbeat(now, |peer, group, bits| {
            for i in bits.iter() {
                if let Some(set) = holders.get_mut(&(group, i)) {
                    set.remove_item(&peer);
                    if set.is_empty() {
                        holders.remove(&(group, i));
                    }
                }
            }
        });

        // Groups a peer named and has not named since.
        let named_count = &mut self.named_count;
        self.named.retain(|(peer, _), left| {
            if *left > 1 {
                *left -= 1;
                return true;
            }
            if let Some(count) = named_count.get_mut(peer) {
                *count = count.saturating_sub(1);
            }
            false
        });

        // `tried`, and `asked_parked` with it, live as long as an offer does; an ask's
        // time, its window; a park, `PARK_TTL` (`protocol.md` §8.1).
        let cutoff = now - self.config.offer_ttl;
        let asked_parked = &mut self.asked_parked;
        self.tried.retain(|ask, peer, at| {
            if at >= cutoff {
                return true;
            }
            if let Some(set) = asked_parked.get_mut(&(ask.group, ask.index)) {
                set.remove_item(&peer);
            }
            false
        });
        prune_empty(&mut self.asked_parked);
        let window = self.config.scaled_iwant_window();
        self.asked_at.retain(|_, &mut at| now - at < window);

        // Expire OFFER_TTL (30s after announcer's last offer of the group,
        // `protocol.md` §8.1)
        while let Some((p, g)) = self.pairs.expired_offer(cutoff) {
            let bits = self.pairs.take_offered(&(p, g)).unwrap_or(Bitmap::EMPTY);
            self.drop_offers(g, &bits, p, env);
        }
    }
}

/// Drops the keys whose list has emptied.
fn prune_empty<K: Eq + std::hash::Hash, T: Copy, const CAP: usize>(
    map: &mut PreallocMap<K, InlineVec<T, CAP>>,
) {
    map.retain(|_, list| !list.is_empty());
}
