use crate::{
    bitmap::Bitmap,
    collections::{InlineVec, MAX_ENTRY_CONTROL, MAX_INLINE_PEERS},
    message::{Graft, Join, Prune, Queued},
    node::SeacastNode,
    traits::{ChunkBuffer, ObjectCatalog, RuntimeEnv},
    types::{
        Colour, Direction, Duty, FamilyId, GroupId, GroupState, InterestKind, PeerId, TypeId,
        UplinkClass,
    },
};

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Handles a `Join` from `peer` (`protocol-v2.md` §4.1 `on_join`).
    pub fn on_join<E, C>(&mut self, peer: PeerId, join: Join, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let t = join.object_type;
        // The type id is the peer's: nothing is asked of the catalog, or kept, for a
        // type this node does not run.
        if !catalog.joined_types().contains(&t) || join.colours != catalog.params(t).m {
            return;
        }
        self.join_recv.insert((peer, t), join);
        if !self.join_sent.contains_key(&(peer, t)) {
            let our = catalog.our_join(t);
            // Recorded only once queued: refused by a full queue, it is sent with the
            // peer's next.
            if self.enqueue(peer, Queued::from_join(our), true, env) {
                self.join_sent.insert((peer, t), our);
            }
        }
    }

    /// Computes what `peer` is to receive of `group`, as far as we know
    /// (`interest_of_peer(p, g)`).
    pub fn interest_of_peer<C>(&self, peer: PeerId, group: &GroupId, catalog: &C) -> Bitmap
    where
        C: ObjectCatalog<B>,
    {
        let t = self.type_of(group, catalog);
        let Some(j) = self.join_recv.get(&(peer, t)) else {
            return Bitmap::EMPTY;
        };
        match j.interest {
            InterestKind::All => Bitmap::EVERY_INDEX,
            InterestKind::Derived => catalog.derived_interest(
                t,
                group,
                self.groups.get(group).and_then(|r| r.hdr.as_ref()),
                peer,
                &catalog.node_id(peer),
                j,
            ),
            InterestKind::Declared => self.pairs.want_p(&(peer, *group)).unwrap_or(Bitmap::EMPTY),
        }
    }

    /// Computes indices of `group` that `peer` still wants from us
    /// (`wants_from_me(p, g)`).
    pub fn wants_from_me<C>(&self, peer: PeerId, group: &GroupId, catalog: &C) -> Bitmap
    where
        C: ObjectCatalog<B>,
    {
        let pushed_bits = &self.pairs.pushed_bits(&(peer, *group));
        if let Some(e) = self.pairs.peer_has(&(peer, *group)) {
            if e.complete {
                return Bitmap::EMPTY;
            }
            let interest = self.interest_of_peer(peer, group, catalog);
            interest.and_not(&e.bits).and_not(pushed_bits)
        } else {
            let interest = self.interest_of_peer(peer, group, catalog);
            interest.and_not(pushed_bits)
        }
    }

    /// Maintains push/in relations for object type `t` at the heartbeat
    /// (`maintain_relations(T)`).
    pub fn maintain_relations<E, C>(&mut self, t: TypeId, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        // A node without duty for the type holds no relations (`protocol-v2.md` §1.2).
        if catalog.our_join(t).duty != Duty::Forward {
            return;
        }
        let prm = catalog.params(t);
        let m = prm.m;
        let f_lo = prm.f_lo;
        let f_hi = prm.f_hi;
        let d_out_fast = prm.d_out_fast;
        let d_out = prm.d_out;

        for fam in catalog.families_with_duty(t) {
            for c in 0..m {
                let ins = self.in_pushers(t, fam, c);
                if ins.len() < f_lo {
                    let cands = self.relation_candidates(t, fam, c, true);
                    for &q in cands.iter().take(f_lo - ins.len()) {
                        let gr = Graft {
                            object_type: t,
                            family: fam,
                            colour: c,
                            direction: Direction::In,
                        };
                        self.enqueue(q, Queued::from_graft(gr), false, env);
                    }
                }
                if ins.len() > f_hi {
                    for &q in &ins[f_hi..] {
                        let pr = Prune {
                            object_type: t,
                            family: fam,
                            colour: c,
                            direction: Direction::In,
                        };
                        self.enqueue(q, Queued::from_prune(pr), false, env);
                        if self.push_in.remove(&(q, t, fam, c)) {
                            self.uncount_relation(q, t, false);
                        }
                    }
                }
                let outs = self.out_pushees(t, fam, c);
                let target = if self.config.uplink_class() == UplinkClass::Fast {
                    d_out_fast
                } else {
                    d_out
                };
                if outs.len() < target {
                    let cands = self.relation_candidates(t, fam, c, false);
                    for &q in cands.iter().take(target - outs.len()) {
                        let gr = Graft {
                            object_type: t,
                            family: fam,
                            colour: c,
                            direction: Direction::Out,
                        };
                        self.enqueue(q, Queued::from_graft(gr), false, env);
                    }
                }
            }
        }
    }

    /// Handles an incoming `Graft` (`protocol-v2.md` §4.1 `on_graft` +
    /// `protocol.md` §5.4 `on_mesh_join`).
    pub fn on_graft<E, C>(
        &mut self,
        peer: PeerId,
        gr: Graft,
        env: &mut E,
        catalog: &C,
    ) -> InlineVec<Prune, MAX_ENTRY_CONTROL>
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let t = gr.object_type;
        let mut back = InlineVec::new();
        if !self.is_linked(peer, t) {
            return back;
        }
        let prm = catalog.params(t);
        let fam = gr.family;
        let c = gr.colour;
        // No such colour: not a relation of this type.
        if c >= prm.m {
            return back;
        }
        // Families x colours one link may carry, per direction (`protocol-v2.md` §6.3,
        // X6).
        let limit = self.config.max_relations_per_link;
        let (pushers, pushees) = self.relation_count.get(&(peer, t)).copied().unwrap_or((0, 0));

        if gr.direction.includes_out() {
            let room = self.push_in.contains(&(peer, t, fam, c)) || pushers < limit;
            if room && self.in_pushers(t, fam, c).len() < prm.f_hi && catalog.wants_family(t, fam) {
                if self.push_in.insert((peer, t, fam, c)) {
                    self.relation_count.entry_or_default((peer, t)).0 += 1;
                }
            } else {
                let _ = back.push(Prune {
                    object_type: t,
                    family: fam,
                    colour: c,
                    direction: Direction::Out,
                });
            }
        }

        if gr.direction.includes_in() {
            let our_duty = self
                .join_sent
                .get(&(peer, t))
                .map(|j| j.duty)
                .unwrap_or_else(|| catalog.our_join(t).duty);
            let room = self.push_out.contains(&(peer, t, fam, c)) || pushees < limit;
            let has_duty =
                our_duty == Duty::Forward && catalog.families_with_duty(t).contains(&fam);
            if room && has_duty && self.out_pushees(t, fam, c).len() < prm.d_out_max {
                if self.push_out.insert((peer, t, fam, c)) {
                    self.relation_count.entry_or_default((peer, t)).1 += 1;
                    self.on_relation_join(peer, t, fam, c, env, catalog);
                }
            } else {
                let _ = back.push(Prune {
                    object_type: t,
                    family: fam,
                    colour: c,
                    direction: Direction::In,
                });
            }
        }
        back
    }

    /// Handles an incoming `Prune` (`protocol-v2.md` §4.1 `on_prune`).
    pub fn on_prune(&mut self, peer: PeerId, pr: Prune) {
        let t = pr.object_type;
        if pr.direction.includes_out() {
            if self.push_in.remove(&(peer, t, pr.family, pr.colour)) {
                self.uncount_relation(peer, t, false);
            }
        }
        if pr.direction.includes_in() {
            if self.push_out.remove(&(peer, t, pr.family, pr.colour)) {
                self.uncount_relation(peer, t, true);
            }
        }
    }

    /// Announces stored chunks when a peer joins our out-relation
    /// (`protocol.md` §5.4 `on_mesh_join`).
    pub fn on_relation_join<E, C>(
        &mut self,
        peer: PeerId,
        t: TypeId,
        fam: FamilyId,
        colour: Colour,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        // Every open group, in the order of their ids.
        let mut groups: InlineVec<GroupId, 512> = InlineVec::new();
        for (g, rec) in self.groups.iter() {
            if rec.t_of.is_some() {
                let _ = groups.push(*g);
            }
        }
        groups.as_mut_slice().sort_unstable();
        let m = catalog.params(t).m.max(1) as u32;
        for g in groups {
            if self.expired(&g) ||
                self.groups.get(&g).and_then(|r| r.state.as_ref()) == Some(&GroupState::Invalid)
            {
                continue;
            }
            let tg = self.type_of(&g, catalog);
            if tg != t || catalog.family(tg, &g) != fam {
                continue;
            }
            let mut bits = Bitmap::new();
            for idx in self
                .groups
                .get(&g)
                .and_then(|r| r.mine.as_ref())
                .unwrap_or(Bitmap::empty_ref())
                .iter()
            {
                if (idx % m) as u16 == colour && self.chunks.contains_key(&(g, idx)) {
                    bits.set(idx);
                }
            }
            if !bits.is_empty() {
                self.announce(peer, g, bits, env, catalog);
            }
        }
    }

    /// Proposes the least-used colour for `(t, fam)` (`propose_colour(T,
    /// fam)`).
    pub fn propose_colour<C>(&self, t: TypeId, fam: FamilyId, catalog: &C) -> Colour
    where
        C: ObjectCatalog<B>,
    {
        let m = catalog.params(t).m.max(1);
        (0..m).min_by_key(|&c| self.in_pushers(t, fam, c).len()).unwrap_or(0)
    }

    /// Returns all peers that have completed a bidirectional `Join` for `t`
    /// (`links(T)`).
    pub fn links(&self, t: TypeId) -> InlineVec<PeerId, MAX_INLINE_PEERS> {
        let mut out = InlineVec::new();
        for &p in self.peers.iter() {
            if self.is_linked(p, t) {
                let _ = out.push(p);
            }
        }
        out
    }

    #[inline]
    pub fn is_linked(&self, peer: PeerId, t: TypeId) -> bool {
        self.join_recv.contains_key(&(peer, t)) && self.join_sent.contains_key(&(peer, t))
    }

    /// Returns peers in `push_in[*][t][fam]` holding `colour` (`in_pushers(T,
    /// fam, c)`).
    pub fn in_pushers(
        &self,
        t: TypeId,
        fam: FamilyId,
        colour: Colour,
    ) -> InlineVec<PeerId, MAX_INLINE_PEERS> {
        let mut out = InlineVec::new();
        for &q in self.peers.iter() {
            if self.push_in.contains(&(q, t, fam, colour)) {
                let _ = out.push(q);
            }
        }
        out
    }

    /// Returns peers in `push_out[*][t][fam]` holding `colour` (`out_pushees(T,
    /// fam, c)`).
    pub fn out_pushees(
        &self,
        t: TypeId,
        fam: FamilyId,
        colour: Colour,
    ) -> InlineVec<PeerId, MAX_INLINE_PEERS> {
        let mut out = InlineVec::new();
        for &q in self.peers.iter() {
            if self.push_out.contains(&(q, t, fam, colour)) {
                let _ = out.push(q);
            }
        }
        out
    }

    pub(crate) fn relation_candidates(
        &self,
        t: TypeId,
        fam: FamilyId,
        colour: Colour,
        inbound: bool,
    ) -> InlineVec<PeerId, MAX_INLINE_PEERS> {
        let mut out = InlineVec::new();
        for q in self.links(t) {
            let peer_duty = self.join_recv.get(&(q, t)).map(|j| j.duty).unwrap_or(Duty::None);
            if peer_duty != Duty::Forward {
                continue;
            }
            let already_in = if inbound {
                self.push_in.contains(&(q, t, fam, colour))
            } else {
                self.push_out.contains(&(q, t, fam, colour))
            };
            if !already_in {
                let _ = out.push(q);
            }
        }
        out
    }

    pub(crate) fn is_related(&self, peer: PeerId) -> bool {
        self.push_out.iter().any(|&(q, _, _, _)| q == peer) ||
            self.push_in.iter().any(|&(q, _, _, _)| q == peer)
    }

    #[inline]
    pub(crate) fn has_push_in_any_colour(&self, peer: PeerId, t: TypeId, fam: FamilyId) -> bool {
        self.push_in.iter().any(|&(q, pt, pf, _)| q == peer && pt == t && pf == fam)
    }

    #[inline]
    pub(crate) fn has_push_out_any_colour(&self, peer: PeerId, t: TypeId, fam: FamilyId) -> bool {
        self.push_out.iter().any(|&(q, pt, pf, _)| q == peer && pt == t && pf == fam)
    }
}
