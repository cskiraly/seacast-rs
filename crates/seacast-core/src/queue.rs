//! The send path: a bounded two-lane queue a peer and the node-wide byte
//! window (`protocol-v2.md` §4.11, §4.12; `protocol.md` §7). The node owns it
//! (`SeacastNode::sends`); each peer's writer calls
//! [`SeacastNode::next_to_send`].

use crate::{
    bitmap::Bitmap,
    collections::{InlineVec, MAX_ENTRY_CONTROL, PeerSlab, PreallocDeque, PreallocMap},
    message::{Control, Have, QueueEntry, Queued},
    node::SeacastNode,
    state::{DispatchOutcome, PeerQueue},
    traits::{ChunkBuffer, ObjectCatalog, RuntimeEnv, TimerEvent},
    types::{Ask, GroupId, NodeConfig, PeerId},
};

#[derive(Debug, Clone)]
pub struct SendQueues {
    config: NodeConfig,
    /// A queue a connection, indexed by `PeerId`.
    pub queue: PeerSlab<PeerQueue>,
    /// Bytes of chunks written and not yet acknowledged or timed out.
    pub in_flight: usize,
    waiters: PreallocDeque<PeerId>,
    pub sent: PreallocMap<(PeerId, GroupId, u32), (u64, usize)>,
}

impl SendQueues {
    /// Preallocates a queue for each of `config`'s peers.
    pub fn new(config: NodeConfig) -> Self {
        let cap = config.capacities;
        Self {
            queue: PeerSlab::with_capacity(cap.max_peers, || {
                PeerQueue::with_capacity(cap.max_queue_entries_per_peer, cap.max_groups)
            }),
            in_flight: 0,
            waiters: PreallocDeque::with_capacity(cap.max_peers),
            sent: PreallocMap::with_capacity(cap.max_peers * 64),
            config,
        }
    }

    /// Opens `peer`'s queue.
    pub fn connect(&mut self, peer: PeerId) {
        self.queue.open(peer);
    }

    /// Closes `peer`'s queue and frees what was in flight to it.
    pub fn disconnect<B: ChunkBuffer, E: RuntimeEnv<B>>(&mut self, peer: PeerId, env: &mut E) {
        if let Some(q) = self.queue.close(peer) {
            q.clear();
        }
        self.leave_line(peer, env);
        let mut freed = 0;
        self.sent.retain(|key, &mut (_, bytes)| {
            if key.0 == peer {
                freed += bytes;
            }
            key.0 != peer
        });
        if freed > 0 {
            self.free_room(freed, env);
        }
    }

    /// Enqueues an entry into `peer`'s bounded two-lane queue and wakes
    /// `peer`'s writer (`enqueue`).
    pub fn send<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        entry: Queued,
        urgent: bool,
        env: &mut E,
    ) -> bool {
        // Nothing is queued to a peer that is gone, which a timer armed before it left
        // may name.
        let Some(q) = self.queue.get_mut(peer) else {
            return false;
        };
        if !q.has_room() {
            return false;
        }
        if urgent {
            let _ = q.urgent.push_back(entry);
        } else {
            let _ = q.normal.push(entry);
        }
        env.wake_writer(peer);
        true
    }

    /// Queues a JOIN, GRAFT or PRUNE, or owes it: one a full queue refuses, and
    /// every later one, waits in order (`protocol-v2.md` §4.1 `send_relation`).
    /// With no room left to owe, the newest is dropped.
    pub fn send_relation<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        message: Control,
        env: &mut E,
    ) {
        let urgent = matches!(message, Control::Join(_));
        let waiting = self.queue.get(peer).is_some_and(|q| !q.owed_relations.is_empty());
        if waiting || !self.send(peer, Queued::Control(message), urgent, env) {
            if let Some(q) = self.queue.get_mut(peer) {
                let _ = q.owed_relations.push_back(message);
            }
            env.wake_writer(peer);
        }
    }

    /// What is owed of the relation's messages, queued in order while there is
    /// room: the writer's first step (`queue_owed_relations`).
    fn queue_owed_relations<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        env: &mut E,
    ) {
        while self.has_queue_room(peer) {
            let Some(message) = self.queue.get_mut(peer).and_then(|q| q.owed_relations.pop_front())
            else {
                return;
            };
            let urgent = matches!(message, Control::Join(_));
            self.send(peer, Queued::Control(message), urgent, env);
        }
    }

    /// Marks `bits` of `group` as owed to `peer` for the next write (`owe(p, g,
    /// bits)`).
    pub fn owe<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        bits: Bitmap,
        env: &mut E,
    ) {
        if let Some(q) = self.queue.get_mut(peer) {
            *q.owed.entry_or_default(group) |= bits;
        }
        env.wake_writer(peer);
    }

    /// Records an answer a full queue refused, to be queued again as the queue
    /// empties.
    pub fn owe_answer(&mut self, peer: PeerId, group: GroupId, index: u32) {
        if let Some(q) = self.queue.get_mut(peer) {
            q.owed_answers.entry_or_default(group).set(index);
        }
    }

    /// Merges a holding of `h.group` into an existing urgent holding still
    /// waiting in `peer`'s queue (`protocol-v2.md` §4.2 `merge_waiting`).
    pub fn merge_waiting(&mut self, peer: PeerId, h: &Have) -> bool {
        let Some(q) = self.queue.get_mut(peer) else {
            return false;
        };
        for idx in 0..q.urgent.len() {
            if let Some(Queued::Control(Control::Have(existing))) = q.urgent.get_mut(idx) {
                if !existing.offer && existing.group == h.group {
                    existing.bits |= &h.bits;
                    existing.claim_all = h.claim_all;
                    existing.complete = h.complete;
                    return true;
                }
            }
        }
        false
    }

    /// Whether an ask for `ask` waits in `peer`'s queue.
    pub fn ask_waiting(&self, peer: PeerId, ask: Ask) -> bool {
        let Some(q) = self.queue.get(peer) else {
            return false;
        };
        q.normal.iter().any(|item| {
            matches!(item, Queued::Control(Control::Want(w)) if w.group == ask.group && w.bits.has(ask.index))
        })
    }

    /// Takes `bits` of `group` out of the asks waiting in `peer`'s queue; a
    /// standing request is not one.
    pub fn cancel_asks(&mut self, peer: PeerId, group: GroupId, bits: &Bitmap) {
        if let Some(q) = self.queue.get_mut(peer) {
            q.normal.retain_mut(|item| match item {
                Queued::Control(Control::Want(w)) if w.group == group && w.track_promise => {
                    w.bits = w.bits.and_not(bits);
                    !w.bits.is_empty()
                }
                _ => true,
            });
        }
    }

    /// Drops the chunks, offers and asks of `group` that wait, and what is owed
    /// of it.
    pub fn cancel_group(&mut self, group: &GroupId) {
        for q in self.queue.iter_mut() {
            q.normal.retain(|item| match item {
                Queued::Chunk { group: of, .. } => of != group,
                Queued::Control(Control::Have(h)) => !h.offer || &h.group != group,
                Queued::Control(Control::Want(w)) => &w.group != group,
                Queued::Control(_) => true,
            });
            q.owed.remove(group);
            q.owed_answers.remove(group);
        }
    }

    /// Attempts to acquire `need` bytes in the node-wide congestion window for
    /// `peer`'s writer (`protocol-v2.md` §4.11 `acquire_room(p, need)`).
    pub fn acquire_room<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        need: usize,
        env: &mut E,
    ) -> bool {
        let w_bytes = self.config.window_bytes();
        let fits = self.in_flight.saturating_add(need) <= w_bytes || self.in_flight == 0;
        if fits && (self.waiters.is_empty() || self.waiters.front() == Some(&peer)) {
            if !self.waiters.is_empty() {
                self.waiters.pop_front();
            }
            self.in_flight = self.in_flight.saturating_add(need);
            if let Some(&next_peer) = self.waiters.front() {
                if self.in_flight < w_bytes {
                    env.wake_writer(next_peer);
                }
            }
            return true;
        }
        if !self.waiters.contains(&peer) {
            let _ = self.waiters.push_back(peer);
        }
        false
    }

    /// Removes `peer` from the congestion window waiter line (`leave_line(p)`).
    pub fn leave_line<B: ChunkBuffer, E: RuntimeEnv<B>>(&mut self, peer: PeerId, env: &mut E) {
        if let Some(pos) = self.waiters.position(|&q| q == peer) {
            self.waiters.remove(pos);
            let w_bytes = self.config.window_bytes();
            if let Some(&next_peer) = self.waiters.front() {
                if self.in_flight < w_bytes {
                    env.wake_writer(next_peer);
                }
            }
        }
    }

    /// Associates `need` window bytes with an in-flight chunk
    /// (`track_in_flight(p, f, need)`).
    pub fn track_in_flight<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        index: u32,
        need: usize,
        env: &mut E,
    ) {
        let key = (peer, group, index);
        // Tracked already, or not trackable, so nothing would free these bytes later:
        // they leave the window now.
        if self.sent.contains_key(&key) || self.sent.is_full() {
            self.free_room(need, env);
            return;
        }
        let now_bits = env.now().to_bits();
        self.sent.insert(key, (now_bits, need));
        env.schedule_after(self.config.window_timeout, TimerEvent::WindowTimeout {
            peer,
            group,
            index,
            at_bits: now_bits,
        });
    }

    /// Frees in-flight window bytes when `peer` reports holding `(group,
    /// index)` (`window_release`).
    pub fn window_release<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        index: u32,
        env: &mut E,
    ) {
        if let Some((_, need)) = self.sent.remove(&(peer, group, index)) {
            self.free_room(need, env);
        }
    }

    /// Frees in-flight window bytes on `WINDOW_TIMEOUT` (`window_timeout`).
    pub fn window_timeout<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        key: (PeerId, GroupId, u32),
        at_bits: u64,
        env: &mut E,
    ) {
        if let Some(&(sent_at, need)) = self.sent.get(&key) {
            if sent_at == at_bits {
                self.sent.remove(&key);
                self.free_room(need, env);
            }
        }
    }

    /// Returns `need` bytes to the congestion window and wakes the first
    /// waiting writer (`free_room`).
    pub fn free_room<B: ChunkBuffer, E: RuntimeEnv<B>>(&mut self, need: usize, env: &mut E) {
        self.in_flight = self.in_flight.saturating_sub(need);
        if let Some(&first) = self.waiters.front() {
            env.wake_writer(first);
        }
    }

    pub fn has_owed_offers(&self, peer: PeerId) -> bool {
        self.queue.get(peer).is_some_and(|q| q.owed.iter().any(|(_, b)| !b.is_empty()))
    }

    fn has_owed_answers(&self, peer: PeerId) -> bool {
        self.queue.get(peer).is_some_and(|q| !q.owed_answers.is_empty())
    }

    fn has_queue_room(&self, peer: PeerId) -> bool {
        self.queue.get(peer).map(|q| q.has_room()).unwrap_or(true)
    }
}

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Selects and filters the next queue entry to write to `peer`
    /// (`protocol-v2.md` §4.11 `next_to_send`).
    pub fn next_to_send<E, C>(
        &mut self,
        peer: PeerId,
        env: &mut E,
        catalog: &C,
    ) -> DispatchOutcome<B>
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        loop {
            self.sends.queue_owed_relations(peer, env);
            if self.sends.has_owed_answers(peer) && self.sends.has_queue_room(peer) {
                if let Some((group, index)) = self.pop_owed_answer(peer) {
                    let entry = Queued::Chunk { group, index, solicited: true };
                    self.sends.send(peer, entry, false, env);
                }
            }
            if let Some(urgent_entry) = self.take_head(peer, true) {
                if let Some(out) = self.with_owed(peer, urgent_entry, catalog) {
                    return DispatchOutcome::Send(out);
                }
                continue;
            }
            let normal_empty =
                self.sends.queue.get(peer).map(|q| q.normal.is_empty()).unwrap_or(true);
            if normal_empty {
                if self.sends.has_owed_offers(peer) {
                    if let Some(out) = self.with_owed(peer, QueueEntry::empty(), catalog) {
                        return DispatchOutcome::Send(out);
                    }
                }
                self.sends.leave_line(peer, env);
                return DispatchOutcome::Empty;
            }

            let k = self.choose_normal_index(peer);
            let item = self.sends.queue.get(peer).and_then(|q| q.normal.get(k)).copied();
            let (entry, need) = match item {
                Some(Queued::Chunk { group, index, solicited }) => {
                    // Gone since it was queued (its group dropped or expired): nothing to send.
                    let Some(chunk) = self.resolve_chunk(&group, index) else {
                        self.sends.queue.get_mut(peer).expect("queue exists").normal.remove(k);
                        continue;
                    };
                    let need = catalog.wire_size(&chunk);
                    if need > 0 && !self.sends.acquire_room(peer, need, env) {
                        return DispatchOutcome::Wait;
                    }
                    self.sends.queue.get_mut(peer).expect("queue exists").normal.remove(k);
                    (QueueEntry::from_chunk(chunk, solicited), need)
                }
                // `choose` names a control item only at the head.
                _ => match self.take_head(peer, false) {
                    Some(entry) => (entry, 0),
                    None => continue,
                },
            };
            let out = self.filter_entry(peer, entry, env, catalog);
            let has_chunk = out.as_ref().and_then(|e| e.chunk.as_ref()).is_some();
            if need > 0 && !has_chunk {
                self.sends.free_room(need, env);
            }
            if let Some(out_entry) = out {
                if let Some(ref ch) = out_entry.chunk {
                    self.sends.track_in_flight(peer, ch.group, ch.index, need, env);
                }
                if let Some(final_entry) = self.with_owed(peer, out_entry, catalog) {
                    return DispatchOutcome::Send(final_entry);
                }
            }
        }
    }

    /// Chooses the index in `queue[peer].normal` to pop next (`protocol-v2.md`
    /// §4.12 `choose(q)`) with zero heap allocation.
    pub fn choose_normal_index(&self, peer: PeerId) -> usize {
        let Some(q) = self.sends.queue.get(peer) else {
            return 0;
        };
        if q.normal.is_empty() || !q.normal[0].is_chunk() {
            return 0;
        }
        if let Some(best_own) = self.pick_rarest_matching(q, |e| self.own_chunk(e)) {
            return best_own;
        }
        if self.config.answers_first {
            if let Some(best_asked) =
                self.pick_rarest_matching(q, |e| matches!(e, Queued::Chunk { solicited: true, .. }))
            {
                return best_asked;
            }
        }
        if self.config.rarest_enabled { self.rarest(q) } else { 0 }
    }

    /// Picks the rarest entry satisfying `pred` without heap allocation
    /// (`protocol-v2.md` §4.12 `pick(q, ks)`).
    fn pick_rarest_matching<F>(&self, q: &PeerQueue, mut pred: F) -> Option<usize>
    where
        F: FnMut(&Queued) -> bool,
    {
        let mut best_k: Option<usize> = None;
        let mut best_h = usize::MAX;
        for (k, entry) in q.normal.iter().enumerate() {
            if !pred(entry) {
                continue;
            }
            if !self.config.rarest_enabled {
                return Some(k);
            }
            let &Queued::Chunk { group, index, .. } = entry else {
                continue;
            };
            let h = self.holder_count(&group, index);
            if best_k.is_none() || h < best_h {
                best_h = h;
                best_k = Some(k);
            }
        }
        best_k
    }

    /// Picks the rarest chunk ahead of the first control-only entry
    /// (`protocol.md` §7.2 `rarest(q)` `[c9]`).
    pub fn rarest(&self, q: &PeerQueue) -> usize {
        let mut best_h = usize::MAX;
        let mut best_i = 0;
        for (i, entry) in q.normal.iter().enumerate() {
            let &Queued::Chunk { group, index, .. } = entry else {
                break;
            };
            let h = self.holder_count(&group, index);
            if h < best_h {
                best_h = h;
                best_i = i;
            }
        }
        best_i
    }

    /// Attaches owed offers for `peer` to `entry` (`protocol.md` §7.2
    /// `with_owed`).
    pub fn with_owed<C: ObjectCatalog<B>>(
        &mut self,
        peer: PeerId,
        mut entry: QueueEntry<B>,
        catalog: &C,
    ) -> Option<QueueEntry<B>> {
        // Only as many groups as the entry has room for leave `owed`: the rest stay
        // owed, and the writer, which runs until the queue and `owed` are both
        // empty, takes them next.
        let room = MAX_ENTRY_CONTROL - entry.haves.len();
        let mut owed_groups: InlineVec<(GroupId, Bitmap), MAX_ENTRY_CONTROL> = InlineVec::new();
        if let Some(q) = self.sends.queue.get_mut(peer) {
            while owed_groups.len() < room {
                // The lowest group id first: the order does not depend on the table's.
                let Some(g) = q.owed.keys().copied().min() else {
                    break;
                };
                let bits = q.owed.remove(&g).unwrap_or(Bitmap::EMPTY);
                let _ = owed_groups.push((g, bits));
            }
        }
        if owed_groups.is_empty() {
            return if entry.is_empty() { None } else { Some(entry) };
        }
        for (g, bits) in owed_groups {
            let pushed_bits = &self.pairs.pushed_bits(&(peer, g));
            let peer_has_bits = &self.pairs.has_bits(&(peer, g));
            let mut b = bits.and_not(pushed_bits).and_not(peer_has_bits);
            if let Some(ref ch) = entry.chunk {
                if ch.group == g {
                    b.clear(ch.index);
                }
            }
            if !b.is_empty() {
                entry.add_offer(Have::offer(self.type_of(&g, catalog), g, b));
            }
        }
        if entry.is_empty() { None } else { Some(entry) }
    }

    /// The entry for the head of a lane of `peer`'s queue, taken off it: a
    /// chunk, or the run of control items there.
    fn take_head(&mut self, peer: PeerId, urgent: bool) -> Option<QueueEntry<B>> {
        loop {
            let q = self.sends.queue.get_mut(peer)?;
            let item = if urgent {
                q.urgent.pop_front()?
            } else if q.normal.is_empty() {
                return None;
            } else {
                q.normal.remove(0)
            };
            match item {
                Queued::Control(control) => {
                    let mut entry = QueueEntry::empty();
                    entry.push_control(control);
                    // The control items behind it leave in the same RPC, as far as it has room.
                    let q = self.sends.queue.get_mut(peer)?;
                    loop {
                        let next = if urgent { q.urgent.front() } else { q.normal.first() };
                        let Some(&Queued::Control(control)) = next else {
                            break;
                        };
                        if !entry.push_control(control) {
                            break;
                        }
                        if urgent {
                            q.urgent.pop_front();
                        } else {
                            q.normal.remove(0);
                        }
                    }
                    return Some(entry);
                }
                Queued::Chunk { group, index, solicited } => {
                    if let Some(chunk) = self.resolve_chunk(&group, index) {
                        return Some(QueueEntry::from_chunk(chunk, solicited));
                    }
                }
            }
        }
    }

    fn pop_owed_answer(&mut self, peer: PeerId) -> Option<(GroupId, u32)> {
        let owed = &mut self.sends.queue.get_mut(peer)?.owed_answers;
        // The lowest group id, then its lowest index.
        let (g, idx) = owed.iter().filter_map(|(&g, bits)| Some((g, bits.first_index()?))).min()?;
        if let Some(bits) = owed.get_mut(&g) {
            bits.clear(idx);
            if bits.is_empty() {
                owed.remove(&g);
            }
        }
        self.chunks.contains_key(&(g, idx)).then_some((g, idx))
    }
}
