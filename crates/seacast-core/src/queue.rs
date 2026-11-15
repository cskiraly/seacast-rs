//! The reference send path: a bounded two-lane queue a peer and the node-wide
//! byte window (`protocol-v2.md` §4.11, §4.12; `protocol.md` §7). It is not
//! part of the node: a host keeps one beside its [`SeacastNode`], passes the
//! node [`SendQueues::env`] as its environment, and has each peer's writer call
//! [`SendQueues::next_to_send`]. A host with a send path of its own implements
//! the same [`RuntimeEnv`] methods instead.

use crate::{
    bitmap::Bitmap,
    collections::{InlineVec, MAX_ENTRY_CONTROL, PreallocDeque, PreallocMap, PreallocVec},
    message::{Control, Have, QueueEntry, Queued},
    node::SeacastNode,
    state::{DispatchOutcome, PeerQueue},
    traits::{ChunkBuffer, ObjectCatalog, PenaltyReason, RuntimeEnv, TimerEvent},
    types::{Ask, GroupId, NodeConfig, PeerId, Timestamp},
};

#[derive(Debug, Clone)]
pub struct SendQueues {
    config: NodeConfig,
    pub queue: PreallocMap<PeerId, PeerQueue>,
    queue_pool: PreallocVec<PeerQueue>,
    /// Bytes of chunks written and not yet acknowledged or timed out.
    pub in_flight: usize,
    waiters: PreallocDeque<PeerId>,
    pub sent: PreallocMap<(PeerId, GroupId, u32), (u64, usize)>,
}

/// A host's environment with the send path's methods answered by `queues`.
pub struct QueueEnv<'a, E> {
    pub queues: &'a mut SendQueues,
    pub env: &'a mut E,
}

impl<B: ChunkBuffer, E: RuntimeEnv<B>> RuntimeEnv<B> for QueueEnv<'_, E> {
    fn now(&self) -> Timestamp {
        self.env.now()
    }
    fn schedule_after(&mut self, delay: f64, event: TimerEvent) {
        self.env.schedule_after(delay, event);
    }
    fn send(&mut self, peer: PeerId, item: Queued, urgent: bool) -> bool {
        self.queues.send(peer, item, urgent, self.env)
    }
    fn cancel_chunk(&mut self, peer: PeerId, group: GroupId, index: u32) {
        self.queues.window_release(peer, group, index, self.env);
    }
    fn cancel_asks(&mut self, peer: PeerId, group: GroupId, bits: &Bitmap) {
        self.queues.cancel_asks(peer, group, bits);
    }
    fn cancel_group(&mut self, group: &GroupId) {
        self.queues.cancel_group(group);
    }
    fn owe_offer(&mut self, peer: PeerId, group: GroupId, bits: Bitmap) {
        self.queues.owe(peer, group, bits, self.env);
    }
    fn owe_answer(&mut self, peer: PeerId, group: GroupId, index: u32) {
        self.queues.owe_answer(peer, group, index);
    }
    fn merge_holding(&mut self, peer: PeerId, have: &Have) -> bool {
        self.queues.merge_waiting(peer, have)
    }
    fn ask_waiting(&self, peer: PeerId, ask: Ask) -> bool {
        self.queues.ask_waiting(peer, ask)
    }
    fn wake_writer(&mut self, peer: PeerId) {
        self.env.wake_writer(peer);
    }
    fn start_decode(&mut self, group: GroupId) {
        self.env.start_decode(group);
    }
    fn deliver(&mut self, group: GroupId, object: B) {
        self.env.deliver(group, object);
    }
    fn publish_evidence(&mut self, group: GroupId, body: B) {
        self.env.publish_evidence(group, body);
    }
    fn unreachable(&mut self, group: GroupId, bits: Bitmap) {
        self.env.unreachable(group, bits);
    }
    fn penalise(&mut self, peer: PeerId, reason: PenaltyReason) {
        self.env.penalise(peer, reason);
    }
}

/// A host's environment that owns its queues: `env`'s methods, with the send
/// path's answered by `queues`.
pub struct WithQueues<E> {
    pub queues: SendQueues,
    pub env: E,
}

impl<E> WithQueues<E> {
    pub fn new(config: NodeConfig, env: E) -> Self {
        Self { queues: SendQueues::new(config), env }
    }

    fn both(&mut self) -> QueueEnv<'_, E> {
        self.queues.env(&mut self.env)
    }

    /// [`SendQueues::next_to_send`].
    pub fn next_to_send<B, C>(
        &mut self,
        node: &mut SeacastNode<B>,
        peer: PeerId,
        catalog: &C,
    ) -> DispatchOutcome<B>
    where
        B: ChunkBuffer,
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        self.queues.next_to_send(node, peer, &mut self.env, catalog)
    }
}

impl<E> std::ops::Deref for WithQueues<E> {
    type Target = E;
    fn deref(&self) -> &E {
        &self.env
    }
}

impl<E> std::ops::DerefMut for WithQueues<E> {
    fn deref_mut(&mut self) -> &mut E {
        &mut self.env
    }
}

impl<B: ChunkBuffer, E: RuntimeEnv<B>> RuntimeEnv<B> for WithQueues<E> {
    fn now(&self) -> Timestamp {
        self.env.now()
    }
    fn schedule_after(&mut self, delay: f64, event: TimerEvent) {
        self.env.schedule_after(delay, event);
    }
    fn send(&mut self, peer: PeerId, item: Queued, urgent: bool) -> bool {
        self.both().send(peer, item, urgent)
    }
    fn cancel_chunk(&mut self, peer: PeerId, group: GroupId, index: u32) {
        self.both().cancel_chunk(peer, group, index);
    }
    fn cancel_asks(&mut self, peer: PeerId, group: GroupId, bits: &Bitmap) {
        self.queues.cancel_asks(peer, group, bits);
    }
    fn cancel_group(&mut self, group: &GroupId) {
        self.queues.cancel_group(group);
    }
    fn owe_offer(&mut self, peer: PeerId, group: GroupId, bits: Bitmap) {
        self.both().owe_offer(peer, group, bits);
    }
    fn owe_answer(&mut self, peer: PeerId, group: GroupId, index: u32) {
        self.queues.owe_answer(peer, group, index);
    }
    fn merge_holding(&mut self, peer: PeerId, have: &Have) -> bool {
        self.queues.merge_waiting(peer, have)
    }
    fn ask_waiting(&self, peer: PeerId, ask: Ask) -> bool {
        self.queues.ask_waiting(peer, ask)
    }
    fn wake_writer(&mut self, peer: PeerId) {
        self.env.wake_writer(peer);
    }
    fn start_decode(&mut self, group: GroupId) {
        self.env.start_decode(group);
    }
    fn deliver(&mut self, group: GroupId, object: B) {
        self.env.deliver(group, object);
    }
    fn publish_evidence(&mut self, group: GroupId, body: B) {
        self.env.publish_evidence(group, body);
    }
    fn unreachable(&mut self, group: GroupId, bits: Bitmap) {
        self.env.unreachable(group, bits);
    }
    fn penalise(&mut self, peer: PeerId, reason: PenaltyReason) {
        self.env.penalise(peer, reason);
    }
}

impl SendQueues {
    /// Preallocates a queue for each of `config`'s peers.
    pub fn new(config: NodeConfig) -> Self {
        let cap = config.capacities;
        let mut queue_pool = PreallocVec::with_capacity(cap.max_peers);
        for _ in 0..cap.max_peers {
            let _ = queue_pool
                .push(PeerQueue::with_capacity(cap.max_queue_entries_per_peer, cap.max_groups));
        }
        Self {
            queue: PreallocMap::with_capacity(cap.max_peers),
            queue_pool,
            in_flight: 0,
            waiters: PreallocDeque::with_capacity(cap.max_peers),
            sent: PreallocMap::with_capacity(cap.max_peers * 64),
            config,
        }
    }

    /// `env` with the send path's methods answered by these queues: what the
    /// node is given.
    pub fn env<'a, E>(&'a mut self, env: &'a mut E) -> QueueEnv<'a, E> {
        QueueEnv { queues: self, env }
    }

    /// Opens `peer`'s queue. Called before `SeacastNode::connect_peer`, which
    /// sends to it.
    pub fn connect(&mut self, peer: PeerId) {
        if self.queue.contains_key(&peer) || self.queue_pool.is_empty() {
            return;
        }
        let mut q = self.queue_pool.remove(self.queue_pool.len() - 1);
        q.clear();
        self.queue.insert(peer, q);
    }

    /// Closes `peer`'s queue and frees what was in flight to it.
    pub fn disconnect<B: ChunkBuffer, E: RuntimeEnv<B>>(&mut self, peer: PeerId, env: &mut E) {
        if let Some(mut q) = self.queue.remove(&peer) {
            q.clear();
            let _ = self.queue_pool.push(q);
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

    /// The window's timer. `false` for an event that is the node's.
    pub fn on_timer<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        event: TimerEvent,
        env: &mut E,
    ) -> bool {
        let TimerEvent::WindowTimeout { peer, group, index, at_bits } = event else {
            return false;
        };
        self.window_timeout((peer, group, index), at_bits, env);
        true
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
        let Some(q) = self.queue.get_mut(&peer) else {
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

    /// Marks `bits` of `group` as owed to `peer` for the next write (`owe(p, g,
    /// bits)`).
    pub fn owe<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        bits: Bitmap,
        env: &mut E,
    ) {
        if let Some(q) = self.queue.get_mut(&peer) {
            *q.owed.entry_or_default(group) |= bits;
        }
        env.wake_writer(peer);
    }

    /// Records an answer a full queue refused, to be queued again as the queue
    /// empties.
    pub fn owe_answer(&mut self, peer: PeerId, group: GroupId, index: u32) {
        if let Some(q) = self.queue.get_mut(&peer) {
            q.owed_answers.entry_or_default(group).set(index);
        }
    }

    /// Merges a holding of `h.group` into an existing urgent holding still
    /// waiting in `peer`'s queue (`protocol-v2.md` §4.2 `merge_waiting`).
    pub fn merge_waiting(&mut self, peer: PeerId, h: &Have) -> bool {
        let Some(q) = self.queue.get_mut(&peer) else {
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
        let Some(q) = self.queue.get(&peer) else {
            return false;
        };
        q.normal.iter().any(|item| {
            matches!(item, Queued::Control(Control::Want(w)) if w.group == ask.group && w.bits.has(ask.index))
        })
    }

    /// Takes `bits` of `group` out of the asks waiting in `peer`'s queue; a
    /// standing request is not one.
    pub fn cancel_asks(&mut self, peer: PeerId, group: GroupId, bits: &Bitmap) {
        if let Some(q) = self.queue.get_mut(&peer) {
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
        for (_, q) in self.queue.iter_mut() {
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

    /// Selects and filters the next queue entry to write to `peer`
    /// (`protocol-v2.md` §4.11 `next_to_send`).
    pub fn next_to_send<B, E, C>(
        &mut self,
        node: &mut SeacastNode<B>,
        peer: PeerId,
        env: &mut E,
        catalog: &C,
    ) -> DispatchOutcome<B>
    where
        B: ChunkBuffer,
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        loop {
            if self.has_owed_answers(peer) && self.has_queue_room(peer) {
                if let Some((group, index)) = self.pop_owed_answer(node, peer) {
                    let entry = Queued::Chunk { group, index, solicited: true };
                    self.send(peer, entry, false, env);
                }
            }
            if let Some(urgent_entry) = self.take_head(node, peer, true) {
                if let Some(out) = self.with_owed(node, peer, urgent_entry, catalog) {
                    return DispatchOutcome::Send(out);
                }
                continue;
            }
            let normal_empty = self.queue.get(&peer).map(|q| q.normal.is_empty()).unwrap_or(true);
            if normal_empty {
                if self.has_owed_offers(peer) {
                    if let Some(out) = self.with_owed(node, peer, QueueEntry::empty(), catalog) {
                        return DispatchOutcome::Send(out);
                    }
                }
                self.leave_line(peer, env);
                return DispatchOutcome::Empty;
            }

            let k = self.choose_normal_index(node, peer);
            let item = self.queue.get(&peer).and_then(|q| q.normal.get(k)).copied();
            let (entry, need) = match item {
                Some(Queued::Chunk { group, index, solicited }) => {
                    // Gone since it was queued (its group dropped or expired): nothing to send.
                    let Some(chunk) = node.resolve_chunk(&group, index) else {
                        self.queue.get_mut(&peer).expect("queue exists").normal.remove(k);
                        continue;
                    };
                    let need = catalog.wire_size(&chunk);
                    if need > 0 && !self.acquire_room(peer, need, env) {
                        return DispatchOutcome::Wait;
                    }
                    self.queue.get_mut(&peer).expect("queue exists").normal.remove(k);
                    (QueueEntry::from_chunk(chunk, solicited), need)
                }
                // `choose` names a control item only at the head.
                _ => match self.take_head(node, peer, false) {
                    Some(entry) => (entry, 0),
                    None => continue,
                },
            };
            let out = node.filter_entry(peer, entry, &mut self.env(env), catalog);
            let has_chunk = out.as_ref().and_then(|e| e.chunk.as_ref()).is_some();
            if need > 0 && !has_chunk {
                self.free_room(need, env);
            }
            if let Some(out_entry) = out {
                if let Some(ref ch) = out_entry.chunk {
                    self.track_in_flight(peer, ch.group, ch.index, need, env);
                    if node.groups.get(&ch.group).is_some_and(|r| r.origin.is_some()) {
                        node.origin_sent(ch.group, ch.index, &mut self.env(env), catalog);
                    }
                }
                if let Some(final_entry) = self.with_owed(node, peer, out_entry, catalog) {
                    return DispatchOutcome::Send(final_entry);
                }
            }
        }
    }

    /// Chooses the index in `queue[peer].normal` to pop next (`protocol-v2.md`
    /// §4.12 `choose(q)`) with zero heap allocation.
    pub fn choose_normal_index<B: ChunkBuffer>(
        &self,
        node: &SeacastNode<B>,
        peer: PeerId,
    ) -> usize {
        let Some(q) = self.queue.get(&peer) else {
            return 0;
        };
        if q.normal.is_empty() || !q.normal[0].is_chunk() {
            return 0;
        }
        if let Some(best_own) = self.pick_rarest_matching(node, q, |e| node.own_chunk(e)) {
            return best_own;
        }
        if self.config.answers_first {
            if let Some(best_asked) = self.pick_rarest_matching(node, q, |e| {
                matches!(e, Queued::Chunk { solicited: true, .. })
            }) {
                return best_asked;
            }
        }
        if self.config.rarest_enabled { self.rarest(node, q) } else { 0 }
    }

    /// Picks the rarest entry satisfying `pred` without heap allocation
    /// (`protocol-v2.md` §4.12 `pick(q, ks)`).
    fn pick_rarest_matching<B: ChunkBuffer, F>(
        &self,
        node: &SeacastNode<B>,
        q: &PeerQueue,
        mut pred: F,
    ) -> Option<usize>
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
            let h = node.holder_count(&group, index);
            if best_k.is_none() || h < best_h {
                best_h = h;
                best_k = Some(k);
            }
        }
        best_k
    }

    /// Picks the rarest chunk ahead of the first control-only entry
    /// (`protocol.md` §7.2 `rarest(q)` `[c9]`).
    pub fn rarest<B: ChunkBuffer>(&self, node: &SeacastNode<B>, q: &PeerQueue) -> usize {
        let mut best_h = usize::MAX;
        let mut best_i = 0;
        for (i, entry) in q.normal.iter().enumerate() {
            let &Queued::Chunk { group, index, .. } = entry else {
                break;
            };
            let h = node.holder_count(&group, index);
            if h < best_h {
                best_h = h;
                best_i = i;
            }
        }
        best_i
    }

    /// Attaches owed offers for `peer` to `entry` (`protocol.md` §7.2
    /// `with_owed`).
    pub fn with_owed<B: ChunkBuffer, C: ObjectCatalog<B>>(
        &mut self,
        node: &SeacastNode<B>,
        peer: PeerId,
        mut entry: QueueEntry<B>,
        catalog: &C,
    ) -> Option<QueueEntry<B>> {
        // Only as many groups as the entry has room for leave `owed`: the rest stay
        // owed, and the writer, which runs until the queue and `owed` are both
        // empty, takes them next.
        let room = MAX_ENTRY_CONTROL - entry.haves.len();
        let mut owed_groups: InlineVec<(GroupId, Bitmap), MAX_ENTRY_CONTROL> = InlineVec::new();
        if let Some(q) = self.queue.get_mut(&peer) {
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
            let pushed_bits = &node.pairs.pushed_bits(&(peer, g));
            let peer_has_bits = &node.pairs.has_bits(&(peer, g));
            let mut b = bits.and_not(pushed_bits).and_not(peer_has_bits);
            if let Some(ref ch) = entry.chunk {
                if ch.group == g {
                    b.clear(ch.index);
                }
            }
            if !b.is_empty() {
                entry.add_offer(Have::offer(node.type_of(&g, catalog), g, b));
            }
        }
        if entry.is_empty() { None } else { Some(entry) }
    }

    pub fn has_owed_offers(&self, peer: PeerId) -> bool {
        self.queue.get(&peer).is_some_and(|q| q.owed.iter().any(|(_, b)| !b.is_empty()))
    }

    fn has_owed_answers(&self, peer: PeerId) -> bool {
        self.queue.get(&peer).is_some_and(|q| !q.owed_answers.is_empty())
    }

    fn has_queue_room(&self, peer: PeerId) -> bool {
        self.queue.get(&peer).map(|q| q.has_room()).unwrap_or(true)
    }

    /// The entry for the head of a lane of `peer`'s queue, taken off it: a
    /// chunk, or the run of control items there.
    fn take_head<B: ChunkBuffer>(
        &mut self,
        node: &SeacastNode<B>,
        peer: PeerId,
        urgent: bool,
    ) -> Option<QueueEntry<B>> {
        loop {
            let q = self.queue.get_mut(&peer)?;
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
                    let q = self.queue.get_mut(&peer)?;
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
                    if let Some(chunk) = node.resolve_chunk(&group, index) {
                        return Some(QueueEntry::from_chunk(chunk, solicited));
                    }
                }
            }
        }
    }

    fn pop_owed_answer<B: ChunkBuffer>(
        &mut self,
        node: &SeacastNode<B>,
        peer: PeerId,
    ) -> Option<(GroupId, u32)> {
        let owed = &mut self.queue.get_mut(&peer)?.owed_answers;
        // The lowest group id, then its lowest index.
        let (g, idx) = owed.iter().filter_map(|(&g, bits)| Some((g, bits.first_index()?))).min()?;
        if let Some(bits) = owed.get_mut(&g) {
            bits.clear(idx);
            if bits.is_empty() {
                owed.remove(&g);
            }
        }
        node.chunks.contains_key(&(g, idx)).then_some((g, idx))
    }
}
