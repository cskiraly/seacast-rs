use crate::{
    bitmap::Bitmap,
    message::{QueueEntry, Queued},
    node::SeacastNode,
    traits::{ChunkBuffer, ObjectCatalog, RuntimeEnv, TimerEvent},
    types::{Ask, PeerId},
};

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Hands `entry` to the host's send path for `peer` (`enqueue`). `false` if
    /// it was refused.
    pub fn enqueue<E>(&mut self, peer: PeerId, entry: Queued, urgent: bool, env: &mut E) -> bool
    where
        E: RuntimeEnv<B>,
    {
        env.send(peer, entry, urgent)
    }

    /// What the host writes to `peer` for `item`, which it was handed by
    /// `RuntimeEnv::send`, called when the item is about to be written:
    /// `None` if it is no longer to be sent. An ask starts its promise here
    /// and a chunk is recorded as sent.
    ///
    /// A host that coalesces control items builds its own [`QueueEntry`] and
    /// passes it to [`Self::filter_entry`], as
    /// [`SendQueues`](crate::SendQueues) does.
    pub fn on_write<E, C>(
        &mut self,
        peer: PeerId,
        item: Queued,
        env: &mut E,
        catalog: &C,
    ) -> Option<QueueEntry<B>>
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let entry = match item {
            Queued::Chunk { group, index, solicited } => {
                QueueEntry::from_chunk(self.resolve_chunk(&group, index)?, solicited)
            }
            Queued::Control(control) => {
                let mut entry = QueueEntry::empty();
                entry.push_control(control);
                entry
            }
        };
        let out = self.filter_entry(peer, entry, env, catalog)?;
        if let Some(chunk) = &out.chunk {
            let (group, index) = (chunk.group, chunk.index);
            if self.groups.get(&group).is_some_and(|r| r.origin.is_some()) {
                self.origin_sent(group, index, env, catalog);
            }
        }
        Some(out)
    }

    /// Returns `true` if `entry` is an unsolicited push of a chunk this node
    /// held from the start as source (`protocol-v2.md` §4.12
    /// `own_chunk(e)`).
    pub fn own_chunk(&self, entry: &Queued) -> bool {
        let &Queued::Chunk { group, index, solicited: false } = entry else {
            return false;
        };
        let in_received = self
            .groups
            .get(&group)
            .and_then(|r| r.received.as_ref())
            .map(|b| b.has(index))
            .unwrap_or(false);
        let in_rebuilt = self
            .groups
            .get(&group)
            .and_then(|r| r.rebuilt.as_ref())
            .map(|b| b.has(index))
            .unwrap_or(false);
        !in_received && !in_rebuilt
    }

    /// Filters a popped queue entry right before sending (`protocol.md` §7.2
    /// `filter_entry` `[c8, c12]`).
    pub fn filter_entry<E, C>(
        &mut self,
        peer: PeerId,
        mut entry: QueueEntry<B>,
        env: &mut E,
        catalog: &C,
    ) -> Option<QueueEntry<B>>
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if let Some(ref f) = entry.chunk {
            let g = f.group;
            let idx = f.index;
            let peer_holds = self.pairs.peer_has(&(peer, g)).map(|e| e.has(idx)).unwrap_or(false);
            if self.config.cancel_enabled && peer_holds {
                entry.chunk = None;
            } else if self.config.project_enabled &&
                !entry.solicited &&
                self.projected(peer, &g, catalog)
            {
                entry.chunk = None;
                self.unpush(peer, g, idx, env, catalog);
            } else {
                let mut sent = self.pairs.sent_to(&(peer, g)).unwrap_or_default();
                sent.set(idx);
                self.pairs.set_sent_to((peer, g), sent);
            }
        }

        let now = env.now();
        let now_bits = now.to_bits();

        for w_idx in 0..entry.wants.len() {
            let g = entry.wants[w_idx].group;
            let t = self
                .groups
                .get(&g)
                .and_then(|r| r.t_of.as_ref())
                .copied()
                .unwrap_or_else(|| catalog.type_of_group(&g));
            let promise_timeout = catalog.params(t).promise;
            let track_promise = entry.wants[w_idx].track_promise;
            let orig_bits = entry.wants[w_idx].bits;
            if self.expired(&g) {
                entry.wants[w_idx].bits = Bitmap::EMPTY;
                continue;
            }
            let mut filtered = Bitmap::new();
            for idx in orig_bits.iter() {
                let a = Ask::new(g, idx);
                if !self.held(a) && !self.gated(a) && !self.tied_to_root(peer, a) {
                    filtered.set(idx);
                    if track_promise && !self.promises.contains(a, peer) {
                        self.promises.insert(a, peer, now_bits);
                        env.schedule_after(promise_timeout, TimerEvent::PromiseDue {
                            ask: a,
                            peer,
                            at_bits: now_bits,
                        });
                    }
                }
            }
            entry.wants[w_idx].bits = filtered;
        }
        entry.wants.retain(|w| !w.bits.is_empty());

        if entry.is_empty() { None } else { Some(entry) }
    }
}
