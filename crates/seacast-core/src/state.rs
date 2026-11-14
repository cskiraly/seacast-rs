use crate::{
    bitmap::{BITMAP_WORDS, Bitmap, MAX_BITMAP_BITS},
    collections::{InlineVec, MAX_INLINE_PEERS, PreallocDeque, PreallocMap, PreallocVec},
    message::{ChunkMsg, QueueEntry, Queued},
    types::{Ask, GroupId, GroupState, HaveEntry, PeerId, PushEntry, Shape, Timestamp, TypeId},
};

/// Maximum groups in a single heartbeat gossip emission batch.
pub const MAX_GOSSIP_GROUPS: usize = 64;

/// Maximum sliding heartbeat windows in [`GossipHistory`].
pub const MAX_GOSSIP_WINDOWS: usize = 8;

/// Outcome of `SeacastNode::next_to_send` for a peer's writer (`protocol-v2.md`
/// §4.11).
// Not boxed: the writer path does not allocate.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome<B> {
    /// Entry ready to be written to the peer's transport stream.
    Send(QueueEntry<B>),
    /// Writer is waiting in the FIFO line for congestion window bytes (`WAIT`).
    Wait,
    /// Queue has nothing to send (`None`).
    Empty,
}

/// The two-lane bounded per-peer send queue (`protocol.md` §7, §8.2),
/// preallocated at initialization.
#[derive(Debug, Clone)]
pub struct PeerQueue {
    pub urgent: PreallocDeque<Queued>,
    pub normal: PreallocVec<Queued>,
    pub max_entries: usize,
    /// Offers a full queue refused, by group: they leave with the peer's next
    /// RPC (`owed`).
    pub owed: PreallocMap<GroupId, Bitmap>,
    /// Answers a full queue refused, by group: queued again as it empties
    /// (`owed_answers`).
    pub owed_answers: PreallocMap<GroupId, Bitmap>,
}

impl PeerQueue {
    /// Preallocates both lanes with fixed capacity `max_entries`, and what is
    /// owed for `max_groups`.
    pub fn with_capacity(max_entries: usize, max_groups: usize) -> Self {
        Self {
            urgent: PreallocDeque::with_capacity(max_entries),
            normal: PreallocVec::with_capacity(max_entries),
            max_entries,
            owed: PreallocMap::with_capacity(max_groups),
            owed_answers: PreallocMap::with_capacity(max_groups),
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.urgent.clear();
        self.normal.clear();
        self.owed.clear();
        self.owed_answers.clear();
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.urgent.len() + self.normal.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.urgent.is_empty() && self.normal.is_empty()
    }

    #[inline]
    pub fn has_room(&self) -> bool {
        self.len() < self.max_entries
    }

    #[inline]
    pub fn has_chunks(&self) -> bool {
        self.normal.iter().any(Queued::is_chunk)
    }
}

/// Everything kept of one group. A field is `None` until it is first written,
/// as its entry was absent when each field was a map of its own.
#[derive(Debug, Clone, Default)]
pub struct Group {
    /// The group's object type: set when the group is opened.
    pub t_of: Option<TypeId>,
    /// The group's index count and threshold, from its header.
    pub hdr: Option<Shape>,
    /// Whether the domain has authenticated the group: asked once, not once a
    /// chunk.
    pub authentic: bool,
    pub state: Option<GroupState>,
    pub received: Option<Bitmap>,
    pub rebuilt: Option<Bitmap>,
    pub mine: Option<Bitmap>,
    pub interest: Option<Bitmap>,
    pub stop_pull: Option<bool>,
    /// Whether a holding of this group has gone out with `claim_all`: any index
    /// may then be asked for.
    pub claimed_all: bool,
    pub origin: Option<Bitmap>,
    pub known_at: Option<Timestamp>,
    pub last_activity: Option<Timestamp>,
    // Claims, deferral, probe and repair sampling (`protocol-v2.md` §3, §4.6)
    pub claims: Option<InlineVec<PeerId, MAX_INLINE_PEERS>>,
    pub reconsider_at: Option<u64>,
    pub deferred: Option<bool>,
    pub waited: Option<bool>,
    pub probe: Option<u32>,
    pub probed: Option<PeerId>,
    pub rsample: Option<InlineVec<u32, MAX_BITMAP_BITS>>,
    pub rsample_step: Option<usize>,
    pub rsample_final: Option<bool>,
}

/// The groups a node keeps anything of, a record each (`protocol-v2.md` §3,
/// `protocol.md` §8.1).
///
/// Two limits, each `max_groups`: on the groups that are open, and on those
/// that are not, which peers name before any chunk of them has been accepted.
/// Neither kind can take the other's room.
#[derive(Debug, Clone)]
pub struct Groups {
    recs: PreallocMap<GroupId, Group>,
    /// Where a group past its limit is written, so that `rec` still returns a
    /// place.
    spill: Group,
    open: usize,
    max_groups: usize,
}

impl Groups {
    pub fn with_capacity(max_groups: usize) -> Self {
        Self {
            recs: PreallocMap::with_capacity(2 * max_groups),
            spill: Group::default(),
            open: 0,
            max_groups,
        }
    }

    #[inline]
    pub fn get(&self, group: &GroupId) -> Option<&Group> {
        self.recs.get(group)
    }

    #[inline]
    pub fn get_mut(&mut self, group: &GroupId) -> Option<&mut Group> {
        self.recs.get_mut(group)
    }

    /// `group`'s record, made if it has none. Past the limit on groups that are
    /// not open the record is not kept: what is written to it is lost.
    pub fn rec(&mut self, group: GroupId) -> &mut Group {
        if !self.recs.contains_key(&group) && self.recs.len() - self.open >= self.max_groups {
            self.spill = Group::default();
            return &mut self.spill;
        }
        self.recs.get_or_insert_with(group, Group::default)
    }

    /// Opens `group` as an object of type `t`. `false`, with nothing changed,
    /// at the limit on open groups.
    pub fn open(&mut self, group: GroupId, t: TypeId) -> bool {
        let is_open = self.recs.get(&group).is_some_and(|rec| rec.t_of.is_some());
        if !is_open {
            if self.open >= self.max_groups {
                return false;
            }
            self.open += 1;
        }
        self.recs.get_or_insert_with(group, Group::default).t_of = Some(t);
        true
    }

    /// Whether one more group may be opened.
    #[inline]
    pub fn can_open(&self) -> bool {
        self.open < self.max_groups
    }

    pub fn remove(&mut self, group: &GroupId) -> Option<Group> {
        let rec = self.recs.remove(group)?;
        if rec.t_of.is_some() {
            self.open -= 1;
        }
        Some(rec)
    }

    /// The number of open groups.
    #[inline]
    pub fn open_count(&self) -> usize {
        self.open
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.recs.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.recs.is_empty()
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&GroupId, &Group)> {
        self.recs.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&GroupId, &mut Group)> {
        self.recs.iter_mut()
    }
}

/// A value per ask and peer, kept by ask: what an arriving chunk closes is one
/// entry of the map, however many peers were asked or tried for it.
#[derive(Debug, Clone)]
pub struct AskPeers<V: Copy> {
    by_ask: PreallocMap<Ask, InlineVec<(PeerId, V), MAX_INLINE_PEERS>>,
}

impl<V: Copy> AskPeers<V> {
    pub fn with_capacity(asks: usize) -> Self {
        Self { by_ask: PreallocMap::with_capacity(asks) }
    }

    pub fn get(&self, ask: Ask, peer: PeerId) -> Option<V> {
        let peers = self.by_ask.get(&ask)?;
        peers.iter().find(|&&(p, _)| p == peer).map(|&(_, v)| v)
    }

    pub fn contains(&self, ask: Ask, peer: PeerId) -> bool {
        self.get(ask, peer).is_some()
    }

    pub fn insert(&mut self, ask: Ask, peer: PeerId, value: V) {
        let peers = self.by_ask.entry_or_default(ask);
        match peers.iter_mut().find(|(p, _)| *p == peer) {
            Some(entry) => entry.1 = value,
            None => {
                let _ = peers.push((peer, value));
            }
        }
    }

    pub fn remove(&mut self, ask: Ask, peer: PeerId) -> Option<V> {
        let peers = self.by_ask.get_mut(&ask)?;
        let at = peers.iter().position(|&(p, _)| p == peer)?;
        let (_, value) = peers.remove(at);
        if peers.is_empty() {
            self.by_ask.remove(&ask);
        }
        Some(value)
    }

    /// Drops every peer's value for `ask`.
    pub fn remove_ask(&mut self, ask: Ask) {
        self.by_ask.remove(&ask);
    }

    pub fn retain(&mut self, mut keep: impl FnMut(Ask, PeerId, V) -> bool) {
        self.by_ask.retain(|&ask, peers| {
            peers.retain(|&(peer, value)| keep(ask, peer, value));
            !peers.is_empty()
        });
    }

    /// The number of (ask, peer) pairs.
    pub fn len(&self) -> usize {
        self.by_ask.iter().map(|(_, peers)| peers.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ask.is_empty()
    }
}

/// Sliding heartbeat message cache for heartbeat gossip (`protocol.md` §6.4,
/// `protocol-v2.md` §4.8).
///
/// Preallocated once at initialization; performs **zero heap allocation**
/// during `put`, `shift`, `gossip_group_bits`, and `remove_group`.
#[derive(Debug, Clone)]
pub struct GossipHistory {
    windows: PreallocVec<PreallocVec<(GroupId, Bitmap)>>,
    head: usize,
    length: usize,
    gossip_windows: usize,
}

impl GossipHistory {
    /// Preallocates `length` sliding windows, each with capacity `max_groups`.
    pub fn with_capacity(length: usize, gossip_windows: usize, max_groups: usize) -> Self {
        let length = length.clamp(1, MAX_GOSSIP_WINDOWS);
        let gossip_windows = gossip_windows.min(length);
        let mut windows = PreallocVec::with_capacity(length);
        for _ in 0..length {
            let _ = windows.push(PreallocVec::with_capacity(max_groups));
        }
        Self { windows, head: 0, length, gossip_windows }
    }

    /// Adds a published or forwarded chunk to the current heartbeat window
    /// (`gossip_history.put(f)`).
    pub fn put<B>(&mut self, chunk: &ChunkMsg<B>) {
        let front = &mut self.windows[self.head];
        for (g, bits) in front.iter_mut() {
            if *g == chunk.group {
                bits.set(chunk.index);
                return;
            }
        }
        let _ = front.push((chunk.group, Bitmap::singleton(chunk.index)));
    }

    /// Shifts the sliding window at each heartbeat without heap allocation.
    pub fn shift(&mut self) {
        self.head = (self.head + self.length - 1) % self.length;
        self.windows[self.head].clear();
    }

    /// Returns chunk `(group, bits)` pairs from the newest `gossip_windows`
    /// heartbeats on the stack (`group_bits(gossip_history.gossip_ids())`).
    pub fn gossip_group_bits(&self) -> InlineVec<(GroupId, Bitmap), MAX_GOSSIP_GROUPS> {
        let mut out: InlineVec<(GroupId, Bitmap), MAX_GOSSIP_GROUPS> = InlineVec::new();
        for offset in 0..self.gossip_windows {
            let idx = (self.head + offset) % self.length;
            for &(group, ref bits) in self.windows[idx].iter() {
                if let Some((_, existing)) = out.iter_mut().find(|(g, _)| *g == group) {
                    *existing |= bits;
                } else {
                    let _ = out.push((group, *bits));
                }
            }
        }
        out
    }

    /// Removes all entries of `group` (`gossip_history.remove_group(g)`).
    pub fn remove_group(&mut self, group: &GroupId) {
        for w in self.windows.iter_mut() {
            w.retain(|(g, _)| g != group);
        }
    }
}

/// The bitmaps a (peer, group) pair keeps, by their place in its record.
#[derive(Clone, Copy)]
enum PairBits {
    Has = 0,
    Pushed = 1,
    SentTo = 2,
    Want = 3,
    Offered = 4,
}

const PAIR_BITMAPS: usize = 5;
/// Words of a bitmap kept in the record itself. A group with more indices than
/// these hold takes a block of full bitmaps from the pool.
const NARROW_WORDS: usize = 2;
const NO_WIDE: u32 = u32::MAX;

const CLAIM_ALL: u8 = 1;
const COMPLETE: u8 = 1 << 1;
const FIRST_PUSH: u8 = 1 << 2;
const OFFER_AT: u8 = 1 << 3;
const PARK: u8 = 1 << 4;

#[derive(Debug, Clone, Copy)]
struct Pair {
    narrow: [[u64; NARROW_WORDS]; PAIR_BITMAPS],
    /// Which bitmaps exist, and which of them are complemented, a bit each.
    present: u8,
    inverted: u8,
    flags: u8,
    /// The pair's block in the pool, if it has one.
    wide: u32,
    have_ttl: u32,
    push_ttl: u32,
    served: u32,
    first_push: Timestamp,
    offer_at: Timestamp,
    park: Timestamp,
}

impl Pair {
    const EMPTY: Self = Self {
        narrow: [[0; NARROW_WORDS]; PAIR_BITMAPS],
        present: 0,
        inverted: 0,
        flags: 0,
        wide: NO_WIDE,
        have_ttl: 0,
        push_ttl: 0,
        served: 0,
        first_push: 0.0,
        offer_at: 0.0,
        park: 0.0,
    };

    fn has(&self, field: PairBits) -> bool {
        self.present & (1 << field as u8) != 0
    }

    fn drop_bits(&mut self, field: PairBits) {
        self.present &= !(1 << field as u8);
    }

    fn is_empty(&self) -> bool {
        self.present == 0 && self.served == 0 && self.flags & (OFFER_AT | PARK) == 0
    }
}

type PairKey = (PeerId, GroupId);

/// Everything kept per peer and group (`peer_has`, `pushed`, `sent_to`,
/// `served`, `want_p`, `offered`, its time and `park` in `protocol-v2.md` §3),
/// one record a pair.
///
/// A record holds its bitmaps narrow. The first index past them moves the
/// pair's bitmaps to a block of the pool; with the pool empty the indices past
/// them are not kept.
#[derive(Debug, Clone)]
pub struct Pairs {
    recs: PreallocMap<PairKey, Pair>,
    wide: Vec<[[u64; BITMAP_WORDS]; PAIR_BITMAPS]>,
    free: Vec<u32>,
}

impl Pairs {
    pub fn with_capacity(pairs: usize, wide_pairs: usize) -> Self {
        Self {
            recs: PreallocMap::with_capacity(pairs),
            wide: vec![[[0; BITMAP_WORDS]; PAIR_BITMAPS]; wide_pairs],
            free: (0..wide_pairs as u32).rev().collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.recs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.recs.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &PairKey> {
        self.recs.iter().map(|(key, _)| key)
    }

    fn load(&self, pair: &Pair, field: PairBits) -> Bitmap {
        let at = field as usize;
        let mut words = [0; BITMAP_WORDS];
        if pair.wide == NO_WIDE {
            words[..NARROW_WORDS].copy_from_slice(&pair.narrow[at]);
        } else {
            words = self.wide[pair.wide as usize][at];
        }
        Bitmap::from_raw(pair.inverted & (1 << at) != 0, words)
    }

    fn bits(&self, key: &PairKey, field: PairBits) -> Option<Bitmap> {
        let pair = self.recs.get(key).filter(|pair| pair.has(field))?;
        Some(self.load(pair, field))
    }

    /// The pair's record, made if there is room for one.
    fn rec(&mut self, key: PairKey) -> Option<&mut Pair> {
        if !self.recs.contains_key(&key) {
            if self.recs.is_full() {
                return None;
            }
            self.recs.insert(key, Pair::EMPTY);
        }
        self.recs.get_mut(&key)
    }

    fn put(&mut self, key: PairKey, field: PairBits, bits: &Bitmap) -> Option<&mut Pair> {
        let at = field as usize;
        let (inverted, words) = bits.raw();
        let is_wide = words[NARROW_WORDS..].iter().any(|&word| word != 0);
        let (wide, free) = (&mut self.wide, &mut self.free);
        let pair = if self.recs.contains_key(&key) || !self.recs.is_full() {
            self.recs.get_or_insert_with(key, || Pair::EMPTY)
        } else {
            return None;
        };
        if is_wide && pair.wide == NO_WIDE {
            if let Some(block) = free.pop() {
                let moved = &mut wide[block as usize];
                *moved = [[0; BITMAP_WORDS]; PAIR_BITMAPS];
                for (to, from) in moved.iter_mut().zip(&pair.narrow) {
                    to[..NARROW_WORDS].copy_from_slice(from);
                }
                pair.wide = block;
            }
        }
        if pair.wide == NO_WIDE {
            pair.narrow[at].copy_from_slice(&words[..NARROW_WORDS]);
        } else {
            wide[pair.wide as usize][at] = *words;
        }
        pair.present |= 1 << at;
        pair.inverted = (pair.inverted & !(1 << at)) | ((inverted as u8) << at);
        Some(pair)
    }

    pub fn peer_has(&self, key: &PairKey) -> Option<HaveEntry> {
        let pair = self.recs.get(key).filter(|pair| pair.has(PairBits::Has))?;
        Some(HaveEntry {
            bits: self.load(pair, PairBits::Has),
            ttl: pair.have_ttl,
            claim_all: pair.flags & CLAIM_ALL != 0,
            complete: pair.flags & COMPLETE != 0,
        })
    }

    /// What the peer holds of the group, empty if it has claimed nothing.
    pub fn has_bits(&self, key: &PairKey) -> Bitmap {
        self.bits(key, PairBits::Has).unwrap_or(Bitmap::EMPTY)
    }

    pub fn set_peer_has(&mut self, key: PairKey, entry: HaveEntry) {
        if let Some(pair) = self.put(key, PairBits::Has, &entry.bits) {
            pair.have_ttl = entry.ttl;
            pair.flags &= !(CLAIM_ALL | COMPLETE);
            if entry.claim_all {
                pair.flags |= CLAIM_ALL;
            }
            if entry.complete {
                pair.flags |= COMPLETE;
            }
        }
    }

    pub fn pushed(&self, key: &PairKey) -> Option<PushEntry> {
        let pair = self.recs.get(key).filter(|pair| pair.has(PairBits::Pushed))?;
        Some(PushEntry {
            bits: self.load(pair, PairBits::Pushed),
            first_push: (pair.flags & FIRST_PUSH != 0).then_some(pair.first_push),
            ttl: pair.push_ttl,
        })
    }

    /// What was pushed to the peer of the group, empty if nothing.
    pub fn pushed_bits(&self, key: &PairKey) -> Bitmap {
        self.bits(key, PairBits::Pushed).unwrap_or(Bitmap::EMPTY)
    }

    pub fn set_pushed(&mut self, key: PairKey, entry: PushEntry) {
        if let Some(pair) = self.put(key, PairBits::Pushed, &entry.bits) {
            pair.push_ttl = entry.ttl;
            pair.flags &= !FIRST_PUSH;
            if let Some(at) = entry.first_push {
                pair.flags |= FIRST_PUSH;
                pair.first_push = at;
            }
        }
    }

    pub fn sent_to(&self, key: &PairKey) -> Option<Bitmap> {
        self.bits(key, PairBits::SentTo)
    }

    pub fn set_sent_to(&mut self, key: PairKey, bits: Bitmap) {
        self.put(key, PairBits::SentTo, &bits);
    }

    pub fn want_p(&self, key: &PairKey) -> Option<Bitmap> {
        self.bits(key, PairBits::Want)
    }

    pub fn set_want_p(&mut self, key: PairKey, bits: Bitmap) {
        self.put(key, PairBits::Want, &bits);
    }

    pub fn offered(&self, key: &PairKey) -> Option<Bitmap> {
        self.bits(key, PairBits::Offered)
    }

    pub fn set_offered(&mut self, key: PairKey, bits: Bitmap) {
        self.put(key, PairBits::Offered, &bits);
    }

    /// Removes the peer's offers of the group with their time, and returns
    /// them.
    pub fn take_offered(&mut self, key: &PairKey) -> Option<Bitmap> {
        let bits = self.bits(key, PairBits::Offered);
        if let Some(pair) = self.recs.get_mut(key) {
            pair.drop_bits(PairBits::Offered);
            pair.flags &= !OFFER_AT;
        }
        bits
    }

    pub fn served(&self, key: &PairKey) -> usize {
        self.recs.get(key).map_or(0, |pair| pair.served as usize)
    }

    pub fn add_served(&mut self, key: PairKey) {
        if let Some(pair) = self.rec(key) {
            pair.served = pair.served.saturating_add(1);
        }
    }

    pub fn set_offer_at(&mut self, key: PairKey, at: Timestamp) {
        if let Some(pair) = self.rec(key) {
            pair.flags |= OFFER_AT;
            pair.offer_at = at;
        }
    }

    /// A pair whose last offer is older than `cutoff`.
    pub fn expired_offer(&self, cutoff: Timestamp) -> Option<PairKey> {
        self.recs
            .iter()
            .find(|(_, pair)| pair.flags & OFFER_AT != 0 && pair.offer_at < cutoff)
            .map(|(&key, _)| key)
    }

    pub fn park(&self, key: &PairKey) -> Option<Timestamp> {
        let pair = self.recs.get(key).filter(|pair| pair.flags & PARK != 0)?;
        Some(pair.park)
    }

    pub fn set_park(&mut self, key: PairKey, until: Timestamp) {
        if let Some(pair) = self.rec(key) {
            pair.flags |= PARK;
            pair.park = until;
        }
    }

    pub fn clear_park(&mut self, key: &PairKey) {
        if let Some(pair) = self.recs.get_mut(key) {
            pair.flags &= !PARK;
        }
    }

    /// Keeps the pairs `keep` accepts.
    pub fn retain(&mut self, mut keep: impl FnMut(&PairKey) -> bool) {
        let free = &mut self.free;
        self.recs.retain(|key, pair| {
            let kept = keep(key);
            if !kept && pair.wide != NO_WIDE {
                free.push(pair.wide);
            }
            kept
        });
    }

    /// One heartbeat: `HAVE_TTL` and `PUSH_TTL` count down and a park past its
    /// time ends. A holding that expires goes with what was sent to the
    /// peer, and is given to `expired`. A pair left with nothing is
    /// removed.
    pub fn heartbeat(&mut self, now: Timestamp, mut expired: impl FnMut(PeerId, GroupId, Bitmap)) {
        let (wide, free) = (&self.wide, &mut self.free);
        self.recs.retain(|&(peer, group), pair| {
            if pair.has(PairBits::Has) {
                if pair.have_ttl > 1 {
                    pair.have_ttl -= 1;
                } else {
                    let mut words = [0; BITMAP_WORDS];
                    if pair.wide == NO_WIDE {
                        words[..NARROW_WORDS].copy_from_slice(&pair.narrow[PairBits::Has as usize]);
                    } else {
                        words = wide[pair.wide as usize][PairBits::Has as usize];
                    }
                    let inverted = pair.inverted & (1 << PairBits::Has as u8) != 0;
                    expired(peer, group, Bitmap::from_raw(inverted, words));
                    pair.drop_bits(PairBits::Has);
                    pair.drop_bits(PairBits::SentTo);
                    pair.flags &= !(CLAIM_ALL | COMPLETE);
                }
            }
            if pair.has(PairBits::Pushed) {
                if pair.push_ttl > 1 {
                    pair.push_ttl -= 1;
                } else {
                    pair.drop_bits(PairBits::Pushed);
                    pair.flags &= !FIRST_PUSH;
                }
            }
            if pair.flags & PARK != 0 && now >= pair.park {
                pair.flags &= !PARK;
            }
            let kept = !pair.is_empty();
            if !kept && pair.wide != NO_WIDE {
                free.push(pair.wide);
            }
            kept
        });
    }
}
