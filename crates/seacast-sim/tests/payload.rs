//! The payload type end to end through a node: real chunks from `build_group`,
//! level 1 with the proof checked off the chunk path, level 2 on any K of them,
//! and the body delivered.

use std::collections::HashMap;

use seacast_codec::{
    MerkleProof, SegmentDescriptor, SegmentedCodec, SnappyBlockCompressor, UNIT, VecBufferPool,
    build_frame, build_group, build_merkle_layers, chunk_id, group_id, group_key,
    merkle_proof_from_layers, split_frame,
};
use seacast_core::{
    BoundedDeferredStore, Bytes32, ChunkMsg, Duty, GroupId, GroupState, InterestKind, Join,
    NodeConfig, NodeId, PeerId, PenaltyReason, Rpc, RuntimeEnv, SeacastNode, SplitMix64,
    TimerEvent, Timestamp, TypeParams, ValidationResult,
};
use seacast_sim::{
    PAYLOAD,
    payload::{PayloadCatalog, PayloadHost},
};

const TOPIC: &[u8] = b"/eth2/00000000/execution_payload_chunk/ssz_snappy";
const SLOT: u64 = 7;
const ROOT: Bytes32 = [0xb1; 32];
/// A payload chunk's context in this domain: its slot, then its block root.
const CONTEXT_LEN: usize = 40;

fn context(slot: u64, root: &Bytes32) -> [u8; CONTEXT_LEN] {
    let mut context = [0; CONTEXT_LEN];
    context[..8].copy_from_slice(&slot.to_le_bytes());
    context[8..].copy_from_slice(root);
    context
}

type Chunk = ChunkMsg<Vec<u8>>;
type Catalog = PayloadCatalog<Blocks, VecBufferPool, Vec<u8>>;

/// The domain: the blocks installed, each with its slot and the group id its
/// bid commits, and the groups whose chunks wait for a block.
#[derive(Default)]
struct Blocks {
    installed: HashMap<Bytes32, (u64, Bytes32)>,
    waiting: Vec<(Bytes32, GroupId)>,
}

impl PayloadHost for Blocks {
    fn authenticate(
        &mut self,
        group: &GroupId,
        header_id: &Bytes32,
        context: &[u8],
    ) -> ValidationResult {
        let slot = u64::from_le_bytes(context[..8].try_into().unwrap());
        let root: Bytes32 = context[8..].try_into().unwrap();
        match self.installed.get(&root) {
            None => {
                self.waiting.push((root, *group));
                ValidationResult::Defer
            }
            Some(&(of, bid)) if of == slot && bid == *header_id => ValidationResult::Accept,
            Some(_) => ValidationResult::Reject,
        }
    }

    fn authenticable(&self, group: &GroupId) -> bool {
        self.installed
            .iter()
            .any(|(root, &(slot, bid))| group_key(PAYLOAD, &bid, &context(slot, root)) == *group)
    }

    fn node_id(&self, peer: PeerId) -> NodeId {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&peer.to_le_bytes());
        id
    }
}

#[derive(Default)]
struct Env {
    to_decode: Vec<GroupId>,
    delivered: Vec<(GroupId, Vec<u8>)>,
    penalties: Vec<(PeerId, PenaltyReason)>,
}

impl RuntimeEnv<Vec<u8>> for Env {
    fn now(&self) -> Timestamp {
        1.0
    }
    fn schedule_after(&mut self, _delay: f64, _event: TimerEvent) {}
    // Nothing is written in these tests: what the node sends is taken and dropped.
    fn send(&mut self, _peer: PeerId, _item: seacast_core::Queued, _urgent: bool) -> bool {
        true
    }
    fn start_decode(&mut self, group: GroupId) {
        self.to_decode.push(group);
    }
    fn deliver(&mut self, group: GroupId, payload: Vec<u8>) {
        self.delivered.push((group, payload));
    }
    fn penalise(&mut self, peer: PeerId, reason: PenaltyReason) {
        self.penalties.push((peer, reason));
    }
}

fn join() -> Join {
    Join {
        object_type: PAYLOAD,
        interest: InterestKind::All,
        custody_count: 0,
        duty: Duty::Forward,
        colours: 1,
    }
}

struct World {
    node: SeacastNode<Vec<u8>>,
    env: Env,
    catalog: Catalog,
    rng: SplitMix64,
    store: BoundedDeferredStore,
}

impl World {
    /// A node with peer 1 connected and joined, and no block installed.
    fn new() -> Self {
        let catalog = PayloadCatalog::new(
            Blocks::default(),
            SegmentedCodec::new(VecBufferPool, CONTEXT_LEN, TOPIC),
            TypeParams::default(),
            join(),
        );
        let mut world = Self {
            node: SeacastNode::new(NodeConfig::default()),
            env: Env::default(),
            catalog,
            rng: SplitMix64::new(3),
            store: BoundedDeferredStore::default(),
        };
        world.node.connect_peer(1, true, &mut world.env, &world.catalog);
        let mut rpc = Rpc::default();
        let _ = rpc.joins.push(join());
        world.rpc(rpc);
        world
    }

    fn rpc(&mut self, rpc: Rpc<Vec<u8>>) {
        self.node.on_rpc(1, rpc, &mut self.env, &mut self.catalog, &mut self.rng, &mut self.store);
    }

    fn chunk(&mut self, chunk: Chunk) {
        self.rpc(Rpc { chunk: Some(chunk), ..Rpc::default() });
    }

    /// The block is installed: the domain can now tell of the groups that
    /// waited for it.
    fn install(&mut self, descriptor: &SegmentDescriptor) {
        let host = &mut self.catalog.host;
        host.installed.insert(ROOT, (SLOT, group_id(descriptor)));
        let mut groups: Vec<GroupId> = Vec::new();
        host.waiting.retain(|&(root, group)| {
            if root == ROOT && !groups.contains(&group) {
                groups.push(group);
            }
            root != ROOT
        });
        self.node.on_groups_authenticated(
            &groups,
            &mut self.env,
            &mut self.catalog,
            &mut self.rng,
            &mut self.store,
        );
    }

    /// The host's side of level 1 and level 2: check each waiting chunk's
    /// proof, then decode what the node asks to have decoded.
    fn run(&mut self) -> usize {
        let mut verified = 0;
        while let Some((peer, chunk)) = self.node.pop_unverified() {
            let verdict = self.catalog.codec.check_proof(&chunk);
            self.node.on_validated(
                peer,
                chunk,
                verdict,
                &mut self.env,
                &mut self.catalog,
                &mut self.rng,
                &mut self.store,
            );
            verified += 1;
        }
        for group in std::mem::take(&mut self.env.to_decode) {
            self.node.decode_group(group, &mut self.env, &mut self.catalog, &mut self.rng);
        }
        verified
    }
}

/// The chunks of a group at `SLOT` in the block `ROOT`, as a peer sends them.
fn chunks(
    descriptor: &SegmentDescriptor,
    leaves: &[Vec<u8>],
    proofs: &[MerkleProof],
) -> Vec<Chunk> {
    let context = context(SLOT, &ROOT);
    let group = group_key(PAYLOAD, &group_id(descriptor), &context);
    (0..leaves.len())
        .map(|i| {
            let frame = build_frame(descriptor, &context, &proofs[i], &leaves[i]);
            ChunkMsg {
                type_id: PAYLOAD,
                group,
                index: i as u32,
                cached_id: chunk_id(TOPIC, PAYLOAD, &group, i as u32, &frame),
                frame,
            }
        })
        .collect()
}

fn built(body: &[u8]) -> (SegmentDescriptor, Vec<Chunk>) {
    let (descriptor, shards) =
        build_group::<Vec<u8>, _, _>(body, &mut VecBufferPool, &SnappyBlockCompressor);
    let leaves: Vec<Vec<u8>> = shards.iter().map(|s| s.data.clone()).collect();
    let proofs: Vec<MerkleProof> = shards.iter().map(|s| s.proof).collect();
    let chunks = chunks(&descriptor, &leaves, &proofs);
    (descriptor, chunks)
}

fn body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i / 3 % 29) as u8 ^ (i >> 10) as u8).collect()
}

/// Chunks that arrive before their block wait for it; once it is installed any
/// K of them, here the parity alone, give every chunk and the body.
#[test]
fn a_payload_is_delivered_from_any_k_chunks() {
    let body = body(4 * UNIT + 321);
    let (descriptor, chunks) = built(&body);
    let (k, n) = (descriptor.k() as usize, descriptor.n() as usize);
    let group = chunks[0].group;
    let mut world = World::new();

    for chunk in &chunks[k..] {
        world.chunk(chunk.clone());
    }
    assert_eq!((world.node.pending.len(), world.run()), (k, 0));
    assert!(world.node.chunks.is_empty());

    world.install(&descriptor);
    assert!(world.node.pending.is_empty() && world.node.chunks.is_empty());
    assert_eq!(world.run(), k);
    assert_eq!(world.node.group_state(&group), Some(GroupState::Complete));
    assert_eq!(world.env.delivered, vec![(group, body)]);
    assert!(world.env.penalties.is_empty());
    // Every chunk is held, the rebuilt data chunks as the builder made them.
    for chunk in &chunks {
        let held = world.node.chunks.get(&(group, chunk.index)).expect("held");
        assert_eq!((&held.frame, held.cached_id), (&chunk.frame, chunk.cached_id));
    }
    assert_eq!(world.node.chunks.len(), n);
}

/// What fails the static checks is rejected at once; what fails only its proof,
/// when the host has checked it. Neither is stored, and both count against the
/// sender.
#[test]
fn chunks_that_fail_level_1_are_rejected() {
    let (descriptor, chunks) = built(&body(2 * UNIT + 5));
    let mut world = World::new();
    world.install(&descriptor);

    // A chunk of the wrong length, which its own codec refuses, and one of a group
    // whose descriptor is not the bid's, which the domain refuses.
    let mut short = chunks[0].clone();
    short.frame.pop();
    short.cached_id[40] ^= 1;
    world.chunk(short);
    let (_, uncommitted) = built(&body(UNIT + 9));
    world.chunk(uncommitted[1].clone());
    assert_eq!((world.env.penalties.len(), world.run()), (2, 0));

    // A chunk with a byte changed: the right shape, the wrong content.
    let mut forged = chunks[2].clone();
    *forged.frame.last_mut().unwrap() ^= 1;
    forged.cached_id[40] ^= 1;
    world.chunk(forged);
    assert_eq!(world.env.penalties.len(), 2);
    assert_eq!(world.run(), 1);
    assert_eq!(world.env.penalties.len(), 3);
    assert!(world.node.chunks.is_empty());

    world.chunk(chunks[2].clone());
    assert_eq!(world.run(), 1);
    assert_eq!((world.node.chunks.len(), world.env.penalties.len()), (1, 3));
}

/// A builder that commits chunks which are not a codeword: each passes level 1,
/// the group fails level 2, nothing is delivered and the group is dropped.
#[test]
fn an_inconsistent_group_is_dropped() {
    let (descriptor, good) = built(&body(3 * UNIT));
    let k = descriptor.k() as usize;
    let mut leaves: Vec<Vec<u8>> =
        good.iter().map(|c| split_frame(&c.frame, CONTEXT_LEN).unwrap().data.to_vec()).collect();
    leaves[k][0] ^= 1;
    let tree = build_merkle_layers(&leaves);
    let descriptor = SegmentDescriptor { root: tree.root(), ..descriptor };
    let proofs: Vec<MerkleProof> =
        (0..leaves.len()).map(|i| merkle_proof_from_layers(&tree, i)).collect();
    let chunks = chunks(&descriptor, &leaves, &proofs);
    let group = chunks[0].group;

    let mut world = World::new();
    world.install(&descriptor);
    for chunk in &chunks[k..] {
        world.chunk(chunk.clone());
    }
    assert_eq!(world.run(), k);
    assert_eq!(world.node.group_state(&group), Some(GroupState::Invalid));
    assert!(world.env.delivered.is_empty() && world.env.penalties.is_empty());
}
