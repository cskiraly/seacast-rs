# Open items

Working notes for whoever picks this up next. Nothing here is decided unless it says so. Remove an item when it is done; put design that has landed in `README.md`, not here.

## Integration into Silver (network and control tiles)

The intended split, discussed but not designed in detail and not checked against Silver's code:

- **Control tile:** `SeacastNode` and the catalog's `Domain` and `Policy`.
- **Network tile:** the per-peer send queues (the state `SendQueues` holds: lanes, owed offers and answers, the byte window), next to the existing per-peer outbound gossip queues. Received chunks are written to tcache there, and the stateless part of level 1 runs inline, so the network tile links `seacast-codec`.

What this needs from seacast-rs:

- **Split `on_write`.** It does two things in one call, and both read or write node state: it filters the item (drop a chunk the peer now holds, drop asks now held or gated) and it applies the effects of the write (start an ask's promise, record a chunk as sent, update the source's paced holding). Across tiles these become two one-way flows:
  - control to network: the cancel callbacks that exist (`cancel_chunk`, `cancel_asks`, `cancel_group`), so the network tile needs only an index of its queued items by (peer, group, index), not a copy of the peer's holdings;
  - network to control: a "written" event per item with the write's timestamp, so a promise starts from the real write time.
  A cancel that loses the race with a write costs one redundant chunk.
- **Level 1 in the network tile is two of its three steps:** the codec check and the Merkle proof need only the chunk and static per-type configuration; the domain step needs consensus state and stays in control. This runs the proof before the domain step, the reverse of the specification's cost order. Judged acceptable (the proof is cheap and bounded by bytes received; a forged group still fails at the domain step), not measured under attack traffic. The control tile's catalog then answers `true` and `Accept` for the codec steps, and the `Pending` path is unused.
- **Receive-side deduplication in the network tile: not at first.** It needs the seen-id set, and a duplicate must still reach control because its sender is owed a HAVE. A small seen cache that turns a duplicate into an event without payload is a possible later step.
- **The byte window is node-wide.** It works as is only if one network tile owns all peers. With peers spread over several tiles it must be split or shared.

Questions that need Silver's code read (the outbound queue of the network tile, and tcache):

- **Chunk lifetime in tcache.** The node keeps a handle for the group's whole life, to serve late asks and to decode from any K chunks. If tcache can overwrite an entry before the group ends, the handle dangles. Either tcache is sized for the worst case over a group's lifetime, or accepted chunks are copied into a per-group slot store, which the codec's in-place functions (`complete_in_place`, `body_into`) already support.
- **Where decode runs.** It takes milliseconds a group and belongs in neither tile's hot loop. `RuntimeEnv::start_decode` is the hook for handing it to a worker.

## Open design questions in the core

- **HAVE and WANT carry no type.** The node asks `Policy::type_of_group` for a group it has not opened. Carrying the type on those messages would remove that method.
- **One catalog object implements all three traits.** `PayloadCatalog` therefore forwards every `TypeCodec` method to its `SegmentedCodec`. Passing codec, domain and policy to the node as separate arguments would remove the forwarding and change every entry point's signature.
- **No catalog composes several types.** Serving a standalone type next to the payload type is left to the host; only the helpers (`standalone_group`, `check_standalone`) exist.
- **A cancelled push leaves an offer owed** through `owe_offer`. Whether the node should send that offer itself was left open.
- **A popped chunk must get a verdict.** A host that takes a chunk from `pop_unverified` and never calls `on_validated` leaves its id in `verifying` until the group ends, and other copies are refused meanwhile. There is no timeout.
- **A deadline is fixed when first asked**, and a group known only from offers has none until its first chunk.
- **Memory.** The per (peer, group) table is the largest. Ideas not tried: peer lists held inline, a dense index for pairs. Memory has not been measured again since the core became domain-agnostic.

## `data_only_root`

An experiment behind a cargo feature of `seacast-codec` (README, "Where this differs"). Open:

- **A node that decodes from bad parity drops the group.** With two roots the data chunks alone still prove the body, so the node could discard the parity it holds, take back its claim and go on pulling data chunks. `drop_group` does none of that: the group goes `Invalid`. leanP2P's Lemma 1 (delivery whatever the parity holds, if the K data chunks are available) therefore holds only for a node that reaches K without a bad parity chunk.
- **No notice of bad parity.** A node does not detect parity it did not decode from, and nothing tells its peers. leanP2P has a `BAD_PARITY` message.
- **Parity that no node received is never created.** Repair pushes rebuilt data chunks only. With a release of few chunks the group's parity indices stay empty.
- **The simulator does not run it.** Its five settings use a catalog of their own with no bytes. Only `crates/seacast-sim/tests/payload.rs` runs the feature through a node, with one peer. The effect on diffusion (fewer holders of parity, no `claim_all`, so no deferral by claim) is not measured.
- **The codec benchmark's last table** times level 2 under both commitments in one build; the lines above it follow the build's feature.
- **`just clippy` lints only the feature build** since it passes `--all-features`.

## Reed-Solomon

- **The FFT parity path covers K a power of two only.** For another K the points `0..2K` are not closed under XOR and the matrix is used. Whether such a K can use a transform without changing the code is open; padding K up changes the parity, so it is a specification change.
- **The NEON and ARMv8 SHA2 arms are compiled and linted for `aarch64-apple-darwin` where they are written, and run on one Apple core**: its tests and benchmark, which asserts every root.
- **`STREAMS` is four on aarch64 by analogy with x86.** On one Apple core two, three and four streams hash at the same rate: its SHA2 rounds overlap less than SHA-NI's do on the x86 core tried, and two streams already reach the limit. Four is kept for a core that overlaps more; none has been tried.
- **The NEON three-input XOR needs the `sha3` target feature**; without it two XORs are used. Only the `sha3` path is compiled here.
- **The row count from which `rs_parity_rows` takes the transform** is one constant for the GFNI kernel, measured, and one for the others, placed from the benchmark's sweep on AVX2 and on one NEON machine: two shapes each, not a sweep of both paths.
- **`combine` copies each strip of the sources side by side on the kernels that make a pass per row**, since segments of one buffer evict each other from the cache. Measured on AVX2; on NEON it is inferred from one machine's benchmark, where the in-place lines were several times slower than the same work on separately allocated chunks, and not yet rerun there. The destinations are still written where they lie.
- **The GFNI and NEON arms compute several rows a pass; AVX2 does not.** It has sixteen registers and needs two for a coefficient's tables, so at most four rows of one vector; not tried.
- **Running the transform in the parity chunks themselves, with no work buffer, was tried and was slower.** Chunks a multiple of the page size apart land in the same cache sets.
- **`fft::parity` allocates its work buffer on every call**, K strips.
- **Recovery is still by matrix.** Its cost grows with the chunks lost; a transform-based erasure decode would bound it. Not tried.
- **`gfni::row` is `#[inline]`** because adding the FFT module stopped it being inlined into `combine`, which slowed recovery. The other kernels' `row` were already out of line and are unchanged.

## Level 2 hashing

- **Four leaves at a time on SHA-NI matched the 16-lane AVX-512 kernel on full batches** on the one machine tried (Zen 5), so `sha256/x16.rs` could go there. Not measured on an Intel core, where the SHA-NI rounds may not overlap as well; the 16-lane kernel stays until it is.
- **`ChunkMsg::memo` is 32 bytes a chunk the node holds**, in every table of chunks. Memory has not been measured with it.
- **A chunk whose `memo` is zero is hashed at level 2**: one from the wire that the host's proof check did not go through `SegmentedCodec::check_proof`, and a publisher's own (`build_chunks` leaves it zero, since it would have to hash each leaf again).
- **`decode_and_reencode` takes the digest of the K chunks it decodes from only.** A parity chunk given beyond those is computed again and hashed, as the specification's re-encode does, so that every node gives the same verdict. `complete_in_place` does not: it leaves a chunk that is there as it is, so a group whose committed parity is not the code's passes at a node that holds all the data. That was so before the digests were reused.
- **A slot that changes after its level 1 is not detected by level 2**, since its digest is not recomputed. Before, the full rehash caught it.

## The chunk id

The codec computes the chunk id with the Altair message-id formula (`MESSAGE_DOMAIN_VALID_SNAPPY`, topic as an input). That formula is the last consensus-specific thing in `seacast-codec`. It was kept on purpose, to follow the specification with the topic supplied by the domain. Moving it out means `build_chunks` and `decode_and_reencode` take an id function instead of a topic.

## Small cleanups

- `projected`, `valid_have`, `tie_room` and `interest_satisfied` keep an unused `_catalog` parameter.
- `tied` and `tied_bits` appear to hold the same thing since ties became keyed by group; check and merge.
- `tied_to_root` keeps the specification's name though the core has no root.
- The doc comment on `RuntimeEnv::owe_offer` says "an offer the host refused"; it is also called for a refused chunk push and a cancelled push.
- `build_chunks` copies each data segment into a frame with its header and proof: one extra copy of the body at the publisher. The benchmark does not cover it.

## Tests and simulator

- The simulator's domain returns no deadline (it has no slots), so deadlines are covered only by `a_deadline_ends_a_group_and_bounds_its_tombstone` in `crates/seacast-core/tests/limits.rs`.
- The host in `crates/seacast-sim/tests/payload.rs` has a slot in its context and could return a slot-boundary deadline; it returns none.

## Specification

- The departures listed in the README have not been written into `informed-diffusion-spec`. The spec repository is unchanged.
- That list was built from the changes made here, each checked by searching the spec for the rule in question. A full audit of the core against both protocol files has not been done, so older departures may be missing.
- "Serving" in that list: the ask-legitimacy check was compared with the `on_want` pseudocode only. The spec's prose may already state the condition, in which case it is an enforcement and not a departure.
