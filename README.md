# `seacast-rs`

A Rust implementation of **SEACAST v2**: chunked, erasure-coded diffusion of large objects (the execution payload, data columns, rows) between peers. It follows `protocol-v2.md` and the rules that document carries over from `protocol.md`, from [Csaba Kiraly](https://www.github.com/cskiraly)'s `informed-diffusion-spec`  [repository](https://github.com/cskiraly/informed-diffusion-spec).

The protocol logic is a single-threaded state machine with no I/O. A host supplies the transport, the clock, the buffers and the domain's checks.

## Where this differs from the specification

- **The specification implemented is `protocol-v2.md` of draft v0.10.1.** Applied from it since the draft this code was written against: a refusal's PRUNE names its sender's side; a GRAFT is answered, the grafter entering the relation at the yes, with a backoff after a PRUNE (§4.1); the symmetric relation (`SYMMETRIC`), and candidates whose interest holds the family (§4.1); a JOIN, GRAFT or PRUNE is owed at a full queue, in order; a source's holding and offers follow a chunk's acknowledgement, and a source with no relation peer for a colour pushes and offers to its links (§4.7 `origin_acked`, `source_pool`); a tied index beyond the group's count is dropped at release, and a tie on a group never told of expires; the announcers beyond an ask's list are tried in a keyed order (`protocol.md` §6.1); `DEFER_WINDOW` is one second; the probe of a claim (R5) is marked (`Want.probe`), draws a random index, is answered by the claimant once for the asker and group whatever the asker holds, and passes only on the claimant's own copy; a sampler asks one peer for each sample in two phases, and a sample no link serves goes as a routed request (§4.5, §4.10). The bullets below say where these differ from the draft.
- **The node opens no link: it reports what the floors are short of.** `keep_floor` and `keep_coverage` open links (§4.1). Here `SeacastNode::link_deficits` reports, per family, the links missing for the relation floor and for the floors `Policy::link_floors` states (repair, source, coverage), and the host opens them. A link counts once both JOINs are in, not from its opening, so the host subtracts the links it has opened and that are not joined yet. Which candidate to open, the draft's most families covered, is the host's.
- **`FORWARD_LIMIT` is per period, not per slot.** The node has no slots. `SeacastNode::reset_period` starts a new period; a host with slots calls it at each slot boundary. The count is kept by `NodeId`, so connecting again does not reset it; the draft does not say. The counts are bounded by `max_peers`: with the table full, a request of a node without a count is not passed on. A host must therefore call `reset_period`.
- **A routed request's first hop is drawn at random.** The draft takes the link nearest the sample's family where routing neighbours are kept (`route_next`, `ROUTE_FLOOR`, an option); none are kept here. With `ROUTE_HOPS` above one, a further step goes to any forwarding link.
- **A forwarder picks its next hop by a keyed hash, not by a draw**, as it has no source of randomness where an ask is handled. It passes a request on only where it also keeps the request standing, since the answer returns by that.
- **The keyed order is under `fxhash`, not HMAC-SHA-256.** `protocol.md` §6.1 asks only for an order no peer can predict or arrange, and gives HMAC as the reference. `fxhash` under `NodeConfig::order_key` is not cryptographic: a peer that saw many of the node's choices could recover the key. The same hash picks a forwarder's next hop.
- **The scope of "one sample per peer" is the domain's.** The draft keys `sampled_from` by block. Here `Domain::sample_scope` maps a group to an opaque id, the group itself unless the domain says otherwise, and an entry lasts `group_ttl` from the ask.
- **The asks held back by `SAMPLE_OUTSTANDING` are taken also when the group of the wait that ended has expired.** The draft returns before that; the asks held may be of another group of the scope.
- **A peer of high custody is the policy's to tell** (`Policy::high_custody`): the base custody count is the domain's. The default knows only interest `ALL`.
- **A stale tie is told by its sender's silence, not by a slot.** The draft drops a tie when the slot its sender's first copy named leaves the live window. Here a tie on a group with no state goes when its sender has not named the group for `group_ttl`.
- **`FORWARD_LIMIT` defaults to 1 and `PRUNE_BACKOFF` to 12 seconds.** The draft states both by their bounds.
- **A link counts from the JOIN's hand-over, not from its queueing.** The draft counts a link in `links(T)` only once its JOIN is queued; here `join_sent` is set when the JOIN is handed to the host, which may still owe it. What is sent before it is written is ignored by the peer.
- **The backoff after a PRUNE is kept only for a relation this node held or had asked for.** The draft records it for any PRUNE; that would let a peer make the node keep an entry per family and colour it names.
- **The window's timeout acknowledges without the room's check.** On `TimerEvent::WindowTimeout` the node frees the room if it is still held and, for a chunk it published, takes the event as the acknowledgement when no holding came. It does the second on any such event of a group it publishes, whether or not the room was still held; after a holding the chunk is acknowledged already, so the result is the same.
- **A departed claimant's claims go with its connection**, and it is then not judged by its probe. The draft announces this and has not yet written it into its pseudocode.
- **A claimant's exempt answer keeps its room in the window at the asker's holding.** The answer to a probe is written whatever the asker holds, so a holding that names it frees nothing: the room goes at `WINDOW_TIMEOUT`.
- **Bitmaps are 1024 bits** (`BITMAP_WORDS` in `bitmap.rs`). `protocol.md` allows 8192 indices in a plain group and a HAVE bitmap. 1024 chunks carry a 16 MiB body uncoded, which is past what consensus gossip lets one message be; a group or an index beyond it is refused. Every table, message and queue item that holds a bitmap grows with the constant, which is why it is not 8192.
- **A body of more than 128 segments is coded too**, where the specification sends it plain (`MAX_CHUNKS`). A group of more than 256 chunks is coded over GF(2^16), since GF(2^8) has no more points: up to `MAX_CODED_CHUNKS` chunks, the 1024 a bitmap names, so a body of up to 8 MiB. The code and the layout of a chunk are those of Leopard-RS (`leo_encode` with K recovery shards), so a chunk is a Leopard shard: the field is GF(2)[x] / (x^16 + x^5 + x^3 + x^2 + 1) with an element written in Leopard's Cantor basis; a chunk is blocks of 64 bytes, the low bytes of 32 symbols and then their high bytes, so the segment size is a multiple of 64; with m the power of two from K up, the data are the values at the points `m..m + K` of a polynomial below degree m that is zero at `m + K..2m`, and parity chunk `K + j` is its value at the point `j`. A group of 256 chunks or fewer keeps the specification's code, which is not Leopard's. The descriptor's version stays 2 and the field follows from its count. A node of the specification refuses such a descriptor. A body past 8 MiB still goes plain.
- **Evidence** (`[D6]`) is carried in the message types and not acted on. The specification carries it and does not define it.
- **The wire encoding** in `seacast-codec::wire` is this implementation's. `protocol-v2.md` §7 leaves the standalone binding's bytes open, and the gossipsub bindings are not implemented.
- **A chunk and control messages are separate messages on the wire**, each starting with a type: a chunk's object type, or `CONTROL_TYPE` for joins, holdings, offers, asks, grafts, prunes and evidence. The specification's RPC carries a chunk and control together. A reader knows from the type how the chunk's frame is laid out, so it runs level 1 on the frame's head before the data has arrived. A host hands the node a chunk and the control sent with it as two `on_rpc` calls, chunk first: the node then responds twice where the specification's `respond` runs once an RPC.
- **Up to 16 joins a message** (`MAX_ENTRY_CONTROL`): a limit of this encoding.
- **The chunk's layout** is `type | group | index | frame`, with the frame `header | context | proof | data`. The specification's `Chunk` has `slot` and `beacon_block_root` as fields of their own and an optional descriptor; here they are the payload's context, and a header is present or absent by type.
- **The group id** is `sha256(0x03 || type || header id || context)`. The specification's `group_key` is `sha256(0x03 || group id || slot)`: the type and the block root are not bound.
- **The chunk id** is `group | index | content`, with `content` the first 20 bytes of the digest of the chunk's Merkle leaf, or of the group id for a standalone chunk. The specification's content id is the Altair message id over a topic and the chunk. Level 1 binds a chunk's data to its group and index, so the leaf's digest names the same bytes, and it is the hash level 1 computes anyway: the chunk is not hashed a second time, and no topic is needed.
- **The gate** is one call, `on_groups_authenticated`, where the specification has `on_block_installed` and `on_header_validated`.
- **Level 2 may run away from the node.** The draft's `decode_group` decodes in place. Here `RuntimeEnv::start_decode` hands the host the chunks to decode and `SeacastNode::on_decoded` takes the result, so the decode may run on another thread; the chunks are those held when the decode was started. `SeacastNode::decode_group` does both on the node's thread.
- **Level 1** is three steps where the specification has one `validate_chunk`: the codec's check of the chunk alone, the domain's answer on the group, then the proof. The domain is asked once a group and its answer is kept, so later chunks of an authentic group run only the codec's steps.
- **The live window** is a deadline the domain gives a group (`Domain::deadline`), a time on the host's clock, where the specification has the group's slot. A group and its deferred chunks go at the deadline at the latest, and its tombstone is kept until it. A group with no deadline has only the node's lifetimes: a deferred chunk goes `GROUP_TTL` after it arrived and a tombstone after `tombstone_ttl`.
- **Standalone types** are new: one chunk a group, no header and no proof, with the group id `sha256(0x04 || type || frame)` and a level 1 that is that hash, index 0 and a length limit. The specification defines no type without a header.
- **HAVE and WANT carry their group's object type**, which the specification's do not. With more than one type a node cannot tell the type of a group it knows only from an offer otherwise.
- **A duplicate may be settled by its head.** The specification's `on_chunk` takes a whole chunk. `SeacastNode::on_chunk_head` lets a host that checks the proof itself drop a copy before reading its body: a copy of a chunk held is answered with a holding, and a copy of a chunk that waits for the domain ties its sender. Neither copy is verified, so a peer can be tied to, or told of, a chunk it sent only the head of. The copy that answers a probe is always read.
- **Serving** has two checks the specification's `on_want` does not have: an ask for an index this node neither holds nor has interest in, as the peer sees that interest, is refused and penalised (`AskOutsideOfferOrInterest`), a routed request to a node with duty excepted, and at most `max_served_per_heartbeat` chunks are served in a heartbeat over all peers, beside `SERVE_LIMIT` per peer and group.
- **The claim at K** is what the type's codec says a node can produce from the chunks it holds (`TypeCodec::producible`), where the specification's `claim_group` sets all `N` bits. The default is all `N`, and a holding carries `claim_all` only when its bitmap is whole.
- **`data_only_root`** (a cargo feature of `seacast-codec`, off by default) replaces the commitment of a coded group. The descriptor has two roots, one over the `K` data chunks and one over the `N - K` parity chunks, and a chunk's proof is a path in its own tree. Level 2 checks the data root and computes no parity, where the specification re-encodes and checks one root over all `N`. A node then holds the data chunks and the parity it received, claims those without `claim_all`, and repairs with data chunks only. The descriptor is 32 bytes longer, so group ids and the wire differ from a build without the feature. See "Completion, decode and delivery".
- **State a peer can create** has limits the specification leaves open or does not name: `max_pairs` and `max_wide_pairs` on (peer, group) records, and `max_relations_per_link`.
- **The asks open at one peer are bounded** by `max_asks_per_peer`, and the ask records of the node by `max_ask_peers`. The specification bounds only the asks made of a peer within a heartbeat (`MAX_IHAVE_LENGTH`). An ask over a bound is not made: its group is taken up again at the next heartbeat, as for an offer over the IHAVE limits.

## Crates

| crate | what it is |
| --- | --- |
| `crates/seacast-core` | The state machine, `SeacastNode`: relations, chunk handling, push, pull, repair, the send window. No dependency but `fxhash`. |
| `crates/seacast-codec` | What a segmented object type needs: segmentation, Snappy, Reed-Solomon over GF(2^8) and, past 256 chunks, GF(2^16), SHA-256, the Merkle tree, and a wire encoding of the messages. |
| `crates/seacast-sim` | Everything specific to the domain: the type ids (payload, column, row), the payload type's catalog, and a discrete-event simulator that runs the five settings of `protocol-v2.md` §6.2 and checks the protocol's invariants. |

## The host's contract

`SeacastNode` never blocks, spawns nothing and holds no lock. Every entry point takes `&mut self`, so one thread owns a node and calls it from its own loop.

```mermaid
flowchart LR
  subgraph host["Host (one thread)"]
    T["transport"]
    TW["timer wheel"]
    V["proof checker"]
    D["decoder"]
    CS["domain: what a group belongs to"]
  end
  N["SeacastNode"]

  T -- "on_rpc(peer, rpc)" --> N
  T -- "connect_peer / disconnect_peer" --> N
  TW -- "on_timer(event)" --> N
  V -- "on_validated(peer, chunk, verdict)" --> N
  D -- "on_decoded(group, given, object, rebuilt)" --> N
  CS -- "on_groups_authenticated(groups), end_group(group)" --> N

  N -. "schedule_after(delay, event)" .-> TW
  N -. "wake_writer(peer)" .-> T
  N -. "start_decode(group, job)" .-> D
  N -. "deliver(group, object), penalise(peer)" .-> CS
  T == "next_to_send(peer)" ==> N
  V == "pop_unverified()" ==> N
```

Solid arrows are calls into the node. Dotted arrows are `RuntimeEnv` callbacks: they only record what the host should do. The thick arrows are polled by the host. The node owns the send queues: `wake_writer` says a peer has something to write, and the host takes it with `next_to_send`.

A `PeerId` names a connection, not a node: the host may use it again once the connection has closed. Every peer id is below `CapacityConfig::max_peers`: the per-connection records are a slab indexed by peer id, and the node panics on an id out of range. Admission of a connection is therefore the host's. What the node gives out for a connection and takes back later carries a `GenerationPeerId`: the peer id with the count of its slot's connections in the high 32 bits. `pop_unverified` returns one, `on_validated` takes it, and `TimerEvent::Resample` holds one. The host passes it back unchanged and reads the peer with `peer_id()`. A verdict or a timer for a connection that has closed is dropped, though another connection has its peer id. The node takes the connection's `NodeId` from `Policy::node_id` at `connect_peer`, and the host allows one connection a node at a time. All state of a connection goes at `disconnect_peer`, except its parks, which are kept by `NodeId` until their end and return on the node's next connection. The count of routed requests passed on (`forwarded`) is by `NodeId` from the start.

Three steps may run on other threads, each as a request out and a result back in: the proof check (`pop_unverified`, `on_validated`), level 2 (`start_decode`, `on_decoded`) and the domain's word on a group (`Domain::authenticate` answers `Defer`, the host calls `on_groups_authenticated`). The node itself stays on one thread.

The traits a host implements, in `seacast_core::traits`:

| trait | role |
| --- | --- |
| `ChunkBuffer` | A handle to a chunk's bytes. The node stores, clones and compares handles and asks only `len()`. It never reads the bytes, so a handle may be a reference into a ring cache. |
| `RuntimeEnv` | Clock, timers, the writer's wake-up, the decode job, delivery, penalties. |
| `TypeCodec` | The networking mechanics of the object types: how a chunk's frame is laid out, its index count and threshold, the checks that need no outside knowledge, decode, projection onto groups. |
| `Domain` | What a group belongs to, whether that is authentic, and when its window closes. Asked once a group, with the id of the group's header and the chunk's context bytes. Called on the node's thread: a domain whose state lives elsewhere answers from a cache, and `Defer` on a miss. Also the scope within which no peer is asked for two samples (`sample_scope`). |
| `Policy` | What this node takes part in: its types, interest, duty and parameters (`TypeParams`), the link floors it keeps (`link_floors`), and which peers hold a family (`holds_family`) or are of high custody (`high_custody`). |
| `ObjectCatalog` | The three together: what the node is given. |
| `DeferredStore` | Reservations for chunks that wait for the domain's word on their group. |
| `RngSource` | Randomness. |

Two entry points are for a host that keeps links and has periods of its own:

- `SeacastNode::link_deficits(type, catalog, report)` reports each family in which the node has fewer links than a floor asks for, with the number missing. The host polls it, for example at its heartbeat, and opens the links. The floors are the relation floor (`F_LO` links per family with duty) and those of `Policy::link_floors`. `Policy::holds_family` says whether a peer's derived interest holds a family.
- `SeacastNode::reset_period()` starts a new period of the limits the specification counts per slot: at present the routed requests passed on per peer (`FORWARD_LIMIT`).

`NodeConfig::order_key` is a secret the host draws at start. It orders the announcers beyond an ask's list and picks a routed request's next hop.

## An object's life

```mermaid
flowchart TB
  subgraph publisher["Publisher"]
    B1["body"] --> B2["Snappy compress"]
    B2 --> B3["cut into K data segments"]
    B3 --> B4["Reed-Solomon: K parity segments"]
    B4 --> B5["Merkle tree over the N = 2K chunks"]
    B5 --> B6["SegmentDescriptor: N, segment size, length, root"]
    B6 --> B7["publish: plan R targets per chunk, holding first, then chunks"]
  end

  subgraph relay["Every node on the way"]
    R1["chunk arrives"] --> R2["level 1: codec check, the domain, then the proof"]
    R2 --> R3["store, claim it (HAVE) to pushers and sender"]
    R3 --> R4["forward: push to a few, offer to the rest"]
    R3 --> R5{"K chunks?"}
    R5 -- "no" --> R6["pull what offers name and pushes did not bring"]
    R6 --> R1
    R5 -- "yes" --> R7["stop pulling, claim all N"]
    R7 --> R8["level 2: fill in missing chunks, check the root"]
    R8 --> R9["push rebuilt chunks to peers still short"]
    R8 --> R10["decompress, deliver the object"]
  end

  B7 --> R1
  R4 --> R1
  R9 --> R1
```

A group is one object's chunks. Its id is known before any chunk of it exists, so peers exchange bitmaps about it and ask for it from the start.

The node knows nothing of blocks, slots or headers. A chunk is its type, its group, its index and a frame of bytes the node never reads:

```text
type      u16
group     32 bytes
index     u32
frame     header | context | proof | data     laid out by the type's codec
```

Every length in the frame follows from the type and the header, so no field carries one. A type may have no header, no context or no proof. The context is what the domain reads (for the payload, a slot and a block root); the codec only knows its length. A group id binds the three: for a segmented type it is `sha256(0x03 || type || header id || context)`, and the header id is what the domain commits to.

## Receiving a chunk

`on_rpc` handles an RPC's parts in a fixed order: joins, the chunk, offers, asks, grafts, prunes, holdings, then one combined response. A GRAFT's answer is not part of that response: it goes through `RuntimeEnv::send_relation`, as every JOIN, GRAFT and PRUNE does, which the host must not lose to a full queue and must keep in order. A message for an object type the peer has not joined on the link is ignored.

```mermaid
flowchart TB
  A["on_chunk(peer, chunk)"] --> A0{"index a bitmap can name?"}
  A0 -- "no" --> X0["drop"]
  A0 -- "yes" --> A1{"id seen, waiting for the domain, or being verified?"}
  A1 -- "yes, and it is the stored chunk" --> H0["HAVE to the sender"]
  A1 -- "yes, waiting for the domain" --> TIE["tie the sender to that group"]
  A1 -- "no" --> A2{"group expired?"}
  A2 -- "yes" --> X1["drop"]
  A2 -- "no" --> A3["level 1: codec check, then the domain (once a group), then the proof"]

  A3 -- "Reject" --> P1["mark seen, penalise the sender"]
  A3 -- "Defer: the domain cannot tell yet" --> DF["tie, reserve, hold until on_groups_authenticated"]
  A3 -- "Ignore: too old or too early" --> X1
  A3 -- "Pending" --> Q["queue for the host: pop_unverified()"]
  A3 -- "Accept" --> OV

  Q --> HV["host checks the proof off the chunk path"]
  HV --> OV["on_validated(peer, chunk, verdict)"]
  DF -. "the domain can tell" .-> A3

  OV --> F0["for each (group, index) the chunk fills"]
  F0 --> F1{"group open?"}
  F1 -- "no" --> F2["open it, within the open-group limit"]
  F1 -- "yes" --> F3
  F2 --> F3{"already held?"}
  F3 -- "yes" --> H1["HAVE to the sender"]
  F3 -- "no" --> F4["store the handle, set the bit in received and mine"]
  F4 --> F5["close promises and offers for that index"]
  F5 --> F6["serve peers with a standing request for it"]
  F6 --> F7["HAVE, the whole bitmap: to the suppression scope and the sender"]
  F7 --> FW["forward, if this node has duty for the group"]
  FW --> CC["check_completion"]
```

A deferred chunk resumes when the host calls `on_groups_authenticated` with its group: for the payload when its block is installed, for a cell group when its header is validated, which may be earlier. The domain is asked once a group; later chunks of an authentic group need only the codec's checks.

Nothing is stored, claimed or forwarded before level 1 passes. Level 1 has three parts, in the order of their cost. `TypeCodec::check` needs only the chunk: the group id is that of its type, header and context, the index is one the header has, the length is what the header says. `Domain::authenticate` says whether the context commits that header. `TypeCodec::check_proof` reads the data (a Merkle path, a KZG proof); it may answer `Pending`, and the host then checks it and reports through `on_validated`.

`forward` works per group the chunk fills: its candidates are the push relation's peers for the chunk's colour that do not hold it and want it. It pushes to `R_NODE` minus the known holders, chosen furthest-behind first, and offers the chunk to the rest.

## Pulling what did not arrive

An offer (a HAVE with `offer = true`) says "you may ask me for these". The node asks one peer at a time per chunk.

```mermaid
sequenceDiagram
  participant A as announcer
  participant N as this node
  participant B as another announcer

  A->>N: HAVE offer {group, bits}
  Note over N: keep bits it wants and lacks in the offer ledger
  Note over N: may_ask: no ask for that chunk in the last IWANT_WINDOW
  N->>A: WANT {group, bits}
  Note over N: when the WANT is written, a promise starts (PROMISE)
  alt chunk arrives in time
    A->>N: chunk
    Note over N: promise and offers for the chunk are closed
  else IWANT_WINDOW passes without it
    Note over N: retry_offer: an untried announcer, else the least recently tried
    N->>B: WANT {group, bits}
  else PROMISE passes without it
    Note over N: A is parked for the group (PARK_TTL)
  end
```

Asks for one offer leave as the bits of one WANT, so none is left behind however many indices it names. When every announcer of a chunk is parked, a last-resort timer asks one of them again, with a doubling wait. Nothing is asked for before its group can be authenticated.

A sampler asks without an offer (`SeacastNode::sample`, `protocol-v2.md` §4.9). Each index goes in a WANT of its own, and no peer is asked for two samples of one scope. The first ask goes to a link whose interest holds the index, else as a routed request (`hops = ROUTE_HOPS`) to a forwarding link. After `SAMPLE_RETRY` without the chunk the peer is parked and another is asked, peers of high custody last, each waiting `SAMPLE_RETRY2`, with at most `SAMPLE_OUTSTANDING` asks of a scope in flight; the rest are held. When nobody is left the host is told through `RuntimeEnv::unreachable`.

A node with duty that cannot serve a routed request passes it one step on, to a link that serves the index, at most `FORWARD_LIMIT` times per asking peer and period. Beyond the limit it is silent. The answer returns through the standing ask.

## Sending

The node queues what it sends (`SeacastNode::sends`, a `SendQueues`): the queue and window of `protocol-v2.md` §4.11 and §4.12. A queued item is small: a chunk's key `(group, index)` or one control message. Each peer has a queue with two lanes: urgent (holdings, joins) and normal (chunks, offers, asks, relation control). `RuntimeEnv::wake_writer(peer)` tells the host that a peer has something to write; the host then calls `SeacastNode::next_to_send(peer)` until it gives nothing. The entry that goes on the wire is built when it is taken, so what is no longer to be sent is dropped then and an ask's promise starts then.

```mermaid
flowchart TB
  E["enqueue(peer, item)"] --> E1{"queue has room?"}
  E1 -- "no" --> E2["refused: an offer or an answer is owed instead"]
  E1 -- "yes" --> E3["urgent or normal lane; wake_writer(peer)"]

  S["next_to_send(peer)"] --> S0["requeue one owed answer if there is room"]
  S0 --> S1{"urgent lane has items?"}
  S1 -- "yes" --> S2["take the run of control items at its head"]
  S1 -- "no" --> S3{"normal lane empty?"}
  S3 -- "yes" --> S4{"offers owed?"}
  S4 -- "yes" --> OW
  S4 -- "no" --> EM["Empty"]
  S3 -- "no" --> S5["choose: control at the head, else this node's own chunks, else the rarest chunk"]
  S5 --> S6{"a chunk?"}
  S6 -- "no" --> S2
  S6 -- "yes" --> S7["look the chunk up; gone means skip"]
  S7 --> S8{"room in the byte window?"}
  S8 -- "no" --> WT["Wait: the peer joins the line of writers"]
  S8 -- "yes" --> S9["filter"]
  S2 --> S9
  S9 --> S10["chunk: drop if the peer now holds it, or is projected to complete without it"]
  S10 --> S11["asks: drop bits now held, gated or tied; start a promise for the rest"]
  S11 --> S12["track the chunk's bytes as in flight; arm WINDOW_TIMEOUT"]
  S12 --> OW["attach owed offers while the entry has room"]
  OW --> SEND["Send(entry)"]

  REL["peer's HAVE covers the chunk, or WINDOW_TIMEOUT"] --> FR["bytes leave the window; the first waiting writer is woken"]
  FR -.-> S
```

`next_to_send` returns `Send(entry)`, `Wait` or `Empty`. An entry carries at most one chunk, whose frame is one buffer handle, plus control messages. The window is in bytes and node-wide; control takes no room in it. Because the chunk is chosen at the moment of sending, a host that polls keeps the late choice: while the window is full, items wait and the rarest goes first when room returns.

## Completion, decode and delivery

```mermaid
stateDiagram-v2
  [*] --> Collecting: first accepted chunk, or publish
  Collecting --> Decoding: interest satisfied and this node decodes at K
  Collecting --> Complete: interest satisfied, no decode duty
  Decoding --> Complete: decode_group, root matches
  Decoding --> Invalid: decode_group, group inconsistent
  Complete --> Complete: a later decode duty (reconsider) may rebuild for others
  Complete --> [*]: expiry
  Invalid --> [*]: expiry
```

At K chunks the node stops pulling and claims all N before decoding: a group that fails level 2 fails at every node, so the claim can only be wrong about a group everyone drops. `RuntimeEnv::start_decode(group, job)` then hands the host the decode: the type, the shape, and the handles of the chunks held with their indices. The job borrows the node's scratch, so the host copies the handles out before it returns. The host runs `TypeCodec::decode` on them, on any thread, and passes the object and the rebuilt chunks to `SeacastNode::on_decoded` with the job's `given`. `on_decoded` stores the rebuilt chunks, fills the other groups a chunk belongs to, pushes rebuilt chunks to peers still short, and delivers. A host that decodes on the node's thread calls `decode_group` instead, which does all of it.

With `data_only_root` the claim at K is the data indices and the parity held, with `complete` set and `claim_all` clear, and `decode_group` stores only the data chunks it rebuilt. A data root that matches proves the parity chunks decoded from; a parity chunk held and not decoded from has passed level 1 only. Parity that is committed and is not the code's fails only the decodes that read it: a node that reaches K with such a chunk fails the data root and drops the group, as it does without the feature. It does not go on to collect the data chunks (`NOTES.md`).

`SegmentedCodec` in `seacast-codec` is the `TypeCodec` of a segmented type: its trait `check_proof` answers `Pending`, and `SegmentedCodec::check_proof` is the Merkle check the host runs. `PayloadCatalog` in `seacast-sim` is the payload object type for a node: a `SegmentedCodec`, a `Domain` that asks its `PayloadHost`, and the node's policy. `crates/seacast-sim/tests/payload.rs` runs real groups through a node with it, with a host that plays the consensus side.

A host that keeps chunks in a slot store uses the codec's slice-level functions, which decode a group where its chunks already lie:

```mermaid
flowchart LR
  subgraph store["Group store: one slot per chunk, slot i at offset i x segment_size"]
    direction LR
    D0["data 0"] --- D1["data 1"] --- D2["..."] --- DK["data K-1"]
    P0["parity 0"] --- P1["..."] --- PK["parity K-1"]
  end
  RX["chunk i arrives"] -- "written once" --> store
  store -- "sent from its slot" --> TX["pushes and answers"]
  store --> CIP["complete_in_place: missing slots computed, root checked"]
  CIP -. "written into their own slots" .-> store
  DK -- "body_into: the data slots end to end are the compressed stream" --> OUT["body buffer, reserved at the declared length"]
```

The code is systematic, so the K data slots are the Snappy stream itself. If every data chunk arrived, no Reed-Solomon runs. Otherwise only the missing slots are computed. Hashing follows the same rule: level 1 has already proved the leaf digest of every chunk that arrived, the host keeps it (32 bytes a chunk), and level 2 hashes only the chunks it computed before it rebuilds the tree's upper nodes and compares the root. The node's own decode does the same: `SegmentedCodec::check_proof` leaves the digest in the chunk's `memo`, a field of `ChunkMsg` the node carries and does not read, and `decode_and_reencode` takes it for the K chunks it decodes from. A chunk's bytes therefore move twice: from the network into its slot, and from the slots into the decompressed body.

| function (`seacast-codec`) | what it does |
| --- | --- |
| `SegmentedCodec` | the `TypeCodec` of a segmented type, over the functions below |
| `build_group` | body to descriptor and shards, at the publisher |
| `group_id`, `group_key` | a descriptor's id, which the domain commits; a group's id from its type, that id and its context |
| `split_frame`, `build_frame`, `build_chunks` | a segmented chunk's frame taken apart and put together; a group's chunks as a publisher hands them to the node |
| `check_frame`, `check_frame_proof`, `frame_leaf_hash` | level 1 for one chunk: descriptor, group id, index and length; then the Merkle proof. `frame_leaf_hash` is the proof check that returns the leaf digest it proved |
| `chunk_id` | a chunk's id: group, index, and 20 bytes of its leaf's digest or its group id |
| `ChunkLayout` | a type's frame layout, and level 1 in the two steps a stream reader takes: `check_head` on the bytes before the proof, `check_body` on the whole frame |
| `standalone_group`, `check_standalone` | a type with one chunk a group and no header or proof: its group id is the hash of its frame |
| `complete_in_place` | level 2 on a slot store: fill in what is missing, hash it, check the root with the digests level 1 proved for the rest, return the tree for proofs. With `data_only_root`: the missing data only, and the data tree |
| `body_len`, `body_into` | the object's length, and its bytes written into a caller's buffer |
| `ChunkHead` | what a chunk is sent with before its frame: `type | group | index` |
| `encode_control_framing` | a control message's bytes except its evidence body, for a gathered send |
| `decode_control_with` | decode a control message with a closure that turns a range of the input into a buffer handle, so nothing is copied |

`build_group`, `decode_and_reencode`, `encode_control` and `decode_control` are the versions for hosts that keep each chunk in memory of its own (`Vec<u8>`, `Arc<[u8]>`).

## A group's lifetime

A group's state lives `GROUP_TTL` after its last chunk or its completion. The domain may give a group a deadline (`Domain::deadline`, asked with `authenticate` on the group's first chunk): the time its window closes, a slot boundary say. The group then goes at the deadline if that is sooner, and the host may end any group at once with `end_group`. When a group goes, one record is removed, with the pull state that named the group, and a tombstone keeps the group from being taken up again: until its deadline, or for `tombstone_ttl` if it has none. A deferred chunk goes at its group's deadline, or `GROUP_TTL` after it arrived. From the deadline on the domain answers `Ignore` for the group, as it does for one that is too early. A group known only from offers has no deadline until its first chunk.

## State

| kept per | where | holds |
| --- | --- | --- |
| group | `groups: Groups`, one `Group` record | type, header, state, the received, rebuilt and held bitmaps, interest, timestamps, probe and repair sampling |
| chunk | `chunks`, `known_id` | the handle and id |
| chunk | `holders`, `standing`, `asked_parked` | who holds it, who asked for it ahead of its arrival, who was asked for it while parked: a bitmask of peers each |
| group | `claims` | the peers that claim it whole, a bitmask |
| ask | `offers`, `asked_at` | announcers in order, when it was last asked |
| ask and peer | `tried`, `promises` | when the peer was asked, its running promise: one flat map each, with a bitmask of peers an ask, bounded by `max_ask_peers` in all and `max_asks_per_peer` a peer |
| peer and group | `pairs: Pairs`, one record a pair | what the peer holds, what was pushed and sent to it, its offers, its park; bitmaps of 128 bits in the record, wider ones in a pool |
| peer | `slots: PeerSlab<Peer>`, one record a connection, indexed by peer id | the connection's `NodeId`, the JOINs received and sent by type, the relation counts by type, the counts per peer of the limits; reset when the connection closes |
| peer | `sends.queue: PeerSlab<PeerQueue>`, indexed by peer id | the two lanes, the offers, answers and relation messages owed |
| type, family and colour | `push_in`, `push_out`: `Relations` | the peers of each direction of the push relation, a bitmask of `max_peers` bits a key |
| type | `linked` | the peers linked for the type (both JOINs crossed), a bitmask |
| group | inside `pairs` | the peers with offers of the group and those with a holding of it, a bitmask each |
| peer and group | `named`, `tied` | the groups a peer has named, the chunks tied to a root |
| node | `forwarded` | the routed requests passed on for it this period |
| node and group | `kept_parks` | the parks of a node without a connection, until their end |
| sample scope | `sampled_from`, `samples_in_flight`, `held_samples` | the peers asked for a sample, the asks in flight, the asks held back |

All tables are sized once, in `SeacastNode::new`, from `CapacityConfig`, and nothing allocates afterwards; a test in `crates/seacast-core/src/lib.rs` counts allocations to check it. Maps are fixed-capacity `FxHashMap`s.

A full table refuses a new key instead of failing, and state a peer can make the node keep is admitted against a limit first:

- groups without a header that a peer names: `max_pending_groups` per peer;
- groups that are only named and groups that are open: `max_groups` each, counted apart, so naming groups cannot stop real ones from opening;
- push relations on one link: `max_relations_per_link` per direction;
- ties to groups the domain cannot tell of yet: `max_pending_groups` per peer;
- routed sample requests passed on: `FORWARD_LIMIT` per asking peer and period.

## Building and running

```bash
cargo test                                         # unit, limit and simulation tests
just fmt                                           # rustfmt, on the pinned nightly
just clippy                                        # clippy, warnings denied
cargo run --release -p seacast-sim                 # the five settings of protocol-v2.md §6.2
cargo run --release -p seacast-codec --example bench   # timings of the codec's hot paths
cargo test --release --workspace --all-features    # the same tests with data_only_root
```

`just clippy` passes `--all-features`, so it lints the `data_only_root` build. Lint the default build with `cargo clippy --no-deps --all-targets -- -D warnings`.

`.cargo/config.toml` sets `-C target-cpu=native`. The codec picks its SHA-256 and GF(2^8) kernels by `cfg(target_feature)`: SHA-NI or the ARMv8 SHA2 instructions, a 16-lane AVX-512 SHA-256 for Merkle leaves with SHA-NI, or the ARMv8 instructions, on four leaves at a time for those that do not fill its batch, and GFNI, AVX2 or NEON for Reed-Solomon, each beside a portable arm. Without that flag every build takes the portable arms, and with it a binary is tied to the CPU it was built on.

Parity is computed two ways, with the same bytes. The general one multiplies the data by the generator matrix: K products a parity byte. When K is a power of two the points `0..2K` are closed under XOR, and an additive FFT (Lin, Chung and Han) gives all K parity chunks in K log K products a byte column. `rs_parity_rows` takes it for a `(K, 2K)` code with such a K when enough parity rows are asked for; every other K, and a few missing rows, stay on the matrix. Recovery of missing data chunks is always by matrix; its coefficients are Lagrange basis values in closed form, so nothing is inverted. On the GFNI and NEON arms the matrix path computes up to eight output chunks in one pass over the inputs. On the arms other than GFNI it first copies each strip of the inputs side by side, since chunks kept end to end in one buffer evict each other from the cache.

## Layout of `seacast-core`

| module | contents |
| --- | --- |
| `node.rs` | `SeacastNode`: its tables, peer lifecycle, `on_rpc`, `on_timer`, admission |
| `relations.rs` | joins and the coloured push relation: `on_join`, `on_graft`, `on_prune`, `maintain_relations`, `link_deficits` |
| `groups.rs` | chunk arrival, validation routing, deferral and ties, completion, decode, expiry |
| `push.rs` | holdings, `forward`, `choose_push`, `announce`, `publish` |
| `pull.rs` | offers, asks, promises, parking, serving |
| `repair.rs` | holdings from peers, claims and the probe, repair pushes, sampler pulls |
| `gossip.rs` | the heartbeat, gossip, heartbeat-counted lifetimes |
| `window.rs` | `enqueue` and the filter applied to an entry as it is taken to be written |
| `queue.rs` | `SendQueues`: the per-peer queue and the byte window; `next_to_send` |
| `state.rs` | `Peer`, `Relations`, `Group`, `Groups`, `Pairs`, `PeerQueue`, `AskPeers`, `GossipHistory` |
| `message.rs`, `types.rs`, `traits.rs` | messages, parameters, the host's traits |
| `bitmap.rs`, `collections.rs` | the bitmap, the fixed-capacity collections, `PeerSlab` and `PeerSets` |
