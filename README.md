<<<<<<< HEAD
# Ethereum-Eclipsing-Proposal


Foundation for *Hardening Ethereum Against Eclipse Attacks*. This is the
reference substrate every later component builds on, so both parts are tested in
isolation against spec / brute-force ground truth before anything is wired on.

**Scope (stated consistently everywhere):** the simulator models peer-selection
**dynamics**, not wire-level network timing. FINDNODE is resolved synchronously;
there is no latency, packet loss, or async I/O.

## What's here

| File | Component | What it does |
|------|-----------|--------------|
| `node.py` | — | 256-bit node IDs; XOR distance and discv5 log distance |
| `routing_table.py` | comp 1 | 256 k-buckets, k-cap, replacement cache, liveness eviction |
| `network.py` | — | synchronous FINDNODE oracle + query-cost counters |
| `discovery.py` | comp 2 | iterative Kademlia lookup + bootstrap that fills the table |
| `demo.py` | — | reproducible smoke test of comps 1–2 together |
| `tests/` | — | isolation tests (15 total, all passing) |

## Spec fidelity (discv5)

- **Distance.** `distance(a,b) = a XOR b`; `logdistance(a,b) = 0 if a==b else
  256 − leading_zero_bits(a XOR b)`. Log distance *is* the bucket index (1..256).
- **k = 16** live entries per bucket (`BUCKET_SIZE`), 256 buckets, replacement
  cache of 10 (go-ethereum `maxReplacements`).
- **Insertion policy.** Incumbents are sticky: a newcomer to a full bucket waits
  in the replacement cache and is only promoted when a live entry is found dead.
  A flood of fresh IDs cannot evict established live peers — the eclipse-relevant
  invariant, tested directly (`test_incumbents_are_sticky...`). Weeks 5–6 rely on
  this being correct.
- **Lookup.** Iterative, concurrency `alpha = 3`, returns the k closest; every
  node learned is offered to the routing table, so lookups are what fill buckets.
- **FINDNODE** returns a responder's closest known nodes to the target and never
  returns the requester to itself.

## Abstractions (the "dynamics not wire" line, concretely)

- Node ID is a 256-bit int, not `keccak256(secp256k1 pubkey)`; records are an
  open dict, not signed ENRs. (IP/ASN attach to `Node.record` in week 7 without
  touching routing or discovery.)
- Wire FINDNODE asks for specific log distances; here it asks "closest to
  target". Same observable effect on discovery and eclipse behaviour.
- No transport timing. Query **counts** are tracked (`SimNetwork.findnode_calls`)
  because query cost — not wall-clock — is what weeks 5/8 measure.

## Run

```bash
python3 tests/test_routing_table.py   # 10/10
python3 tests/test_discovery.py       # 5/5
python3 demo.py                       # reproducible stats
```

All randomness flows through `random.Random(seed)`; **seed = 20240711**.

### Reproducible demo output (seed 20240711)

200 nodes, k=16, 3 bootnodes, 2 rounds: avg table grows from 3 seeds to **69.3
peers**, ~7.9 occupied buckets, **92%** of nodes locate their true nearest
neighbour, 37,634 FINDNODE queries. Log every run's params + outcome here as you
go.

## What the tests verify

Routing table: XOR symmetry; log-distance vs. spec; correct bucket assignment;
self-insertion ignored; k-cap; replacement-cache bounds; MRU bump on re-seeing;
liveness eviction promotes newest replacement; incumbents immune to ID flood;
`closest_nodes` matches brute force.

Discovery: lookup returns true k-closest under full knowledge; bootstrap finds
true nearest neighbours; lookups populate the table; termination + alpha bound;
network-wide convergence from a realistic multi-bootnode list (single-bootnode
convergence is poor *by design* — noted in the test).

## How comp 3 (week 4, baseline peer selection) plugs in

Baseline selection is IP-blind: after a victim node has discovered candidates
(run `Discovery.bootstrap` / `lookup`), it forms a live peer set by choosing from
`routing_table.all_nodes()` — no subnet/ASN awareness yet. That set is the
reference point the week-6 defense and week-5 attacker are measured against.
`Node.record` is the slot where IP/ASN metadata will live; keep it empty for the
IP-blind baseline so the comparison stays clean.
>>>>>>> 6976d64 (Initial commit)
