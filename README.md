# Ethereum Eclipse Defense — Replacement List (Bench) Grinding

**Project:** Hardening Ethereum Against Eclipse Attacks
**Student:** Archa · M.Tech Cyber Security, Amrita Vishwa Vidyapeetham

This repository studies a specific, concrete weakness in Ethereum's peer
discovery table: the **replacement list** ("the bench") that backs each
Kademlia/Discv5 bucket has essentially no admission control beyond a /24
subnet check. An attacker who repeatedly offers contacts to a victim can
grind that bench — pushing honest backups out — and, as honest live peers
die naturally over time, get promoted into the victim's actual peer set.

This repo (1) reproduces that attack quantitatively against logic mirrored
from the real go-ethereum source, and (2) evaluates three admission schemes
on the same cost curve: today's behaviour, a naive rate-limiting fix, and a
deterministic (addrman-style) placement scheme.

## Status: the codebase moved from Python to Go

Weeks 1–3 of this project built a Python prototype (`archive/python-simulator/`)
of the Kademlia/Discv5 routing table and iterative discovery, to establish and
test the protocol foundation. **The project has since moved entirely to Go**,
so that the attack and defense logic can be verified directly against
go-ethereum's real implementation (`p2p/discover/table.go`) rather than a
from-memory reimplementation, and so the same code can eventually be
exercised against a real geth node. The Python prototype is kept for
provenance, not deleted — see [`archive/python-simulator/`](archive/python-simulator/).

## What's here

| Package | Role |
|---|---|
| [`bench/`](bench/) | The bucket: live entries + replacement list, three admission schemes |
| [`attacker/`](attacker/) | The bench-grinding attacker + honest background churn model |
| [`experiment/`](experiment/) | The four experiments, producing CSV output |
| [`cmd/benchgrind/`](cmd/benchgrind/) | CLI: runs all four experiments, writes results to `results/` |
| `archive/python-simulator/` | Weeks 1–3 Python prototype (routing table + discovery), superseded |

## Verified against the real geth source

Rather than reimplement `table.go` from the project brief's description, the
constants and admission/promotion logic here were checked directly against
`github.com/ethereum/go-ethereum`, package `p2p/discover`, `table.go`:

```go
bucketSize      = 16  // live entries per bucket
maxReplacements = 10  // replacement list ("bench") size per bucket
bucketIPLimit   = 2   // max nodes from the same /24 subnet, per bucket
tableIPLimit    = 10  // max nodes from the same /24 subnet, whole table
```

Two behaviours were confirmed against the real source and are reproduced
exactly:

- **`pushNode`** inserts a new node at the **front** and evicts from the
  **back** once the replacement list is full — this front-insert/back-evict
  rule is exactly what a grinding attacker exploits.
- **`deleteInBucket`** promotes a **uniformly random** replacement into the
  live entries (`tab.rand.Intn(len(b.replacements))`), **not** a
  newest-first rule. (An earlier iteration of this project incorrectly
  assumed newest-first promotion; corrected after cross-checking the real
  source directly.)

## The three schemes

| Scheme | Admission rule | Grinding helps the attacker? |
|---|---|---|
| **Baseline** | Today's geth: front-insert / evict-back, /24 limit only | Yes, substantially |
| **Fraction sampling** | Accept each offer with probability P | Slightly — throttles both attacker and honest traffic equally |
| **Deterministic (addrman-style)** | `slot = hash(subnet ‖ secret) % 10` — same subnet always lands in the same slot | No — repeated insertion of the same node is a no-op |

## Run it

```bash
go build ./...
go test ./...                    # 18 tests across bench/ and attacker/
go run ./cmd/benchgrind           # runs all four experiments, writes results/*.csv
```

All randomness is seeded (`SEED = 20240711`); every run is reproducible.

## Reproducible results (seed 20240711)

**Experiment 1 — reproduce the grind (baseline, no honest counter-traffic).**
5 attacker subnets, insertion rate 20, 200 rounds:
**attacker bench share converges to 1.000, attacker entry share reaches 0.562.**
The vulnerability described in the project brief, reproduced directly.

**Experiment 2 — three-scheme comparison under sustained honest churn.**
Same attack parameters, plus ongoing honest background traffic (rate 2/round),
300 rounds — final attacker bench share:

| Scheme | Final attacker bench share |
|---|---|
| Baseline | 0.500 |
| Fraction sampling (P=0.5) | 0.600 |
| Deterministic | 0.333 |

*(Single-seed snapshot; fraction sampling's edge over baseline is small and
noisy at any one seed — averaged over 30 seeds it is baseline 0.374 >
sampling 0.353 > deterministic 0.254. Deterministic's advantage is large
and robust at any seed; sampling's is not — see Experiment 3.)*

**Experiment 3 — attacker effort curves (rounds to reach 90% bench share).**
The headline finding: deterministic placement's cost to the attacker is
**independent of insertion rate**.

| Insertion rate | Baseline | Fraction sampling | Deterministic |
|---|---|---|---|
| 2 | 127.0 | 109.5 | 100.0 |
| 5 | 2.0 | 8.1 | 127.1 |
| 10 | 1.0 | 3.4 | 127.1 |
| 20 | 1.0 | 1.8 | 127.1 |
| 40 | 1.0 | 1.0 | 127.1 |
| 80 | 1.0 | 1.0 | 127.1 |

Baseline and fraction sampling both collapse toward 1 round as the attacker
inserts faster — grinding works, it's just a question of how much effort.
Deterministic placement stays flat at ~127 rounds **regardless of how hard
the attacker grinds**, because achievable bench share is capped by hash-slot
coverage, not by insertion rate at all.

**Experiment 4 — honest-node overhead (no attacker present).**

| Scheme | Honest rejection rate |
|---|---|
| Baseline | 3.0% |
| Fraction sampling (P=0.5) | 51.4% |
| Deterministic | 0.0% |

Fraction sampling is a genuinely bad trade: it can't distinguish attacker
from honest traffic, so it throttles both indiscriminately, rejecting over
half of ordinary honest admission attempts for a defense that (per
Experiment 3) barely raises attacker cost. Deterministic placement raises
attacker cost the most while imposing **no** honest-node cost in this
setup — though see [Limitations](#limitations).

## What the tests verify

`bench/bucket_test.go` (11 tests): capacity bounds, subnet-limit enforcement
under every scheme, front-insert/back-evict ordering, the core grind
(baseline bench eventually fully attacker-controlled), fraction sampling
requiring strictly more insertions than baseline for the same share,
deterministic grinding being a genuine no-op (1000 repeated insertions ==
1 insertion), the attacker's deterministic-scheme occupancy being capped by
actual distinct hash-slot count (not a naive ratio — collisions among
honest seed subnets are accounted for), and promotion being uniformly
random rather than newest-first (verified statistically across 2000 trials).

`attacker/attacker_test.go` (7 tests): end-to-end attack trajectories across
all three schemes, unopposed vs. sustained-churn scenarios, the
deterministic-vs-baseline and deterministic-vs-sampling advantage holding
under averaging, monotonicity of attacker cost with insertion rate, and
reproducibility under a fixed seed.

## Limitations

- Deterministic placement's zero honest-overhead result here reflects 40
  distinct honest subnets contending for 10 slots with no attacker present;
  it does not yet model the effect of the secret changing (e.g. on restart)
  or adversarial subnet selection aimed at deliberately colliding with
  specific honest subnets.
- The simulator models one bucket's admission/promotion dynamics, not the
  full 256-bucket table, DNS-based peer discovery, or connection-slot
  occupation — those are separate attack surfaces (see Shi et al., WWW 2026)
  outside this project's scope.
- Not yet validated against a real geth node; see Next Steps.

## Next steps

- Validate the attack against a real geth node running in discovery-only
  mode on Sepolia testnet.
- Patch the deterministic-placement scheme into a modified `table.go`,
  rebuild geth, and confirm the defense holds against a real bench-grinding
  attacker over the wire (requires Go ≥ 1.24 for current go-ethereum).
- Plotting code for the four experiments' CSV output.
