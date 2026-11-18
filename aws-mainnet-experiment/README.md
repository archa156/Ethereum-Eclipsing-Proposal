# AWS Mainnet Experiment — reaching 90% bench share in one bucket

This folder holds the two scripts that actually produced the headline
result: **~90% attacker share of a single Kademlia bucket on a real
go-ethereum node synced to live Ethereum mainnet**, running on AWS EC2 (one
victim node + 5 attacker VMs), not the simulator in `bench/`/`attacker/`.

## What's here

- **`grind_nodekey.go`** — brute-forces attacker node keys so their node ID
  lands in a chosen Kademlia bucket relative to the victim's node ID. We
  used this to generate 15 identities all targeting the same near-empty
  bucket (bucket 0), so they'd all compete for the same small set of slots
  instead of spreading out.
- **`live_entries_share.py`** — parses the victim's geth log and computes
  the time-weighted attacker share of the *live* routing-table entries for
  that bucket (not just the replacement bench — live entries are what geth
  actually uses for peer connections, so this is the real measure of
  "occupied").

## What's *not* here, and why

Earlier in the project we tried a "ping once, close the socket" attacker
(open a connection, complete one handshake, close it, repeat). It got
admitted but was evicted within seconds every time. We only found out why
after testing it directly: geth does a liveness/revalidation check on a
node shortly after admitting it, and if the socket is already closed, that
check fails and the node is evicted. That approach is not included here
because it's the thing that *didn't* work — it's mentioned so the reviewer
doesn't wonder why it's missing.

## The actual fix: `devp2p discv5 listen`

The piece that made eviction stop isn't a file we wrote — it's go-ethereum's
own `devp2p` CLI, used in **listen mode** instead of **ping mode**:

```bash
# Didn't work (socket closes right after the handshake):
./devp2p discv5 ping --nodekey <hex> --addr <bind> --extaddr <ip> "<victim-enr>"

# Works (socket stays open, so it answers the victim's later liveness checks):
./devp2p discv5 listen --addr <bind> --extaddr <ip> --nodekey <hex> \
    -bootnodes "<victim-enr>"
```

Each of the 15 ground identities was run in `listen` mode as its own
long-lived process on the attacker VMs.

## Building `grind_nodekey.go`

This file imports real go-ethereum packages (`crypto`, `p2p/enode`) rather
than reimplementing them, so it needs the go-ethereum module available:

```bash
go mod tidy    # pulls in github.com/ethereum/go-ethereum
go run grind_nodekey.go -target <id> -bucket 0 -out atk1-nodekey.txt
```

This worked on the EC2 instances where we actually ran it. If you build it
somewhere with restricted network access (e.g. a sandboxed environment with
no route to `proxy.golang.org`), `go mod tidy` will fail to fetch the
dependency — that's an environment restriction, not a code issue.

## How to reproduce

1. **Grind 15 identities into the target bucket** (run once per identity,
   or loop with different `-out` names):
   ```bash
   go run grind_nodekey.go -target <victim-node-id-hex> -bucket 0 -out atk1-nodekey.txt
   ```
2. **Launch each identity in listen mode** on the attacker VMs (see command
   above) — this is what occupies the bucket.
3. **Let the victim run** with its own geth log being written at
   `--verbosity 4` or higher.
4. **Measure the result**:
   ```bash
   python3 live_entries_share.py victim.log --bucket 0 \
       --attackers <comma-separated 8-char node-ID prefixes>
   ```
   This prints the time-weighted attacker share of that bucket's live
   entries, and a snapshot of who's currently live. In our run this
   peaked around 91–92% and settled into an 85–90% band over the
   measurement window, with the single honest node in that bucket never
   evicted.

## Why bucket 0, not a busy bucket

We scanned all 16 buckets for honest-node traffic first. Mainnet traffic
per bucket is very uneven — some buckets had almost no real nodes, others
had dozens of active arrivals per minute. We picked the emptiest bucket on
purpose: a slot only opens up when an *existing* entry fails its liveness
check, and busy buckets have a stable core of long-lived honest nodes that
rarely churn. Flooding a busy bucket with identities doesn't open slots by
itself — getting past that would mean actively interfering with real
nodes' connectivity, which was out of scope for this project. We treat this
as a finding (busy buckets show natural resistance to pure identity
flooding), not a gap.
