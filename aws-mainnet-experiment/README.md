# AWS Mainnet Experiment – 90% Bucket Occupancy

## 1. What was the goal?

We tested whether attackers could occupy most of a Kademlia bucket in a
real Ethereum mainnet node running on AWS, not a simulator.

Setup:
- 1 victim node
- 5 attacker VMs
- 15 attacker identities

## 2. Important files

- `grind_nodekey.go` – Generates 15 attacker identities targeting the same
  bucket (bucket 0).
- `live_entries_share.py` – Reads victim logs and calculates the
  percentage of attacker nodes in that bucket.

## 3. What didn't work?

Initially, attackers connected, completed a handshake and immediately
closed the connection. Geth later checked whether they were alive and
removed them. Problem: attackers could enter the bucket but couldn't stay.

## 4. What was the fix?

We switched from `ping` mode to `listen` mode using geth's `devp2p`
command.

- Ping mode: closes the connection.
- Listen mode: keeps running and responds to later liveness checks.

This stopped the attackers from being removed due to closed connections.

## 5. Experiment result

- **91–92%** peak attacker share
- Settled around **85–90%** during measurement
- The single honest node in that bucket was never evicted

## 6. Why bucket 0?

We checked all 16 buckets and selected the emptiest one.

- Empty buckets have fewer honest nodes.
- Busy buckets have stable honest nodes.
- Stable honest nodes naturally resist identity flooding.

## Main takeaway

We generated 15 identities targeting one bucket, kept them alive using
listen mode, and measured their occupancy using victim logs. Result:
attackers achieved approximately 90% occupancy of one bucket on a real
Ethereum mainnet-connected node.
