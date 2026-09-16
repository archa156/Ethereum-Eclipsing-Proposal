
import random

from discovery import Discovery
from network import SimNetwork
from node import ID_BITS, Node, xor_distance
from routing_table import BUCKET_SIZE, RoutingTable

SEED = 20240711
N_NODES = 200
N_BOOTNODES = 3
ROUNDS = 2
REFRESH = 4


def build():
    rng = random.Random(SEED)
    net = SimNetwork()
    ids, seen = [], set()
    while len(ids) < N_NODES:
        v = rng.getrandbits(ID_BITS)
        if v not in seen:
            seen.add(v)
            ids.append(v)
    for nid in ids:
        net.register(Node(nid), RoutingTable(nid, bucket_size=BUCKET_SIZE))
    for nid in ids:  # small shared-style bootnode list
        for b in rng.sample([x for x in ids if x != nid], N_BOOTNODES):
            net.tables[nid].add_node(Node(b))
    return net, ids, rng


def main():
    net, ids, rng = build()
    net.reset_counters()
    for _ in range(ROUNDS):
        order = ids[:]
        rng.shuffle(order)
        for nid in order:
            Discovery(net.nodes[nid], net.tables[nid], net).bootstrap(
                [], refresh=REFRESH, rng=random.Random(rng.getrandbits(32)))

    sizes = [net.tables[nid].size() for nid in ids]
    buckets = [net.tables[nid].occupied_buckets() for nid in ids]
    hits = 0
    for nid in ids:
        nearest = min((i for i in ids if i != nid), key=lambda x: xor_distance(x, nid))
        if nearest in {n.node_id for n in net.tables[nid].all_nodes()}:
            hits += 1

    print(f"seed={SEED}  nodes={N_NODES}  k={BUCKET_SIZE}  "
          f"bootnodes={N_BOOTNODES}  rounds={ROUNDS}  refresh={REFRESH}")
    print(f"  avg table size ......... {sum(sizes)/len(sizes):.1f} peers "
          f"(started from {N_BOOTNODES})")
    print(f"  min / max table size ... {min(sizes)} / {max(sizes)}")
    print(f"  avg occupied buckets ... {sum(buckets)/len(buckets):.1f}")
    print(f"  nearest-neighbour found. {hits}/{len(ids)} "
          f"({100*hits/len(ids):.0f}%)")
    print(f"  total FINDNODE queries . {net.findnode_calls}")


if __name__ == "__main__":
    main()
