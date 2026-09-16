
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from discovery import Discovery
from network import SimNetwork
from node import ID_BITS, Node
from routing_table import BUCKET_SIZE, RoutingTable

SEED = 20240711


def _build_network(n, seed, bucket_size=10_000):
    
    rng = random.Random(seed)
    net = SimNetwork()
    ids, seen = [], set()
    while len(ids) < n:
        v = rng.getrandbits(ID_BITS)
        if v not in seen:
            seen.add(v)
            ids.append(v)
    for nid in ids:
        node = Node(nid)
        net.register(node, RoutingTable(nid, bucket_size=bucket_size))
    return net, ids, rng


def test_lookup_returns_true_k_closest_under_full_knowledge():
    
    net, ids, rng = _build_network(60, SEED)
    for a in ids:                     
        for b in ids:
            if a != b:
                net.tables[a].add_node(Node(b))
    seeker = ids[0]
    disc = Discovery(net.nodes[seeker], net.tables[seeker], net)
    target = rng.getrandbits(ID_BITS)
    got = [n.node_id for n in disc.lookup(target, k=BUCKET_SIZE)]
    expected = sorted((i for i in ids if i != seeker),
                      key=lambda x: x ^ target)[:BUCKET_SIZE]
    assert got == expected


def test_bootstrap_finds_true_nearest_neighbours():
    
    net, ids, rng = _build_network(80, SEED + 1)
    boot = ids[0]
    for other in ids:
        if other != boot:
            net.tables[boot].add_node(Node(other))  

    joiner = ids[1]
    disc = Discovery(net.nodes[joiner], net.tables[joiner], net)
    disc.bootstrap([Node(boot)], refresh=0, rng=random.Random(SEED + 1))

    learned = {n.node_id for n in net.tables[joiner].closest_nodes(joiner, 16)}
    expected = set(sorted((i for i in ids if i != joiner),
                          key=lambda x: x ^ joiner)[:16])
    assert expected.issubset(learned)


def test_lookup_populates_the_table():
    net, ids, rng = _build_network(80, SEED + 2)
    boot = ids[0]
    for other in ids:
        if other != boot:
            net.tables[boot].add_node(Node(other))
    joiner = ids[1]
    disc = Discovery(net.nodes[joiner], net.tables[joiner], net)
    assert net.tables[joiner].size() == 0
    disc.bootstrap([Node(boot)], refresh=3, rng=random.Random(SEED + 2))
    
    assert net.tables[joiner].size() > 1
    assert net.tables[joiner].occupied_buckets() >= 1


def test_lookup_terminates_and_respects_alpha():
    .
    net, ids, rng = _build_network(10, SEED + 3)
    seeker = ids[0]
    net.tables[seeker].add_node(Node(ids[1]))
    disc = Discovery(net.nodes[seeker], net.tables[seeker], net)
    net.reset_counters()
    out = disc.lookup(rng.getrandbits(ID_BITS), alpha=3)
    assert isinstance(out, list)
    assert net.findnode_calls <= 3  


def test_whole_network_converges_from_a_realistic_bootnode_list():
   
    net, ids, rng = _build_network(60, SEED + 4, bucket_size=BUCKET_SIZE)
    n_boot = 3
    for nid in ids:
        for b in rng.sample([x for x in ids if x != nid], n_boot):
            net.tables[nid].add_node(Node(b))

    for _ in range(2): 
        order = ids[:]
        rng.shuffle(order)
        for nid in order:
            Discovery(net.nodes[nid], net.tables[nid], net).bootstrap(
                [], refresh=4, rng=random.Random(rng.getrandbits(32)))

    hits, sizes = 0, []
    for nid in ids:
        nearest = min((i for i in ids if i != nid), key=lambda x: x ^ nid)
        known = {n.node_id for n in net.tables[nid].all_nodes()}
        hits += nearest in known
        sizes.append(net.tables[nid].size())

    hit_rate = hits / len(ids)
    avg_table = sum(sizes) / len(sizes)
    assert hit_rate > 0.8, f"nearest-neighbour hit rate too low: {hit_rate:.2f}"
    assert avg_table > 20, f"tables under-populated: avg {avg_table:.1f}"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
