"""Isolation tests for comp 1 (routing table) — verified against discv5 spec.

Run: python3 tests/test_routing_table.py   (from the package dir)
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from node import ID_BITS, Node, log_distance, xor_distance
from routing_table import KBucket, RoutingTable

SEED = 20240711  # fixed for reproducibility


# --- distance metric -------------------------------------------------------
def test_xor_is_symmetric_and_zero_on_self():
    rng = random.Random(SEED)
    for _ in range(1000):
        a, b = rng.getrandbits(ID_BITS), rng.getrandbits(ID_BITS)
        assert xor_distance(a, b) == xor_distance(b, a)
    assert xor_distance(42, 42) == 0


def test_log_distance_matches_spec():
    # self -> 0
    assert log_distance(0, 0) == 0
    # differ only in the least-significant bit -> closest bucket, index 1
    assert log_distance(0, 1) == 1
    # differ in the most-significant (255th) bit -> farthest bucket, index 256
    assert log_distance(0, 1 << 255) == 256
    # 256 - leading_zeros definition, checked directly
    rng = random.Random(SEED + 1)
    for _ in range(1000):
        a, b = rng.getrandbits(ID_BITS), rng.getrandbits(ID_BITS)
        d = a ^ b
        expected = 0 if d == 0 else ID_BITS - (bin(d)[2:].zfill(ID_BITS).index("1"))
        assert log_distance(a, b) == expected


# --- bucket assignment -----------------------------------------------------
def test_nodes_land_in_the_bucket_equal_to_their_log_distance():
    rng = random.Random(SEED + 2)
    self_id = rng.getrandbits(ID_BITS)
    rt = RoutingTable(self_id)
    for _ in range(500):
        nid = rng.getrandbits(ID_BITS)
        if nid == self_id:
            continue
        rt.add_node(Node(nid))
    for idx, bucket in rt.buckets.items():
        for n in bucket.entries + bucket.replacements:
            assert log_distance(self_id, n.node_id) == idx


def test_self_insertion_is_ignored():
    rt = RoutingTable(self_id=12345)
    assert rt.add_node(Node(12345)) == "self"
    assert rt.size() == 0


# --- k-cap + replacement cache ---------------------------------------------
def _ids_in_bucket(index, n, rng):
    """n distinct ids whose log distance to 0 is exactly `index`."""
    lo, hi = 1 << (index - 1), (1 << index) - 1
    ids, seen = [], set()
    while len(ids) < n:
        v = rng.randint(lo, hi)
        if v not in seen:
            seen.add(v)
            ids.append(v)
    return ids


def test_k_cap_and_replacement_cache_bounds():
    rng = random.Random(SEED + 3)
    rt = RoutingTable(self_id=0, bucket_size=4, replacement_capacity=2)
    ids = _ids_in_bucket(8, 10, rng)  # 10 nodes all in bucket 8
    events = [rt.add_node(Node(i)) for i in ids]
    b = rt.buckets[8]
    assert len(b.entries) == 4                 # live entries never exceed k
    assert len(b.replacements) == 2            # cache bounded
    assert events[:4] == ["added"] * 4
    assert events[4:] == ["cached"] * 6        # overflow is cached, not live
    # the two survivors in the cache are the two most recently offered
    assert [r.node_id for r in b.replacements] == ids[-2:]


def test_reseeing_a_node_bumps_it_to_mru():
    rt = RoutingTable(self_id=0, bucket_size=8)
    a, bb, c = _ids_in_bucket(5, 3, random.Random(SEED + 4))
    for i in (a, bb, c):
        rt.add_node(Node(i))
    bucket = rt.buckets[5]
    assert [n.node_id for n in bucket.entries] == [a, bb, c]
    assert rt.add_node(Node(a)) == "bumped"
    assert [n.node_id for n in bucket.entries] == [bb, c, a]  # a moved to MRU


# --- liveness eviction ------------------------------------------------------
def test_dead_entry_is_replaced_by_newest_replacement():
    rng = random.Random(SEED + 5)
    rt = RoutingTable(self_id=0, bucket_size=4, replacement_capacity=2)
    ids = _ids_in_bucket(9, 6, rng)
    for i in ids:
        rt.add_node(Node(i))
    b = rt.buckets[9]
    live_before = [n.node_id for n in b.entries]
    newest_replacement = b.replacements[-1].node_id
    dead = live_before[0]                       # evict the LRU live entry
    assert rt.remove_dead(dead) == "replaced"
    assert dead not in [n.node_id for n in b.entries]
    assert len(b.entries) == 4                  # capacity maintained
    assert b.entries[-1].node_id == newest_replacement  # promoted to MRU
    assert len(b.replacements) == 1


def test_incumbents_are_sticky_newcomers_cannot_evict_live_peers():
    # The eclipse-relevant invariant: a full bucket of live nodes is immune to
    # a flood of fresh ids — none of them displace an incumbent.
    rng = random.Random(SEED + 6)
    rt = RoutingTable(self_id=0, bucket_size=4, replacement_capacity=2)
    incumbents = _ids_in_bucket(7, 4, rng)
    for i in incumbents:
        rt.add_node(Node(i))
    flood = _ids_in_bucket(7, 50, rng)          # attacker-style flood
    for i in flood:
        rt.add_node(Node(i))
    live = {n.node_id for n in rt.buckets[7].entries}
    assert live == set(incumbents)              # incumbents untouched


def test_remove_dead_on_absent_node():
    rt = RoutingTable(self_id=0, bucket_size=4)
    ids = _ids_in_bucket(3, 1, random.Random(SEED + 7))
    assert rt.remove_dead(ids[0]) == "absent"


# --- closest_nodes ----------------------------------------------------------
def test_closest_nodes_ordering_matches_brute_force():
    rng = random.Random(SEED + 8)
    rt = RoutingTable(self_id=0, bucket_size=10_000)  # big cap: keep everyone
    ids = [rng.getrandbits(ID_BITS) for _ in range(300)]
    for i in ids:
        rt.add_node(Node(i))
    target = rng.getrandbits(ID_BITS)
    got = [n.node_id for n in rt.closest_nodes(target, 16)]
    expected = sorted(set(ids), key=lambda x: x ^ target)[:16]
    assert got == expected


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
