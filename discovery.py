from __future__ import annotations

import random
from typing import Dict, List, Optional

from network import SimNetwork
from node import Node, random_id, xor_distance
from routing_table import BUCKET_SIZE, RoutingTable

ALPHA = 3  # lookup concurrency parameter


class Discovery:
    def __init__(self, node: Node, table: RoutingTable, network: SimNetwork):
        self.node = node
        self.table = table
        self.net = network

    def lookup(self, target_id: int, k: int = BUCKET_SIZE,
               alpha: int = ALPHA) -> List[Node]:
        seen: Dict[int, Node] = {}
        queried: set[int] = set()

        for n in self.table.closest_nodes(target_id, k):
            seen[n.node_id] = n

        def by_distance(nodes):
            return sorted(nodes, key=lambda n: xor_distance(n.node_id, target_id))

        while True:
            k_closest = by_distance(seen.values())[:k]
            if all(n.node_id in queried for n in k_closest):
                break  # the k closest have all responded -> converged

            batch = [n for n in by_distance(seen.values())
                     if n.node_id not in queried][:alpha]
            if not batch:
                break

            for n in batch:
                queried.add(n.node_id)
                for r in self.net.find_node(n.node_id, target_id, k,
                                            requester_id=self.node.node_id):
                    if r.node_id == self.node.node_id:
                        continue
                    seen.setdefault(r.node_id, r)
                    self.table.add_node(r)  # discovery fills the table

        return by_distance(seen.values())[:k]

    def bootstrap(self, bootstrap_nodes: List[Node], refresh: int = 3,
                  rng: Optional[random.Random] = None) -> None:
        for b in bootstrap_nodes:
            self.table.add_node(b)
        self.lookup(self.node.node_id)          # self-lookup: learn neighbours
        for _ in range(refresh):                # refresh random buckets
            self.lookup(random_id(rng))
