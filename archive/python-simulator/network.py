
from __future__ import annotations

from collections import Counter
from typing import Dict, List

from node import Node
from routing_table import BUCKET_SIZE, RoutingTable


class SimNetwork:
    def __init__(self) -> None:
        self.nodes: Dict[int, Node] = {}
        self.tables: Dict[int, RoutingTable] = {}
        self.findnode_calls: int = 0
        self.findnode_by_responder: Counter = Counter()

    def register(self, node: Node, table: RoutingTable) -> None:
        self.nodes[node.node_id] = node
        self.tables[node.node_id] = table

    def find_node(self, responder_id: int, target_id: int,
                  count: int = BUCKET_SIZE,
                  requester_id: int | None = None) -> List[Node]:
       
        table = self.tables.get(responder_id)
        if table is None:
            return []  # unknown / unreachable responder
        self.findnode_calls += 1
        self.findnode_by_responder[responder_id] += 1
        # fetch one extra so filtering the requester still yields `count`
        candidates = table.closest_nodes(target_id, count + 1)
        result = [n for n in candidates if n.node_id != requester_id]
        return result[:count]

    def reset_counters(self) -> None:
        self.findnode_calls = 0
        self.findnode_by_responder.clear()
