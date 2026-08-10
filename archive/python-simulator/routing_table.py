
from __future__ import annotations

from typing import Dict, List, Optional

from node import ID_BITS, Node, log_distance, xor_distance

BUCKET_SIZE = 16            
NUM_BUCKETS = ID_BITS       
REPLACEMENT_CACHE_SIZE = 10  


class KBucket:
    def __init__(self, capacity: int = BUCKET_SIZE,
                 replacement_capacity: int = REPLACEMENT_CACHE_SIZE):
        self.capacity = capacity
        self.replacement_capacity = replacement_capacity
        self.entries: List[Node] = []       
        self.replacements: List[Node] = []   

    def contains(self, node_id: int) -> bool:
        return any(n.node_id == node_id for n in self.entries)

    def add(self, node: Node) -> str:
        
        for i, n in enumerate(self.entries):
            if n.node_id == node.node_id:
                self.entries.pop(i)
                self.entries.append(node)       
                return "bumped"

        if len(self.entries) < self.capacity:
            self.entries.append(node)
            return "added"

        
        self.replacements = [r for r in self.replacements
                             if r.node_id != node.node_id]
        self.replacements.append(node)
        if len(self.replacements) > self.replacement_capacity:
            self.replacements.pop(0)            
        return "cached"

    def remove_dead(self, node_id: int) -> str:
        
        idx = next((i for i, n in enumerate(self.entries)
                    if n.node_id == node_id), None)
        if idx is None:
            return "absent"
        self.entries.pop(idx)
        if self.replacements:
            promoted = self.replacements.pop()  
            self.entries.append(promoted)
            return "replaced"
        return "removed"


class RoutingTable:
    def __init__(self, self_id: int,
                 bucket_size: int = BUCKET_SIZE,
                 replacement_capacity: int = REPLACEMENT_CACHE_SIZE):
        self.self_id = self_id
        self.bucket_size = bucket_size
        self.buckets: Dict[int, KBucket] = {
            i: KBucket(bucket_size, replacement_capacity)
            for i in range(1, NUM_BUCKETS + 1)
        }

    def bucket_index(self, node_id: int) -> int:
        return log_distance(self.self_id, node_id)

    def add_node(self, node: Node) -> str:
        
        if node.node_id == self.self_id:
            return "self"
        return self.buckets[self.bucket_index(node.node_id)].add(node)

    def remove_dead(self, node_id: int) -> str:
        if node_id == self.self_id:
            return "self"
        return self.buckets[self.bucket_index(node_id)].remove_dead(node_id)

    def all_nodes(self) -> List[Node]:
        out: List[Node] = []
        for b in self.buckets.values():
            out.extend(b.entries)
        return out

    def size(self) -> int:
        return sum(len(b.entries) for b in self.buckets.values())

    def occupied_buckets(self) -> int:
        return sum(1 for b in self.buckets.values() if b.entries)

    def closest_nodes(self, target_id: int, count: int) -> List[Node]:
        
        nodes = self.all_nodes()
        nodes.sort(key=lambda n: xor_distance(n.node_id, target_id))
        return nodes[:count]
