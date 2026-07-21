from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import random

ID_BITS = 256
ID_MAX = (1 << ID_BITS) - 1


def random_id(rng: Optional[random.Random] = None) -> int:
    
    if rng is None:
        return secrets.randbits(ID_BITS)
    return rng.getrandbits(ID_BITS)


def xor_distance(a: int, b: int) -> int:
    
    return a ^ b


def log_distance(a: int, b: int) -> int:
    
    d = a ^ b
    if d > ID_MAX:
        raise ValueError("node id exceeds 256 bits")
    return d.bit_length()  


@dataclass
class Node:
    
    node_id: int
    record: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return self.node_id

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Node) and self.node_id == other.node_id

    def __repr__(self) -> str:
        return f"Node(0x{self.node_id:064x})"[:18] + "...)"
