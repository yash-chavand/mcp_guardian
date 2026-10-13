"""
Session-Level Attack Graph Builder & Store for MCP Guardian V2 (Feature 7).

Also detects an explicit "encode/transform" hop between a data READ and an
outbound SENT_TO edge, so that classic exfiltration chains
(read sensitive data -> encode -> external request) are represented as their
own TRANSFORMED edge/node rather than being indistinguishable from a plain
read-then-send. See GraphRiskAnalyzer for how this hop is scored.
"""

import math
import time
import uuid
from typing import Dict, List, Set, Any, Tuple, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class GraphNode:
    id: str
    label: str
    node_type: str  # agent | session | server | tool | resource | entity | destination
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    relation: str  # CALLED | READ | SENT_TO | TRANSFORMED | ACCESSED
    timestamp: float
    risk_level: str = "low"


class SessionAttackGraph:
    """Represents a single session's interaction graph."""

    # Tool-name keywords that indicate an encoding/obfuscation/serialization step,
    # the classic middle hop of a "read -> encode -> exfiltrate" chain.
    TRANSFORM_KEYWORDS = [
        "encode", "decode", "base64", "obfuscate", "compress", "zip",
        "encrypt", "hex", "serialize", "stringify", "convert", "escape"
    ]

    # Minimum length before we bother running an entropy check on a string argument.
    _ENTROPY_MIN_LEN = 24
    # Shannon entropy (bits/char) above which a string looks encoded rather than natural text.
    _ENTROPY_THRESHOLD = 4.0

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    @classmethod
    def _detect_transform(cls, tool_name: str, arguments: Dict[str, Any]) -> Optional[str]:
        """
        Detect whether this tool call itself performs (or carries the output of) an
        encode/transform step. Returns a short human-readable reason, or None.
        """
        name_lower = (tool_name or "").lower()
        for kw in cls.TRANSFORM_KEYWORDS:
            if kw in name_lower:
                return f"tool_name_keyword:{kw}"

        for arg_key, arg_val in (arguments or {}).items():
            if not isinstance(arg_val, str) or len(arg_val) < cls._ENTROPY_MIN_LEN:
                continue
            entropy = cls._shannon_entropy(arg_val)
            if entropy >= cls._ENTROPY_THRESHOLD:
                return f"high_entropy_argument:{arg_key}"

        return None

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []

        # Add root session node
        self.add_node(f"session:{session_id}", label=f"Session {session_id[:8]}", node_type="session")

    def add_node(self, node_id: str, label: str, node_type: str, properties: Dict[str, Any] = None):
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(
                id=node_id,
                label=label,
                node_type=node_type,
                properties=properties or {}
            )

    def add_edge(self, source: str, target: str, relation: str, risk_level: str = "low"):
        edge = GraphEdge(
            id=str(uuid.uuid4())[:8],
            source=source,
            target=target,
            relation=relation,
            timestamp=time.time(),
            risk_level=risk_level
        )
        self.edges.append(edge)

    def record_tool_call(
        self,
        tool_name: str,
        server_id: str,
        records_requested: int,
        recipient: str = "",
        risk_level: str = "low",
        arguments: Dict[str, Any] = None
    ):
        tool_node_id = f"tool:{tool_name}"
        self.add_node(tool_node_id, label=tool_name, node_type="tool", properties={"records": records_requested})

        # Session -> Tool (CALLED)
        self.add_edge(f"session:{self.session_id}", tool_node_id, "CALLED", risk_level=risk_level)

        if records_requested > 1:
            res_id = f"resource:bulk_records_{records_requested}"
            self.add_node(res_id, label=f"Database ({records_requested} rows)", node_type="resource")
            self.add_edge(tool_node_id, res_id, "READ", risk_level=risk_level)

        # Encode/transform hop: the middle step of "read -> encode -> exfiltrate".
        # Detected via tool-name keywords (e.g. "encode_payload") or high-entropy
        # argument values (e.g. a base64 blob passed as a parameter).
        transform_reason = self._detect_transform(tool_name, arguments or {})
        if transform_reason:
            transform_id = f"transform:{tool_name}:{len(self.edges)}"
            self.add_node(
                transform_id,
                label=f"Encode/Transform ({tool_name})",
                node_type="transform",
                properties={"detected_via": transform_reason}
            )
            self.add_edge(tool_node_id, transform_id, "TRANSFORMED", risk_level=risk_level)

        if recipient:
            dest_id = f"dest:{recipient}"
            self.add_node(dest_id, label=recipient, node_type="destination")
            self.add_edge(tool_node_id, dest_id, "SENT_TO", risk_level=risk_level)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "nodes": [asdict(n) for n in self.nodes.values()],
            "edges": [asdict(e) for e in self.edges]
        }


class SessionGraphStore:
    """Manages attack graphs across all active sessions."""

    def __init__(self):
        self.graphs: Dict[str, SessionAttackGraph] = {}

    def get_or_create(self, session_id: str) -> SessionAttackGraph:
        if session_id not in self.graphs:
            self.graphs[session_id] = SessionAttackGraph(session_id)
        return self.graphs[session_id]

    def export_graph(self, session_id: str) -> Dict[str, Any]:
        if session_id in self.graphs:
            return self.graphs[session_id].to_dict()
        return {"session_id": session_id, "nodes": [], "edges": []}
