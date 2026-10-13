"""
Attack Graph Risk Pattern Analyzer for MCP Guardian V2 (Feature 7).
"""

from typing import Dict, List, Any, Tuple, Optional
from ..core.events import RiskReason
from .attack_graph import SessionAttackGraph


class GraphRiskAnalyzer:
    """Analyzes topology and flow chains within a SessionAttackGraph to detect exfiltration paths."""

    @classmethod
    def _has_ordered_chain(cls, edges: List, relations_in_order: List[str]) -> bool:
        """
        Check whether edges (already chronological, since they're appended in call order)
        contain the given relation types in that relative order, allowing other edges
        in between. This is how we recognize a multi-hop attack chain such as
        READ -> TRANSFORMED -> SENT_TO regardless of what else happened in the session.
        """
        cursor = 0
        for edge in edges:
            if cursor >= len(relations_in_order):
                break
            if edge.relation == relations_in_order[cursor]:
                cursor += 1
        return cursor == len(relations_in_order)

    @classmethod
    def analyze(cls, graph: SessionAttackGraph) -> Tuple[float, Optional[RiskReason]]:
        """
        Evaluate attack graph patterns.
        Returns: (graph_risk_score [0.0, 1.0], Optional[RiskReason])
        """
        nodes = graph.nodes
        edges = graph.edges

        has_resource_read = any(e.relation == "READ" for e in edges)
        has_bulk_resource = any(n.node_type == "resource" and "bulk" in n.id for n in nodes.values())
        has_external_send = any(e.relation == "SENT_TO" for e in edges)
        has_transform = any(e.relation == "TRANSFORMED" for e in edges)

        # 0. Most specific & highest-confidence chain: sensitive data was READ, then
        # explicitly encoded/transformed, then SENT_TO an outbound destination, in that
        # order. This is a stronger signal than a plain read->send because it matches
        # the classic exfiltration pattern of disguising data before it leaves the system.
        if has_resource_read and has_transform and has_external_send:
            if cls._has_ordered_chain(edges, ["READ", "TRANSFORMED", "SENT_TO"]):
                return 0.97, RiskReason(
                    type="attack_graph_encode_exfiltration_chain",
                    severity="critical",
                    message="Graph correlation detected a classic exfiltration chain: sensitive data read, "
                            "encoded/transformed, then transmitted to an external destination."
                )

        # 1. Critical Chain: Bulk Database Read followed by Outbound Send
        if has_bulk_resource and has_external_send:
            return 0.96, RiskReason(
                type="attack_graph_bulk_exfiltration_chain",
                severity="critical",
                message="Graph correlation detected attack chain: Bulk Resource Extraction ➔ External Destination Transmission."
            )

        # 2. High Risk Chain: Resource Read followed by External Send
        if has_resource_read and has_external_send:
            # Check if destination is suspicious
            dest_nodes = [n for n in nodes.values() if n.node_type == "destination"]
            is_suspicious_dest = any("evil" in n.id or ".xyz" in n.id for n in dest_nodes)
            if is_suspicious_dest:
                return 0.90, RiskReason(
                    type="attack_graph_sensitive_exfiltration",
                    severity="high",
                    message="Graph analysis identified sensitive entity access followed by unverified outbound transmission."
                )

        return 0.05, None
