"""
Network Destination Novelty & Reputation Tracker for MCP Guardian V2 (Feature 6).
"""

import time
from typing import Dict, Set, List, Any, Tuple, Optional
from dataclasses import dataclass, field
from ..core.events import RiskReason


@dataclass
class DestinationRecord:
    destination: str
    destination_type: str  # domain | email_domain | ip | webhook
    first_seen: float
    last_seen: float
    invocation_count: int = 1
    associated_tools: Set[str] = field(default_factory=set)
    associated_sessions: Set[str] = field(default_factory=set)


class DestinationNoveltyTracker:
    """
    Monitors all external network destinations (domains, webhooks, email endpoints).
    Computes novelty scores based on observation history and fuses with data sensitivity.
    """

    def __init__(self, trusted_domains: Set[str] = None):
        self.trusted_domains = trusted_domains or {
            "example.com", "example.org", "api.company.internal", "localhost", "127.0.0.1"
        }
        self.observed_destinations: Dict[str, DestinationRecord] = {}

    def _extract_domain(self, target: str) -> str:
        t = target.strip().lower()
        if "@" in t:
            return t.split("@")[-1]
        if "://" in t:
            t = t.split("://")[1].split("/")[0].split(":")[0]
        return t

    def evaluate_destination(
        self,
        raw_destination: str,
        tool_name: str,
        session_id: str,
        data_sensitivity_level: str = "medium",
        records_count: int = 1
    ) -> Tuple[float, Optional[RiskReason]]:
        """
        Evaluate novelty of network destination.
        Returns: (novelty_risk_score [0.0, 1.0], Optional[RiskReason])
        """
        if not raw_destination:
            return 0.0, None

        domain = self._extract_domain(raw_destination)
        now = time.time()

        # 1. Trusted Allow-list Check
        if domain in self.trusted_domains:
            if domain in self.observed_destinations:
                rec = self.observed_destinations[domain]
                rec.last_seen = now
                rec.invocation_count += 1
                rec.associated_tools.add(tool_name)
                rec.associated_sessions.add(session_id)
            else:
                self.observed_destinations[domain] = DestinationRecord(
                    destination=domain,
                    destination_type="domain",
                    first_seen=now,
                    last_seen=now,
                    associated_tools={tool_name},
                    associated_sessions={session_id}
                )
            return 0.05, None

        # 2. Known vs Novel Domain
        is_novel = domain not in self.observed_destinations

        if is_novel:
            self.observed_destinations[domain] = DestinationRecord(
                destination=domain,
                destination_type="domain",
                first_seen=now,
                last_seen=now,
                associated_tools={tool_name},
                associated_sessions={session_id}
            )

            # Novelty risk weighting combined with data sensitivity and volume
            base_novelty = 0.70
            if data_sensitivity_level in ["high", "critical"] or records_count > 1:
                base_novelty = 0.92
            elif ".evil." in domain or domain.endswith(".xyz") or domain.endswith(".top"):
                base_novelty = 0.95

            score = min(1.0, base_novelty)
            reason = RiskReason(
                type="destination_novelty",
                severity="critical" if score > 0.85 else "high",
                message=f"Outbound destination '{domain}' is novel/unseen in cluster baseline (tool: '{tool_name}')."
            )
            return round(score, 4), reason
        else:
            rec = self.observed_destinations[domain]
            rec.last_seen = now
            rec.invocation_count += 1
            rec.associated_tools.add(tool_name)
            rec.associated_sessions.add(session_id)

            # Previously seen un-whitelisted destination -> medium risk
            score = 0.40 if rec.invocation_count < 5 else 0.20
            return round(score, 4), None

    def get_destinations_summary(self) -> List[Dict[str, Any]]:
        return [
            {
                "destination": k,
                "type": v.destination_type,
                "first_seen": v.first_seen,
                "last_seen": v.last_seen,
                "count": v.invocation_count,
                "tools": list(v.associated_tools),
                "is_trusted": k in self.trusted_domains
            }
            for k, v in self.observed_destinations.items()
        ]
