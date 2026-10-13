"""
Zero-Config Auto-Discovery V2 & Schema Mutation Monitor (Feature 11).
"""

import json
from typing import Dict, List, Any, Tuple, Optional
from ..semantic.profile_generator import ExpectedBehaviorProfile, ExpectedBehaviorProfileGenerator
from ..core.events import SecurityEvent, RiskReason, EventType, RiskLevel, Decision


class AutoDiscoveryV2:
    """Discovers MCP tools, generates profiles and detects runtime schema mutation attacks."""

    def __init__(self, storage=None):
        self.profiles: Dict[str, ExpectedBehaviorProfile] = {}
        self.schema_hashes: Dict[str, str] = {}
        self.storage = storage
        self.mutation_alerts: List[Dict[str, Any]] = []

    def ingest_tools_list(self, tools: List[Dict[str, Any]], server_id: str = "primary-server") -> List[SecurityEvent]:
        """
        Ingest tools returned from MCP tools/list.
        Returns a list of SecurityEvents if any schema mutation/change was detected.
        """
        alerts: List[SecurityEvent] = []

        for t in tools:
            name = t.get("name")
            if not name:
                continue

            current_hash = ExpectedBehaviorProfileGenerator.generate_schema_hash(t)
            is_new = name not in self.profiles
            has_mutated = (not is_new) and (self.schema_hashes.get(name) != current_hash)

            if is_new or has_mutated:
                old_hash = self.schema_hashes.get(name, "")
                profile = ExpectedBehaviorProfileGenerator.generate_profile(t)
                self.profiles[name] = profile
                self.schema_hashes[name] = current_hash

                if self.storage:
                    self.storage.save_tool_profile(name, server_id, current_hash, profile.to_dict())

                if has_mutated:
                    alert_msg = f"Schema mutation detected for tool '{name}'. Definition or parameters changed mid-deployment."
                    print(f"[MCP Guardian V2] ⚠️ SCHEMA MUTATION ALERT: {alert_msg}")

                    event = SecurityEvent(
                        event_type=EventType.SCHEMA_CHANGE.value,
                        server_id=server_id,
                        tool_name=name,
                        risk_score=0.85,
                        risk_level=RiskLevel.HIGH.value,
                        decision=Decision.MONITOR.value,
                        reasons=[RiskReason(
                            type="schema_mutation",
                            severity="high",
                            message=alert_msg
                        ).to_dict()],
                        evidence={
                            "old_schema_hash": old_hash,
                            "new_schema_hash": current_hash,
                            "new_profile": profile.to_dict()
                        }
                    )
                    alerts.append(event)
                    self.mutation_alerts.append(event.to_dict())
                    if self.storage:
                        self.storage.save_event(event)
                else:
                    print(f"[MCP Guardian V2] Auto-discovered profile for '{name}': risk={profile.risk_level}, outbound={profile.is_outbound}")

        return alerts

    def get_profile(self, tool_name: str) -> ExpectedBehaviorProfile:
        return self.profiles.get(tool_name, ExpectedBehaviorProfile(tool=tool_name))

    def list_inventory(self) -> Dict[str, Dict[str, Any]]:
        return {
            name: {
                "profile": p.to_dict(),
                "schema_hash": self.schema_hashes.get(name, "")
            }
            for name, p in self.profiles.items()
        }
