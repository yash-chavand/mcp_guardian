"""
Explainable Risk Engine & Reason Builder for MCP Guardian V2 (Feature 8).
Generates transparent, structured root-cause explanations for every security decision.
"""

from typing import List, Dict, Any, Optional
from ..core.events import RiskReason, RiskLevel


class RiskExplanationBuilder:
    """Consolidates and orders risk reasons across all security evaluation layers."""

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    @classmethod
    def build_explanations(
        cls,
        reasons: List[Optional[RiskReason]],
        composite_score: float,
        decision: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Deduplicate, filter and sort risk reasons by severity.

        Every decision -- ALLOW, MONITOR, or BLOCK -- must come with a reason a
        person can act on. When individual layers didn't each cross their own
        reason threshold but the *combined* weighted score still moved the
        composite into MONITOR or BLOCK territory, we synthesize a reason that
        reflects the actual decision rather than falling back to a generic
        "normal" message that would misrepresent a MONITOR/BLOCK outcome.
        """
        valid_reasons = [r for r in reasons if r is not None]
        if not valid_reasons:
            if decision == "BLOCK" or (decision is None and composite_score > 0.60):
                valid_reasons.append(RiskReason(
                    type="composite_risk_threshold_exceeded",
                    severity="high",
                    message=f"Composite risk score ({composite_score:.3f}) exceeded the block threshold "
                            f"even though no single signal individually triggered a block."
                ))
            elif decision == "MONITOR":
                valid_reasons.append(RiskReason(
                    type="composite_risk_elevated",
                    severity="medium",
                    message=f"Composite risk score ({composite_score:.3f}) is elevated above baseline -- "
                            f"several weaker signals combined -- so this interaction is being monitored "
                            f"rather than blocked or silently allowed."
                ))
            else:
                return [{"type": "normal_operation", "severity": "low", "message": "Interaction matches learned baseline."}]

        # Deduplicate by type and message
        seen = set()
        deduped = []
        for r in valid_reasons:
            key = (r.type, r.message)
            if key not in seen:
                seen.add(key)
                deduped.append(r)

        # Sort by severity priority
        deduped.sort(key=lambda x: cls.SEVERITY_ORDER.get(x.severity.lower(), 99))
        return [r.to_dict() for r in deduped]

    @classmethod
    def format_summary_message(cls, reasons_dict: List[Dict[str, str]]) -> str:
        if not reasons_dict:
            return "normal"
        top_reason = reasons_dict[0]
        return f"{top_reason['type']}: {top_reason['message']}"
