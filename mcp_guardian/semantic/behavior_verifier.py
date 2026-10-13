"""
Semantic Behavior Verifier for MCP Guardian V2 (Feature 1).
Compares ExpectedBehaviorProfile vs Actual Runtime Call Telemetry to calculate Semantic Deviation Score.
"""

from typing import Dict, Any, List, Tuple
from ..core.events import RiskReason
from .profile_generator import ExpectedBehaviorProfile


class SemanticBehaviorVerifier:
    """Calculates semantic deviation score between expected tool profile and actual invocation."""

    # Configurable deviation weights
    WEIGHTS = {
        "unexpected_file_access": 0.85,
        "unknown_network_destination": 0.90,
        "unexpected_data_type": 0.70,
        "unauthorized_bulk_data": 0.80,
        "unauthorized_external_send": 0.95,
        "destructive_action_anomaly": 0.85,
    }

    @classmethod
    def verify(
        cls,
        profile: ExpectedBehaviorProfile,
        arguments: Dict[str, Any],
        runtime_context: Dict[str, Any]
    ) -> Tuple[float, List[RiskReason], Dict[str, Any]]:
        """
        Verify expected vs actual behavior.
        Returns: (deviation_score, reasons, actual_behavior_summary)
        """
        deviation_score = 0.0
        reasons: List[RiskReason] = []

        records_requested = runtime_context.get("records_requested", 1)
        recipient = str(runtime_context.get("recipient", "")).strip()
        is_recipient_mismatch = runtime_context.get("recipient_mismatch", False)
        destination_domain = runtime_context.get("destination_domain", "")
        file_access_attempted = runtime_context.get("file_access_attempted", False)

        actual_summary = {
            "records_requested": records_requested,
            "recipient": recipient,
            "destination_domain": destination_domain,
            "is_outbound": bool(recipient or destination_domain or profile.is_outbound),
            "file_access": file_access_attempted,
            "arguments_passed": list(arguments.keys())
        }

        # 1. Check Unauthorized Outbound Action (if tool is not outbound but sends externally)
        if not profile.is_outbound and (recipient or destination_domain):
            deviation_score = max(deviation_score, cls.WEIGHTS["unauthorized_external_send"])
            reasons.append(RiskReason(
                type="unauthorized_external_send",
                severity="critical",
                message=f"Tool '{profile.tool}' is declared as local/read-only but attempted outbound communication to '{recipient or destination_domain}'."
            ))

        # 2. Check Unauthorized Bulk Data Extraction
        if records_requested > profile.max_expected_records:
            score = min(1.0, cls.WEIGHTS["unauthorized_bulk_data"] * (records_requested / max(1, profile.max_expected_records * 2)))
            deviation_score = max(deviation_score, score)
            reasons.append(RiskReason(
                type="unauthorized_bulk_data",
                severity="high" if records_requested < 100 else "critical",
                message=f"Tool '{profile.tool}' expected max {profile.max_expected_records} records, but requested {records_requested} records."
            ))

        # 3. Check Unknown / Mismatched Destination
        if is_recipient_mismatch:
            deviation_score = max(deviation_score, cls.WEIGHTS["unknown_network_destination"])
            reasons.append(RiskReason(
                type="unknown_network_destination",
                severity="critical",
                message=f"Outbound recipient '{recipient}' deviates from authorized session entities and trusted destinations."
            ))

        # 4. Check Unexpected File Access
        if file_access_attempted and "filesystem_access" not in profile.expected_actions:
            deviation_score = max(deviation_score, cls.WEIGHTS["unexpected_file_access"])
            reasons.append(RiskReason(
                type="unexpected_file_access",
                severity="high",
                message=f"Tool '{profile.tool}' attempted filesystem operations which are outside its declared profile."
            ))

        # 5. Check Argument Schema Conformance (unexpected keys)
        declared_params = {p.split(":")[0] for p in profile.allowed_data_types}
        if declared_params:
            for arg_k, arg_v in arguments.items():
                if arg_k not in declared_params and arg_k not in ["session_id", "correlation_id"]:
                    deviation_score = max(deviation_score, 0.40)
                    reasons.append(RiskReason(
                        type="unexpected_parameter",
                        severity="medium",
                        message=f"Undeclared argument '{arg_k}' passed to tool '{profile.tool}'."
                    ))
                    break

        deviation_score = min(1.0, round(deviation_score, 4))
        return deviation_score, reasons, actual_summary
