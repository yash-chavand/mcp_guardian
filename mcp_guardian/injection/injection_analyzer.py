"""
Multi-Layer Prompt Injection & Action-Risk Correlation Analyzer for MCP Guardian V2 (Feature 10).
"""

import re
from typing import Dict, List, Any, Tuple, Optional
from ..core.events import RiskReason


class PromptInjectionAnalyzer:
    """
    4-Layer Prompt Injection Engine:
      Layer 1: Deterministic Patterns (Override markers, delimiter bypasses)
      Layer 2: Suspicious Instruction Semantics (Jailbreaks, role impersonation)
      Layer 3: Context-Aware Separation (Embedded instructions inside data payloads)
      Layer 4: Action-Risk Correlation (Suspicious instruction + Dangerous tool requested)
    """

    # Layer 1: Deterministic Regex Patterns
    L1_PATTERNS = [
        r"(?i)ignore\s+(all\s+|your\s+)?previous\s+instructions",
        r"(?i)disregard\s+(all\s+|your\s+)?prior\s+rules",
        r"(?i)system\s+override",
        r"(?i)developer\s+mode\s+(enabled|on|activate)",
        r"(?i)you\s+are\s+now\s+in\s+admin\s+mode",
        r"(?i)jailbreak\s+mode",
        r"(?i)\[\s*system\s*\]|\{\s*system\s*\}|---\s*begin\s+system\s*---",
    ]

    # Layer 2: Role Impersonation & Embedded Directives
    L2_KEYWORDS = [
        "admin note:", "supervisor override:", "debug mode:", "compliance audit demo:",
        "training exercise:", "emergency protocol:", "security test:"
    ]

    # Layer 3: Data-Exfiltration Directive Signatures
    EXFIL_SIGNATURES = [
        r"(?i)fetch\s+all\s+(customer\s+|user\s+)?orders",
        r"(?i)dump\s+(the\s+)?database",
        r"(?i)email\s+(all\s+)?(of\s+them|the\s+results|them)\s+to\s+[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        r"(?i)send\s+(the\s+)?(records|passwords|keys|secrets|data)\s+to",
    ]

    @classmethod
    def analyze(
        cls,
        user_message: str,
        tool_name: str = "",
        arguments: Dict[str, Any] = None,
        is_high_risk_tool: bool = False
    ) -> Tuple[float, Optional[RiskReason], Dict[str, Any]]:
        """
        Analyze prompt text and correlate with requested tool action.
        Returns: (injection_score [0.0, 1.0], Optional[RiskReason], details)
        """
        if not user_message:
            return 0.0, None, {}

        text_lower = user_message.lower().strip()
        layer_hits = []
        score = 0.0

        # ---- Layer 1: Deterministic Override Patterns ----
        for pat in cls.L1_PATTERNS:
            if re.search(pat, user_message):
                layer_hits.append("Layer 1: Deterministic Instruction Override")
                score = max(score, 0.85)
                break

        # ---- Layer 2: Suspicious Instruction Semantics ----
        if any(kw in text_lower for kw in cls.L2_KEYWORDS):
            layer_hits.append("Layer 2: Fake Context / Role Impersonation Directive")
            score = max(score, 0.75)

        # ---- Layer 3: Exfiltration Directive Signatures ----
        for sig in cls.EXFIL_SIGNATURES:
            if re.search(sig, user_message):
                layer_hits.append("Layer 3: Data Exfiltration Directive Pattern")
                score = max(score, 0.85)
                break

        # ---- Layer 4: Action-Risk Correlation ----
        # If user message has suspicious instructions AND requested action is a data/outbound tool
        records_val = str(arguments.get("order_id", arguments.get("records", ""))).upper() if arguments else ""
        has_bulk_arg = records_val in ["ALL", "*", "ANY"]

        if (score >= 0.70 or len(layer_hits) >= 1) and (is_high_risk_tool or has_bulk_arg or "email" in tool_name or "send" in tool_name):
            layer_hits.append("Layer 4: High-Risk Action Correlation (Prompt Directive + Critical Tool Request)")
            score = 0.98

        reason = None
        if score >= 0.70:
            reason = RiskReason(
                type="prompt_injection_detected",
                severity="critical" if score >= 0.90 else "high",
                message=f"Prompt injection identified across {len(layer_hits)} detection layers: {'; '.join(layer_hits)}."
            )

        details = {
            "score": round(score, 3),
            "layers_triggered": layer_hits,
            "detected": score >= 0.70
        }

        return round(score, 4), reason, details
