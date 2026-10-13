"""
Expected Behavior Profile Generator for MCP Guardian V2 (Feature 1 & 11).
Automatically infers capability boundaries and risk profiles from MCP tools/list schemas.
"""

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


@dataclass
class ExpectedBehaviorProfile:
    tool: str
    description: str = ""
    expected_actions: List[str] = field(default_factory=list)
    allowed_data_types: List[str] = field(default_factory=list)
    allowed_destinations: List[str] = field(default_factory=list)
    expected_network_behavior: List[str] = field(default_factory=list)
    risk_level: str = "low"  # low | medium | high | critical
    is_outbound: bool = False
    is_destructive: bool = False
    is_bulk_capable: bool = False
    records_field: Optional[str] = None
    recipient_field: Optional[str] = None
    max_expected_records: int = 1
    schema_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ExpectedBehaviorProfileGenerator:
    """Infers structured expected behavior profiles from tool metadata without hardcoding."""

    ACTION_KEYWORDS = {
        "database_read": ["get", "fetch", "find", "read", "lookup", "query", "search", "select", "order", "customer"],
        "database_write": ["create", "insert", "update", "modify", "save", "put"],
        "destructive_action": ["delete", "remove", "drop", "truncate", "purge", "cancel", "terminate", "kill"],
        "external_send": ["send", "email", "notify", "post", "webhook", "publish", "slack", "alert", "message", "dispatch"],
        "filesystem_access": ["file", "path", "directory", "folder", "download", "upload", "write_file", "read_file"],
        "credential_access": ["auth", "token", "password", "secret", "key", "credential", "admin"],
        "code_execution": ["exec", "run", "eval", "script", "command", "bash", "shell"]
    }

    RECIPIENT_KEYWORDS = ["email", "to", "recipient", "address", "destination", "target", "channel", "webhook_url"]
    RECORD_PARAM_KEYWORDS = ["id", "order_id", "user_id", "record", "limit", "count", "query", "batch", "page"]

    @classmethod
    def generate_schema_hash(cls, tool_def: Dict[str, Any]) -> str:
        """Compute SHA256 of tool definition (name, description, inputSchema)."""
        clean_def = {
            "name": tool_def.get("name", ""),
            "description": tool_def.get("description", ""),
            "inputSchema": tool_def.get("inputSchema") or tool_def.get("input_schema") or {}
        }
        serialized = json.dumps(clean_def, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def generate_profile(cls, tool_def: Dict[str, Any]) -> ExpectedBehaviorProfile:
        name = str(tool_def.get("name", "")).strip()
        name_lower = name.lower()
        desc = str(tool_def.get("description", "")).strip()
        desc_lower = desc.lower()

        schema = tool_def.get("inputSchema") or tool_def.get("input_schema") or {}
        properties = schema.get("properties", {})
        combined_text = f"{name_lower} {desc_lower} {' '.join(properties.keys()).lower()}"

        # 1. Infer expected actions
        expected_actions = []
        for action, keywords in cls.ACTION_KEYWORDS.items():
            if any(kw in combined_text for kw in keywords):
                expected_actions.append(action)
        if not expected_actions:
            expected_actions.append("generic_tool_invocation")

        # 2. Infer data types
        allowed_data_types = []
        for p_name, p_spec in properties.items():
            t_type = p_spec.get("type", "string") if isinstance(p_spec, dict) else "string"
            allowed_data_types.append(f"{p_name}:{t_type}")

        # 3. Identify Outbound Communications & Destinations
        is_outbound = "external_send" in expected_actions
        recipient_field = None
        for p_name in properties.keys():
            if any(kw in p_name.lower() for kw in cls.RECIPIENT_KEYWORDS):
                recipient_field = p_name
                is_outbound = True
                break

        # 4. Identify Records / Bulk Parameters
        records_field = None
        for p_name in properties.keys():
            if any(kw in p_name.lower() for kw in cls.RECORD_PARAM_KEYWORDS):
                records_field = p_name
                break

        is_destructive = "destructive_action" in expected_actions or "code_execution" in expected_actions
        is_bulk_capable = any(kw in combined_text for kw in ["all", "bulk", "batch", "list", "multiple", "export"])

        # 5. Risk Level Assignment
        risk_level = "low"
        if "code_execution" in expected_actions or "credential_access" in expected_actions:
            risk_level = "critical"
        elif is_destructive or (is_outbound and is_bulk_capable):
            risk_level = "high"
        elif is_outbound or "database_write" in expected_actions or is_bulk_capable:
            risk_level = "medium"

        allowed_destinations = ["internal_network", "customer_profile_on_record"] if is_outbound else ["local_mcp_host"]

        return ExpectedBehaviorProfile(
            tool=name,
            description=desc,
            expected_actions=expected_actions,
            allowed_data_types=allowed_data_types,
            allowed_destinations=allowed_destinations,
            expected_network_behavior=["internal_service"] if not is_outbound else ["trusted_smtp", "external_api"],
            risk_level=risk_level,
            is_outbound=is_outbound,
            is_destructive=is_destructive,
            is_bulk_capable=is_bulk_capable,
            records_field=records_field,
            recipient_field=recipient_field,
            max_expected_records=50 if is_bulk_capable else 1,
            schema_hash=cls.generate_schema_hash(tool_def)
        )
