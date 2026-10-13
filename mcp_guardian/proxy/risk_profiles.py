"""
Tool Risk Profiles — makes MCP Guardian's proxy generic to ANY MCP server's
tool schema, not just our demo's get_customer_order/send_email.

A deployment operator describes, per tool, which argument (if any) signals
"how much data" a call touches, and which argument (if any) is an outbound
recipient/destination that should be checked against a trusted allow-list.
Guardian does not need to know anything about the tool's actual business
logic -- just these two generic risk signals.

Example config (config.json):
{
  "tools": {
    "get_customer_order": {
      "records_field": "order_id",
      "bulk_values": ["ALL", "*", "all"]
    },
    "send_email": {
      "is_outbound": true,
      "recipient_field": "customer_email",
      "trusted_domains": ["example.com", "mycompany.com"]
    },
    "run_database_query": {
      "records_field": "limit",
      "bulk_threshold": 100
    }
  }
}

Any tool NOT listed in the config still gets scored using generic defaults
(records_this_call=1, is_email=False) -- so nothing goes fully unmonitored,
it just won't have tool-specific tuning until the operator adds it.
"""

import json
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class ToolRiskProfile:
    records_field: str = None          # arg name holding a "how much data" signal
    bulk_values: list = field(default_factory=list)  # values in records_field meaning "everything"
    bulk_threshold: int = None         # OR: numeric threshold in records_field meaning "too much"
    is_outbound: bool = False          # does this tool send data externally (email, webhook, API call)?
    recipient_field: str = None        # arg name holding the outbound destination
    trusted_domains: list = field(default_factory=list)  # allowed destination domains, e.g. for email tools


class RiskProfileRegistry:
    def __init__(self, config_path: str = None):
        self.profiles: dict[str, ToolRiskProfile] = {}
        if config_path and Path(config_path).exists():
            self.load(config_path)

    def load(self, config_path: str):
        with open(config_path) as f:
            raw = json.load(f)
        for tool_name, cfg in raw.get("tools", {}).items():
            self.profiles[tool_name] = ToolRiskProfile(**cfg)

    def get(self, tool_name: str) -> ToolRiskProfile:
        return self.profiles.get(tool_name, ToolRiskProfile())

    def auto_discover_profiles(self, tools: list):
        """
        Automatically analyze tool schema definitions and names from tools/list
        to configure outbound and bulk risk profiles with ZERO manual config.
        """
        for t in tools:
            name = t.get("name", "").lower()
            description = t.get("description", "").lower()
            properties = t.get("inputSchema", {}).get("properties", {})
            if not properties:
                properties = t.get("input_schema", {}).get("properties", {})

            if t["name"] in self.profiles:
                continue

            profile = ToolRiskProfile()

            # 1. Infer outbound communication
            outbound_keywords = ["email", "send", "notify", "slack", "webhook", "post", "publish", "alert", "message"]
            is_outbound_name = any(kw in name for kw in outbound_keywords)
            is_outbound_desc = any(kw in description for kw in outbound_keywords)

            if is_outbound_name or is_outbound_desc:
                recipient_keywords = ["email", "to", "recipient", "address", "destination", "channel", "url", "target"]
                for prop_name in properties.keys():
                    if any(kw in prop_name.lower() for kw in recipient_keywords):
                        profile.is_outbound = True
                        profile.recipient_field = prop_name
                        profile.trusted_domains = ["example.com", "example.org"] # Default trusted domains
                        break

            # 2. Infer bulk parameters
            record_keywords = ["id", "records", "limit", "path", "query", "user", "order", "item"]
            for prop_name in properties.keys():
                if any(kw in prop_name.lower() for kw in record_keywords):
                    profile.records_field = prop_name
                    profile.bulk_values = ["ALL", "all", "*", "any", "everything"]
                    profile.bulk_threshold = 100
                    break

            if profile.is_outbound or profile.records_field:
                self.profiles[t["name"]] = profile
                print(f"[MCP Guardian] Auto-discovered risk profile for tool '{t['name']}': "
                      f"is_outbound={profile.is_outbound}, records_field={profile.records_field}")

    def evaluate_call(self, tool_name: str, arguments: dict):
        """
        Generic risk extraction: given ANY tool's arguments, returns
        (records_this_call, recipient_mismatch, is_email) using only the
        operator-supplied profile -- no hardcoded knowledge of the tool.
        """
        profile = self.get(tool_name)
        records = 1

        if profile.records_field and profile.records_field in arguments:
            val = arguments[profile.records_field]
            if isinstance(val, str) and val in profile.bulk_values:
                records = 10_000  # sentinel: "everything" -- always trips the hard-rule layer
            elif isinstance(val, list):
                records = len(val)
            elif profile.bulk_threshold and isinstance(val, (int, float)):
                records = int(val) if val > profile.bulk_threshold else 1

        recipient_mismatch = False
        if profile.is_outbound and profile.recipient_field:
            recipient = str(arguments.get(profile.recipient_field, ""))
            domain = recipient.split("@")[-1] if "@" in recipient else recipient
            if profile.trusted_domains and domain not in profile.trusted_domains:
                recipient_mismatch = True

        return records, recipient_mismatch, profile.is_outbound
