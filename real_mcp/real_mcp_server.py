"""
REAL MCP Server (spec-compliant) — built with Anthropic's official `mcp` Python SDK.

This replaces the earlier hand-rolled `mcp_server.py` simulation with a genuine
MCP server that speaks the actual protocol: it can be launched over stdio and
connected to by ANY real MCP client (Claude Desktop, an Ollama-based agent,
a custom client, etc.), not just our own Python code.

Two tools are exposed, matching our customer-support scenario:
    - get_customer_order(order_id)
    - send_email(customer_email, message)

Every tool call is logged with rich metadata to traffic_log.jsonl, in the
same schema as before, so the existing anomaly-detection pipeline
(build_features.py / train_and_evaluate.py) works unchanged on real traffic.
"""

import json
import time
import random
import uuid
from pathlib import Path

from mcp.server.mcpserver import MCPServer

LOG_PATH = Path(__file__).parent.parent / "data" / "real_traffic_log.jsonl"

# ---- Fake "database" (same as before, kept deterministic for repeatable demos) ----
random.seed(7)
NUM_CUSTOMERS = 50
CUSTOMER_DB = {
    i: {
        "customer_id": i,
        "email": f"customer{i}@example.com",
        "order_id": 10000 + i,
        "order_status": random.choice(["shipped", "processing", "delivered", "delayed"]),
    }
    for i in range(1, NUM_CUSTOMERS + 1)
}
ORDER_TO_CUSTOMER = {v["order_id"]: k for k, v in CUSTOMER_DB.items()}

# tracks the most recent customer looked up, PER SESSION, used to check
# whether a send_email call's recipient is legitimate
_session_state: dict[str, int] = {}

mcp_app = MCPServer(
    name="customer-support-mcp",
    version="1.0.0",
    instructions=(
        "Tools for a customer support agent. Use get_customer_order to look up "
        "a single order by its ID, then use send_email to notify that SAME "
        "customer about their order. Never fetch or email more than one "
        "customer per request."
    ),
)


def _log(record: dict):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")


@mcp_app.tool()
def get_customer_order(order_id: str, session_id: str = "default") -> dict:
    """Look up a single customer's order by order ID. Only accepts ONE order ID
    at a time (not 'ALL' or a list) — this is a single-record lookup tool."""
    t0 = time.time()
    record = {
        "request_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": t0,
        "tool": "get_customer_order",
        "params": {"order_id": order_id},
    }

    if str(order_id).upper() == "ALL" or isinstance(order_id, list):
        n_records = NUM_CUSTOMERS
        result = {"status": "rejected", "reason": "bulk_fetch_not_supported"}
        record["records_requested"] = n_records
        record["response_status"] = "rejected"
        _log(record)
        return result

    try:
        oid = int(order_id)
    except (ValueError, TypeError):
        record["records_requested"] = 1
        record["response_status"] = "invalid_order_id"
        _log(record)
        return {"status": "error", "reason": "invalid_order_id"}

    cust_id = ORDER_TO_CUSTOMER.get(oid)
    record["records_requested"] = 1
    if cust_id:
        _session_state[session_id] = cust_id
        record["response_status"] = "ok"
        _log(record)
        return {"status": "ok", "order": CUSTOMER_DB[cust_id]}
    else:
        record["response_status"] = "not_found"
        _log(record)
        return {"status": "not_found"}


@mcp_app.tool()
def send_email(customer_email: str, message: str, session_id: str = "default") -> dict:
    """Send an email update to a customer. Should only be used to email the
    SAME customer whose order was just looked up in this session."""
    t0 = time.time()
    expected_cust = _session_state.get(session_id)
    expected_email = CUSTOMER_DB[expected_cust]["email"] if expected_cust else None
    recipient_matches = (customer_email == expected_email)

    record = {
        "request_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp": t0,
        "tool": "send_email",
        "params": {"customer_email": customer_email, "message": message[:80]},
        "recipient_matches_last_lookup": recipient_matches,
        "recipient_domain": customer_email.split("@")[-1] if "@" in customer_email else "invalid",
        "response_status": "ok",
    }
    _log(record)
    return {"status": "sent", "to": customer_email}


if __name__ == "__main__":
    # Launches the real MCP server over stdio, exactly how Claude Desktop /
    # any real MCP client would connect to it.
    mcp_app.run()
