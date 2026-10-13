"""
Fake MCP Server - simulates a customer support AI agent's tool infrastructure.

Two tools are exposed, exactly like a real MCP server would:
  1. get_customer_order(order_id)  -> looks up order info
  2. send_email(customer_id, message) -> "sends" an email (just logs it)

Every incoming request is logged with rich metadata so the anomaly
detector (built later) can learn what "normal" traffic looks like.
"""

import json
import time
import random
import uuid
from datetime import datetime
from pathlib import Path

LOG_PATH = Path(__file__).parent.parent / "data" / "traffic_log.jsonl"

# ---- Fake "database" of customers/orders ----
NUM_CUSTOMERS = 500
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


class MCPServer:
    """Minimal MCP-style server: receives a tool call, executes it, logs it."""

    def __init__(self):
        self.session_state = {}  # tracks last lookup per session, for legitimacy checks

    def _log(self, record: dict):
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")

    def handle_request(self, session_id: str, tool: str, params: dict, request_time: float = None):
        """
        This is the core MCP entrypoint: a tool call comes in, gets executed,
        and full metadata about the call is logged for anomaly analysis.
        """
        t0 = request_time if request_time is not None else time.time()
        record = {
            "request_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": t0,
            "tool": tool,
            "params": params,
        }

        if tool == "get_customer_order":
            order_id = params.get("order_id")
            if order_id == "ALL" or isinstance(order_id, list):
                # Bulk-fetch pattern -- highly abnormal for a support agent
                n_records = NUM_CUSTOMERS if order_id == "ALL" else len(order_id)
                result = {"status": "ok", "records_returned": n_records}
            else:
                n_records = 1
                cust_id = ORDER_TO_CUSTOMER.get(order_id)
                result = {"status": "ok" if cust_id else "not_found", "records_returned": 1 if cust_id else 0}
                if cust_id:
                    self.session_state[session_id] = cust_id

            record["records_requested"] = n_records
            record["response_status"] = result["status"]

        elif tool == "send_email":
            recipient = params.get("customer_email", "")
            expected_cust = self.session_state.get(session_id)
            expected_email = CUSTOMER_DB[expected_cust]["email"] if expected_cust else None
            recipient_matches = (recipient == expected_email)

            record["recipient_matches_last_lookup"] = recipient_matches
            record["recipient_domain"] = recipient.split("@")[-1] if "@" in recipient else "invalid"
            record["response_status"] = "ok"

        else:
            record["response_status"] = "unknown_tool"

        self._log(record)
        return record


if __name__ == "__main__":
    # quick smoke test
    if LOG_PATH.exists():
        LOG_PATH.unlink()
    srv = MCPServer()
    sid = str(uuid.uuid4())
    print(srv.handle_request(sid, "get_customer_order", {"order_id": 10005}))
    print(srv.handle_request(sid, "send_email", {"customer_email": "customer5@example.com", "message": "shipped!"}))
    print("Smoke test OK. Log written to", LOG_PATH)
