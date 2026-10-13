# MCP Guardian

**Real-time anomaly detection for MCP (Model Context Protocol) servers.**
Catches prompt injection and tool misuse against AI agents *as it happens* — not after the fact.

100% free and open-source (MIT license). No paid APIs, no subscriptions, no
API keys required to run the core tool. Every dependency below is free.

---

## What This Is

An AI agent connected to tools via MCP can be tricked (via prompt injection)
into misusing those tools — e.g., dumping an entire database instead of one
record, or emailing sensitive data to an attacker. MCP Guardian sits between
your agent and your real MCP server, scoring every tool call in real time
and blocking anomalous ones before they reach your actual backend.

```
[AI Agent] ---> [MCP Guardian Proxy] ---> [Your Real MCP Server]
                       |
                 blocks anomalies,
                 forwards everything else
```

**Your existing MCP server needs zero code changes.** Works regardless of
what language it's written in (Python, Node.js, Go, anything) — Guardian
operates purely at the HTTP/JSON-RPC layer.

---

## Cost: $0

| Component | Cost |
|---|---|
| MCP Guardian itself | Free (MIT license, open source) |
| scikit-learn, FastAPI, React | Free (open-source libraries) |
| Running it on your own machine/server | Free (your own compute) |

No component of this tool requires a paid API key, cloud subscription, or
usage-based billing. If you also want to test against a real LLM agent (a
separate, optional part of this project), that uses Ollama — also free,
runs locally, no API key needed.

---

## Quickstart (2 Ways to Integrate)

### Option A — Reverse Proxy (works with ANY MCP server, any language)

**1. Install:**
```bash
pip install -e .
```

**2. Describe your tools' risk signals** in a config file (`my_tools.json`):
```json
{
  "tools": {
    "your_bulk_read_tool": {
      "records_field": "id",
      "bulk_values": ["ALL", "*"]
    },
    "your_email_or_webhook_tool": {
      "is_outbound": true,
      "recipient_field": "to",
      "trusted_domains": ["yourcompany.com"]
    }
  }
}
```
(Tools you don't list still get generic default protection — this file just
adds tuning, it's not required for every single tool.)

**3. Run the proxy in front of your real server:**
```bash
mcp-guardian-proxy --upstream http://localhost:YOUR_SERVER_PORT --config my_tools.json --port 8000
```

**4. Point your AI agent at the proxy instead of your server directly:**
```
http://localhost:8000/mcp
```

**5. Watch it live:**
```
http://localhost:8000/guardian/dashboard
```

That's it — your real server is now protected, with zero changes to its code.

### Option B — Python Decorator (if your MCP server is written in Python)

```python
from mcp_guardian import MCPGuardian

guardian = MCPGuardian()

@mcp_app.tool()
@guardian.protect(records_fn=lambda kwargs: 1)
def your_tool(order_id: str, session_id: str = "default") -> dict:
    ...  # your existing tool logic, completely unchanged
```

---

## What You Get

- **Real-time blocking** — attacks are stopped mid-session, not discovered after the fact
- **Hybrid detection** — deterministic hard rules (e.g. "never allow >N records in one call") plus ML anomaly scoring for subtler patterns
- **Live monitoring dashboard** (React, accessible, WCAG-conscious) — see every decision as it happens, filter by blocked/allowed, search by session
- **Configurable sensitivity** — tune false-positive vs. false-negative trade-off to your own traffic
- **Allow-listing** — exempt trusted internal sessions from checks entirely
- **Full audit log** — every decision written to `guardian_decisions.jsonl` for compliance/review

## Known Limitations (see also the in-app Limitations panel)

- The shipped model is trained on simulated + limited real traffic — retrain on your own normal traffic before fully trusting it in production (see `mcp_guardian/train_realtime_model.py`)
- Cold-start actions (a tool call with no prior session history) can be over-flagged
- Session state is in-memory per proxy process — for multi-replica deployments, use sticky routing or add a shared store (not yet implemented)
- Precision is moderate (~60-67%) — treat early blocks as "flag for review," not infallible, until calibrated on your own traffic

## Requirements

- Python 3.9+
- (Only if you want to rebuild the dashboard UI yourself) Node.js 18+ — not required to run the tool, since a pre-built dashboard is already included

## License

MIT — free for personal, academic, and commercial use.
