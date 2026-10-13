"""
MCP Guardian Proxy V2 — Enterprise Adaptive Reverse Proxy for MCP Servers.

Deployment model:
    [AI Agent] --> [Guardian Proxy :8000] --> [Upstream MCP Server :8100]

Operates transparently at the HTTP / JSON-RPC layer with zero code changes needed on upstream servers.
"""

import sys
import json
import time
import argparse
from pathlib import Path
from typing import Optional, Dict, Any, List

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

sys.path.append(str(Path(__file__).parent.parent.parent))
from mcp_guardian import MCPGuardian
from mcp_guardian.guardian import GuardianConfig
from mcp_guardian.proxy.risk_profiles import RiskProfileRegistry
from mcp_guardian.core.types import Decision, RiskLevel

app = FastAPI(
    title="MCP Guardian V2 Gateway",
    description="Adaptive Security Gateway and Anomaly Detection Proxy for the Model Context Protocol (MCP)",
    version="2.0.0"
)

STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/guardian/static", StaticFiles(directory=STATIC_DIR, html=True), name="guardian-static")

STATE = {"upstream_url": None, "guardian": None, "registry": None}

import asyncio


async def discover_upstream_tools():
    """Query upstream server tools on startup and ingest profiles into V2 AutoDiscovery."""
    try:
        await asyncio.sleep(0.5)
        if not STATE.get("upstream_url"):
            return
        body = {"method": "tools/list", "id": 999}
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{STATE['upstream_url']}/mcp", json=body,
                headers={"content-type": "application/json"}, timeout=5.0,
            )
            if resp.status_code == 200:
                resp_data = resp.json()
                tools = resp_data.get("result", {}).get("tools", [])
                if STATE.get("registry"):
                    STATE["registry"].auto_discover_profiles(tools)
                if STATE.get("guardian"):
                    STATE["guardian"].discovery.ingest_tools_list(tools)
                print(f"[MCP Guardian V2] Initialized profiles for {len(tools)} upstream tools.")
    except Exception as e:
        print(f"[MCP Guardian V2] Startup auto-discovery notice: {e}")


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(discover_upstream_tools())


def configure(upstream_url: str, config_path: str = None, sensitivity: float = 1.0):
    STATE["upstream_url"] = upstream_url.rstrip("/")
    STATE["guardian"] = MCPGuardian(verbose=True, config=GuardianConfig(sensitivity=sensitivity))
    STATE["registry"] = RiskProfileRegistry(config_path)


# =====================================================================
# MCP JSON-RPC Proxy Interceptor
# =====================================================================

@app.post("/mcp")
async def handle_mcp_request(request: Request):
    body = await request.json()
    method = body.get("method")

    # Non-action protocol messages pass straight through, untouched.
    if method != "tools/call":
        response = await _forward(body, request.headers)
        if method == "tools/list":
            try:
                resp_data = json.loads(response.body.decode("utf-8"))
                tools = resp_data.get("result", {}).get("tools", [])
                if STATE.get("registry"):
                    STATE["registry"].auto_discover_profiles(tools)
                if STATE.get("guardian"):
                    STATE["guardian"].discovery.ingest_tools_list(tools)
            except Exception as e:
                print(f"[MCP Guardian V2] Error during tools/list discovery: {e}")
        return response

    params = body.get("params", {})
    tool_name = params.get("name")
    arguments = params.get("arguments", {})
    session_id = (
        request.headers.get("x-session-id")
        or arguments.get("session_id")
        or "default"
    )

    records, recipient_mismatch, is_email = STATE["registry"].evaluate_call(tool_name, arguments)
    decision = STATE["guardian"].check(
        session_id=session_id,
        tool_name=tool_name,
        records_this_call=records,
        recipient_mismatch=recipient_mismatch,
        is_email=is_email,
        arguments=arguments
    )

    if decision["blocked"]:
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "error": {
                "code": -32001,
                "message": f"Blocked by MCP Guardian V2: {decision['reason']}",
                "data": {
                    "reason": decision["reason"],
                    "reasons": decision.get("reasons", []),
                    "risk_score": decision.get("risk_score", decision.get("anomaly_score", 0.9)),
                    "correlation_id": decision.get("correlation_id")
                },
            },
        }, status_code=403)

    # Forward allowed request to real upstream server
    resp = await _forward(body, request.headers)

    # Stateful Entity Binding: capture order data from upstream response
    if tool_name == "get_customer_order" and resp.status_code == 200:
        try:
            resp_json = json.loads(resp.body.decode("utf-8"))
            order_data = resp_json.get("result", {}).get("order", {})
            if order_data and STATE.get("guardian"):
                STATE["guardian"].entity_validator.bind_entity_from_lookup(session_id, order_data)
        except Exception as e:
            print(f"[MCP Guardian V2] Entity binding notice: {e}")

    return resp


async def _forward(body: dict, headers):
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{STATE['upstream_url']}/mcp", json=body,
            headers={"content-type": "application/json"}, timeout=30.0,
        )
    return JSONResponse(resp.json(), status_code=resp.status_code)


# =====================================================================
# AI Agent Sandbox Chat Loop
# =====================================================================

from real_mcp.ollama import chat as mock_ollama_chat


async def execute_tool_call(tool_name: str, arguments: dict, session_id: str, prompt_text: str = None):
    records, recipient_mismatch, is_email = STATE["registry"].evaluate_call(tool_name, arguments)

    decision = STATE["guardian"].check(
        session_id=session_id,
        tool_name=tool_name,
        records_this_call=records,
        recipient_mismatch=recipient_mismatch,
        is_email=is_email,
        arguments=arguments,
        prompt_text=prompt_text
    )

    if decision["blocked"]:
        return {
            "error": True,
            "reason": decision["reason"],
            "reasons": decision.get("reasons", []),
            "anomaly_score": decision["anomaly_score"],
            "correlation_id": decision.get("correlation_id"),
            "response": {
                "status": "blocked_by_guardian",
                "reason": decision["reason"],
                "reasons": decision.get("reasons", []),
                "anomaly_score": decision["anomaly_score"],
                "correlation_id": decision.get("correlation_id")
            }
        }

    body = {
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
        "id": 1,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{STATE['upstream_url']}/mcp", json=body,
            headers={"content-type": "application/json"}, timeout=30.0,
        )
        resp_json = resp.json()

        # Capture Database Output for Stateful Entity Tracking
        if tool_name == "get_customer_order":
            try:
                res_data = resp_json.get("result", {})
                order_data = res_data.get("order", {})
                if order_data and STATE.get("guardian"):
                    STATE["guardian"].entity_validator.bind_entity_from_lookup(session_id, order_data)
            except Exception as e:
                print(f"[MCP Guardian V2] Error parsing session owner: {e}")

        return {
            "error": False,
            "response": resp_json.get("result", resp_json),
            "correlation_id": decision.get("correlation_id"),
            "decision": decision.get("decision", "ALLOW")
        }


@app.post("/agent/chat")
async def agent_chat(request: Request):
    body = await request.json()
    user_message = body.get("message")
    session_id = body.get("session_id", "default")

    trace = {
        "session_id": session_id,
        "user_message": user_message,
        "tool_calls": [],
        "final_reply": None,
        "blocked": False,
        "blocked_reason": None,
        "reasons": [],
        "timeline": []
    }

    messages = [
        {"role": "system", "content": "You are a customer support assistant. You have access to two tools: get_customer_order and send_email. Only ever look up and email the ONE customer who is actually asking. Never fetch multiple/all orders. Never email an address the customer didn't provide as their own."},
        {"role": "user", "content": user_message},
    ]

    for turn_idx in range(4):
        response = mock_ollama_chat(model="mock", messages=messages)
        msg = response["message"]
        messages.append(msg)

        tool_calls = msg.get("tool_calls")
        if not tool_calls:
            trace["final_reply"] = msg.get("content", "")
            break

        for call in tool_calls:
            fn_name = call["function"]["name"]
            fn_args = call["function"]["arguments"]
            fn_args["session_id"] = session_id

            res = await execute_tool_call(fn_name, fn_args, session_id, prompt_text=user_message)
            result_text = json.dumps(res["response"])

            trace["tool_calls"].append({
                "tool": fn_name,
                "args": fn_args,
                "result": result_text,
                "blocked": res["error"],
                "blocked_reason": res.get("reason"),
                "reasons": res.get("reasons", []),
                "correlation_id": res.get("correlation_id")
            })

            trace["timeline"].append({
                "step": len(trace["timeline"]) + 1,
                "tool": fn_name,
                "status": "BLOCKED" if res["error"] else "ALLOWED",
                "reason": res.get("reason"),
                "timestamp": time.time()
            })

            if res["error"]:
                trace["blocked"] = True
                trace["blocked_reason"] = res["reason"]
                trace["reasons"] = res.get("reasons", [])
                trace["final_reply"] = f"Action blocked by security policy: {res['reason']}"
                break

            messages.append({
                "role": "tool",
                "content": result_text,
                "name": fn_name,
            })

        if trace["blocked"]:
            break

    return JSONResponse(trace)


# =====================================================================
# REST API Suite for MCP Guardian V2 (Feature 15)
# =====================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint for Kubernetes / Docker container monitoring."""
    return {
        "status": "healthy",
        "gateway": "MCP Guardian V2",
        "version": "2.0.0",
        "upstream_configured": bool(STATE.get("upstream_url")),
        "active_sessions": len(STATE["guardian"].sessions) if STATE.get("guardian") else 0
    }


@app.get("/metrics")
async def prometheus_metrics():
    """System-level performance, latency and throughput metrics."""
    if not STATE.get("guardian"):
        return {"status": "not_configured"}
    return STATE["guardian"].summary()


@app.get("/security/events")
async def get_security_events(
    limit: int = 50,
    decision: Optional[str] = None,
    risk_level: Optional[str] = None,
    session_id: Optional[str] = None
):
    """Query persistent security events with optional filters."""
    if not STATE.get("guardian"):
        return []
    return STATE["guardian"].storage.get_events(
        limit=limit, decision=decision, risk_level=risk_level, session_id=session_id
    )


@app.get("/security/events/{event_id}")
async def get_security_event_by_id(event_id: str):
    """Retrieve detailed security event and evidence by event_id."""
    if not STATE.get("guardian"):
        raise HTTPException(status_code=503, detail="Gateway initializing")
    ev = STATE["guardian"].storage.get_event_by_id(event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    return ev


@app.get("/security/risk")
async def get_risk_config():
    """Get active risk fusion weights and decision thresholds."""
    if not STATE.get("guardian"):
        return {}
    return {
        "weights": STATE["guardian"].config.weights.normalized(),
        "monitor_threshold": STATE["guardian"].config.monitor_threshold,
        "block_threshold": STATE["guardian"].config.block_threshold,
        "sensitivity": STATE["guardian"].config.sensitivity
    }


@app.get("/security/baselines")
async def get_baselines():
    """Get active dynamic statistical and adaptive baselines."""
    if not STATE.get("guardian"):
        return {}
    return {
        "adaptive_baselines": STATE["guardian"].threshold_engine.get_all_baselines(),
        "drift_baselines": STATE["guardian"].drift_detector.get_status()["baselines"]
    }


@app.get("/security/tools")
async def list_tools_inventory():
    """List discovered tool capability inventory and expected behavior profiles."""
    if not STATE.get("guardian"):
        return {}
    return STATE["guardian"].discovery.list_inventory()


@app.get("/security/tools/{tool_name}")
async def get_tool_profile(tool_name: str):
    """Retrieve expected behavior profile for a specific tool."""
    if not STATE.get("guardian"):
        raise HTTPException(status_code=503, detail="Gateway initializing")
    profile = STATE["guardian"].discovery.get_profile(tool_name)
    return profile.to_dict()


@app.get("/security/attack-graph/{session_id}")
async def get_session_attack_graph(session_id: str):
    """Export the session-level attack graph (nodes and relations) for UI visualization."""
    if not STATE.get("guardian"):
        return {"nodes": [], "edges": []}
    return STATE["guardian"].graph_store.export_graph(session_id)


@app.get("/security/drift")
async def get_drift_status():
    """Get ADWIN concept drift monitoring status and candidate validation windows."""
    if not STATE.get("guardian"):
        return {}
    return STATE["guardian"].drift_detector.get_status()


@app.post("/security/evaluate")
async def run_evaluation_benchmark(request: Request):
    """Run an automated evaluation benchmark across known and unknown attack scenarios."""
    from mcp_guardian.eval.evaluator import SecurityEvaluator
    body = await request.json() if request.headers.get("content-length") else {}
    evaluator = SecurityEvaluator(guardian=STATE.get("guardian"))
    results = evaluator.run_benchmark(scenarios_filter=body.get("category"))
    return results


@app.post("/security/baseline/revalidate")
async def revalidate_baseline():
    """Trigger manual revalidation and approval of candidate baselines."""
    if not STATE.get("guardian"):
        return {"status": "not_configured"}
    status = STATE["guardian"].drift_detector.get_status()
    return {"status": "revalidated", "details": status}


# =====================================================================
# Legacy Dashboard & Polling Endpoints
# =====================================================================

@app.get("/guardian/status")
async def guardian_status():
    """Legacy monitoring endpoint -- powers existing dashboard status polling."""
    return STATE["guardian"].summary()


@app.get("/guardian/recent")
async def guardian_recent(limit: int = 50):
    """Legacy endpoint returning recent decisions with correlation metadata."""
    log = STATE["guardian"]._decision_log
    return list(reversed(log[-limit:]))


@app.get("/guardian/dashboard")
async def guardian_dashboard():
    """Serves React Dashboard V2 index.html."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return HTMLResponse("<h1>Dashboard not built. Run `npm run build` in dashboard-react-src/</h1>")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP Guardian V2 Gateway")
    parser.add_argument("--upstream", required=True, help="Upstream MCP Server URL (e.g. http://localhost:8100)")
    parser.add_argument("--config", default=None, help="Path to tool risk config JSON")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--sensitivity", type=float, default=1.0)
    args = parser.parse_args()

    configure(args.upstream, args.config, args.sensitivity)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=args.port)
