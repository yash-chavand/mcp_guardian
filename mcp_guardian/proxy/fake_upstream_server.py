"""
A minimal HTTP JSON-RPC MCP-like server, standing in for "the developer's
own real MCP server, written in whatever language they use." This is ONLY
for testing the proxy end-to-end -- the proxy itself doesn't know or care
that this happens to be written in Python; it only speaks HTTP/JSON-RPC.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Fake Upstream MCP Server")

CUSTOMER_DB = {i: {"email": f"customer{i}@example.com", "order_id": 10000 + i} for i in range(1, 50)}
ORDER_TO_CUSTOMER = {v["order_id"]: k for k, v in CUSTOMER_DB.items()}


@app.post("/mcp")
async def handle(request: Request):
    body = await request.json()
    method = body.get("method")
    req_id = body.get("id")

    if method == "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"serverInfo": {"name": "fake-upstream"}}})

    if method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": [
            {
                "name": "get_customer_order",
                "description": "Look up one order by order_id",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "order_id": {"type": "string"}
                    },
                    "required": ["order_id"]
                }
            },
            {
                "name": "send_email",
                "description": "Email a customer",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "customer_email": {"type": "string"},
                        "message": {"type": "string"}
                    },
                    "required": ["customer_email", "message"]
                }
            }
        ]}})

    if method == "tools/call":
        params = body.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})

        if name == "get_customer_order":
            oid = args.get("order_id")
            if str(oid).upper() == "ALL":
                result = {"status": "ok", "records": len(CUSTOMER_DB)}
            else:
                cust_id = ORDER_TO_CUSTOMER.get(int(oid))
                result = {"status": "ok", "order": CUSTOMER_DB[cust_id]} if cust_id else {"status": "not_found"}
        elif name == "send_email":
            result = {"status": "sent", "to": args.get("customer_email")}
        else:
            result = {"status": "unknown_tool"}

        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})

    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "method not found"}})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8100)
