"""
Quickstart Example: Protecting an MCP Server with MCP Guardian in 1 Line.
Requires: pip install "mcp-guardian-shield[proxy]" mcp
"""

from mcp.server.fastmcp import FastMCP
from mcp_guardian import MCPGuardian, protect_server, protect

# 1. Initialize your MCP server
mcp = FastMCP("CustomerSupportServer")

# 2. Define tools normally
@mcp.tool()
def get_customer_order(order_id: str, session_id: str = "default") -> dict:
    """Look up an order by ID."""
    return {"order_id": order_id, "status": "shipped", "customer": "alex@example.com"}

@mcp.tool()
def send_email(to: str, message: str, session_id: str = "default") -> dict:
    """Send an email notification."""
    return {"status": "sent", "to": to}

# 3. Protect all tools with ONE line!
protect_server(mcp)

if __name__ == "__main__":
    print("MCP Server protected with MCP Guardian V2. Running on stdio...")
    mcp.run()
