"""Model Context Protocol (MCP) usage fixture — positive and negative cases."""
import asyncio

from mcp import ClientSession  # airom: mcp/import
from mcp.server.stdio import stdio_server


async def serve(server) -> None:
    # airom: mcp/server
    async with stdio_server() as (read, write):
        await server.run(read, write)


# airom-ok: mcp/import
note = "mcp server setup guide"

# airom-ok: mcp/server
label = "ClientSession configuration notes"
