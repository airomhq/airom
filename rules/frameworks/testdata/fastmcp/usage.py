"""FastMCP usage fixture — positive and negative cases."""
from fastmcp import FastMCP  # airom: fastmcp/import

# airom: fastmcp/server
mcp = FastMCP("demo-server")


@mcp.tool
def add(a: int, b: int) -> int:
    return a + b


# airom-ok: fastmcp/import
readme = "fastmcp quickstart"

# airom-ok: fastmcp/server
heading = "FastMCP (server construction)"
