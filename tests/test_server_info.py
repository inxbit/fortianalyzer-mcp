"""The server must report its own version in the MCP initialize handshake.

``MCPServer`` defaults ``version`` to an empty string, so without passing it
every client saw ``serverInfo.version == ""`` and could not tell which release
it was talking to.
"""

from mcp.client import Client

import fortianalyzer_mcp.server as server
from fortianalyzer_mcp import __version__


async def test_initialize_reports_package_version() -> None:
    async with Client(server.mcp) as client:
        assert client.server_info is not None
        assert client.server_info.name == "FortiAnalyzer API Server"
        assert client.server_info.version == __version__
