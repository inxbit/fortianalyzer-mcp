"""The server serves at once and connects to FortiAnalyzer in the background.

Awaiting the connect before serving made ``initialize`` wait out the whole
connect timeout when FortiAnalyzer was unreachable with username/password
auth, past Claude Code's own 30 s MCP connect timeout, and a failed startup
connect left every tool answering "Not connected" until a restart.
"""

import asyncio
import os
import sys
import time
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

import fortianalyzer_mcp.server as server
from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.tools import system_tools
from fortianalyzer_mcp.utils.errors import ConnectionError

REPO_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
# RFC 5737 TEST-NET-1: never routed, so a connect to it hangs until the timeout.
UNREACHABLE_HOST = "192.0.2.1"
CONNECT_TIMEOUT = 20


@pytest.fixture(autouse=True)
def _restore_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "faz_client", None)


def _connected(client: FortiAnalyzerClient) -> None:
    fmg = MagicMock()
    fmg.get.return_value = (0, {"Hostname": "faz-01", "Version": "v7.6.5"})
    client._fmg = fmg
    client._connected = True
    client._ever_connected = True


class TestStartupDoesNotBlock:
    async def test_start_returns_before_the_connect_finishes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        release = asyncio.Event()

        async def slow_connect(self_: FortiAnalyzerClient) -> None:
            await release.wait()
            _connected(self_)

        monkeypatch.setattr(FortiAnalyzerClient, "connect", slow_connect)
        task = server._start_faz_client()
        await asyncio.sleep(0)
        assert not task.done()
        assert server.get_faz_client() is not None

        release.set()
        await task
        assert server.get_faz_client().is_connected

    async def test_stop_cancels_a_pending_connect(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def hanging_connect(self_: FortiAnalyzerClient) -> None:
            await asyncio.Event().wait()

        monkeypatch.setattr(FortiAnalyzerClient, "connect", hanging_connect)
        task = server._start_faz_client()
        await asyncio.sleep(0)
        await asyncio.wait_for(server._stop_faz_client(task), timeout=2)
        assert task.cancelled()


class TestRecoveryAfterAFailedStartup:
    async def test_tool_connects_once_fortianalyzer_is_reachable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reachable = False

        async def connect(self_: FortiAnalyzerClient) -> None:
            if not reachable:
                raise ConnectionError("Failed to connect to FortiAnalyzer: timed out")
            _connected(self_)

        monkeypatch.setattr(FortiAnalyzerClient, "connect", connect)
        task = server._start_faz_client()
        await task  # the startup attempt fails and only logs

        down: dict[str, Any] = await system_tools.get_system_status()
        assert down["status"] == "error"
        assert "Failed to connect" in down["message"]

        reachable = True
        up: dict[str, Any] = await system_tools.get_system_status()
        assert up["status"] == "success"


class TestStdioHandshake:
    async def test_initialize_does_not_wait_for_an_unreachable_fortianalyzer(self) -> None:
        """The real stdio path, with FortiAnalyzer unreachable.

        Username/password auth, because that login makes a network round-trip
        (API-token login does not). Before the fix ``initialize`` was answered
        only after the connect timeout. The dummy credentials also keep the
        repo's .env secrets from being sent anywhere.
        """
        env = {
            **os.environ,
            "PYTHONPATH": REPO_SRC,
            "MCP_SERVER_MODE": "stdio",
            "LOG_LEVEL": "WARNING",
            "FORTIANALYZER_HOST": UNREACHABLE_HOST,
            "FORTIANALYZER_API_TOKEN": "",
            "FORTIANALYZER_USERNAME": "dummy",
            "FORTIANALYZER_PASSWORD": "dummy",
            "FORTIANALYZER_TIMEOUT": str(CONNECT_TIMEOUT),
            "MASKING_ENABLED": "false",
        }
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "fortianalyzer_mcp"], env=env
        )
        with open(os.devnull, "w") as errlog:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    started = time.monotonic()
                    result = await session.initialize()
                    elapsed = time.monotonic() - started

        assert result.server_info.name
        assert elapsed < CONNECT_TIMEOUT / 2, f"initialize took {elapsed:.1f}s"
