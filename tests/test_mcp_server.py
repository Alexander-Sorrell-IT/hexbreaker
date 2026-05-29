"""Tests for the Hexbreaker MCP server's pure dispatch core.

These exercise the registry/dispatch WITHOUT a live MCP client: they call the
pure functions (`supported_tool_specs`, `execute_sift_tool`) directly and inject
a fake runner exactly like test_tools.py, so no real SIFT subprocess is spawned.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import mcp.types as types
import orjson
import pytest

from hexbreaker.mcp.server import (
    RUN_TOOL_NAME,
    build_server,
    execute_sift_tool,
    supported_tool_specs,
)
from hexbreaker.tools import SUPPORTED_TOOLS
from hexbreaker.transcript import Transcript, verify


def _fake_runner_factory(stdout: bytes, stderr: bytes, rc: int = 0, duration: float = 0.01):
    def runner(_argv, _cwd, _timeout):
        return rc, stdout, stderr, duration
    return runner


def test_advertises_single_gated_tool() -> None:
    specs = supported_tool_specs()
    assert len(specs) == 1
    tool = specs[0]
    assert tool.name == RUN_TOOL_NAME
    enum = tool.inputSchema["properties"]["tool"]["enum"]
    # The advertised enum IS the gate; it must equal the supported set exactly.
    assert set(enum) == set(SUPPORTED_TOOLS)
    assert enum == sorted(SUPPORTED_TOOLS)


def test_dispatch_runs_supported_tool(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "mcp.jsonl")
    stdout = b"file listing"
    content = execute_sift_tool(
        t,
        RUN_TOOL_NAME,
        {"tool": "fls", "args": ["-m", "C:", "/case/image.dd"]},
        runner=_fake_runner_factory(stdout, b""),
    )
    assert len(content) == 1
    assert content[0].type == "text"
    payload = orjson.loads(content[0].text)
    assert payload["tool"] == "fls"
    assert payload["argv"] == ["fls", "-m", "C:", "/case/image.dd"]
    assert payload["returncode"] == 0
    assert payload["step_id"] == "S-001"
    # Honest chain-of-custody: the reply carries the hash, not raw stdout.
    assert payload["stdout_hash"] == "sha256:" + hashlib.sha256(stdout).hexdigest()
    assert payload["stdout_bytes"] == len(stdout)
    assert Path(payload["stdout_path"]).read_bytes() == stdout


def test_dispatch_refuses_unsupported_sift_tool(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "mcp.jsonl")
    with pytest.raises(ValueError, match="unsupported tool"):
        execute_sift_tool(
            t,
            RUN_TOOL_NAME,
            {"tool": "rm", "args": ["-rf", "/"]},
            runner=_fake_runner_factory(b"", b""),
        )


def test_dispatch_refuses_unknown_mcp_tool(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "mcp.jsonl")
    with pytest.raises(ValueError, match="unknown MCP tool"):
        execute_sift_tool(
            t,
            "exfiltrate",
            {"tool": "fls"},
            runner=_fake_runner_factory(b"", b""),
        )


def test_dispatch_validates_tool_argument(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "mcp.jsonl")
    with pytest.raises(ValueError, match="'tool' is required"):
        execute_sift_tool(t, RUN_TOOL_NAME, {}, runner=_fake_runner_factory(b"", b""))


def test_dispatch_validates_args_argument(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "mcp.jsonl")
    with pytest.raises(ValueError, match="'args' must be a list of strings"):
        execute_sift_tool(
            t,
            RUN_TOOL_NAME,
            {"tool": "fls", "args": "-m"},
            runner=_fake_runner_factory(b"", b""),
        )


def test_dispatch_preserves_chain_integrity(tmp_path: Path) -> None:
    path = tmp_path / "mcp.jsonl"
    t = Transcript.open(path)
    execute_sift_tool(t, RUN_TOOL_NAME, {"tool": "fls", "args": ["a"]},
                      runner=_fake_runner_factory(b"out1", b""))
    execute_sift_tool(t, RUN_TOOL_NAME, {"tool": "yara", "args": ["r.yar", "."]},
                      runner=_fake_runner_factory(b"out2", b""))
    ok, reason = verify(path)
    assert ok, reason


def test_failed_subprocess_reports_returncode_honestly(tmp_path: Path) -> None:
    """A tool absent from PATH / failing must surface its rc, never fake success."""
    t = Transcript.open(tmp_path / "mcp.jsonl")
    content = execute_sift_tool(
        t,
        RUN_TOOL_NAME,
        {"tool": "vol", "args": ["-f", "mem.raw", "windows.pslist"]},
        runner=_fake_runner_factory(b"", b"command not found", rc=127),
    )
    payload = orjson.loads(content[0].text)
    assert payload["returncode"] == 127
    assert payload["stderr_hash"] == "sha256:" + hashlib.sha256(b"command not found").hexdigest()


async def test_sdk_list_tools_adapter_advertises_gate() -> None:
    """Lock in the async @server.list_tools() adapter (asyncio_mode=auto)."""
    server = build_server()
    handler = server.request_handlers[types.ListToolsRequest]
    result = await handler(types.ListToolsRequest(method="tools/list"))
    tools = result.root.tools
    assert [t.name for t in tools] == [RUN_TOOL_NAME]
    assert set(tools[0].inputSchema["properties"]["tool"]["enum"]) == set(SUPPORTED_TOOLS)
