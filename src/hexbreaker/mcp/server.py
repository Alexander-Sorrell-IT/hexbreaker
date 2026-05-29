"""MCP stdio server exposing Hexbreaker's gated SIFT tool layer.

Design: a small pure core (testable without the async SDK) wrapped by thin
async adapters registered on `mcp.server.Server`.

    pure core:
        supported_tool_specs() -> list[Tool]      # the honest advertisement
        execute_sift_tool(...)  -> list[TextContent]  # gate + run_tool + format
    sdk adapters:
        @server.list_tools()  -> calls supported_tool_specs()
        @server.call_tool()   -> calls execute_sift_tool()
    entry:
        main() runs the server over stdio; `python -m hexbreaker.mcp.server`.

Honesty contract (this is an anti-hallucination forensics project):
  * Only `run_sift_tool` is exposed, and its `tool` argument is constrained to
    `sorted(SUPPORTED_TOOLS)` both in the advertised JSON Schema enum AND by
    `run_tool`, which raises ValueError on any other name. There is no path
    that runs an LLM-supplied arbitrary command.
  * The server NEVER fabricates output. If a SIFT tool is absent from the host
    PATH the subprocess fails and the recorded return code / stderr reflect
    that — see docs/mcp.md.
  * The reply is the on-disk StepRecord content (step_id + hashes + sidecar
    paths) on a hash-chained transcript, not raw stdout presented as truth.
    The caller can re-read and re-hash the sidecars to verify chain of custody.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import mcp.types as types
import orjson
from mcp.server import Server

from ..tools import SUPPORTED_TOOLS, ToolRunner, run_tool, subprocess_runner
from ..transcript import Transcript

SERVER_NAME = "hexbreaker-sift"

#: The single tool name advertised over MCP. Keeping it to one tool keeps the
#: surface honest: there is exactly one capability — run a *supported* SIFT tool.
RUN_TOOL_NAME = "run_sift_tool"

#: Where tool invocations are recorded. The transcript is hash-chained and its
#: sidecar `.outputs/` directory holds full stdout/stderr. Overridable so a host
#: can point it at a per-run path; defaults next to the cwd.
TRANSCRIPT_ENV = "HEXBREAKER_MCP_TRANSCRIPT"
DEFAULT_TRANSCRIPT = "hexbreaker-mcp.jsonl"


def transcript_path() -> Path:
    """Resolve the transcript path from the environment or fall back to default."""
    return Path(os.environ.get(TRANSCRIPT_ENV, DEFAULT_TRANSCRIPT))


def supported_tool_specs() -> list[types.Tool]:
    """Advertise the single gated SIFT runner.

    The `tool` property is an enum of `sorted(SUPPORTED_TOOLS)` — that enum IS
    the honest gating advertisement; a conformant client cannot even request an
    unsupported tool, and `run_tool` enforces the same set server-side.
    """
    return [
        types.Tool(
            name=RUN_TOOL_NAME,
            title="Run a supported SIFT forensic tool",
            description=(
                "Run one of Hexbreaker's allow-listed SIFT/forensics tools as a "
                "local subprocess on the server host, hash its stdout/stderr, write "
                "the full output to sidecar files, and append a hash-chained "
                "TOOL_CALL record to the transcript. Returns the record (step_id, "
                "return code, output hashes, sidecar paths) — not raw output dressed "
                "as verified. The tool must be on the server host's PATH (the SIFT "
                "VM or the Hexbreaker Docker image); otherwise the subprocess fails "
                "and the non-zero return code is reported faithfully."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tool": {
                        "type": "string",
                        "enum": sorted(SUPPORTED_TOOLS),
                        "description": "SIFT tool name. Restricted to the allow-list.",
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": [],
                        "description": "Positional arguments passed after the tool name.",
                    },
                },
                "required": ["tool"],
                "additionalProperties": False,
            },
        )
    ]


def execute_sift_tool(
    transcript: Transcript,
    name: str,
    arguments: dict[str, Any] | None,
    *,
    runner: ToolRunner = subprocess_runner,
) -> list[types.TextContent]:
    """Gate, dispatch through `run_tool`, and format the chain-of-custody record.

    `name` is the MCP tool name (must be RUN_TOOL_NAME). `arguments["tool"]`
    selects the SIFT tool and is gated by `run_tool` against SUPPORTED_TOOLS,
    which raises ValueError for anything else — we do not duplicate that gate.
    `runner` is threaded through so tests can inject a fake (the default is
    bound at run_tool def-time, so it must be passed explicitly to override).
    """
    if name != RUN_TOOL_NAME:
        raise ValueError(
            f"unknown MCP tool {name!r}; only {RUN_TOOL_NAME!r} is exposed"
        )

    arguments = arguments or {}
    tool = arguments.get("tool")
    if not isinstance(tool, str):
        raise ValueError("argument 'tool' is required and must be a string")
    args = arguments.get("args", [])
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ValueError("argument 'args' must be a list of strings")

    # run_tool raises ValueError("unsupported tool ...") for non-allow-listed
    # names; we let it propagate so the gate has a single source of truth.
    result = run_tool(transcript, tool, args, runner=runner)

    payload = {
        "step_id": result.step_id,
        "tool": result.tool,
        "argv": result.argv,
        "returncode": result.returncode,
        "stdout_hash": result.stdout_hash,
        "stderr_hash": result.stderr_hash,
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
        "stdout_path": str(result.stdout_path),
        "stderr_path": str(result.stderr_path),
        "transcript": str(transcript.path),
    }
    return [
        types.TextContent(
            type="text",
            text=orjson.dumps(payload, option=orjson.OPT_INDENT_2).decode(),
        )
    ]


def build_server() -> Server:
    """Wire the pure core onto an MCP Server via thin async adapters."""
    server: Server = Server(SERVER_NAME)

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return supported_tool_specs()

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        # A fresh Transcript per call resumes/extends the same hash chain on disk.
        transcript = Transcript.open(transcript_path())
        return execute_sift_tool(transcript, name, arguments)

    return server


async def serve_stdio() -> None:
    """Serve the MCP protocol over stdio until the client disconnects."""
    from mcp.server.stdio import stdio_server

    server = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    """Console entry point: run the stdio MCP server."""
    import anyio

    anyio.run(serve_stdio)


if __name__ == "__main__":
    main()
