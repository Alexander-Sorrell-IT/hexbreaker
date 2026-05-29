# Hexbreaker MCP server

A minimal, honest [Model Context Protocol](https://modelcontextprotocol.io) server
that exposes Hexbreaker's gated SIFT tool layer to an MCP-speaking agent over
stdio. It is intentionally small: it adds **no** forensics intelligence of its
own. It gates a tool name against the allow-list, shells out through the same
`ToolRunner` seam the Court orchestrator uses, and returns a chain-of-custody
record.

This is the component the hackathon architecture diagram labels
**"remote endpoints via MCP"** — scoped honestly (see *What is NOT wired* below).

## What it exposes

Exactly **one** MCP tool:

| Tool | Argument | Description |
|------|----------|-------------|
| `run_sift_tool` | `tool` (string, **enum** = the allow-list), `args` (list of strings) | Run one allow-listed SIFT/forensics tool as a local subprocess, hash its stdout/stderr, sidecar the full output, append a hash-chained `TOOL_CALL` record, and return that record. |

The advertised JSON Schema constrains `tool` to an `enum` of
`sorted(SUPPORTED_TOOLS)` (from `hexbreaker.tools`). That enum **is** the gate:
a conformant MCP client cannot even request a tool outside the set, and the
server enforces the same set again server-side — `run_tool` raises
`ValueError("unsupported tool ...")` for anything else. There is no code path
that runs an arbitrary, model-supplied command.

Current allow-list (`SUPPORTED_TOOLS`): `MFTECmd`, `AmcacheParser`, `PECmd`,
`EvtxECmd`, `RECmd`, `vol`, `log2timeline.py`, `fls`, `yara`, `bulk_extractor`,
`icat`, `mmls`, `fsstat`, `ewfverify`.

### What the call returns

The reply is the on-disk `StepRecord` content as JSON text — **not** raw stdout
presented as verified truth:

```json
{
  "step_id": "S-001",
  "tool": "fls",
  "argv": ["fls", "-m", "C:", "/case/image.dd"],
  "returncode": 0,
  "stdout_hash": "sha256:...",
  "stderr_hash": "sha256:...",
  "stdout_bytes": 1234,
  "stderr_bytes": 0,
  "stdout_path": ".../hexbreaker-mcp.jsonl.outputs/S-001.stdout",
  "stderr_path": ".../hexbreaker-mcp.jsonl.outputs/S-001.stderr",
  "transcript": ".../hexbreaker-mcp.jsonl"
}
```

The full output lives in the sidecar files; the transcript is hash-chained, so
the caller can re-read and re-hash the sidecars to verify chain of custody. This
is the same Layer 1 (orchestrator owns `step_id`s) + Layer 4 (hash chain) safeguard
the Court uses.

## How it fits the architecture

```
MCP client / agent  --(MCP, stdio)-->  hexbreaker MCP server  -->  run_tool()  -->  SIFT subprocess
                                              |                         |
                                       gate vs SUPPORTED_TOOLS    hash + sidecar + hash-chained transcript
```

## How to run it

The SIFT tools must be on the **server host's** `PATH` (the SANS SIFT VM, or the
Hexbreaker Docker image). Install the SDK extra and run over stdio:

```bash
pip install -e '.[mcp]'        # installs the `mcp` SDK (see registration note)
PYTHONPATH=src python -m hexbreaker.mcp.server
```

By default the transcript is written to `./hexbreaker-mcp.jsonl` (with a
`.outputs/` sidecar dir alongside). Override with:

```bash
HEXBREAKER_MCP_TRANSCRIPT=/runs/case-42/mcp.jsonl python -m hexbreaker.mcp.server
```

Point any MCP client (Claude Desktop, an MCP CLI, your own agent) at that
command as a stdio server.

## Honesty notes — what this does and does NOT do

* **No fabrication.** If a SIFT tool is absent from the host `PATH`, or fails,
  the subprocess returns a non-zero code and that code (plus the real stderr
  hash) is reported faithfully. The server never invents output.
* **No answer-key access.** The server only runs tools and hashes output. It has
  no knowledge of any case's ground truth.
* **Deterministic surface.** The advertised tool set is derived directly from
  `SUPPORTED_TOOLS`; there is no hidden or dynamic capability.

### NOT wired yet

* **Remote-endpoint execution.** Despite the diagram label "remote endpoints",
  this server runs SIFT tools as **local subprocesses on its own host**. The
  seam for remote execution already exists — `hexbreaker.tools.ToolRunner` is a
  swappable callable, and `tools.py` notes "later this can be swapped for SSH
  execution." Today only `subprocess_runner` (local) is implemented; an
  SSH/remote runner is the future plug-in and is **not** present.
* **No multi-tool composition / Court orchestration over MCP.** MCP exposes the
  raw tool layer only. The adversarial Court, scorer, and provocateur are not
  reachable through this server.
* **No streaming of large output over MCP.** Full output stays in sidecar files;
  the MCP reply carries the hash and path, not the bytes.
