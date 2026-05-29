"""Hexbreaker MCP — Model Context Protocol exposure of the SIFT tool layer.

A thin, honest MCP server that lets an MCP-speaking agent invoke Hexbreaker's
gated SIFT tool wrappers (`hexbreaker.tools.run_tool`) over stdio. The server
adds no forensics intelligence of its own: it gates the tool name against
`SUPPORTED_TOOLS`, shells out via the same `ToolRunner` seam the orchestrator
uses, and returns the chain-of-custody record (step_id, return code, output
hashes, sidecar paths) rather than raw output dressed up as verified.

Scope is deliberately local: the server runs SIFT tools as subprocesses on its
own host. Remote-endpoint execution is NOT wired — see docs/mcp.md.
"""
