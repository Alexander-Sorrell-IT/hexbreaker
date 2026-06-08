"""Offline finding -> tool-execution tracer (C5: Audit Trail Quality).

`verify` (transcript.py) proves the chain and re-hashes sidecars, but it works on
the transcript alone. The committed artifact a reviewer actually downloads is a
pair: `findings.json` (the conclusions) and `transcript.jsonl` (the evidence). A
finding's `cited_steps` is a list of bare `step_id` strings — to answer "which
tool execution produced this finding, and are its bytes intact?" a reviewer must
hand-join findings -> transcript -> sidecar files.

This module does that join in one pass, so any finding can be traced to the exact
tool execution that produced it. For each cited step it checks, in order:
  1. missing_step    — the cited step_id is not in the transcript at all.
  2. not_a_tool_call — the step exists but is not a TOOL_CALL (no tool output).
  3. hash_mismatch   — the verdict's recorded stdout_hash for that step disagrees
                       with the tool_call record's stdout_hash (a fabricated cite).
  4. sidecar         — the recorded stdout_hash does not match the bytes on disk,
                       or the sidecar path is missing / escapes the transcript dir.

It re-derives everything from the committed files and fabricates nothing. The
chain itself is NOT checked here — run `verify`/`verify_signature` for that; this
adds the finding<->bytes linkage `verify` does not cover.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Literal

import orjson
from pydantic import BaseModel

from ..transcript import Kind, StepRecord
from ..transcript import read as read_transcript

TraceCode = Literal[
    "ok",
    "missing_step",
    "not_a_tool_call",
    "hash_mismatch",
    "sidecar_missing",
    "sidecar_mismatch",
    "sidecar_escape",
]


def _hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class StepTrace(BaseModel):
    """One cited step resolved to (and checked against) its tool output."""

    step_id: str
    code: TraceCode
    tool: str | None = None
    argv: list[str] | None = None
    stdout_hash: str | None = None
    stdout_path: str | None = None
    stdout_preview: str | None = None
    detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.code == "ok"


class FindingTrace(BaseModel):
    """A single finding with every cited step resolved."""

    index: int
    artifact_kind: str
    target: str
    verdict: str
    cited_steps: list[StepTrace]

    @property
    def ok(self) -> bool:
        return bool(self.cited_steps) and all(s.ok for s in self.cited_steps)


class TraceReport(BaseModel):
    ok: bool
    transcript: str
    findings_total: int
    findings_ok: int
    findings: list[FindingTrace]


def _records_by_id(records: list[StepRecord]) -> dict[str, StepRecord]:
    return {r.step_id: r for r in records}


def _verdict_hashes(records: list[StepRecord]) -> dict[str, str]:
    """Map step_id -> the stdout_hash a VERDICT recorded when it cited that step.

    The Defender's verdict attests, per cited step, the stdout_hash it relied on.
    Comparing that against the tool_call's own stdout_hash catches a verdict that
    cites a real step but a hash the tool never emitted (a fabricated citation).
    """
    out: dict[str, str] = {}
    for rec in records:
        if rec.kind != Kind.VERDICT:
            continue
        for ref in rec.content.get("cited_steps", []) or []:
            sid = ref.get("step_id")
            sh = ref.get("stdout_hash")
            if sid and sh:
                out[sid] = sh
    return out


def _trace_step(
    step_id: str,
    records_by_id: dict[str, StepRecord],
    verdict_hashes: dict[str, str],
    transcript_dir: Path,
    *,
    preview_bytes: int,
) -> StepTrace:
    rec = records_by_id.get(step_id)
    if rec is None:
        return StepTrace(
            step_id=step_id,
            code="missing_step",
            detail=f"{step_id} not present in transcript",
        )
    if rec.kind != Kind.TOOL_CALL:
        return StepTrace(
            step_id=step_id,
            code="not_a_tool_call",
            detail=f"{step_id} is a {rec.kind.value}, not a tool_call",
        )

    tool = rec.content.get("tool")
    argv = rec.content.get("argv")
    tool_hash = rec.content.get("stdout_hash")
    rel_path = rec.content.get("stdout_path")

    # A verdict that cited this step must have cited the SAME hash the tool emitted.
    cited_hash = verdict_hashes.get(step_id)
    if cited_hash is not None and cited_hash != tool_hash:
        return StepTrace(
            step_id=step_id,
            code="hash_mismatch",
            tool=tool,
            argv=argv,
            stdout_hash=tool_hash,
            stdout_path=rel_path,
            detail=f"verdict cited {cited_hash} but tool_call recorded {tool_hash}",
        )

    if not rel_path:
        return StepTrace(
            step_id=step_id,
            code="sidecar_missing",
            tool=tool,
            argv=argv,
            stdout_hash=tool_hash,
            detail=f"{step_id} tool_call has no stdout_path",
        )

    candidate = (transcript_dir / rel_path).resolve()
    if not candidate.is_relative_to(transcript_dir):
        return StepTrace(
            step_id=step_id,
            code="sidecar_escape",
            tool=tool,
            argv=argv,
            stdout_hash=tool_hash,
            stdout_path=rel_path,
            detail=f"sidecar path escapes transcript dir: {rel_path}",
        )
    try:
        data = candidate.read_bytes()
    except OSError:
        return StepTrace(
            step_id=step_id,
            code="sidecar_missing",
            tool=tool,
            argv=argv,
            stdout_hash=tool_hash,
            stdout_path=rel_path,
            detail=f"sidecar missing or unreadable: {rel_path}",
        )
    if _hash(data) != tool_hash:
        return StepTrace(
            step_id=step_id,
            code="sidecar_mismatch",
            tool=tool,
            argv=argv,
            stdout_hash=tool_hash,
            stdout_path=rel_path,
            detail=f"sidecar bytes do not match recorded hash: {rel_path}",
        )

    preview = data[:preview_bytes].decode("utf-8", errors="replace")
    return StepTrace(
        step_id=step_id,
        code="ok",
        tool=tool,
        argv=argv,
        stdout_hash=tool_hash,
        stdout_path=rel_path,
        stdout_preview=preview,
    )


def trace_findings(
    findings_path: str | Path,
    transcript_path: str | Path,
    *,
    preview_bytes: int = 240,
) -> TraceReport:
    """Resolve every finding's cited_steps to verified tool output.

    Reads the committed findings.json and transcript.jsonl, joins each finding to
    its tool executions, and re-hashes the referenced sidecar bytes. A finding is
    `ok` only if it cites at least one step and every cited step resolves to a
    tool_call whose recorded hash matches both the verdict's citation and the
    bytes on disk.
    """
    f_path = Path(findings_path)
    t_path = Path(transcript_path)
    transcript_dir = t_path.parent.resolve()

    records = list(read_transcript(t_path))
    by_id = _records_by_id(records)
    vhashes = _verdict_hashes(records)

    payload: Any = orjson.loads(f_path.read_bytes())
    raw_findings = payload.get("findings", []) if isinstance(payload, dict) else payload

    findings: list[FindingTrace] = []
    for i, f in enumerate(raw_findings):
        cited = f.get("cited_steps", []) or []
        steps = [
            _trace_step(sid, by_id, vhashes, transcript_dir, preview_bytes=preview_bytes)
            for sid in cited
        ]
        findings.append(
            FindingTrace(
                index=i,
                artifact_kind=f.get("artifact_kind", "?"),
                target=f.get("target", "?"),
                verdict=f.get("verdict", "?"),
                cited_steps=steps,
            )
        )

    findings_ok = sum(1 for ft in findings if ft.ok)
    return TraceReport(
        ok=bool(findings) and findings_ok == len(findings),
        transcript=str(t_path),
        findings_total=len(findings),
        findings_ok=findings_ok,
        findings=findings,
    )
