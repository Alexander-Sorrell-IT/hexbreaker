"""SIFT tool subprocess wrappers with capture + hash + step_id allocation.

Every tool invocation goes through `run_tool()`, which:
  1. Validates the tool name is in the supported set (no LLM-supplied tool names).
  2. Runs the subprocess via a swappable `runner` callable (default shells out;
     tests inject a fake; later this can be swapped for SSH execution).
  3. Hashes stdout and stderr.
  4. Writes full stdout/stderr to sidecar files next to the transcript so the
     JSONL stays small even when the tool emits megabytes.
  5. Appends a TOOL_CALL StepRecord to the transcript, which assigns the step_id.

This is Layer 1 (orchestrator owns step_ids) and Layer 4 (hash chain) of the
hallucination safeguards working together. Defender verdicts later cite
`step_id` and `stdout_hash`; the validator (Wed) checks both.
"""

from __future__ import annotations

import hashlib
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .transcript import Actor, Kind, StepRecord, Transcript

SUPPORTED_TOOLS: frozenset[str] = frozenset({
    "MFTECmd",
    "AmcacheParser",
    "PECmd",
    "EvtxECmd",
    "RECmd",
    "vol",
    "log2timeline.py",
    "fls",
    "yara",
    "bulk_extractor",
})

ToolRunner = Callable[
    [list[str], Path | None, float | None],
    tuple[int, bytes, bytes, float],
]


def subprocess_runner(
    argv: list[str],
    cwd: Path | None,
    timeout: float | None,
) -> tuple[int, bytes, bytes, float]:
    """Default runner — execute argv locally and capture output.

    Catches TimeoutExpired so a long-running tool produces a clean failed
    TOOL_CALL record (rc=124, stderr explaining the timeout) rather than
    crashing the Court turn — code-review Tier B finding (wrapper/proxy E5).
    """
    t0 = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            cwd=cwd,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as te:
        stdout = te.stdout or b""
        stderr = (te.stderr or b"") + f"\n[hexbreaker] timeout after {timeout}s: {' '.join(argv)}\n".encode()
        return 124, stdout, stderr, time.monotonic() - t0
    return completed.returncode, completed.stdout, completed.stderr, time.monotonic() - t0


def _hash_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class ToolResult:
    """In-memory view of a tool invocation. The on-disk record is the StepRecord."""

    step_id: str
    tool: str
    argv: list[str]
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_hash: str
    stderr_hash: str
    duration_s: float
    stdout_path: Path
    stderr_path: Path
    record: StepRecord


def run_tool(
    transcript: Transcript,
    tool: str,
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = 300.0,
    runner: ToolRunner = subprocess_runner,
) -> ToolResult:
    """Run a supported SIFT tool, hash output, sidecar full output, append to transcript."""
    if tool not in SUPPORTED_TOOLS:
        raise ValueError(
            f"unsupported tool {tool!r}; allowed: {sorted(SUPPORTED_TOOLS)}"
        )

    argv = [tool, *args]
    returncode, stdout, stderr, duration = runner(argv, cwd, timeout)

    stdout_hash = _hash_bytes(stdout)
    stderr_hash = _hash_bytes(stderr)

    # Sidecar files live next to the transcript so a run is self-contained.
    sidecar_dir = transcript.path.parent / f"{transcript.path.stem}.outputs"
    sidecar_dir.mkdir(parents=True, exist_ok=True)
    step_id = transcript.next_step_id  # peek; append() will assign it
    stdout_path = sidecar_dir / f"{step_id}.stdout"
    stderr_path = sidecar_dir / f"{step_id}.stderr"
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)

    record = transcript.append(
        actor=Actor.TOOL,
        kind=Kind.TOOL_CALL,
        content={
            "tool": tool,
            "argv": argv,
            "returncode": returncode,
            "stdout_hash": stdout_hash,
            "stderr_hash": stderr_hash,
            "stdout_path": str(stdout_path.relative_to(transcript.path.parent)),
            "stderr_path": str(stderr_path.relative_to(transcript.path.parent)),
            "duration_s": round(duration, 4),
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
        },
    )

    return ToolResult(
        step_id=record.step_id,
        tool=tool,
        argv=argv,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_hash=stdout_hash,
        stderr_hash=stderr_hash,
        duration_s=duration,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        record=record,
    )
