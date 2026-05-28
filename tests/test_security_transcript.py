"""Regression tests for the security-review path-traversal findings (Vuln 2).

Vulnerability: a malicious case directory ships a pre-poisoned transcript.jsonl
whose TOOL_CALL records have `stdout_path: "../../etc/passwd"`. Without the
runtime is_relative_to check in _render_transcript, the runner reads that path
and inlines it into the LLM prompt — arbitrary file read + LLM-channel exfil.

These tests prove the defense layers hold:
  - _render_transcript refuses to read sidecars that escape transcript_dir
  - run_court_on_case refuses to resume a pre-existing transcript in the case
    dir (the attacker's vector for shipping the poisoned chain)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hexbreaker.forge import template_timestomp
from hexbreaker.runner.court_runner import _render_transcript, run_court_on_case
from hexbreaker.transcript import Actor, Kind, Transcript


def test_render_transcript_refuses_traversal_stdout_path(tmp_path: Path) -> None:
    """A TOOL_CALL record whose stdout_path escapes the transcript dir must
    not produce file contents in the rendering — even if the chain is valid."""
    transcript_path = tmp_path / "run.jsonl"
    t = Transcript.open(transcript_path)
    # Plant a hostile record that points sidecar at /etc/passwd (or any file
    # the test process can read). Hash chain stays valid because we're going
    # through the proper append() path; the issue is the sidecar resolution.
    t.append(
        actor=Actor.TOOL,
        kind=Kind.TOOL_CALL,
        content={
            "tool": "MFTECmd",
            "argv": ["MFTECmd"],
            "returncode": 0,
            "stdout_hash": "sha256:" + "0" * 64,
            "stderr_hash": "sha256:" + "0" * 64,
            "stdout_path": "../../../../etc/passwd",
            "stderr_path": "../../../../etc/passwd",
            "duration_s": 0.01,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
        },
    )
    rendered = _render_transcript(transcript_path)
    # The rendering must NOT contain /etc/passwd content. It must explicitly
    # mark the sidecar as refused so a Prosecutor can't be tricked.
    assert "sidecar refused" in rendered
    # Sanity: real /etc/passwd content (root:) absent.
    assert "root:x:0:0" not in rendered


def test_render_transcript_refuses_absolute_stdout_path(tmp_path: Path) -> None:
    transcript_path = tmp_path / "run.jsonl"
    t = Transcript.open(transcript_path)
    t.append(
        actor=Actor.TOOL,
        kind=Kind.TOOL_CALL,
        content={
            "tool": "fls",
            "argv": ["fls"],
            "returncode": 0,
            "stdout_hash": "sha256:" + "0" * 64,
            "stderr_hash": "sha256:" + "0" * 64,
            "stdout_path": "/etc/passwd",
            "stderr_path": "/dev/null",
            "duration_s": 0.01,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
        },
    )
    rendered = _render_transcript(transcript_path)
    assert "sidecar refused" in rendered


def test_run_court_refuses_preexisting_transcript_in_case_dir(tmp_path: Path) -> None:
    """The full attack: an attacker ships a case dir with a poisoned
    transcript.jsonl alongside the manifest. run_court_on_case must refuse
    to resume it (so _render_transcript is never called against attacker
    records that were not produced by this run's CourtSession)."""
    case_dir = tmp_path / "case"
    template_timestomp.generate(seed=99, out_dir=case_dir)
    # Attacker plants a transcript.jsonl in the case dir.
    poisoned = case_dir / "transcript.jsonl"
    poisoned.write_bytes(b'{"step_id":"S-001","fake":"yes"}\n')
    with pytest.raises(RuntimeError, match="refusing to resume"):
        run_court_on_case(case_dir)


def test_run_court_accepts_clean_case_dir(tmp_path: Path) -> None:
    """Sanity: the security guard does not false-positive on a clean case dir
    (no pre-existing transcript). Uses a stub LLM client so we don't burn
    real DeepSeek tokens on what should be a pure path-existence check."""
    from hexbreaker import llm
    case_dir = tmp_path / "case"
    template_timestomp.generate(seed=100, out_dir=case_dir)
    # No transcript.jsonl exists. Stub the LLM client so the security guard
    # is exercised but no real HTTP call leaves the box.

    class _StubClient:
        def call(self, *_args, **_kwargs):
            raise RuntimeError("stub-llm-called")

    try:
        run_court_on_case(case_dir, client=_StubClient())  # type: ignore[arg-type]
    except RuntimeError as e:
        if "refusing to resume" in str(e):
            raise  # the security guard fired on a clean dir — bug
        # stub-llm-called is expected — the guard cleared, we got to the LLM call
