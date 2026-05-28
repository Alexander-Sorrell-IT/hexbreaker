"""Tests for the Court session FSM — Layer 2 (forced tool-call sequence)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import orjson
import pytest

from hexbreaker.court.orchestrator import CourtSession, FSMError, State
from hexbreaker.transcript import Transcript, verify

GOOD_CLAIM = lambda step_id, h: orjson.dumps(  # noqa: E731
    {
        "text": "binary persistence under HKLM Run",
        "artifact_kind": "persistence",
        "target": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil",
        "cited_steps": [{"step_id": step_id, "stdout_hash": h}],
    }
)


def _runner(stdout: bytes, rc: int = 0):
    def run(_argv, _cwd, _timeout):
        return rc, stdout, b"", 0.001
    return run


def _hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def test_session_starts_awaiting_claim(tmp_path: Path) -> None:
    s = CourtSession(Transcript.open(tmp_path / "run.jsonl"))
    assert s.state == State.AWAITING_CLAIM
    assert s.is_open


def test_observe_tool_before_claim_raises(tmp_path: Path) -> None:
    s = CourtSession(Transcript.open(tmp_path / "run.jsonl"))
    with pytest.raises(FSMError, match="claim"):
        s.observe_tool("fls", ["x"], runner=_runner(b"out"))


def test_premature_verdict_is_rejected_but_session_stays_open(tmp_path: Path) -> None:
    """R2: a verdict before any tool observation is rejected; the Defender may retry."""
    t = Transcript.open(tmp_path / "run.jsonl")
    s = CourtSession(t)

    # Drive a claim that will be accepted — first need a tool step to cite.
    out = b"prior-tool"
    t2 = Transcript.open(tmp_path / "evidence.jsonl")
    from hexbreaker.tools import run_tool
    r = run_tool(t2, "fls", ["x"], runner=_runner(out))
    claim_json = GOOD_CLAIM(r.step_id, _hash(out))
    # Use a fresh session pointed at the evidence transcript (cited step lives there).
    s = CourtSession(t2)
    outcome = s.submit_claim(claim_json)
    assert outcome.claim is not None
    assert s.state == State.AWAITING_TOOL
    assert s.must_call_tool

    # Attempt verdict with no fresh tool observation since claim.
    premature = orjson.dumps(
        {
            "verdict": "CONTESTED",
            "cited_steps": [{"step_id": r.step_id, "stdout_hash": _hash(out)}],
            "challenge_text": "premature",
        }
    )
    v = s.submit_verdict(premature)
    assert v.accepted is False
    assert s.is_open
    assert s.state == State.AWAITING_TOOL


def test_verdict_with_fabricated_step_is_rejected_session_stays_open(tmp_path: Path) -> None:
    """Layer 1: fabricated step_id is rejected, but the Defender can retry."""
    t = Transcript.open(tmp_path / "run.jsonl")
    s = CourtSession(t)
    from hexbreaker.tools import run_tool
    r = run_tool(t, "fls", ["x"], runner=_runner(b"o"))
    s.submit_claim(GOOD_CLAIM(r.step_id, _hash(b"o")))
    r2 = s.observe_tool("yara", ["rule.yar"], runner=_runner(b"yara-out"))

    fabricated = orjson.dumps(
        {
            "verdict": "CONFIRMED",
            "cited_steps": [{"step_id": "S-999", "stdout_hash": _hash(b"o")}],
            "challenge_text": "I cite a step that does not exist",
        }
    )
    v = s.submit_verdict(fabricated)
    assert v.accepted is False
    assert v.result.first_issue.code == "missing_step"
    assert s.is_open

    # Retry with a real citation.
    good = orjson.dumps(
        {
            "verdict": "CONFIRMED",
            "cited_steps": [{"step_id": r2.step_id, "stdout_hash": _hash(b"yara-out")}],
            "challenge_text": "yara hit matches the persistence claim",
        }
    )
    v2 = s.submit_verdict(good)
    assert v2.accepted is True
    assert s.state == State.VERDICT_ACCEPTED


def test_double_verdict_after_accept_raises(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "run.jsonl")
    s = CourtSession(t)
    from hexbreaker.tools import run_tool
    r = run_tool(t, "fls", ["x"], runner=_runner(b"o"))
    s.submit_claim(GOOD_CLAIM(r.step_id, _hash(b"o")))
    r2 = s.observe_tool("yara", ["r"], runner=_runner(b"yo"))
    good = orjson.dumps(
        {
            "verdict": "CONFIRMED",
            "cited_steps": [{"step_id": r2.step_id, "stdout_hash": _hash(b"yo")}],
            "challenge_text": "ok",
        }
    )
    assert s.submit_verdict(good).accepted
    with pytest.raises(FSMError, match="closed"):
        s.submit_verdict(good)


def test_full_session_transcript_is_chain_valid(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    t = Transcript.open(path)
    s = CourtSession(t)
    from hexbreaker.tools import run_tool
    r = run_tool(t, "fls", ["x"], runner=_runner(b"o"))
    s.submit_claim(GOOD_CLAIM(r.step_id, _hash(b"o")))
    # Premature attempt — recorded as system event.
    s.submit_verdict(b'{"verdict": "CONFIRMED", "cited_steps": [], "challenge_text": "x"}')
    r2 = s.observe_tool("yara", ["r"], runner=_runner(b"yo"))
    s.submit_verdict(b'{"verdict": "CONFIRMED", "cited_steps": [{"step_id": "%s", "stdout_hash": "%s"}], "challenge_text": "ok"}' % (r2.step_id.encode(), _hash(b"yo").encode()))
    ok, reason = verify(path)
    assert ok, reason
