"""Tests for citation referential integrity — Layer 1 in code form.

The smoke test caught V3 fabricating S-015 and R1 fabricating S-102. These tests
prove the deterministic validator catches both classes of fabrication and the
hash-substitution attack (citing a real step_id with a wrong hash).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import orjson

from hexbreaker.court.validator import (
    validate_claim_json,
    validate_verdict_json,
)
from hexbreaker.tools import run_tool
from hexbreaker.transcript import Transcript, read

VALID_HASH = "sha256:" + "a" * 64


def _runner(stdout: bytes, stderr: bytes = b"", rc: int = 0):
    def run(_argv, _cwd, _timeout):
        return rc, stdout, stderr, 0.001
    return run


def _real_step_and_hash(tmp_path: Path) -> tuple[str, str, Transcript]:
    """Helper: run one fake tool, return (step_id, stdout_hash, transcript)."""
    t = Transcript.open(tmp_path / "run.jsonl")
    stdout = b"a real tool output"
    result = run_tool(t, "fls", ["-r", "/img"], runner=_runner(stdout))
    expected_hash = "sha256:" + hashlib.sha256(stdout).hexdigest()
    return result.step_id, expected_hash, t


def test_verdict_accepted_when_citation_matches(tmp_path: Path) -> None:
    step_id, h, t = _real_step_and_hash(tmp_path)
    verdict_json = orjson.dumps(
        {
            "verdict": "CONTESTED",
            "cited_steps": [{"step_id": step_id, "stdout_hash": h}],
            "challenge_text": "the MFT cited here does not show $SI/$FN divergence",
        }
    )
    result, verdict = validate_verdict_json(verdict_json, list(read(t.path)))
    assert result.ok, result.issues
    assert verdict is not None
    assert verdict.verdict == "CONTESTED"


def test_verdict_rejected_on_fabricated_step_id(tmp_path: Path) -> None:
    _, h, t = _real_step_and_hash(tmp_path)
    verdict_json = orjson.dumps(
        {
            "verdict": "CONFIRMED",
            "cited_steps": [{"step_id": "S-015", "stdout_hash": h}],  # S-015 was V3's fabrication
            "challenge_text": "I rely on the cited step",
        }
    )
    result, verdict = validate_verdict_json(verdict_json, list(read(t.path)))
    assert not result.ok
    assert verdict is None
    assert result.first_issue is not None
    assert result.first_issue.code == "missing_step"
    assert result.first_issue.step_id == "S-015"


def test_verdict_rejected_on_hash_substitution(tmp_path: Path) -> None:
    step_id, _real_hash, t = _real_step_and_hash(tmp_path)
    verdict_json = orjson.dumps(
        {
            "verdict": "CONFIRMED",
            "cited_steps": [{"step_id": step_id, "stdout_hash": VALID_HASH}],  # wrong hash
            "challenge_text": "x",
        }
    )
    result, verdict = validate_verdict_json(verdict_json, list(read(t.path)))
    assert not result.ok
    assert verdict is None
    assert result.first_issue is not None
    assert result.first_issue.code == "hash_mismatch"


def test_verdict_rejected_when_citation_points_to_non_tool_step(tmp_path: Path) -> None:
    """A Verdict cannot cite another Verdict / Claim / SYSTEM_EVENT as evidence."""
    from hexbreaker.transcript import Actor, Kind
    t = Transcript.open(tmp_path / "run.jsonl")
    # First step is a CLAIM, not a TOOL_CALL.
    claim_record = t.append(actor=Actor.PROSECUTOR, kind=Kind.CLAIM, content={"x": 1})
    verdict_json = orjson.dumps(
        {
            "verdict": "CONFIRMED",
            "cited_steps": [{"step_id": claim_record.step_id, "stdout_hash": VALID_HASH}],
            "challenge_text": "x",
        }
    )
    result, verdict = validate_verdict_json(verdict_json, list(read(t.path)))
    assert not result.ok
    assert result.first_issue.code == "not_a_tool_call"


def test_verdict_rejected_on_schema_failure(tmp_path: Path) -> None:
    _, _, t = _real_step_and_hash(tmp_path)
    result, verdict = validate_verdict_json(b'{"verdict": "MAYBE"}', list(read(t.path)))
    assert not result.ok
    assert verdict is None
    assert result.first_issue.code == "schema"


def test_claim_validation_uses_same_rules(tmp_path: Path) -> None:
    step_id, h, t = _real_step_and_hash(tmp_path)
    claim_json = orjson.dumps(
        {
            "text": "binary X is timestomped",
            "artifact_kind": "timestomp",
            "target": "suspicious.sys",
            "cited_steps": [{"step_id": step_id, "stdout_hash": h}],
        }
    )
    result, claim = validate_claim_json(claim_json, list(read(t.path)))
    assert result.ok
    assert claim is not None
    assert claim.artifact_kind == "timestomp"
