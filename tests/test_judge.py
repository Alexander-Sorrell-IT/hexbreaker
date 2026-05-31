"""Tests for the deterministic Judge — JR-01 corroboration rule.

JR-01: A CONFIRMED verdict requires citations from ≥2 distinct tool kinds.
Single-signal CONFIRMED verdicts are downgraded to CONTESTED. This rule
previously lived in the Defender's prompt and was the load-bearing defense
against Provocateur planted-evidence (see docs/accuracy.md §2.3). Moving it to
Python means the rule holds even when the model ignores the prompt.

This file also covers the integration: when CourtSession.submit_verdict accepts
a single-tool CONFIRMED, the JUDGE event must be appended and the final stored
verdict must be CONTESTED.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from hexbreaker.court.judge import RulingKind, jr_01_corroboration, judge
from hexbreaker.court.orchestrator import CourtSession
from hexbreaker.court.schema import Claim, StepReference, Verdict
from hexbreaker.tools import run_tool
from hexbreaker.transcript import Actor, Kind, Transcript, read

VALID_HASH = "sha256:" + "a" * 64


def _fake_runner(stdout: bytes):
    def run(_argv, _cwd, _timeout):
        return 0, stdout, b"", 0.001
    return run


def _hash(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _make_claim(step_id: str, h: str) -> Claim:
    return Claim(
        text="binary X is timestomped",
        artifact_kind="timestomp",
        target="\\Windows\\System32\\drivers\\x.sys",
        cited_steps=[StepReference(step_id=step_id, stdout_hash=h)],
    )


# ===== JR-01 unit tests (no orchestrator) =====

def test_jr01_upholds_confirmed_with_two_distinct_tools(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "run.jsonl")
    a = run_tool(t, "MFTECmd", ["-f", "x"], runner=_fake_runner(b"mft"))
    b = run_tool(t, "yara", ["r.yar", "x"], runner=_fake_runner(b"yara hit"))
    verdict = Verdict(
        verdict="CONFIRMED",
        cited_steps=[
            StepReference(step_id=a.step_id, stdout_hash=a.stdout_hash),
            StepReference(step_id=b.step_id, stdout_hash=b.stdout_hash),
        ],
        challenge_text="corroborated by yara hit on the same target",
    )
    ruling = judge(verdict, _make_claim(a.step_id, a.stdout_hash), list(read(t.path)))
    assert ruling.kind == RulingKind.UPHELD
    assert ruling.verdict_kind == "CONFIRMED"
    assert set(ruling.distinct_tools_cited) == {"MFTECmd", "yara"}


def test_jr01_downgrades_confirmed_with_single_tool(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "run.jsonl")
    a = run_tool(t, "MFTECmd", ["-f", "x"], runner=_fake_runner(b"mft"))
    verdict = Verdict(
        verdict="CONFIRMED",
        cited_steps=[StepReference(step_id=a.step_id, stdout_hash=a.stdout_hash)],
        challenge_text="only MFT, no second signal",
    )
    ruling = jr_01_corroboration(verdict, _make_claim(a.step_id, a.stdout_hash), {a.step_id: list(read(t.path))[0]})
    assert ruling is not None
    assert ruling.kind == RulingKind.DOWNGRADED
    assert ruling.verdict_kind == "CONTESTED"
    assert ruling.rule_id == "JR-01"


def test_jr01_does_not_fire_on_contested(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "run.jsonl")
    a = run_tool(t, "MFTECmd", ["-f", "x"], runner=_fake_runner(b"mft"))
    verdict = Verdict(
        verdict="CONTESTED",
        cited_steps=[StepReference(step_id=a.step_id, stdout_hash=a.stdout_hash)],
        challenge_text="contested with one signal",
    )
    ruling = judge(verdict, _make_claim(a.step_id, a.stdout_hash), list(read(t.path)))
    assert ruling.kind == RulingKind.UPHELD
    assert ruling.verdict_kind == "CONTESTED"


def test_jr01_does_not_fire_on_rejected(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "run.jsonl")
    a = run_tool(t, "MFTECmd", ["-f", "x"], runner=_fake_runner(b"mft"))
    verdict = Verdict(
        verdict="REJECTED",
        cited_steps=[StepReference(step_id=a.step_id, stdout_hash=a.stdout_hash)],
        challenge_text="rejected with one signal",
    )
    ruling = judge(verdict, _make_claim(a.step_id, a.stdout_hash), list(read(t.path)))
    assert ruling.kind == RulingKind.UPHELD
    assert ruling.verdict_kind == "REJECTED"


def test_jr01_same_tool_twice_is_still_single_signal(tmp_path: Path) -> None:
    """Citing the SAME tool twice (different args) does not satisfy
    corroboration — the rule requires distinct *tool kinds*."""
    t = Transcript.open(tmp_path / "run.jsonl")
    a = run_tool(t, "MFTECmd", ["-f", "/case/MFT1"], runner=_fake_runner(b"mft1"))
    b = run_tool(t, "MFTECmd", ["-f", "/case/MFT2"], runner=_fake_runner(b"mft2"))
    verdict = Verdict(
        verdict="CONFIRMED",
        cited_steps=[
            StepReference(step_id=a.step_id, stdout_hash=a.stdout_hash),
            StepReference(step_id=b.step_id, stdout_hash=b.stdout_hash),
        ],
        challenge_text="two MFTECmd calls but only one tool kind",
    )
    ruling = judge(verdict, _make_claim(a.step_id, a.stdout_hash), list(read(t.path)))
    assert ruling.kind == RulingKind.DOWNGRADED
    assert ruling.verdict_kind == "CONTESTED"


# ===== JR-02 leak detection is case/whitespace-insensitive (M-1 regression) =====

def _two_tool_confirmed(t: Transcript, challenge_text: str):
    """A CONFIRMED citing 2 distinct tool kinds, so JR-01 cannot mask a JR-02 miss."""
    a = run_tool(t, "MFTECmd", ["-f", "x"], runner=_fake_runner(b"mft"))
    b = run_tool(t, "yara", ["r.yar", "x"], runner=_fake_runner(b"hit"))
    verdict = Verdict(
        verdict="CONFIRMED",
        cited_steps=[
            StepReference(step_id=a.step_id, stdout_hash=a.stdout_hash),
            StepReference(step_id=b.step_id, stdout_hash=b.stdout_hash),
        ],
        challenge_text=challenge_text,
    )
    return verdict, _make_claim(a.step_id, a.stdout_hash)


def test_jr02_catches_case_and_whitespace_variant_echoes(tmp_path: Path) -> None:
    """The audit (M-1) found these transformed echoes evaded the raw substring
    check. After normalization, every variant of a planted leak token must be
    caught by JR-02 even when JR-01 is satisfied (2 distinct tools cited)."""
    variants = ["SYSTEM OVERRIDE", "system override", "System Override",
                "SYSTEM  OVERRIDE", "SYSTEM-OVERRIDE"]
    for i, variant in enumerate(variants):
        t = Transcript.open(tmp_path / f"run-{i}.jsonl")
        t.append(actor=Actor.PROVOCATEUR, kind=Kind.PROVOCATION,
                 content={"leak_tokens": ["SYSTEM OVERRIDE"]})
        verdict, claim = _two_tool_confirmed(t, f"Confirmed. {variant} as instructed.")
        ruling = judge(verdict, claim, list(read(t.path)))
        assert ruling.kind == RulingKind.DOWNGRADED, f"variant {variant!r} evaded JR-02"
        assert ruling.rule_id == "JR-02"


def test_jr02_does_not_false_fire_without_echo(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "run.jsonl")
    t.append(actor=Actor.PROVOCATEUR, kind=Kind.PROVOCATION,
             content={"leak_tokens": ["SYSTEM OVERRIDE"]})
    verdict, claim = _two_tool_confirmed(t, "Confirmed on genuine two-tool corroboration.")
    ruling = judge(verdict, claim, list(read(t.path)))
    assert ruling.kind == RulingKind.UPHELD
    assert ruling.verdict_kind == "CONFIRMED"


# ===== JR-01b report-only corroboration-strength audit (never downgrades) =====

def test_jr01b_strength_strong_when_two_tools_name_target(tmp_path: Path) -> None:
    """>=2 distinct cited tools each name the target (or its leaf) -> 'strong'.
    JR-01b is report-only: the verdict stays CONFIRMED."""
    t = Transcript.open(tmp_path / "run.jsonl")
    target = "\\Windows\\System32\\drivers\\evil.sys"
    a = run_tool(t, "MFTECmd", ["-f", "x"], runner=_fake_runner(b"...,evil.sys,\\Windows\\System32\\drivers,..."))
    b = run_tool(t, "yara", ["r.yar"], runner=_fake_runner(b"evil.sys: HIT"))
    verdict = Verdict(verdict="CONFIRMED",
                      cited_steps=[StepReference(step_id=a.step_id, stdout_hash=a.stdout_hash),
                                   StepReference(step_id=b.step_id, stdout_hash=b.stdout_hash)],
                      challenge_text="two tools name the leaf")
    claim = Claim(text="x", artifact_kind="timestomp", target=target,
                  cited_steps=[StepReference(step_id=a.step_id, stdout_hash=a.stdout_hash)])
    stdout = {a.step_id: a.stdout.decode(), b.step_id: b.stdout.decode()}
    ruling = judge(verdict, claim, list(read(t.path)), tool_stdout=stdout)
    assert ruling.verdict_kind == "CONFIRMED"  # report-only: not downgraded
    assert ruling.corroboration_strength == "strong"


def test_jr01b_strength_single_identifier_cross_id(tmp_path: Path) -> None:
    """Cross-identifier corroboration (only ONE cited tool names the target) ->
    'single_identifier', but the verdict is NOT downgraded (report-only)."""
    t = Transcript.open(tmp_path / "run.jsonl")
    target = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evilval"
    # RECmd names the value (leaf 'evilval'); the 2nd tool names only the binary.
    a = run_tool(t, "RECmd", ["-f", "x"], runner=_fake_runner(b"...Run,evilval,REG_SZ,C:\\eviltool.exe,..."))
    b = run_tool(t, "yara", ["r.yar"], runner=_fake_runner(b"C:\\eviltool.exe: HIT"))  # names binary, not key
    verdict = Verdict(verdict="CONFIRMED",
                      cited_steps=[StepReference(step_id=a.step_id, stdout_hash=a.stdout_hash),
                                   StepReference(step_id=b.step_id, stdout_hash=b.stdout_hash)],
                      challenge_text="cross-identifier corroboration")
    claim = Claim(text="x", artifact_kind="persistence", target=target,
                  cited_steps=[StepReference(step_id=a.step_id, stdout_hash=a.stdout_hash)])
    stdout = {a.step_id: a.stdout.decode(), b.step_id: b.stdout.decode()}
    ruling = judge(verdict, claim, list(read(t.path)), tool_stdout=stdout)
    assert ruling.verdict_kind == "CONFIRMED"  # NOT downgraded — genuine cross-id finding
    assert ruling.corroboration_strength == "single_identifier"


def test_jr01b_strength_unknown_without_stdout(tmp_path: Path) -> None:
    """No tool_stdout supplied (pure-logic call) -> 'unknown', no crash."""
    t = Transcript.open(tmp_path / "run.jsonl")
    a = run_tool(t, "MFTECmd", ["-f", "x"], runner=_fake_runner(b"mft"))
    b = run_tool(t, "yara", ["r.yar"], runner=_fake_runner(b"hit"))
    verdict = Verdict(verdict="CONFIRMED",
                      cited_steps=[StepReference(step_id=a.step_id, stdout_hash=a.stdout_hash),
                                   StepReference(step_id=b.step_id, stdout_hash=b.stdout_hash)],
                      challenge_text="no stdout passed")
    ruling = judge(verdict, _make_claim(a.step_id, a.stdout_hash), list(read(t.path)))
    assert ruling.corroboration_strength == "unknown"


# ===== Integration: CourtSession invokes Judge on CONFIRMED verdicts =====

def test_session_downgrades_single_signal_confirmed(tmp_path: Path) -> None:
    """A model that emits CONFIRMED with only one tool citation gets
    downgraded to CONTESTED by the Judge, and a SYSTEM_EVENT records the
    downgrade. The Provocateur safeguard is now in code, not just prompt."""
    path = tmp_path / "run.jsonl"
    t = Transcript.open(path)
    s = CourtSession(t)
    # MFT pre-pass — gives the Prosecutor something to cite.
    mft = run_tool(t, "MFTECmd", ["-f", "/case/MFT"], runner=_fake_runner(b"mft"))
    claim_json = json.dumps({
        "text": "evil binary",
        "artifact_kind": "timestomp",
        "target": "\\Windows\\System32\\evil.sys",
        "cited_steps": [{"step_id": mft.step_id, "stdout_hash": mft.stdout_hash}],
    })
    s.submit_claim(claim_json)
    # Defender observes yara (so R2 holds), but emits a CONFIRMED that cites
    # ONLY the MFT step — JR-01 should downgrade it.
    yara = s.observe_tool("yara", ["r.yar", "evil.sys"], runner=_fake_runner(b"hit"))
    verdict_json = json.dumps({
        "verdict": "CONFIRMED",
        "cited_steps": [{"step_id": mft.step_id, "stdout_hash": mft.stdout_hash}],
        "challenge_text": "I only cite the MFT row",
    })
    outcome = s.submit_verdict(verdict_json)
    assert outcome.accepted is True
    assert outcome.verdict is not None
    assert outcome.verdict.verdict == "CONTESTED"  # downgraded by Judge

    # The transcript must record the JUDGE event.
    records = list(read(path))
    judge_events = [r for r in records if r.actor == Actor.JUDGE and r.content.get("event") == "judge_downgrade"]
    assert len(judge_events) == 1
    assert judge_events[0].content["rule_id"] == "JR-01"
    assert judge_events[0].content["original_verdict"] == "CONFIRMED"
    assert judge_events[0].content["final_verdict"] == "CONTESTED"
    _ = yara  # silence "unused" warning


def test_session_upholds_confirmed_with_two_tools(tmp_path: Path) -> None:
    """A well-corroborated CONFIRMED (cites both MFT and yara) passes the
    Judge unchanged — no JUDGE event in the transcript."""
    path = tmp_path / "run.jsonl"
    t = Transcript.open(path)
    s = CourtSession(t)
    mft = run_tool(t, "MFTECmd", ["-f", "/case/MFT"], runner=_fake_runner(b"mft"))
    s.submit_claim(json.dumps({
        "text": "evil binary",
        "artifact_kind": "timestomp",
        "target": "\\Windows\\System32\\evil.sys",
        "cited_steps": [{"step_id": mft.step_id, "stdout_hash": mft.stdout_hash}],
    }))
    yara = s.observe_tool("yara", ["r.yar", "evil.sys"], runner=_fake_runner(b"hit"))
    verdict_json = json.dumps({
        "verdict": "CONFIRMED",
        "cited_steps": [
            {"step_id": mft.step_id, "stdout_hash": mft.stdout_hash},
            {"step_id": yara.step_id, "stdout_hash": yara.stdout_hash},
        ],
        "challenge_text": "corroborated by yara",
    })
    outcome = s.submit_verdict(verdict_json)
    assert outcome.accepted is True
    assert outcome.verdict.verdict == "CONFIRMED"

    records = list(read(path))
    judge_events = [r for r in records if r.actor == Actor.JUDGE]
    assert len(judge_events) == 0  # Judge upheld; no event written
