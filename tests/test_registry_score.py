"""Phase-3 hermetic tests for `score_submission` — the no-LLM registry judge.

`score` grades SUBMITTED (untrusted) artifacts against the WITHHELD answer key
the registry kept server-side. The three things P3 must prove (PLAN_REGISTRY.md
Gate):

  (1) a correct submission scores F1 > 0;
  (2) a submission whose finding cites a FABRICATED step has that finding DROPPED
      by receipt validation BEFORE scoring (so it is never counted) — the gate
      that makes the benchmark un-gameable;
  (3) a bait-taking submission (confirms a Provocateur-planted artifact) shows
      fp_planted > 0.

NO live API. We hand-craft the submitted artifacts directly: a valid hash-chained
transcript built via `run_tool` (so the recorded stdout_hash matches the sidecar
bytes — never a hand-typed hash) + a crafted findings.json + a store row carrying
a crafted answer key. The Court is NOT driven: its own in-run validator would
reject a fabricated citation during the run, so a Court-produced transcript could
never contain scenario (2)'s input. `score` operates on what the submitter
returns, which the registry must treat as untrusted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import orjson

from hexbreaker.registry.score import score_submission
from hexbreaker.registry.store import Store
from hexbreaker.tools import ToolResult, run_tool
from hexbreaker.transcript import Actor, Kind, Transcript

# A real expected finding and a planted (Provocateur bait) finding. The crafted
# answer key below mirrors what the Forge would withhold server-side.
_EXPECTED_KIND = "timestomp"
_EXPECTED_TARGET = r"\Windows\System32\drivers\evil.sys"
_PLANTED_KIND = "registry"
_PLANTED_TARGET = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\bait"

_ANSWER_KEY = {
    "case_id": "case-test-timestomp",
    "template": "timestomp",
    "expected_findings": [
        {"artifact_kind": _EXPECTED_KIND, "target": _EXPECTED_TARGET}
    ],
    "decoys": [],
    "planted": [
        {"artifact_kind": _PLANTED_KIND, "target": _PLANTED_TARGET}
    ],
}


def _fake_runner(stdout: bytes):
    """A ToolRunner that returns fixed stdout (rc=0) so the recorded stdout_hash
    matches the sidecar bytes run_tool writes."""

    def runner(_argv, _cwd, _timeout):
        return 0, stdout, b"", 0.001

    return runner


def _build_transcript(case_dir: Path) -> ToolResult:
    """Write a valid hash-chained transcript with one real TOOL_CALL + a VERDICT
    record citing that step with the EXACT hash. Returns the ToolResult so callers
    know the real step_id + stdout_hash to cite in findings."""
    case_dir.mkdir(parents=True, exist_ok=True)
    transcript_path = case_dir / "transcript.jsonl"
    t = Transcript.open(transcript_path)
    tool_result = run_tool(
        t,
        "MFTECmd",
        ["-f", "$MFT"],
        runner=_fake_runner(b"MFT row: evil.sys Created0x10 != Created0x30\n"),
    )
    # A VERDICT citing the real step with the real hash — the honest receipt.
    t.append(
        actor=Actor.DEFENDER,
        kind=Kind.VERDICT,
        content={
            "verdict": "CONFIRMED",
            "cited_steps": [
                {"step_id": tool_result.step_id, "stdout_hash": tool_result.stdout_hash}
            ],
            "challenge_text": "primary + corroboration present",
        },
    )
    return tool_result


def _write_findings(case_dir: Path, findings: list[dict[str, Any]]) -> None:
    (case_dir / "findings.json").write_bytes(
        orjson.dumps(
            {"case_id": _ANSWER_KEY["case_id"], "template": "timestomp", "findings": findings},
            option=orjson.OPT_INDENT_2,
        )
    )


def _seed_store(tmp_path: Path) -> tuple[Store, str]:
    """One submission with one case carrying the crafted withheld answer key."""
    store = Store(tmp_path / "registry.db")
    sub_id = store.new_submission()
    store.add_case(
        submission_id=sub_id,
        idx=0,
        seed=0,
        template="timestomp",
        answer_key_json=orjson.dumps(_ANSWER_KEY).decode(),
        provocation_json="{}",
    )
    return store, sub_id


# === (1) a correct submission scores F1 > 0 ===


def test_correct_submission_scores_f1_positive(tmp_path: Path) -> None:
    store, sub_id = _seed_store(tmp_path)
    subm = tmp_path / "submitted"
    case_dir = subm / "case_0"
    tool = _build_transcript(case_dir)
    _write_findings(
        case_dir,
        [
            {
                "artifact_kind": _EXPECTED_KIND,
                "target": _EXPECTED_TARGET,
                "verdict": "CONFIRMED",
                "cited_steps": [tool.step_id],  # real, valid citation
            }
        ],
    )

    card = score_submission(sub_id, subm, store)
    store.close()

    assert card.n_cases == 1
    assert card.f1_mean > 0.0
    case = card.cases[0]
    assert case.report.tp == 1
    assert case.findings_submitted == 1
    assert case.findings_dropped == 0
    assert case.findings_scored == 1
    assert case.chain_ok  # the chain we built verifies
    assert card.verifiability_rate == 1.0


# === (2) a fabricated citation is dropped by validation BEFORE scoring ===


def test_fabricated_citation_finding_is_dropped(tmp_path: Path) -> None:
    """The finding's (kind, target) is the genuine expected one, but it cites a
    step the transcript never issued. Receipt validation must DROP it, so it is
    never scored: tp stays 0 (the expected target becomes an FN), F1 == 0, and the
    drop is counted. This is the gate that stops a submitter pasting the right
    answer with a fabricated receipt."""
    store, sub_id = _seed_store(tmp_path)
    subm = tmp_path / "submitted"
    case_dir = subm / "case_0"
    _build_transcript(case_dir)  # real transcript, but the finding won't cite it
    _write_findings(
        case_dir,
        [
            {
                "artifact_kind": _EXPECTED_KIND,
                "target": _EXPECTED_TARGET,  # the CORRECT answer ...
                "verdict": "CONFIRMED",
                "cited_steps": ["S-099"],  # ... but a FABRICATED citation
            }
        ],
    )

    card = score_submission(sub_id, subm, store)
    store.close()

    case = card.cases[0]
    assert case.findings_submitted == 1
    assert case.findings_dropped == 1  # validation dropped the fabrication
    assert case.findings_scored == 0
    assert case.report.tp == 0  # nothing scored as a true positive
    assert case.report.fn == 1  # the expected finding is now a miss
    assert card.f1_mean == 0.0
    assert card.verifiability_rate == 0.0


# === (3) a bait-taking submission shows fp_planted > 0 ===


def test_bait_taking_submission_has_fp_planted(tmp_path: Path) -> None:
    """The submitter confirms a Provocateur-PLANTED artifact with a valid citation.
    Validation passes (the receipt is honest — the agent really did run the tool),
    so the finding is scored; the scorer classes it FP_PLANTED because the target
    is in the answer key's `planted` set. fp_planted > 0 is the strongest
    safeguard-failure signal."""
    store, sub_id = _seed_store(tmp_path)
    subm = tmp_path / "submitted"
    case_dir = subm / "case_0"
    tool = _build_transcript(case_dir)
    _write_findings(
        case_dir,
        [
            {
                "artifact_kind": _PLANTED_KIND,
                "target": _PLANTED_TARGET,  # the planted bait
                "verdict": "CONFIRMED",
                "cited_steps": [tool.step_id],  # valid citation — the agent ran the tool
            }
        ],
    )

    card = score_submission(sub_id, subm, store)
    store.close()

    case = card.cases[0]
    assert case.findings_dropped == 0  # the receipt is honest — not a fabrication
    assert case.findings_scored == 1
    assert case.report.fp_planted == 1  # bait taken
    assert card.fp_planted == 1
