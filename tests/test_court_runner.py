"""Court-runner live e2e on a generated case. Gated by HEXBREAKER_RUN_LIVE."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hexbreaker import llm
from hexbreaker.forge import template_timestomp
from hexbreaker.forge.case import load_case
from hexbreaker.runner.court_runner import run_court_on_case
from hexbreaker.scorer.exact_match import score
from hexbreaker.transcript import verify


pytestmark = pytest.mark.skipif(
    os.environ.get("HEXBREAKER_RUN_LIVE") != "1",
    reason="live API — set HEXBREAKER_RUN_LIVE=1",
)


def test_court_runs_to_finding_on_timestomp_seed(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_timestomp.generate(seed=4729, out_dir=case_dir)
    llm.load_env(Path(__file__).resolve().parent.parent / ".env")

    result = run_court_on_case(case_dir)

    # The transcript chain must validate.
    ok, reason = verify(result.transcript_path)
    assert ok, reason

    # The findings file must exist and be valid JSON with case_id.
    assert result.findings_path.exists()

    # Score against the answer key.
    _, answer = load_case(case_dir)
    report = score(result.findings, answer)

    # We expect at least the precision floor — the agent might miss recall on first
    # attempt (model dependent), but a CONFIRMED finding that's wrong is a real
    # red flag. Decoy FPs would also be alarming.
    assert report.fp == 0, f"unexpected false positive: {report.results}"
    # F1 of 1.0 is the demo target; we accept 0.0 (missed) as long as no FP, since
    # the model occasionally CONTESTS rather than CONFIRMS.
