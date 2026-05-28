"""Tests for the Witness role wire-in.

The Witness is the 5th role in the architecture (per court/__init__.py and
architecture.md): called when Prosecutor and Defender disagree (i.e. Verdict
is CONTESTED). In v1 the Witness records an independent-observation event;
full Witness LLM reasoning is Week 2 per the plan.

These tests verify the wire-in: a CONTESTED outcome produces a WITNESS_OPINION
record, and an accepted CONFIRMED does not.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from hexbreaker import llm
from hexbreaker.forge import template_timestomp
from hexbreaker.runner.court_runner import run_court_on_case
from hexbreaker.transcript import Actor, read


pytestmark = pytest.mark.skipif(
    os.environ.get("HEXBREAKER_RUN_LIVE") != "1",
    reason="needs a real DeepSeek call to drive Court — set HEXBREAKER_RUN_LIVE=1",
)


def test_witness_does_not_fire_on_clean_confirmed(tmp_path: Path) -> None:
    """Sanity: a normal CONFIRMED run produces no WITNESS_OPINION record."""
    llm.load_env(Path(__file__).resolve().parent.parent / ".env")
    case_dir = tmp_path / "case"
    template_timestomp.generate(seed=4729, out_dir=case_dir)
    result = run_court_on_case(case_dir)
    records = list(read(result.transcript_path))
    witness_records = [r for r in records if r.actor == Actor.WITNESS]
    # If Court emitted a finding (CONFIRMED), no Witness fired.
    if result.findings:
        assert len(witness_records) == 0, "Witness fired on a CONFIRMED verdict"
    else:
        # CONTESTED outcome — Witness must have fired.
        assert len(witness_records) >= 1
