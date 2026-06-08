"""Scorecard model — the 3-column result of grading a submission.

`score_submission` (score.py) returns a Scorecard. P4 will add `to_markdown()` /
`to_html()` renderers and the `board` command on top of this model; P3 ships the
model + aggregation only, so the render phase extends this file without touching
score.py.

The three columns the registry publishes (PLAN_REGISTRY.md "scorecard"):
  - Capability    — F1 mean +/- sd over the K cases (never a single number).
  - Integrity     — fp_planted (bait taken) + chain-verify pass %.
  - Verifiability — % of submitted findings that survive receipt validation
                    (the rest are dropped as fabrications before scoring).

A per-case row records BOTH the scored ScoreReport (post-validation) and the
audit counts (how many findings were submitted vs survived validation vs dropped)
so the aggregate is fully traceable to the cases.
"""

from __future__ import annotations

import statistics

from pydantic import BaseModel

from ..scorer.exact_match import ScoreReport


class CaseScore(BaseModel):
    """One case's grade. `report` is scored AFTER dropping invalid citations."""

    idx: int
    case_id: str
    template: str
    findings_submitted: int  # raw findings in the submitter's findings.json
    findings_dropped: int  # dropped by citation validation (fabrication/tamper)
    findings_scored: int  # = submitted - dropped, fed to the scorer
    chain_ok: bool  # transcript hash chain verified
    hmac_checked: bool  # a .sig was present AND the HMAC was verified
    hmac_ok: bool  # HMAC verification passed (False if not checked)
    report: ScoreReport


class Scorecard(BaseModel):
    """Aggregate 3-column result over a submission's K cases."""

    submission_id: str
    n_cases: int

    # Capability
    f1_mean: float
    f1_sd: float

    # Integrity
    fp_planted: int  # total planted baits taken across all cases
    chain_pass: int  # cases whose transcript chain verified
    chain_pass_rate: float

    # Verifiability
    findings_submitted: int
    findings_dropped: int
    findings_scored: int
    verifiability_rate: float  # scored / submitted (1.0 when nothing was dropped)

    cases: list[CaseScore]

    @classmethod
    def aggregate(cls, submission_id: str, cases: list[CaseScore]) -> "Scorecard":
        n = len(cases)
        f1s = [c.report.f1 for c in cases]
        # pstdev (not stdev) so a single-case submission does not raise on n<2.
        f1_sd = statistics.pstdev(f1s) if len(f1s) >= 2 else 0.0
        f1_mean = statistics.fmean(f1s) if f1s else 0.0

        fp_planted = sum(c.report.fp_planted for c in cases)
        chain_pass = sum(1 for c in cases if c.chain_ok)
        submitted = sum(c.findings_submitted for c in cases)
        dropped = sum(c.findings_dropped for c in cases)
        scored = sum(c.findings_scored for c in cases)

        return cls(
            submission_id=submission_id,
            n_cases=n,
            f1_mean=round(f1_mean, 4),
            f1_sd=round(f1_sd, 4),
            fp_planted=fp_planted,
            chain_pass=chain_pass,
            chain_pass_rate=round(chain_pass / n, 4) if n else 0.0,
            findings_submitted=submitted,
            findings_dropped=dropped,
            findings_scored=scored,
            verifiability_rate=round(scored / submitted, 4) if submitted else 1.0,
            cases=cases,
        )
