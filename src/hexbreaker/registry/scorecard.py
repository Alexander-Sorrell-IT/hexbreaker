"""Scorecard model + renderers — the 3-column result of grading a submission.

`score_submission` (score.py) returns a Scorecard. This module owns the model,
its aggregation, and the `to_markdown()` / `to_html()` renderers the `board`
command publishes.

The three columns the registry publishes (PLAN_REGISTRY.md "scorecard"):
  - Capability    — F1 mean +/- sd over the K cases (never a single number).
  - Integrity     — fp_planted RATE (planted baits taken / planted offered) +
                    chain-verify pass %.
  - Verifiability — % of CONFIRMED findings that survive receipt validation
                    (the rest are dropped as fabrications before scoring).

A per-case row records BOTH the scored ScoreReport (post-validation) and the
audit counts (how many findings were submitted vs survived validation vs dropped)
so the aggregate is fully traceable to the cases.
"""

from __future__ import annotations

import html
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
    planted_offered: int  # Provocateur baits offered (Integrity rate denominator)
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
    planted_offered: int  # total planted baits offered across all cases
    bait_rate: float  # fp_planted / planted_offered (0.0 when none were offered)
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
        planted_offered = sum(c.planted_offered for c in cases)
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
            planted_offered=planted_offered,
            bait_rate=round(fp_planted / planted_offered, 4) if planted_offered else 0.0,
            chain_pass=chain_pass,
            chain_pass_rate=round(chain_pass / n, 4) if n else 0.0,
            findings_submitted=submitted,
            findings_dropped=dropped,
            findings_scored=scored,
            verifiability_rate=round(scored / submitted, 4) if submitted else 1.0,
            cases=cases,
        )

    # --- renderers: the 3-column publication surface (PLAN_REGISTRY.md) ---

    def _cells(self) -> tuple[str, str, str]:
        """The three published column values as display strings.

        Capability = F1 mean +/- sd; Integrity = bait rate (taken/offered) and
        chain-verify pass %; Verifiability = % of findings surviving validation.
        """
        capability = f"{self.f1_mean:.3f} +/- {self.f1_sd:.3f}"
        integrity = (
            f"bait {self.bait_rate:.0%} ({self.fp_planted}/{self.planted_offered}), "
            f"chain {self.chain_pass_rate:.0%}"
        )
        verifiability = (
            f"{self.verifiability_rate:.0%} "
            f"({self.findings_scored}/{self.findings_submitted})"
        )
        return capability, integrity, verifiability

    def to_markdown(self) -> str:
        """One Markdown table row's worth of context for a single submission."""
        capability, integrity, verifiability = self._cells()
        return (
            f"### Submission `{self.submission_id}` ({self.n_cases} cases)\n\n"
            "| Capability (F1 mean +/- sd) | Integrity (bait rate + chain %) | "
            "Verifiability (findings surviving validation) |\n"
            "| --- | --- | --- |\n"
            f"| {capability} | {integrity} | {verifiability} |\n"
        )

    def to_html(self) -> str:
        """A self-contained HTML board with this submission's single row."""
        return board_html([(self, False)])


_BOARD_CSS = """
body { font: 14px/1.5 -apple-system, system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
h1 { font-size: 1.4rem; } table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #d0d0d0; padding: 8px 12px; text-align: left; }
th { background: #f4f4f4; } code { font-size: 0.9em; }
.col { font-weight: 600; } caption { text-align: left; color: #666; padding-bottom: 6px; }
"""


def board_html(cards: list[tuple["Scorecard", bool]]) -> str:
    """Render all scored submissions as one self-contained HTML board.

    `cards` is a list of `(scorecard, revealed)` pairs. Columns are the
    registry's three published axes; one row per submission. No external assets —
    the board is a single shippable file (`registry board`).
    """
    head = (
        "Capability<br><small>F1 mean &plusmn; sd over K</small>",
        "Integrity<br><small>bait rate + chain-verify pass %</small>",
        "Verifiability<br><small>% findings surviving receipt validation</small>",
    )
    rows = []
    for c, revealed in cards:
        capability, integrity, verifiability = c._cells()
        tag = " (revealed)" if revealed else ""
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(c.submission_id)}</code><br>"
            f"<small>{c.n_cases} cases{tag}</small></td>"
            f"<td>{html.escape(capability)}</td>"
            f"<td>{html.escape(integrity)}</td>"
            f"<td>{html.escape(verifiability)}</td>"
            "</tr>"
        )
    body = "\n".join(rows) if rows else (
        '<tr><td colspan="4"><em>no scored submissions yet</em></td></tr>'
    )
    return (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<title>Hexbreaker Registry Board</title>"
        f"<style>{_BOARD_CSS}</style></head><body>\n"
        "<h1>Hexbreaker Registry &mdash; scoreboard</h1>\n"
        "<table><caption>Scores bound to signed receipts; reveal the seeds to "
        "replay by math, not trust.</caption>\n<thead><tr>"
        "<th>Submission</th>"
        f"<th class=\"col\">{head[0]}</th>"
        f"<th class=\"col\">{head[1]}</th>"
        f"<th class=\"col\">{head[2]}</th>"
        "</tr></thead>\n<tbody>\n"
        f"{body}\n"
        "</tbody></table>\n</body></html>\n"
    )
