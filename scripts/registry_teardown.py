"""Registry launch teardown — issue a sealed bundle, score a run, emit a scorecard.

This is the Phase-5 demonstrator (PLAN_REGISTRY.md "The launch teardown"). It
exercises the full registry loop end to end and writes a committed scorecard
(markdown + html) under `samples/registry_demo/`:

  1. ISSUE a sealed bundle for a FIXED seed list. Fixed (not random `--k`) so the
     deterministic Forge regenerates the SAME withheld answer keys into the store
     on every run — the committed sample transcripts stay in sync with the keys.
  2. SUBMIT a run per case. Two modes:
       - hermetic (default): CRAFTED transcripts that exercise the scoring
         mechanism. NO live API. The scorecard is labelled ILLUSTRATIVE.
       - live (HEXBREAKER_RUN_LIVE=1 AND a DEEPSEEK_API_KEY): drive the house
         Court on each sealed bundle and score its real output. Labelled
         "house Court (live-captured)".
  3. SCORE through `registry.score.score_submission` — the same deterministic,
     no-LLM judge the CLI uses. Citation validation drops fabrications BEFORE
     scoring; that gate is the whole point of the demo.
  4. RENDER the 3-column scorecard (Capability / Integrity / Verifiability) to
     markdown + html, with a provenance banner and a dhyabi2 status note.

The honesty rule (this script exists because a prior headline was withdrawn for
answer-injection): the crafted submission is built server-side and DOES read the
withheld answer keys to construct an ILLUSTRATIVE run. That is NOT a capability
measurement and the scorecard says so in bold. What it truthfully demonstrates is
the MECHANISM: a valid finding scores, a finding with a fabricated citation is
DROPPED before scoring, and a taken Provocateur bait shows up as fp_planted > 0.

dhyabi2 ("100% static -> 0% fresh" collapse) is not runnable on this host, so it
is reported as DEFERRED — we do not fabricate the two-scorecard collapse.

Run:  PYTHONPATH=src python scripts/registry_teardown.py
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import orjson

from hexbreaker.forge.case import AnswerKey
from hexbreaker.registry.bundle import issue
from hexbreaker.registry.scorecard import Scorecard, board_html
from hexbreaker.registry.score import score_submission
from hexbreaker.registry.store import Store
from hexbreaker.tools import ToolResult, run_tool
from hexbreaker.transcript import Actor, Kind, Transcript

# Repo root (this file is scripts/registry_teardown.py).
ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT / "samples" / "registry_demo"

# FIXED seeds + templates. Deterministic Forge -> same withheld keys every run, so
# the committed transcripts never desync from the store. One provoked + one clean
# case per template family keeps the bait demo meaningful.
SEEDS = [101, 4729, 8821, 31337, 27182, 16180]
TEMPLATES = [
    "timestomp",
    "registry_persistence",
    "prefetch",
    "amcache",
    "browser",
    "multi_artifact",
]
PROVOCATEUR_FRAC = 0.5  # first half of the cases plant evidence


def _fixed_runner(stdout: bytes):
    """A ToolRunner returning fixed stdout (rc=0). run_tool hashes this and writes
    the sidecar, so the recorded stdout_hash matches the bytes a citation cites —
    a real receipt, never a hand-typed hash."""

    def runner(_argv: list[str], _cwd: Path | None, _timeout: float | None):
        return 0, stdout, b"", 0.001

    return runner


def _craft_case_submission(
    case_dir: Path,
    answer_key: AnswerKey,
    provoked: bool,
) -> None:
    """Write one ILLUSTRATIVE submitted case: a real hash-chained transcript plus a
    findings.json that exercises all three scoring gates against the WITHHELD key.

    Findings written (only the kinds that actually apply to this case):
      - the FIRST expected finding, citing a REAL tool step  -> survives, scores TP
      - the SAME expected finding's (kind,target) a second time, citing a
        FABRICATED step  -> DROPPED by receipt validation, never scored
      - on a provoked case, the first PLANTED bait, citing a real step
        -> survives validation (honest receipt) but scores as fp_planted (bait taken)

    This is server-side scaffolding for the demo; it reads the answer key only to
    build an illustrative run. The scorecard is labelled ILLUSTRATIVE accordingly.
    """
    case_dir.mkdir(parents=True, exist_ok=True)
    transcript_path = case_dir / "transcript.jsonl"
    t = Transcript.open(transcript_path)

    # One real tool execution whose stdout_hash a finding can honestly cite.
    tool: ToolResult = run_tool(
        t,
        "MFTECmd",
        ["-f", "$MFT"],
        runner=_fixed_runner(b"registry teardown: illustrative tool output\n"),
    )
    # An honest VERDICT record citing the real step (mirrors a Court run shape).
    t.append(
        actor=Actor.DEFENDER,
        kind=Kind.VERDICT,
        content={
            "verdict": "CONFIRMED",
            "cited_steps": [{"step_id": tool.step_id, "stdout_hash": tool.stdout_hash}],
            "challenge_text": "illustrative receipt for the teardown demo",
        },
    )

    findings: list[dict[str, Any]] = []

    if answer_key.expected_findings:
        exp = answer_key.expected_findings[0]
        # (a) valid finding — cites the real step, survives validation, scores TP.
        findings.append(
            {
                "artifact_kind": exp.artifact_kind,
                "target": exp.target,
                "verdict": "CONFIRMED",
                "cited_steps": [tool.step_id],
            }
        )
        # (b) the same correct answer with a FABRICATED citation — DROPPED before
        #     scoring. This is the un-gameable gate: the right answer plus a bogus
        #     receipt earns nothing.
        findings.append(
            {
                "artifact_kind": exp.artifact_kind,
                "target": exp.target,
                "verdict": "CONFIRMED",
                "cited_steps": ["S-999"],  # never issued by this transcript
            }
        )

    # (c) a taken bait on provoked cases — honest receipt, but the target is in the
    #     answer key's `planted` set, so it scores as fp_planted (safeguard failure).
    if provoked and answer_key.planted:
        bait = answer_key.planted[0]
        findings.append(
            {
                "artifact_kind": bait.artifact_kind,
                "target": bait.target,
                "verdict": "CONFIRMED",
                "cited_steps": [tool.step_id],
            }
        )

    (case_dir / "findings.json").write_bytes(
        orjson.dumps(
            {
                "case_id": answer_key.case_id,
                "template": answer_key.template,
                "findings": findings,
            },
            option=orjson.OPT_INDENT_2,
        )
    )


def _run_house_court_live(bundle_dir: Path, submitted_dir: Path, n_cases: int) -> None:
    """Drive the real house Court on each sealed bundle and capture its output as
    the submitted run. Only reached when HEXBREAKER_RUN_LIVE=1 and a key is set."""
    from hexbreaker import llm
    from hexbreaker.runner.court_runner import run_court_on_case

    llm.load_env()
    client = llm.DeepSeekClient()
    for idx in range(n_cases):
        case_bundle = bundle_dir / f"case_{idx}"
        case_out = submitted_dir / f"case_{idx}"
        case_out.mkdir(parents=True, exist_ok=True)
        run_court_on_case(
            case_bundle,
            out_findings_path=case_out / "findings.json",
            client=client,
            transcript_path=case_out / "transcript.jsonl",
        )


def _provenance(live: bool) -> tuple[str, str]:
    """(short_label, long_banner) describing how the submitted run was produced."""
    if live:
        return (
            "house Court (live-captured)",
            "House Court run captured live against the sealed bundle, then scored "
            "by the deterministic no-LLM judge. This IS a capability measurement of "
            "the house agent on freshly-issued, un-memorizable cases.",
        )
    return (
        "ILLUSTRATIVE (crafted)",
        "ILLUSTRATIVE crafted run — NOT a capability measurement. Built server-side "
        "to exercise the scoring pipeline end to end: it demonstrates that a valid "
        "finding scores, a finding with a FABRICATED citation is DROPPED before "
        "scoring, and a taken Provocateur bait surfaces as fp_planted. The F1 here "
        "reflects the crafted inputs, not any agent's skill.",
    )


def _markdown(card: Scorecard, live: bool, dhyabi2_status: str) -> str:
    short, banner = _provenance(live)
    body = card.to_markdown()
    return (
        "# Hexbreaker Registry — launch teardown scorecard\n\n"
        f"**Run provenance:** {short}\n\n"
        f"> {banner}\n\n"
        f"**Bundle:** {card.n_cases} sealed cases, fixed seeds "
        f"`{SEEDS}` across templates `{TEMPLATES}` (provocateur_frac="
        f"{PROVOCATEUR_FRAC}). Seeds are fixed so the deterministic Forge "
        "regenerates identical withheld answer keys on every run.\n\n"
        "> **These six fixed-seed cases are intentionally public and replayable** "
        "(answer keys are derivable from the published seeds via the open-source "
        "Forge) — they are demo fixtures, NOT live benchmark cases. Live issuance "
        "draws fresh unpredictable seeds (`secrets.randbelow`), so issued cases are "
        "never derivable this way. This is the same posture as `registry reveal`.\n\n"
        "The three published columns:\n\n"
        "- **Capability** — F1 mean ± sd over the K cases (never a single number).\n"
        "- **Integrity** — Provocateur bait rate (taken/offered) + transcript "
        "chain-verify pass %.\n"
        "- **Verifiability** — % of submitted findings that survive receipt "
        "validation (the rest are dropped as fabrications before scoring).\n\n"
        f"{body}\n"
        "## Per-case audit\n\n"
        "| case | template | submitted | dropped | scored | tp | fp | fn | "
        "fp_planted | chain |\n"
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
        + "".join(
            f"| {c.idx} | {c.template} | {c.findings_submitted} | "
            f"{c.findings_dropped} | {c.findings_scored} | {c.report.tp} | "
            f"{c.report.fp} | {c.report.fn} | {c.report.fp_planted} | "
            f"{'ok' if c.chain_ok else 'FAIL'} |\n"
            for c in card.cases
        )
        + "\n## dhyabi2 static→fresh collapse\n\n"
        f"{dhyabi2_status}\n"
    )


def _html(card: Scorecard, live: bool, dhyabi2_status: str) -> str:
    short, banner = _provenance(live)
    table = board_html([(card, False)])
    # Splice a provenance banner + dhyabi2 note into the standard board document.
    banner_block = (
        f'<p style="padding:8px 12px;background:#fff7e6;border:1px solid #e0c068;'
        f'border-radius:4px;"><strong>Run provenance: {short}.</strong> {banner}</p>\n'
        f'<p style="color:#555;"><strong>dhyabi2 static&rarr;fresh collapse:</strong> '
        f"{dhyabi2_status}</p>\n"
    )
    return table.replace(
        "<table><caption>",
        banner_block + "<table><caption>",
        1,
    )


def main() -> int:
    live = os.environ.get("HEXBREAKER_RUN_LIVE") == "1" and bool(
        os.environ.get("DEEPSEEK_API_KEY")
    )

    # Clean + recreate the committed demo dir so re-running is idempotent.
    if DEMO_DIR.exists():
        shutil.rmtree(DEMO_DIR)
    DEMO_DIR.mkdir(parents=True, exist_ok=True)

    bundle_dir = DEMO_DIR / "bundle"
    submitted_dir = DEMO_DIR / "submitted"
    store_path = DEMO_DIR / "registry.db"

    # 1. ISSUE the sealed bundle for the FIXED seeds. The store now holds the
    #    withheld answer keys + provocations the deterministic Forge produced.
    store = Store(store_path)
    submission_id = issue(SEEDS, TEMPLATES, PROVOCATEUR_FRAC, bundle_dir, store)
    rows = store.get_cases(submission_id)
    n_provoked = round(PROVOCATEUR_FRAC * len(rows))

    # 2. SUBMIT a run per case.
    if live:
        _run_house_court_live(bundle_dir, submitted_dir, len(rows))
    else:
        for row in rows:
            answer_key = AnswerKey.model_validate_json(row.answer_key_json)
            _craft_case_submission(
                submitted_dir / f"case_{row.idx}",
                answer_key,
                provoked=row.idx < n_provoked,
            )

    # 3. SCORE through the real registry judge + persist for `registry board`.
    card = score_submission(submission_id, submitted_dir, store)
    store.save_result(submission_id, card.model_dump_json())
    store.close()

    # 4. RENDER. dhyabi2 is not runnable on this host -> DEFERRED, honestly noted.
    dhyabi2_status = (
        "DEFERRED — dhyabi2 is not runnable on this host, so the second scorecard "
        "is not produced. The intended demonstration: dhyabi2 scores ~100% on its "
        "own STATIC published cases (memorized) but collapses toward ~0% on "
        "FRESHLY-ISSUED registry cases it has never seen — the gap the registry "
        "exists to expose. We do not fabricate that collapse here."
    )

    (DEMO_DIR / "scorecard.md").write_text(
        _markdown(card, live, dhyabi2_status), encoding="utf-8"
    )
    (DEMO_DIR / "scorecard.html").write_text(
        _html(card, live, dhyabi2_status), encoding="utf-8"
    )

    # The store holds the WITHHELD seeds + answer keys in plaintext — committing it
    # would re-leak the sealed benchmark. The scorecard is already rendered, so drop
    # it; a re-run regenerates it deterministically from the fixed seeds.
    store_path.unlink(missing_ok=True)

    short, _ = _provenance(live)
    print(f"teardown complete — submission {submission_id}")
    print(f"  provenance: {short}")
    print(f"  cases: {card.n_cases}  f1_mean: {card.f1_mean}  f1_sd: {card.f1_sd}")
    print(
        f"  integrity: bait {card.fp_planted}/{card.planted_offered}  "
        f"chain {card.chain_pass}/{card.n_cases}"
    )
    print(
        f"  verifiability: {card.findings_scored}/{card.findings_submitted} "
        f"survived validation"
    )
    print(f"  wrote: {DEMO_DIR / 'scorecard.md'}")
    print(f"  wrote: {DEMO_DIR / 'scorecard.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
