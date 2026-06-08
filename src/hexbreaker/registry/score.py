"""Score a submitted run against the withheld answer key — the registry judge.

`score_submission` is the deterministic (no-LLM) judge. The submitter ran the
Court on each sealed `case_<idx>/` and returns, per case, a `transcript.jsonl`
(the orchestrator-owned receipt) and a `findings.json` (its conclusions). The
registry holds the withheld seed + answer key for each case in the store; the
submitter never saw them. This module grades the return:

For each case (PLAN_REGISTRY.md "score.py"):
  1. Locate the submitter's transcript.jsonl + findings.json under
     `transcripts_dir/case_<idx>/`.
  2. Verify the transcript hash chain (+ HMAC if a .sig is present AND the
     password is set). The chain result feeds the Integrity column.
  3. RECEIPT VALIDATION (the core gate): every cited step in a finding must
     resolve to a TOOL_CALL whose stored stdout hash matches the cited hash and
     whose sidecar bytes are intact. A finding that fails this is a fabrication
     (or rests on tampered evidence), so it is DROPPED before scoring — a
     fabricated citation is not a finding. This is `trace_findings`, which was
     built for exactly this finding<->tool-execution join.
  4. Score the SURVIVING findings against the withheld answer key with the
     deterministic exact-match scorer.

Aggregate into a 3-column Scorecard. No LLM is called anywhere here.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import orjson

from ..court.hmac_chain import HMAC_ENV, verify_signature
from ..court.trace import trace_findings
from ..forge.case import AnswerKey
from ..scorer.exact_match import score
from ..transcript import verify as verify_chain
from .scorecard import CaseScore, Scorecard
from .store import Store


def _load_findings(findings_path: Path) -> list[dict[str, Any]]:
    """Read the submitter's findings list (tolerates the {"findings": [...]} wrap)."""
    payload: Any = orjson.loads(findings_path.read_bytes())
    if isinstance(payload, dict):
        return list(payload.get("findings", []))
    return list(payload)


def _score_one_case(
    idx: int,
    case_dir: Path,
    answer_key: AnswerKey,
) -> CaseScore:
    """Grade a single submitted case: verify -> drop fabrications -> score."""
    transcript_path = case_dir / "transcript.jsonl"
    findings_path = case_dir / "findings.json"

    raw_findings = _load_findings(findings_path)

    # 2. Chain (+ HMAC if signed). HMAC needs the password; only attempt it when a
    #    .sig exists AND the env var is set, so the hermetic path (unsigned
    #    transcripts, no password) never crashes — it falls back to chain-only.
    sig_path = transcript_path.with_suffix(transcript_path.suffix + ".sig")
    hmac_checked = False
    hmac_ok = False
    if sig_path.exists() and os.environ.get(HMAC_ENV):
        result = verify_signature(transcript_path)
        hmac_checked = True
        hmac_ok = result.ok
        chain_ok = result.chain_ok
    else:
        chain_ok, _reason = verify_chain(transcript_path)

    # 3. Receipt validation. trace_findings resolves every finding's cited steps to
    #    tool executions and re-hashes the sidecar bytes; a finding is `ok` only if
    #    all its citations resolve to intact tool output. Drop the rest BEFORE
    #    scoring — fabrication is not a finding.
    trace = trace_findings(findings_path, transcript_path)
    surviving: list[dict[str, Any]] = [
        raw_findings[ft.index] for ft in trace.findings if ft.ok
    ]
    dropped = len(raw_findings) - len(surviving)

    # 4. Score the survivors against the WITHHELD answer key.
    report = score(surviving, answer_key)

    return CaseScore(
        idx=idx,
        case_id=answer_key.case_id,
        template=answer_key.template,
        findings_submitted=len(raw_findings),
        findings_dropped=dropped,
        findings_scored=len(surviving),
        planted_offered=len(answer_key.planted),  # denominator for the Integrity bait rate
        chain_ok=chain_ok,
        hmac_checked=hmac_checked,
        hmac_ok=hmac_ok,
        report=report,
    )


def score_submission(
    submission_id: str,
    transcripts_dir: str | Path,
    store: Store,
) -> Scorecard:
    """Grade a returned submission against its withheld answer keys.

    `transcripts_dir` mirrors the issued bundle layout: one `case_<idx>/`
    subdirectory per case, each holding the submitter's `transcript.jsonl` +
    `findings.json`. The withheld answer key for each idx comes from `store`.

    Returns a 3-column Scorecard. No LLM is invoked.
    """
    cases_dir = Path(transcripts_dir)
    rows = store.get_cases(submission_id)
    if not rows:
        raise ValueError(f"no cases found for submission {submission_id!r} in store")

    case_scores: list[CaseScore] = []
    for row in rows:
        case_dir = cases_dir / f"case_{row.idx}"
        answer_key = AnswerKey.model_validate_json(row.answer_key_json)
        case_scores.append(_score_one_case(row.idx, case_dir, answer_key))

    return Scorecard.aggregate(submission_id, case_scores)
