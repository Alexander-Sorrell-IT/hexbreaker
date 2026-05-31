"""Court session FSM — Layer 2 of the safeguards (forced tool-call sequence).

A CourtSession is one Prosecutor claim through to a Defender verdict. The FSM
holds three rules:

  R1. A Claim must be submitted before any tool is observed.
  R2. The Defender cannot emit a verdict before at least one tool has been
      observed since the claim was accepted.
  R3. A submitted but invalid Verdict is logged as a SYSTEM_EVENT and the
      session stays open — the Defender may try again. The FSM does NOT
      terminate on rejection. Termination happens only on an accepted Verdict.

The session class deliberately does NOT call an LLM. Prompt construction and
LLM I/O live one layer up (in the runner). Keeping the FSM LLM-free is what
makes it cheap to unit-test against canned JSON strings.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel

from ..tools import ToolResult, ToolRunner, run_tool
from ..transcript import Actor, Kind, StepRecord, Transcript
from .schema import Claim, Verdict
from .judge import RulingKind, judge
from .validator import (
    ValidationIssue,
    ValidationResult,
    validate_claim_json,
    validate_verdict_json,
)


class State(str, Enum):
    AWAITING_CLAIM = "awaiting_claim"
    AWAITING_TOOL = "awaiting_tool"
    TOOL_OBSERVED = "tool_observed"
    VERDICT_ACCEPTED = "verdict_accepted"


class FSMError(RuntimeError):
    """Raised on an operation that violates the FSM contract."""


class ClaimOutcome(BaseModel):
    result: ValidationResult
    claim: Claim | None
    record: StepRecord | None


class VerdictOutcome(BaseModel):
    result: ValidationResult
    verdict: Verdict | None
    record: StepRecord | None
    accepted: bool
    corroboration_strength: str = "unknown"  # JR-01b report-only audit


class CourtSession:
    """One Prosecutor-vs-Defender bout, persisted to a hash-chained transcript."""

    def __init__(self, transcript: Transcript) -> None:
        self.transcript = transcript
        self.state: State = State.AWAITING_CLAIM
        self.claim: Claim | None = None
        self.verdict: Verdict | None = None
        self._tools_observed_since_claim: int = 0

    @property
    def must_call_tool(self) -> bool:
        """True iff the Defender is required to observe a tool before verdicting."""
        return self.state == State.AWAITING_TOOL

    @property
    def is_open(self) -> bool:
        return self.state != State.VERDICT_ACCEPTED

    def submit_claim(self, raw_json: str | bytes) -> ClaimOutcome:
        if self.state != State.AWAITING_CLAIM:
            raise FSMError(f"submit_claim disallowed in state {self.state.value}")

        result, claim = validate_claim_json(raw_json, list(_read_records(self.transcript)))
        if not result.ok or claim is None:
            rec = self.transcript.append(
                actor=Actor.ORCHESTRATOR,
                kind=Kind.SYSTEM_EVENT,
                content={
                    "event": "claim_rejected",
                    "issues": [i.model_dump() for i in result.issues],
                    "raw_json": _stringify(raw_json),
                },
            )
            return ClaimOutcome(result=result, claim=None, record=rec)

        rec = self.transcript.append(
            actor=Actor.PROSECUTOR,
            kind=Kind.CLAIM,
            content=claim.model_dump(),
        )
        self.claim = claim
        self.state = State.AWAITING_TOOL
        self._tools_observed_since_claim = 0
        return ClaimOutcome(result=result, claim=claim, record=rec)

    def observe_tool(
        self,
        tool: str,
        args: list[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = 300.0,
        runner: ToolRunner | None = None,
    ) -> ToolResult:
        """Run a tool through the FSM. `runner` defaults to a SAFE no-op that
        refuses to execute — callers must opt in to live subprocess via
        `runner=subprocess_runner` or pass a mock runner from the Forge case.

        Without this default, test code that forgets to pass `runner=` would
        silently shell out to host binaries (yara, fls, vol) with whatever
        argv the test happens to pass — caught by the code review's wrapper-E
        angle.
        """
        if self.state == State.AWAITING_CLAIM:
            raise FSMError("observe_tool requires an accepted claim first")
        if self.state == State.VERDICT_ACCEPTED:
            raise FSMError("session is closed (verdict accepted)")
        if runner is None:
            raise FSMError(
                "observe_tool requires an explicit `runner=` argument. "
                "Pass `runner=subprocess_runner` for live execution or "
                "`runner=mock_runner_from_case(case_dir, manifest)` for stub mode. "
                "The previous default (subprocess_runner) silently shelled out "
                "to host binaries from test code — code review wrapper-E finding."
            )

        result = run_tool(
            self.transcript, tool, args, cwd=cwd, timeout=timeout, runner=runner
        )
        self._tools_observed_since_claim += 1
        self.state = State.TOOL_OBSERVED
        return result

    def submit_verdict(self, raw_json: str | bytes) -> VerdictOutcome:
        if self.state == State.AWAITING_CLAIM:
            raise FSMError("submit_verdict requires a claim first")
        if self.state == State.VERDICT_ACCEPTED:
            raise FSMError("verdict already accepted; session is closed")

        # R2: must have observed at least one tool since the claim.
        if self._tools_observed_since_claim == 0:
            result = ValidationResult(
                ok=False,
                issues=[
                    ValidationIssue(
                        code="schema",
                        detail="verdict submitted before any tool was observed (R2 violation)",
                    )
                ],
            )
            rec = self.transcript.append(
                actor=Actor.ORCHESTRATOR,
                kind=Kind.SYSTEM_EVENT,
                content={
                    "event": "verdict_rejected_premature",
                    "raw_json": _stringify(raw_json),
                },
            )
            return VerdictOutcome(result=result, verdict=None, record=rec, accepted=False)

        records = list(_read_records(self.transcript))
        result, verdict = validate_verdict_json(raw_json, records)
        if not result.ok or verdict is None:
            rec = self.transcript.append(
                actor=Actor.ORCHESTRATOR,
                kind=Kind.SYSTEM_EVENT,
                content={
                    "event": "verdict_rejected_invalid",
                    "issues": [i.model_dump() for i in result.issues],
                    "raw_json": _stringify(raw_json),
                },
            )
            return VerdictOutcome(result=result, verdict=None, record=rec, accepted=False)

        # Schema + citation integrity passed. Run the deterministic Judge to
        # apply rules that the Defender's prompt was previously the only
        # enforcer for (corroboration etc.). A downgrade is recorded as a
        # JUDGE event and the stored Verdict is the post-Judge one.
        assert self.claim is not None  # claim accepted before any verdict
        # Build the cited tools' stdout so JR-01b can check per-target relevance.
        # The wired path ALWAYS supplies it (never silently skipped); sidecars are
        # read path-safely, mirroring transcript._verify_sidecar.
        tool_stdout = _cited_tool_stdout(verdict, records, self.transcript.path.parent)
        ruling = judge(verdict, self.claim, records, tool_stdout=tool_stdout)
        if ruling.kind == RulingKind.DOWNGRADED:
            self.transcript.append(
                actor=Actor.JUDGE,
                kind=Kind.SYSTEM_EVENT,
                content={
                    "event": "judge_downgrade",
                    "rule_id": ruling.rule_id,
                    "reason": ruling.reason,
                    "original_verdict": verdict.verdict,
                    "final_verdict": ruling.verdict_kind,
                    "distinct_tools_cited": ruling.distinct_tools_cited,
                    "corroboration_strength": ruling.corroboration_strength,
                },
            )
            verdict_dict = verdict.model_dump()
            verdict_dict["verdict"] = ruling.verdict_kind
            verdict = type(verdict).model_validate(verdict_dict)

        rec = self.transcript.append(
            actor=Actor.DEFENDER,
            kind=Kind.VERDICT,
            content=verdict.model_dump(),
        )
        self.verdict = verdict
        self.corroboration_strength = ruling.corroboration_strength
        self.state = State.VERDICT_ACCEPTED
        return VerdictOutcome(
            result=result, verdict=verdict, record=rec, accepted=True,
            corroboration_strength=ruling.corroboration_strength,
        )


def _stringify(raw: str | bytes) -> str:
    return raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw


def _read_records(transcript: Transcript) -> list[StepRecord]:
    """Read the on-disk records for cross-referential validation."""
    from ..transcript import read as read_records  # local import avoids cycle at import time
    return list(read_records(transcript.path))


def _cited_tool_stdout(
    verdict: Verdict, records: list[StepRecord], transcript_dir: Path
) -> dict[str, str]:
    """Read the stdout of each cited TOOL_CALL step from its sidecar, path-safely.

    JR-01b needs the actual tool output to verify the cited evidence names the
    target. Paths resolve against the transcript dir; any that escape it are
    skipped (treated as absent), mirroring transcript._verify_sidecar's defense.
    """
    by_id = {r.step_id: r for r in records}
    base = transcript_dir.resolve()
    out: dict[str, str] = {}
    for ref in verdict.cited_steps:
        rec = by_id.get(ref.step_id)
        if rec is None or rec.kind != Kind.TOOL_CALL:
            continue
        rel = rec.content.get("stdout_path")
        if not isinstance(rel, str):
            continue
        candidate = (base / rel).resolve()
        if not candidate.is_relative_to(base):
            continue
        try:
            out[ref.step_id] = candidate.read_text(errors="replace")
        except OSError:
            continue
    return out
