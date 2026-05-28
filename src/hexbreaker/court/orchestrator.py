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

from ..tools import ToolResult, ToolRunner, run_tool, subprocess_runner
from ..transcript import Actor, Kind, StepRecord, Transcript
from .schema import Claim, Verdict
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
        runner: ToolRunner = subprocess_runner,
    ) -> ToolResult:
        if self.state == State.AWAITING_CLAIM:
            raise FSMError("observe_tool requires an accepted claim first")
        if self.state == State.VERDICT_ACCEPTED:
            raise FSMError("session is closed (verdict accepted)")

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

        result, verdict = validate_verdict_json(
            raw_json, list(_read_records(self.transcript))
        )
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

        rec = self.transcript.append(
            actor=Actor.DEFENDER,
            kind=Kind.VERDICT,
            content=verdict.model_dump(),
        )
        self.verdict = verdict
        self.state = State.VERDICT_ACCEPTED
        return VerdictOutcome(result=result, verdict=verdict, record=rec, accepted=True)


def _stringify(raw: str | bytes) -> str:
    return raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw


def _read_records(transcript: Transcript) -> list[StepRecord]:
    """Read the on-disk records for cross-referential validation."""
    from ..transcript import read as read_records  # local import avoids cycle at import time
    return list(read_records(transcript.path))
