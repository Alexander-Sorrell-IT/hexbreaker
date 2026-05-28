"""Pydantic schemas for Court structured exchanges — Layer 3 of the safeguards.

The Prosecutor emits Claims. The Defender emits Verdicts. Both must cite specific
transcript steps via StepReference (step_id + expected stdout hash). Parse
failures auto-reject — that's the entire point of strict schema mode.

These are also the shapes we'll pin into the LLM prompts as JSON schema, so
DeepSeek's response_format=json_object returns something the orchestrator can
deserialize without a regex.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

VerdictKind = Literal["CONFIRMED", "CONTESTED", "REJECTED"]

ArtifactKind = Literal[
    "timestomp",
    "persistence",
    "execution",
    "exfiltration",
    "browser",
    "registry",
    "evtx",
    "prefetch",
    "amcache",
    "memory",
    "other",
]


class StepReference(BaseModel):
    """Pointer into the transcript. step_id + hash so a citation is verifiable."""

    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(pattern=r"^S-\d{3,}$")
    stdout_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class Claim(BaseModel):
    """A Prosecutor accusation: what was found, why it's evil, what proves it.

    `target` is the identifying string for the accused artifact — a filename, a
    registry path, a URL, a process name. The scorer matches on
    (artifact_kind, target) so this field must be reproducible from tool output.
    """

    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1)
    artifact_kind: ArtifactKind
    target: str = Field(min_length=1)
    cited_steps: list[StepReference] = Field(min_length=1)

    @field_validator("cited_steps")
    @classmethod
    def _unique_step_ids(cls, v: list[StepReference]) -> list[StepReference]:
        seen = set()
        for ref in v:
            if ref.step_id in seen:
                raise ValueError(f"duplicate step_id in cited_steps: {ref.step_id}")
            seen.add(ref.step_id)
        return v


class Verdict(BaseModel):
    """A Defender ruling on a Claim. Must cite at least one tool step."""

    model_config = ConfigDict(extra="forbid")

    verdict: VerdictKind
    cited_steps: list[StepReference] = Field(min_length=1)
    challenge_text: str = Field(min_length=1)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    @field_validator("cited_steps")
    @classmethod
    def _unique_step_ids(cls, v: list[StepReference]) -> list[StepReference]:
        seen = set()
        for ref in v:
            if ref.step_id in seen:
                raise ValueError(f"duplicate step_id in cited_steps: {ref.step_id}")
            seen.add(ref.step_id)
        return v


CLAIM_JSON_SCHEMA_HINT = """
{
  "text": "<one-paragraph forensic accusation>",
  "artifact_kind": "timestomp | persistence | execution | exfiltration | browser | registry | evtx | prefetch | amcache | memory | other",
  "target": "<exact identifier of the accused artifact — filename, registry path, URL, etc>",
  "cited_steps": [{"step_id": "S-NNN", "stdout_hash": "sha256:<64 hex>"}]
}
""".strip()

VERDICT_JSON_SCHEMA_HINT = """
{
  "verdict": "CONFIRMED | CONTESTED | REJECTED",
  "cited_steps": [{"step_id": "S-NNN", "stdout_hash": "sha256:<64 hex>"}],
  "challenge_text": "<why you concede or contest, in plain forensic English>",
  "confidence": 0.0
}
""".strip()
