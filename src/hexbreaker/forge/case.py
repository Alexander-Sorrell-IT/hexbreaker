"""Case manifest + answer key + mock-output runner.

Every Forge-generated case is a directory with three things:

  case_<id>/
    manifest.json   — what the case is, which tools to run, where mock outputs live
    answer_key.json — ground truth: expected findings + decoys
    mock_outputs/   — pre-baked tool stdout files referenced by the manifest

Stub mode (used by the Friday gate and the demo) reads `mock_outputs/` instead
of executing real subprocesses, so a case is fully reproducible without SIFT.
Real mode swaps `mock_runner_from_case` for `subprocess_runner` and runs the
tools against the case's artifacts/ directory. Same case schema, two backends.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..court.schema import ArtifactKind, VerdictKind
from ..tools import ToolRunner


class ToolInvocation(BaseModel):
    """A single tool the case wants the agent (or pre-pass) to execute."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    args: list[str] = Field(default_factory=list)

    @property
    def key(self) -> str:
        """Stable key used to look the invocation up in mock_outputs."""
        return "|".join([self.tool, *self.args])


class CaseManifest(BaseModel):
    """Describes a case. Lives at case_dir/manifest.json."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    seed: int
    template: str
    description: str
    pre_pass_steps: list[ToolInvocation] = Field(default_factory=list)
    defender_steps: list[ToolInvocation] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    mock_outputs: dict[str, str] = Field(default_factory=dict)  # key -> relative path


class ExpectedFinding(BaseModel):
    """One entry in the ground-truth answer key."""

    model_config = ConfigDict(extra="forbid")

    artifact_kind: ArtifactKind
    target: str
    must_have_verdict: VerdictKind = "CONFIRMED"
    note: str = ""


class AnswerKey(BaseModel):
    """Ground truth. Withheld from the agent at run time, used at score time.

    `planted` entries are Provocateur-injected: artifacts deliberately designed
    to look evil so we can measure whether the agent gets baited. Confirming a
    planted entry is the strongest signal of safeguard failure — worse than a
    decoy FP, because the planted evidence is specifically engineered to look
    like the real finding.
    """

    model_config = ConfigDict(extra="forbid")

    case_id: str
    template: str
    expected_findings: list[ExpectedFinding] = Field(default_factory=list)
    decoys: list[ExpectedFinding] = Field(default_factory=list)
    planted: list[ExpectedFinding] = Field(default_factory=list)


def load_case(case_dir: str | Path) -> tuple[CaseManifest, AnswerKey]:
    """Read manifest + answer key from a case directory."""
    d = Path(case_dir)
    manifest = CaseManifest.model_validate_json((d / "manifest.json").read_bytes())
    answer = AnswerKey.model_validate_json((d / "answer_key.json").read_bytes())
    return manifest, answer


def mock_runner_from_case(case_dir: str | Path, manifest: CaseManifest) -> ToolRunner:
    """Build a ToolRunner that serves pre-baked outputs from manifest.mock_outputs.

    If the agent tries a tool/args combo the case doesn't have a mock for, the
    runner returns rc=1 and an explanatory stderr — that's a real signal to the
    agent that the tool didn't find what it expected, not a silent zero-byte
    "success" that would look like a clean scan.
    """
    case_path = Path(case_dir)

    def runner(argv, _cwd, _timeout):
        key = "|".join(argv)
        if key not in manifest.mock_outputs:
            msg = f"hexbreaker stub: no mock_output for {key!r}\n".encode()
            return 1, b"", msg, 0.001
        stdout_path = case_path / manifest.mock_outputs[key]
        return 0, stdout_path.read_bytes(), b"", 0.001

    return runner
