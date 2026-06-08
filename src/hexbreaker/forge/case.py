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

from pathlib import Path, PurePosixPath, PureWindowsPath

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..court.schema import ArtifactKind, VerdictKind
from ..tools import ToolRunner


def _is_safe_relative(p: str) -> bool:
    """True iff `p` is a relative path with no '..' segments and no absolute prefix.

    Checks against both POSIX and Windows path semantics — a manifest authored
    on Windows must not be able to inject "C:\\foo" or "..\\..\\etc\\passwd"
    that a POSIX Path() would treat as relative.
    """
    if not p:
        return False
    posix = PurePosixPath(p)
    win = PureWindowsPath(p)
    if posix.is_absolute() or win.is_absolute():
        return False
    if win.drive or win.anchor:
        return False
    parts = list(posix.parts) + list(win.parts)
    return ".." not in parts and not any(part.startswith("/") or part.startswith("\\") for part in parts)


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
    # Real int at generation time; None in an issued registry bundle. The seed is
    # withheld from submitters because the Forge is open-source (MIT) — a leaked
    # seed lets a submitter run `generate --seed N` locally and reconstruct the
    # answer key. Registry-mode ships a precomputed provocation.json instead so the
    # Provocateur (Layer 6) still fires without the seed. See PLAN_REGISTRY.md.
    seed: int | None = None
    template: str
    description: str
    pre_pass_steps: list[ToolInvocation] = Field(default_factory=list)
    defender_steps: list[ToolInvocation] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    mock_outputs: dict[str, str] = Field(default_factory=dict)  # key -> relative path

    @field_validator("mock_outputs")
    @classmethod
    def _mock_outputs_must_be_relative_and_inside_case_dir(cls, v: dict[str, str]) -> dict[str, str]:
        """Reject path-traversal payloads in untrusted manifests.

        Without this check, a malicious case directory's manifest can name
        `../../etc/passwd` as a mock output and the runner will (a) copy the
        host's /etc/passwd into a sidecar file under the case dir AND (b)
        inline the first ~3KB of it into the Prosecutor's prompt sent to a
        third-party LLM API. See `docs/accuracy.md` §5 / sweeps/code-review-...
        and the security-review markdown for the original finding.
        """
        bad: list[str] = []
        for key, path in v.items():
            if not _is_safe_relative(path):
                bad.append(f"{key!r} -> {path!r}")
        if bad:
            raise ValueError(
                "mock_outputs values must be relative paths inside the case "
                f"directory (no absolute paths, no '..' traversal). Rejected: "
                + "; ".join(bad)
            )
        return v


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


def load_manifest(case_dir: str | Path) -> CaseManifest:
    """Read just the manifest from a case directory.

    Used by the Court runner, which is forbidden from reading the answer key.
    An issued registry bundle has NO answer_key.json (it's withheld for scoring),
    so the runner must be able to load a case from the manifest alone.
    """
    d = Path(case_dir)
    return CaseManifest.model_validate_json((d / "manifest.json").read_bytes())


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
    case_path = Path(case_dir).resolve()

    def runner(argv, _cwd, _timeout):
        key = "|".join(argv)
        if key not in manifest.mock_outputs:
            msg = f"hexbreaker stub: no mock_output for {key!r}\n".encode()
            return 1, b"", msg, 0.001
        # Defense in depth: schema validator already rejected absolute/traversal
        # paths, but verify containment at runtime too. A manifest could have
        # been constructed in code (bypassing model_validate) or someone may
        # have widened the validator in the future.
        candidate = (case_path / manifest.mock_outputs[key]).resolve()
        if not candidate.is_relative_to(case_path):
            msg = (
                f"hexbreaker stub: mock_output {key!r} resolves outside case dir "
                f"({candidate} not under {case_path})\n"
            ).encode()
            return 1, b"", msg, 0.001
        return 0, candidate.read_bytes(), b"", 0.001

    return runner
