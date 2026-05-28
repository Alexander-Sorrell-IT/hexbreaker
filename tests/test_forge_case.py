"""Tests for case schema + mock-runner."""

from __future__ import annotations

from pathlib import Path

import orjson
import pytest

from hexbreaker.forge.case import (
    AnswerKey,
    CaseManifest,
    ExpectedFinding,
    ToolInvocation,
    load_case,
    mock_runner_from_case,
)


def _write_case(tmp_path: Path) -> Path:
    case_dir = tmp_path / "case"
    (case_dir / "mock_outputs").mkdir(parents=True)
    (case_dir / "mock_outputs" / "mft.csv").write_bytes(b"col1,col2\n1,2\n")
    manifest = CaseManifest(
        case_id="case-test",
        seed=1,
        template="timestomp",
        description="tiny",
        pre_pass_steps=[ToolInvocation(tool="MFTECmd", args=["-f", "/case/MFT"])],
        defender_steps=[],
        allowed_tools=["MFTECmd"],
        mock_outputs={"MFTECmd|-f|/case/MFT": "mock_outputs/mft.csv"},
    )
    answer = AnswerKey(
        case_id="case-test",
        template="timestomp",
        expected_findings=[ExpectedFinding(artifact_kind="timestomp", target="x.sys")],
    )
    (case_dir / "manifest.json").write_bytes(orjson.dumps(manifest.model_dump()))
    (case_dir / "answer_key.json").write_bytes(orjson.dumps(answer.model_dump()))
    return case_dir


def test_load_case_roundtrip(tmp_path: Path) -> None:
    case_dir = _write_case(tmp_path)
    manifest, answer = load_case(case_dir)
    assert manifest.case_id == "case-test"
    assert manifest.pre_pass_steps[0].tool == "MFTECmd"
    assert answer.expected_findings[0].target == "x.sys"


def test_tool_invocation_key_is_argv_join() -> None:
    t = ToolInvocation(tool="yara", args=["rules.yar", "target"])
    assert t.key == "yara|rules.yar|target"


def test_mock_runner_returns_baked_output(tmp_path: Path) -> None:
    case_dir = _write_case(tmp_path)
    manifest, _ = load_case(case_dir)
    runner = mock_runner_from_case(case_dir, manifest)
    rc, stdout, stderr, _dt = runner(["MFTECmd", "-f", "/case/MFT"], None, None)
    assert rc == 0
    assert b"col1,col2" in stdout
    assert stderr == b""


def test_mock_runner_returns_error_for_unknown_invocation(tmp_path: Path) -> None:
    case_dir = _write_case(tmp_path)
    manifest, _ = load_case(case_dir)
    runner = mock_runner_from_case(case_dir, manifest)
    rc, stdout, stderr, _ = runner(["yara", "no-rule", "no-file"], None, None)
    assert rc == 1
    assert stdout == b""
    assert b"no mock_output" in stderr


# === Security: path-traversal in mock_outputs ===
# These regression tests cover the HIGH-severity finding from the
# 2026-05-27 security review (sweeps/code-review-2026-05-27.json /
# /tmp/.../task.output for security-review). Without the field_validator on
# CaseManifest.mock_outputs + the is_relative_to runtime check, a malicious
# case manifest gives an attacker arbitrary file read + LLM-channel exfil.


def test_mock_outputs_rejects_absolute_path(tmp_path: Path) -> None:
    """A manifest naming an absolute path as a mock output must fail validation."""
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="mock_outputs"):
        CaseManifest(
            case_id="c", seed=1, template="t", description="d",
            mock_outputs={"MFTECmd|-f|/case/MFT": "/etc/passwd"},
        )


def test_mock_outputs_rejects_dot_dot_traversal(tmp_path: Path) -> None:
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="mock_outputs"):
        CaseManifest(
            case_id="c", seed=1, template="t", description="d",
            mock_outputs={"MFTECmd|-f|/case/MFT": "../../../etc/passwd"},
        )


def test_mock_outputs_rejects_windows_drive_path(tmp_path: Path) -> None:
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="mock_outputs"):
        CaseManifest(
            case_id="c", seed=1, template="t", description="d",
            mock_outputs={"MFTECmd|-f|/case/MFT": "C:\\Windows\\System32\\config\\SAM"},
        )


def test_mock_outputs_rejects_windows_backslash_traversal(tmp_path: Path) -> None:
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="mock_outputs"):
        CaseManifest(
            case_id="c", seed=1, template="t", description="d",
            mock_outputs={"MFTECmd|-f|/case/MFT": "..\\..\\Windows\\System32\\config\\SAM"},
        )


def test_mock_outputs_accepts_safe_relative_subpath() -> None:
    """Sanity: a normal relative path (the actual use case) still validates."""
    m = CaseManifest(
        case_id="c", seed=1, template="t", description="d",
        mock_outputs={"MFTECmd|-f|/case/MFT": "mock_outputs/mft.csv"},
    )
    assert m.mock_outputs["MFTECmd|-f|/case/MFT"] == "mock_outputs/mft.csv"


def test_mock_runner_defense_in_depth_against_runtime_traversal(tmp_path: Path) -> None:
    """If a manifest is constructed in code (bypassing validation) with a
    traversal, the runtime is_relative_to check must still refuse to read."""
    case_dir = tmp_path / "case"
    (case_dir / "mock_outputs").mkdir(parents=True)
    (case_dir / "mock_outputs" / "real.csv").write_bytes(b"legit")
    # model_construct bypasses validators — simulates someone widening the
    # validator or building the manifest directly without round-tripping JSON.
    manifest = CaseManifest.model_construct(
        case_id="c", seed=1, template="t", description="d",
        pre_pass_steps=[], defender_steps=[], allowed_tools=[],
        mock_outputs={"MFTECmd|-f|/case/MFT": "../../../../etc/passwd"},
    )
    runner = mock_runner_from_case(case_dir, manifest)
    rc, stdout, stderr, _ = runner(["MFTECmd", "-f", "/case/MFT"], None, None)
    assert rc == 1
    assert stdout == b""
    assert b"resolves outside case dir" in stderr
