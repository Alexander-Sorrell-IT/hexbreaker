"""Tests for the offline finding -> tool-execution tracer (C5 audit trail).

The tracer joins a committed findings.json to its transcript and re-hashes the
referenced sidecar bytes, so a reviewer can prove any finding rests on intact
tool output with one command. These tests pin both the happy path (the committed
NIST sample traces clean) and the adversarial paths the tracer exists to catch:
a tampered sidecar, a fabricated citation, and a citation to a non-tool step.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import orjson
import pytest

from hexbreaker.court.trace import trace_findings

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "nist_fsm_run" / "run1"


def _copy_sample(tmp_path: Path) -> tuple[Path, Path]:
    dst = tmp_path / "run"
    shutil.copytree(SAMPLE, dst)
    return dst / "findings.json", dst / "transcript.jsonl"


@pytest.mark.skipif(not SAMPLE.exists(), reason="committed NIST sample not present")
def test_committed_sample_traces_clean() -> None:
    report = trace_findings(SAMPLE / "findings.json", SAMPLE / "transcript.jsonl")
    assert report.ok
    assert report.findings_total == report.findings_ok > 0
    # Every cited step resolves to a real tool with a non-empty stdout preview.
    for ft in report.findings:
        assert ft.cited_steps
        for s in ft.cited_steps:
            assert s.ok
            assert s.tool
            assert s.stdout_preview


@pytest.mark.skipif(not SAMPLE.exists(), reason="committed NIST sample not present")
def test_tampered_sidecar_is_caught(tmp_path: Path) -> None:
    """Editing a sidecar's bytes (the real evidence) must break the trace even
    though the transcript JSONL is untouched."""
    findings, transcript = _copy_sample(tmp_path)
    sidecar = transcript.parent / "transcript.outputs" / "S-001.stdout"
    sidecar.write_bytes(sidecar.read_bytes() + b"\nINJECTED EVIL LINE\n")
    report = trace_findings(findings, transcript)
    assert not report.ok
    bad = [s for ft in report.findings for s in ft.cited_steps if s.step_id == "S-001"]
    assert bad and all(s.code == "sidecar_mismatch" for s in bad)


@pytest.mark.skipif(not SAMPLE.exists(), reason="committed NIST sample not present")
def test_missing_sidecar_is_caught(tmp_path: Path) -> None:
    """A finding whose tool output was never exported cannot be traced — this is
    exactly the sift_vm_run situation, surfaced per-finding."""
    findings, transcript = _copy_sample(tmp_path)
    (transcript.parent / "transcript.outputs" / "S-001.stdout").unlink()
    report = trace_findings(findings, transcript)
    assert not report.ok
    codes = {s.code for ft in report.findings for s in ft.cited_steps if s.step_id == "S-001"}
    assert codes == {"sidecar_missing"}


def test_fabricated_citation_is_caught(tmp_path: Path) -> None:
    """A finding that cites a step_id the transcript never issued must fail to
    trace — the tracer cannot invent a tool execution."""
    transcript = tmp_path / "transcript.jsonl"
    transcript.write_text("")  # empty transcript: no steps at all
    findings = tmp_path / "findings.json"
    findings.write_bytes(
        orjson.dumps(
            {
                "findings": [
                    {
                        "artifact_kind": "timestomp",
                        "target": "X",
                        "verdict": "CONFIRMED",
                        "cited_steps": ["S-099"],
                    }
                ]
            }
        )
    )
    report = trace_findings(findings, transcript)
    assert not report.ok
    assert report.findings[0].cited_steps[0].code == "missing_step"
