"""Tests for SIFT tool wrappers with injected runner — no real subprocess calls."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hexbreaker.tools import SUPPORTED_TOOLS, run_tool
from hexbreaker.transcript import Actor, Kind, Transcript, verify


def _fake_runner_factory(stdout: bytes, stderr: bytes, rc: int = 0, duration: float = 0.01):
    def runner(_argv, _cwd, _timeout):
        return rc, stdout, stderr, duration
    return runner


def test_run_tool_appends_step_to_transcript(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "run.jsonl")
    result = run_tool(
        t,
        "fls",
        ["-m", "C:", "/case/image.dd"],
        runner=_fake_runner_factory(b"file listing", b""),
    )
    assert result.step_id == "S-001"
    assert result.tool == "fls"
    assert result.argv == ["fls", "-m", "C:", "/case/image.dd"]
    assert result.returncode == 0
    assert result.record.actor == Actor.TOOL
    assert result.record.kind == Kind.TOOL_CALL


def test_run_tool_hashes_stdout_and_stderr(tmp_path: Path) -> None:
    stdout, stderr = b"hello mft world", b"a warning"
    t = Transcript.open(tmp_path / "run.jsonl")
    result = run_tool(t, "MFTECmd", ["-f", "/m/$MFT"], runner=_fake_runner_factory(stdout, stderr))
    assert result.stdout_hash == "sha256:" + hashlib.sha256(stdout).hexdigest()
    assert result.stderr_hash == "sha256:" + hashlib.sha256(stderr).hexdigest()


def test_run_tool_writes_sidecar_files(tmp_path: Path) -> None:
    stdout = b"large output payload" * 100
    stderr = b""
    t = Transcript.open(tmp_path / "run.jsonl")
    result = run_tool(t, "EvtxECmd", ["-f", "Security.evtx"], runner=_fake_runner_factory(stdout, stderr))
    assert result.stdout_path.exists()
    assert result.stdout_path.read_bytes() == stdout
    assert result.stderr_path.exists()
    assert result.stderr_path.read_bytes() == b""


def test_run_tool_rejects_unsupported_tool(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "run.jsonl")
    with pytest.raises(ValueError, match="unsupported tool"):
        run_tool(t, "rm", ["-rf", "/"], runner=_fake_runner_factory(b"", b""))


def test_run_tool_preserves_chain_integrity(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    t = Transcript.open(path)
    run_tool(t, "fls", ["arg"], runner=_fake_runner_factory(b"out1", b""))
    run_tool(t, "yara", ["rule.yar", "."], runner=_fake_runner_factory(b"out2", b""))
    run_tool(t, "vol", ["-f", "mem.raw", "windows.pslist"], runner=_fake_runner_factory(b"out3", b""))
    ok, reason = verify(path)
    assert ok, reason


def test_supported_tools_covers_plan_set() -> None:
    """The plan calls out the 10 SIFT tools; we also support the *nix
    forensics utilities we use for NIST (icat/mmls/fsstat/ewfverify)."""
    plan_minimum = {
        "MFTECmd", "AmcacheParser", "PECmd", "EvtxECmd", "RECmd",
        "vol", "log2timeline.py", "fls", "yara", "bulk_extractor",
    }
    assert plan_minimum.issubset(SUPPORTED_TOOLS)


def test_run_tool_records_returncode_in_content(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "run.jsonl")
    result = run_tool(t, "yara", ["bad.yar", "."], runner=_fake_runner_factory(b"", b"compile error", rc=2))
    assert result.returncode == 2
    assert result.record.content["returncode"] == 2
    assert result.record.content["tool"] == "yara"
