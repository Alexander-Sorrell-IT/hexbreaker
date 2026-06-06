"""Honesty tests for the NIST recycle-bin FSM adapter (scripts/court_on_nist_fsm.py).

Two guarantees, enforced hermetically (no live API, no real disk needed):

  1. ``max_rounds`` is derived from the INFO2 evidence
     (``_info2_original_exe_paths``), which is the SAME source as the prompt
     evidence (``_info2_ascii_paths``) — NOT from ``answer_key.json``. So the loop
     length equals a count a neutral examiner reads off the real disk, not the
     withheld ground truth.

  2. The withheld answer key never reaches the agent. ``load_case`` reads
     ``answer_key.json`` and the runner immediately discards it
     (``manifest, _ = load_case(...)``); its scorer-only content never appears in
     any Prosecutor or Defender prompt. (The deleted-exe *paths* DO legitimately
     appear in prompts — they are in the INFO2 evidence the agent reads — so we
     pin the answer-key-EXCLUSIVE text instead.)
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

from hexbreaker import llm
from hexbreaker.forge.case import load_case
from hexbreaker.runner.court_runner import run_court_on_case

# scripts/ is not a package — load the adapter module by path.
_SPEC = importlib.util.spec_from_file_location(
    "court_on_nist_fsm",
    Path(__file__).resolve().parent.parent / "scripts" / "court_on_nist_fsm.py",
)
nist = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(nist)

FAKE_EXES = [
    r"C:\Documents and Settings\Mr. Evil\Desktop\toolA_1_2.exe",
    r"C:\Documents and Settings\Mr. Evil\Desktop\toolB-0.9.exe",
]

_TOOL_RE = re.compile(r"(S-\d+) \| TOOL \| tool_call \| meta=(\{[^}]*\})")


def _resp(content: str, model: str, reasoning: str | None = None) -> llm.LLMResponse:
    return llm.LLMResponse(
        model=model,
        content=content,
        reasoning_content=reasoning,
        usage=llm.Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
        latency_s=0.0,
        raw={},
    )


def _stage_fake_extracts(tmp_path: Path) -> Path:
    """Fixture INFO2 + fls listing so the adapter builds a case with no real disk."""
    extracts = tmp_path / "extracts"
    extracts.mkdir()
    # INFO2 raw bytes: the ASCII path section the regex scans, NUL-separated.
    info2 = b"\x00\x05" + b"\x00".join(p.encode("latin1") for p in FAKE_EXES) + b"\x00"
    (extracts / "INFO2").write_bytes(info2)
    fls = (
        "\n".join(
            f"r/r {1000 + i}-128-4:\tRECYCLER/S-1-5-21-FAKE/Dc{i + 1}.exe"
            for i in range(len(FAKE_EXES))
        )
        + "\nr/r 1850-128-3:\tRECYCLER/S-1-5-21-FAKE/INFO2\n"
    )
    (extracts / "fls_recycler.txt").write_text(fls)
    return extracts


def _patch_extracts(tmp_path: Path, monkeypatch) -> Path:
    extracts = _stage_fake_extracts(tmp_path)
    monkeypatch.setattr(nist, "EXTRACTS_DIR", extracts)
    # point MOUNT_RAW at a path that does not exist so fls reads the staged listing.
    monkeypatch.setattr(nist, "MOUNT_RAW", tmp_path / "no_such_mount" / "ewf1")
    return extracts


class _RecordingClient:
    """Returns valid NIST Claim/Verdict JSON and records every prompt it is sent."""

    def __init__(self, targets):
        self.targets = list(targets)
        self._pi = 0
        self.prompts: list[str] = []

    def call(self, messages, *, model, temperature=0.2, json_mode=False) -> llm.LLMResponse:
        self.prompts.append("\n".join(m["content"] for m in messages))
        user = messages[-1]["content"]
        parsed = [(s, json.loads(meta)) for s, meta in _TOOL_RE.findall(user)]
        if model == llm.DEEPSEEK_CHAT:  # Prosecutor: accuse the next un-accused exe.
            target = self.targets[min(self._pi, len(self.targets) - 1)]
            self._pi += 1
            sid, meta = parsed[0]
            claim = {
                "text": f"accuse {target}",
                "artifact_kind": "other",
                "target": target,
                "cited_steps": [{"step_id": sid, "stdout_hash": meta["stdout_hash"]}],
            }
            return _resp(json.dumps(claim), model)
        # Defender: cite two distinct tool kinds (fls + icat) -> CONFIRMED clears JR-01.
        by_tool: dict[str, tuple[str, str]] = {}
        for sid, meta in parsed:
            by_tool.setdefault(meta["tool"], (sid, meta["stdout_hash"]))
        chosen = list(by_tool.values())[:2]
        verdict = {
            "verdict": "CONFIRMED",
            "cited_steps": [{"step_id": s, "stdout_hash": h} for s, h in chosen],
            "challenge_text": "fls slot and INFO2 original-path both corroborate",
        }
        return _resp(json.dumps(verdict), model, reasoning="fake")


def test_max_rounds_source_is_info2_not_answer_key(tmp_path, monkeypatch):
    _patch_extracts(tmp_path, monkeypatch)
    # The loop-length source IS the prompt-evidence source (both = INFO2 bytes).
    assert nist._info2_original_exe_paths() == nist._info2_ascii_paths() == FAKE_EXES


def test_answer_key_content_never_reaches_the_agent(tmp_path, monkeypatch):
    _patch_extracts(tmp_path, monkeypatch)
    case_dir = tmp_path / "case"
    _manifest, expected = nist.build_case(case_dir)

    # answer_key.json on disk holds the ground truth (scorer reads it AFTER the run).
    answer = load_case(case_dir)[1]
    assert [e.target for e in answer.expected_findings] == FAKE_EXES

    client = _RecordingClient(expected)
    run_court_on_case(
        case_dir,
        client=client,
        prosecutor_system=nist.NIST_PROSECUTOR_SYSTEM,
        defender_system=nist.NIST_DEFENDER_SYSTEM,
        max_rounds=len(expected),  # exactly what main() passes
    )

    # All expected exes recovered (multi-round loop works end-to-end).
    found = json.loads((case_dir / "findings.json").read_bytes())["findings"]
    assert sorted(f["target"] for f in found) == sorted(FAKE_EXES)

    # The answer-key-EXCLUSIVE text (the scorer note + the filename) never leaks into
    # any prompt. (The exe paths themselves DO appear — they are real INFO2 evidence.)
    blob = "\n".join(client.prompts)
    assert answer.expected_findings[0].note not in blob
    assert "answer_key" not in blob
    assert "must_have_verdict" not in blob
