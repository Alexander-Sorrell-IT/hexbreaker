"""Hermetic tests for the multi-finding investigation loop (court_runner.max_rounds).

No live API: a FakeClient parses the rendered transcript in each prompt and returns
deterministic Claim/Verdict JSON. Pins (a) max_rounds=1 byte-stability, (b) genuine
multi-finding, (c) termination, (e) FSM re-enforcement across sessions on one chain.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from hexbreaker import llm
from hexbreaker.forge import template_timestomp as TS
from hexbreaker.runner.court_runner import run_court_on_case
from hexbreaker.transcript import Transcript, read, verify
from hexbreaker.court.orchestrator import CourtSession

_TOOL_RE = re.compile(r"(S-\d+) \| TOOL \| tool_call \| meta=(\{[^}]*\})")


def _resp(content: str, *, model: str, reasoning: str | None = None) -> llm.LLMResponse:
    return llm.LLMResponse(
        model=model,
        content=content,
        reasoning_content=reasoning,
        usage=llm.Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
        latency_s=0.0,
        raw={},
    )


def _tool_steps(user: str):
    out = []
    for m in _TOOL_RE.finditer(user):
        meta = json.loads(m.group(2))
        out.append((m.group(1), meta["tool"], meta["stdout_hash"]))
    return out


class FakeClient:
    """Deterministic stand-in for DeepSeekClient. Prosecutor (chat) accuses the next
    configured target citing the pre-pass tool; Defender (reasoner) cites N distinct
    tool kinds so JR-01 leaves CONFIRMED intact (cite_n_tools>=2) or downgrades it (1).
    """

    def __init__(self, targets, *, verdict="CONFIRMED", cite_n_tools=2):
        self.targets = list(targets)
        self.verdict = verdict
        self.cite_n_tools = cite_n_tools
        self.prosecutor_msgs: list[str] = []
        self._pi = 0

    def call(self, messages, *, model, temperature=0.2, json_mode=False) -> llm.LLMResponse:
        user = messages[-1]["content"]
        steps = _tool_steps(user)
        if model == llm.DEEPSEEK_CHAT:
            self.prosecutor_msgs.append(user)
            target = self.targets[min(self._pi, len(self.targets) - 1)]
            self._pi += 1
            sid, _tool, h = steps[0]  # cite the pre-pass tool (always present)
            claim = {
                "text": f"accuse {target} of timestomp",
                "artifact_kind": "timestomp",
                "target": target,
                "cited_steps": [{"step_id": sid, "stdout_hash": h}],
            }
            return _resp(json.dumps(claim), model=model)
        # Defender: cite the first cite_n_tools DISTINCT tool kinds available.
        by_tool: dict[str, tuple[str, str]] = {}
        for sid, tool, h in steps:
            by_tool.setdefault(tool, (sid, h))
        chosen = list(by_tool.values())[: self.cite_n_tools]
        verdict = {
            "verdict": self.verdict,
            "cited_steps": [{"step_id": sid, "stdout_hash": h} for sid, h in chosen],
            "challenge_text": "fake verdict for test",
        }
        return _resp(json.dumps(verdict), model=model, reasoning="fake reasoning")


def _make_case(tmp_path: Path, seed: int = 4729) -> Path:
    d = tmp_path / f"case-{seed}"
    TS.generate(seed, d)
    return d


def _findings(case_dir: Path) -> dict:
    return json.loads((case_dir / "findings.json").read_bytes())


# (a) max_rounds=1: one finding, deterministic findings.json, transcript verifies.
def test_max_rounds_1_single_finding_and_deterministic(tmp_path: Path):
    c1 = _make_case(tmp_path / "a", 4729)
    run_court_on_case(c1, client=FakeClient(["\\Windows\\System32\\evil.sys"]), max_rounds=1)
    f1 = (c1 / "findings.json").read_bytes()
    assert len(_findings(c1)["findings"]) == 1
    assert verify(c1 / "transcript.jsonl")[0] is True

    c2 = _make_case(tmp_path / "b", 4729)
    run_court_on_case(c2, client=FakeClient(["\\Windows\\System32\\evil.sys"]), max_rounds=1)
    # findings.json carries no timestamps -> byte-identical across runs (headline invariant).
    assert (c2 / "findings.json").read_bytes() == f1


# (b) multi-finding: N distinct CONFIRMs, ONE chain, dedup holds.
def test_multi_finding_three_rounds_one_chain(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HEXBREAKER_HMAC_PASSWORD", "test-multi")
    case = _make_case(tmp_path, 4729)
    targets = [r"\A\1.sys", r"\B\2.sys", r"\C\3.sys"]
    run_court_on_case(case, client=FakeClient(targets), max_rounds=3)

    found = _findings(case)["findings"]
    assert sorted(f["target"] for f in found) == sorted(targets)  # 3 distinct findings

    tpath = case / "transcript.jsonl"
    assert verify(tpath)[0] is True  # single monotonic hash chain across 3 rounds
    from hexbreaker.court.hmac_chain import verify_signature
    assert verify_signature(tpath, password="test-multi").ok is True  # one signature over all


# (b2) dedup: a re-accused target on a later round does not inflate the count.
def test_dedup_repeated_target(tmp_path: Path):
    case = _make_case(tmp_path, 4729)
    # FakeClient repeats the last target once it exhausts the list.
    run_court_on_case(case, client=FakeClient([r"\X\dup.sys"]), max_rounds=3)
    found = _findings(case)["findings"]
    assert len(found) == 1  # repeated accusation -> exhaustion break, single finding


# (c) round>0 prompt is agent-authored continuation (no answer-key leakage).
def test_round2_prompt_lists_only_accused(tmp_path: Path):
    case = _make_case(tmp_path, 4729)
    fc = FakeClient([r"\A\1.sys", r"\B\2.sys"])
    run_court_on_case(case, client=fc, max_rounds=2)
    # The 2nd prosecutor prompt must name the round-1 accusation and ask for a different one.
    assert any("Already accused" in m and r"\A\1.sys" in m for m in fc.prosecutor_msgs)
    # And must never contain the withheld answer-key's expected target wording.
    ak = json.loads((case / "answer_key.json").read_bytes())
    expected_target = ak["expected_findings"][0]["target"]
    assert all(expected_target not in m for m in fc.prosecutor_msgs)


# (e) FSM re-enforced across two sessions on ONE transcript (no runner, pure FSM).
def test_two_sessions_one_transcript_fsm(tmp_path: Path):
    from hexbreaker.tools import run_tool

    t = Transcript.open(tmp_path / "t.jsonl")

    def mft(argv, cwd, timeout):
        return (0, b"Created0x10,Created0x30\n2017,2026\n", b"", 0.0)

    def yar(argv, cwd, timeout):
        return (0, b"evil.sys: HIT\n", b"", 0.0)

    for _ in range(2):  # two independent bouts on the same chain
        pre = run_tool(t, "MFTECmd", ["-f"], runner=mft)
        s = CourtSession(t)
        claim = json.dumps({"text": "x", "artifact_kind": "timestomp", "target": "evil.sys",
                            "cited_steps": [{"step_id": pre.step_id, "stdout_hash": pre.stdout_hash}]})
        assert s.submit_claim(claim).claim is not None  # R1 re-enforced (fresh AWAITING_CLAIM)
        y = s.observe_tool("yara", ["evil.sys"], runner=yar)
        v = json.dumps({"verdict": "CONFIRMED",
                        "cited_steps": [{"step_id": pre.step_id, "stdout_hash": pre.stdout_hash},
                                        {"step_id": y.step_id, "stdout_hash": y.stdout_hash}],
                        "challenge_text": "ok"})
        assert s.submit_verdict(v).accepted is True

    recs = list(read(t.path))
    ids = [r.step_id for r in recs]
    assert ids == [f"S-{i:03d}" for i in range(1, len(recs) + 1)]  # contiguous across sessions
    assert verify(t.path)[0] is True


# (f) CONTESTED surfaces as an inferred_not_confirmed row — shown, never scored as TP.
def test_contested_surfaces_as_inferred(tmp_path: Path):
    case = _make_case(tmp_path, 4729)
    # cite_n_tools=1 -> JR-01 downgrades CONFIRMED to CONTESTED at runtime.
    run_court_on_case(case, client=FakeClient([r"\Windows\System32\evil.sys"], cite_n_tools=1),
                      max_rounds=1)
    payload = _findings(case)
    assert payload["findings"] == []                       # nothing CONFIRMED -> 0 TP
    inf = payload.get("inferred", [])
    assert len(inf) == 1 and inf[0]["status"] == "inferred_not_confirmed"
    assert inf[0]["verdict"] == "CONTESTED"
    assert inf[0]["target"] == r"\Windows\System32\evil.sys"


# (g) a CONFIRMED-only run OMITS the `inferred` key entirely (byte-identity invariant).
def test_confirmed_only_omits_inferred_key(tmp_path: Path):
    case = _make_case(tmp_path, 4729)
    run_court_on_case(case, client=FakeClient([r"\Windows\System32\evil.sys"]), max_rounds=1)
    payload = _findings(case)
    assert len(payload["findings"]) == 1
    assert "inferred" not in payload  # omit-when-empty -> findings.json byte-identical
