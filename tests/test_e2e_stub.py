"""End-to-end stub: real DeepSeek + real FSM + fake tool output.

This is the integration test that proves Tuesday's pieces (transcript, tools,
llm) compose correctly with Wednesday's pieces (schema, validator, orchestrator)
under a live model. Skipped by default — set HEXBREAKER_RUN_LIVE=1 to run.

Why this is also useful as a demo seed:
The reasoner is known (from the 2026-05-26 smoke test) to fabricate step_ids
when given a forensic prompt. The CourtSession validator catches that
fabrication in code. If the live Defender's first attempt cites a fake step_id,
the test still passes — the rejection is exactly the behavior we're proving.
"""

from __future__ import annotations

import os
from pathlib import Path

import orjson
import pytest

from hexbreaker import llm
from hexbreaker.court.orchestrator import CourtSession, State
from hexbreaker.court.schema import CLAIM_JSON_SCHEMA_HINT, VERDICT_JSON_SCHEMA_HINT
from hexbreaker.transcript import Transcript, verify


pytestmark = pytest.mark.skipif(
    os.environ.get("HEXBREAKER_RUN_LIVE") != "1",
    reason="live API e2e — set HEXBREAKER_RUN_LIVE=1 to run",
)


def _fake_runner(stdout: bytes):
    def run(_argv, _cwd, _timeout):
        return 0, stdout, b"", 0.01
    return run


PROSECUTOR_SYSTEM = """You are the Prosecutor in a Court for digital forensics.
You will be shown one transcript step (the output of a SIFT forensic tool) and
must emit a single Claim accusing the host of an evil action that this output
supports.

CRITICAL: cite ONLY step_ids that appear in the transcript shown to you. Do not
invent step_ids. If you are uncertain, cite the one real step you have.

Emit STRICT JSON matching this shape:
""" + CLAIM_JSON_SCHEMA_HINT


DEFENDER_SYSTEM = """You are the Defender in a Court for digital forensics.
You will be shown a Claim from the Prosecutor and the transcript so far. Your
job is to either CONFIRM, CONTEST, or REJECT the claim based on the evidence.

CRITICAL: cite ONLY step_ids that appear in the transcript. Do not invent
step_ids. Do not invent tool outputs. Cite the real step_id and the real
stdout_hash from the transcript shown to you.

Emit STRICT JSON matching this shape:
""" + VERDICT_JSON_SCHEMA_HINT


def test_live_end_to_end_court_round(tmp_path: Path) -> None:
    """Drive: tool -> Prosecutor claim -> Defender verdict, with the real model."""
    llm.load_env(Path(__file__).resolve().parent.parent / ".env")
    client = llm.DeepSeekClient()

    path = tmp_path / "run.jsonl"
    t = Transcript.open(path)
    session = CourtSession(t)

    # 1. Run a fake tool BEFORE the claim so the prosecutor has something to cite.
    fake_stdout = (
        b"MFTECmd output:\n"
        b"FN: C:\\Windows\\System32\\drivers\\suspicious.sys\n"
        b"$SI Created: 2019-01-15T10:23:11Z\n"
        b"$FN Created: 2025-11-04T22:18:43Z\n"
        b"NOTE: $SI/$FN divergence suggests timestomping.\n"
    )
    tool_result = _run_evidence_tool(t, fake_stdout)

    # 2. Prosecutor turn — emit a Claim citing the real step.
    transcript_view = _render_transcript(path)
    claim_resp = client.call(
        [
            {"role": "system", "content": PROSECUTOR_SYSTEM},
            {"role": "user", "content": f"Transcript so far:\n{transcript_view}\n\nEmit your Claim."},
        ],
        model=llm.DEEPSEEK_CHAT,
        temperature=0.2,
        json_mode=True,
    )
    claim_outcome = session.submit_claim(claim_resp.content)
    # Either the claim was accepted, or the validator caught a fabrication —
    # both prove the system works. Retry once with a heavy hint if rejected.
    if claim_outcome.claim is None:
        hint = (
            f"The only real step is {tool_result.step_id} with stdout_hash "
            f"{tool_result.stdout_hash}. Use exactly these values."
        )
        claim_resp2 = client.call(
            [
                {"role": "system", "content": PROSECUTOR_SYSTEM},
                {"role": "user", "content": f"Transcript:\n{transcript_view}\n\n{hint}\n\nEmit the Claim now."},
            ],
            model=llm.DEEPSEEK_CHAT,
            temperature=0.0,
            json_mode=True,
        )
        claim_outcome = session.submit_claim(claim_resp2.content)

    assert claim_outcome.claim is not None, claim_outcome.result.issues
    assert session.state == State.AWAITING_TOOL

    # 3. Defender's tool observation — confirm via yara that the signature checks out.
    yara_out = b"suspicious.sys: APT_DRIVER_HEURISTIC\n"
    yara_result = session.observe_tool("yara", ["rules.yar", "suspicious.sys"], runner=_fake_runner(yara_out))

    # 4. Defender turn — emit a Verdict citing the real step. Reasoner is V4-pro.
    transcript_view = _render_transcript(path)
    verdict_resp = client.call(
        [
            {"role": "system", "content": DEFENDER_SYSTEM},
            {"role": "user", "content": f"Transcript:\n{transcript_view}\n\nClaim:\n{claim_outcome.claim.model_dump_json()}\n\nEmit your Verdict."},
        ],
        model=llm.DEEPSEEK_REASONER,
        temperature=0.2,
    )
    # Defender reasoning_content should be present — that's the visible CoT we'll use for the demo.
    assert verdict_resp.reasoning_content is not None
    assert len(verdict_resp.reasoning_content) > 50

    verdict_outcome = session.submit_verdict(verdict_resp.content)
    # As with the claim: accept the verdict or, if fabricated, demonstrate the safeguard
    # and retry with a stronger hint.
    if not verdict_outcome.accepted:
        hint = (
            f"Real step ids: {tool_result.step_id} (MFT), {yara_result.step_id} (yara). "
            f"Hashes: MFT={tool_result.stdout_hash}, yara={yara_result.stdout_hash}. "
            f"Cite at least one of these exactly."
        )
        verdict_resp2 = client.call(
            [
                {"role": "system", "content": DEFENDER_SYSTEM},
                {"role": "user", "content": f"Transcript:\n{transcript_view}\n\nClaim:\n{claim_outcome.claim.model_dump_json()}\n\n{hint}\n\nEmit your Verdict now."},
            ],
            model=llm.DEEPSEEK_REASONER,
            temperature=0.0,
        )
        verdict_outcome = session.submit_verdict(verdict_resp2.content)

    assert verdict_outcome.accepted, verdict_outcome.result.issues
    assert session.state == State.VERDICT_ACCEPTED

    # 5. The whole transcript must hash-chain-validate.
    ok, reason = verify(path)
    assert ok, reason


def _run_evidence_tool(transcript: Transcript, stdout: bytes):
    from hexbreaker.tools import run_tool
    return run_tool(
        transcript,
        "MFTECmd",
        ["-f", "/case/MFT"],
        runner=lambda *_: (0, stdout, b"", 0.01),
    )


def _render_transcript(path: Path) -> str:
    """Render the transcript as a compact view suitable for an LLM prompt."""
    from hexbreaker.transcript import read

    lines: list[str] = []
    for r in read(path):
        lines.append(
            f"{r.step_id} | {r.actor.value} | {r.kind.value} | "
            f"{orjson.dumps(r.content).decode()[:400]}"
        )
    return "\n".join(lines)
