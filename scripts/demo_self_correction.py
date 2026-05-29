"""Replayable self-correction demonstration (committed artifact for criterion 1).

Runs the REAL Court pipeline (CourtSession FSM + deterministic Judge, no LLM, no
network) to show the architectural self-correction in action: a Defender that
CONFIRMS an accusation on a single signal — exactly the Provocateur bait-taking
failure mode — is overridden at runtime by the deterministic Judge (JR-01
corroboration) and downgraded to CONTESTED, so no finding is emitted.

This is deterministic and fully replayable:

    PYTHONPATH=src python scripts/demo_self_correction.py

It writes a hash-chained, HMAC-signed transcript to
samples/self_correction/transcript.jsonl and verifies both layers. Unlike a
narrated anecdote, every step here is a committed, re-derivable artifact.
"""
from __future__ import annotations

import json
from pathlib import Path

from hexbreaker.transcript import Transcript, read
from hexbreaker.tools import run_tool
from hexbreaker.court.orchestrator import CourtSession
from hexbreaker.court.hmac_chain import sign_transcript, verify_signature
from hexbreaker.transcript import verify as verify_chain

OUT = Path("samples/self_correction")
TARGET = r"\Windows\System32\drivers\tcpipsvc.sys"
PASSWORD = "demo-self-correction"  # demo-only; real runs use $HEXBREAKER_HMAC_PASSWORD


def _mft_runner(argv, cwd, timeout):
    out = (
        b"Created0x10,Created0x30,FileName\n"
        b"2017-01-02 03:04:05,2026-02-03 04:05:06," + TARGET.encode() + b"\n"
    )
    return (0, out, b"", 0.01)


def _yara_runner(argv, cwd, timeout):
    return (0, b"" + TARGET.encode() + b": APT_DRIVER_HEURISTIC\n", b"", 0.01)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    tpath = OUT / "transcript.jsonl"
    if tpath.exists():
        tpath.unlink()
    outputs = OUT / "transcript.outputs"
    if outputs.exists():
        for f in outputs.iterdir():
            f.unlink()

    t = Transcript.open(tpath)
    # Pre-pass: MFTECmd produces the single $SI/$FN-divergence signal (S-001).
    pre = run_tool(t, "MFTECmd", ["-f", "/case/MFT", "--csv"], runner=_mft_runner)

    session = CourtSession(t)
    claim = json.dumps({
        "text": f"{TARGET} shows $SI/$FN timestamp divergence (timestomp)",
        "artifact_kind": "timestomp",
        "target": TARGET,
        "cited_steps": [{"step_id": pre.step_id, "stdout_hash": pre.stdout_hash}],
    })
    session.submit_claim(claim)

    # A corroborating tool IS available this turn (yara, S-003), satisfying R2 ...
    yara = session.observe_tool("yara", ["/rules/drivers.yar", TARGET], runner=_yara_runner)

    # ... but the Defender takes the bait: CONFIRMS citing ONLY the single MFT
    # signal (one distinct tool kind), ignoring the available corroboration.
    verdict = json.dumps({
        "verdict": "CONFIRMED",
        "cited_steps": [{"step_id": pre.step_id, "stdout_hash": pre.stdout_hash}],
        "challenge_text": "Single MFT signal looks decisive; confirming.",
        "confidence": 0.9,
    })
    outcome = session.submit_verdict(verdict)

    # Sign + verify both layers.
    sign_transcript(tpath, password=PASSWORD)
    chain_ok, chain_reason = verify_chain(tpath)
    sig = verify_signature(tpath, password=PASSWORD)

    final = outcome.verdict.verdict if outcome.verdict else None
    records = list(read(tpath))
    downgrade = next((r for r in records if r.content.get("event") == "judge_downgrade"), None)

    print("Defender emitted     : CONFIRMED (citing only S-001, a single tool kind)")
    print(f"Judge final verdict  : {final}")
    if downgrade:
        print(f"Self-correction      : {downgrade.content['rule_id']} downgraded "
              f"{downgrade.content['original_verdict']} -> {downgrade.content['final_verdict']}")
        print(f"  reason             : {downgrade.content['reason']}")
    print(f"Findings emitted     : {'0 (bait rejected)' if final != 'CONFIRMED' else '1'}")
    print(f"Chain verify         : ok={chain_ok} reason={chain_reason}")
    print(f"HMAC verify          : ok={sig.ok} (chain_ok={sig.chain_ok} hmac_ok={sig.hmac_ok})")

    ok = (final == "CONTESTED" and downgrade is not None and chain_ok and sig.ok
          and yara.step_id is not None)
    print("\nRESULT:", "PASS — runtime self-correction demonstrated + artifact verified"
          if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
