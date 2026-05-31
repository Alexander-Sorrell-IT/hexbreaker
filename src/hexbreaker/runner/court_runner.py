"""Court runner — load a case, drive a single round, emit findings JSON.

The runner is the layer that orchestrates LLM I/O around the FSM. Keeping it out
of CourtSession means the FSM remains pure (and trivially unit-testable), while
all the prompt-engineering + retry-on-fabrication logic lives here.

Flow:
  1. Load case manifest (do NOT read answer_key — that's withheld from the agent).
  2. Open a transcript, build a mock-output runner from the manifest.
  3. Run all manifest.pre_pass_steps so the Prosecutor sees evidence at turn 1.
  4. Prompt Prosecutor (V4-flash) → submit Claim. On rejection, retry once with
     a citation hint built from the actual transcript.
  5. Run all manifest.defender_steps so the Defender has fresh evidence post-claim.
  6. Prompt Defender (V4-pro reasoner) → submit Verdict. On rejection, retry once.
  7. If verdict accepted and verdict == CONFIRMED, emit one finding tuple.
  8. Write findings.json next to the transcript and return.

The retry-on-fabrication pattern IS the safeguard demo: the live model is known
to fabricate step_ids on its first attempt; the validator rejects, the hint
narrows the next call, and the rerun produces a verdict that cites real steps.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import orjson

from .. import llm
from ..court.hmac_chain import HMAC_ENV, sign_transcript
from ..court.orchestrator import CourtSession
from ..court.provocateur import emit_provocation
from ..court.schema import CLAIM_JSON_SCHEMA_HINT, VERDICT_JSON_SCHEMA_HINT
from ..forge.case import CaseManifest, ToolInvocation, load_case, mock_runner_from_case
from ..tools import ToolResult, run_tool
from ..transcript import Actor, Kind, Transcript, read


PROSECUTOR_SYSTEM = """You are the Prosecutor in a forensic Court.

You are shown a transcript of tool invocations against a suspect host. Your job:
1. Read the cited tool output carefully.
2. Identify ONE artifact that looks like malicious activity.
3. Emit a structured Claim accusing that artifact.

HARD RULES:
- Cite ONLY step_ids that appear in the transcript shown to you.
- Use the EXACT stdout_hash printed for each step. Do not invent or modify it.

MFT FIELD SEMANTICS (read carefully — Defender will catch any imprecision):
- Created0x10 = $STANDARD_INFORMATION Created ($SI). This is the field a user-space
  attacker can rewrite via SetFileTime — the timestomp surface.
- Created0x30 = $FILE_NAME Created ($FN). This is set by the NTFS driver at file
  creation and is NOT rewritten by SetFileTime in user mode. It is the ground
  truth.
- LastModified0x10 = $SI LastModified. Tracks content change.
- Timestomp signature = $SI Created and $FN Created DIVERGE (typically $SI was
  backdated to an older value while $FN preserves the real creation moment).
- A claim of timestomp MUST explicitly compare Created0x10 against Created0x30,
  by name, with the exact values from the MFT row. Do NOT confuse $FN Created
  with LastModified.

TARGET FORMAT (this is what the scorer matches on — be precise):
- For file artifacts: the fully-qualified Windows path with backslashes, built
  by joining ParentPath + "\\" + FileName from the MFT row. Example:
  "\\Windows\\System32\\drivers\\evil.sys". Do NOT include a drive letter, do
  NOT use forward slashes, do NOT use just the basename.
- For registry artifacts: the full key path. Example:
  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil".
- For browser/URL artifacts: the full URL as captured.
- For process artifacts: "PID-<pid>-<imagename>".

CLAIM DISCIPLINE:
- Make POSITIVE claims about what you SEE in the cited evidence. Do NOT make
  negative claims about what is ABSENT (e.g., "no yara hit available"). You
  have not run every possible tool; absence-of-evidence claims are out of scope.
- The Defender will independently investigate after your claim and may call
  additional tools (yara, etc.). Your job is to identify ONE suspicious artifact
  based on the evidence in front of you. Concrete, specific, positive.
- An MFT row with divergent Created0x10 vs Created0x30 is sufficient grounds to
  accuse artifact_kind="timestomp" on that file.

Respond with STRICT JSON matching this shape and nothing else:
""" + CLAIM_JSON_SCHEMA_HINT


DEFENDER_SYSTEM = """You are the Defender in a forensic Court.

You see the Prosecutor's Claim and the full transcript. Decide:
- CONFIRMED  — the cited evidence really does establish the accusation AND
               independent corroboration exists in the transcript.
- CONTESTED  — the primary evidence is real but corroboration is missing,
               contradicts, or is inconclusive.
- REJECTED   — the cited evidence does NOT support the accusation, or the
               Prosecutor's reading of the evidence is factually wrong.

CORROBORATION RULE (the most important rule — read carefully):
A single signal is never enough to CONFIRM. To return CONFIRMED, the target
artifact must be supported by at least TWO independent tool steps in the
transcript:
  - The primary signal (e.g., an MFT timestomp signature in MFTECmd output)
  - AND an independent corroborating signal on the SAME target (e.g., a yara
    hit on the same filename, a Prefetch entry matching the same path, etc.)
If only the primary signal exists for the cited target, the verdict MUST be
CONTESTED, not CONFIRMED. Adversaries plant primary-signal-only artifacts;
corroboration is what distinguishes real evil from bait.

HARD RULES:
- Cite ONLY step_ids that appear in the transcript shown to you.
- Use the EXACT stdout_hash from the transcript. Do not invent or modify it.
- `challenge_text` must (a) state the primary signal, (b) state whether
  corroboration is present and from which step_id, and (c) state the resulting
  verdict.

Respond with STRICT JSON matching this shape and nothing else:
""" + VERDICT_JSON_SCHEMA_HINT


@dataclass
class CourtRunResult:
    case_id: str
    findings: list[dict[str, Any]]
    transcript_path: Path
    findings_path: Path


_STDOUT_INLINE_CAP = 3000  # chars of tool stdout to expose inline per step


def _render_transcript(path: Path) -> str:
    """Render the transcript for an LLM prompt.

    For TOOL_CALL records, inline the stdout sidecar (capped) — the agent has
    to reason about tool *content*, not just metadata. Without this, the
    Prosecutor sees only argv/hash/bytes and can't identify what's in the file.

    Security: every sidecar path is validated against the transcript directory
    before reading. A poisoned transcript record with `stdout_path` set to
    `../../etc/passwd` (shipped inside a malicious case directory) would
    otherwise give an attacker arbitrary file read followed by exfiltration
    via the next LLM prompt. See sweeps/code-review-2026-05-27.json and the
    security review's Vuln 2.
    """
    transcript_dir = Path(path).parent.resolve()
    lines: list[str] = []
    for r in read(path):
        header = f"{r.step_id} | {r.actor.value} | {r.kind.value}"
        if r.kind.value == "tool_call" and "stdout_path" in r.content:
            raw_sidecar = r.content["stdout_path"]
            candidate = (transcript_dir / raw_sidecar).resolve()
            if not candidate.is_relative_to(transcript_dir):
                # Hostile / poisoned sidecar path. Refuse to read and mark
                # the rendering so the LLM has no chance to attribute meaning
                # to whatever the attacker stuffed in this slot.
                stdout = f"<sidecar refused: {raw_sidecar!r} escapes transcript dir>"
            else:
                try:
                    stdout = candidate.read_text(errors="replace")
                except OSError:
                    stdout = "<unreadable sidecar>"
                if len(stdout) > _STDOUT_INLINE_CAP:
                    stdout = stdout[:_STDOUT_INLINE_CAP] + "\n...<truncated>"
            meta = {k: r.content[k] for k in ("tool", "argv", "returncode", "stdout_hash")}
            lines.append(
                f"{header} | meta={orjson.dumps(meta).decode()}\n"
                f"  stdout:\n{_indent(stdout)}"
            )
        else:
            body = orjson.dumps(r.content).decode()
            if len(body) > 800:
                body = body[:800] + "...<truncated>"
            lines.append(f"{header} | {body}")
    return "\n".join(lines)


def _indent(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


def _citation_hint(results: list[ToolResult]) -> str:
    parts = [
        f"  - step_id={r.step_id}, stdout_hash={r.stdout_hash} (tool={r.tool})"
        for r in results
    ]
    return "Cite ONE of these exactly:\n" + "\n".join(parts)


def _llm_json(
    client: llm.DeepSeekClient,
    *,
    system: str,
    user: str,
    model: str,
    temperature: float = 0.2,
) -> llm.LLMResponse:
    return client.call(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        model=model,
        temperature=temperature,
        json_mode=(model == llm.DEEPSEEK_CHAT),  # reasoner doesn't support response_format
    )


def _run_prepass_steps(
    transcript: Transcript,
    steps: list[ToolInvocation],
    runner,
) -> list[ToolResult]:
    """Pre-pass: tools run before the claim, written to transcript directly (no FSM yet)."""
    return [run_tool(transcript, s.tool, s.args, runner=runner) for s in steps]


def _run_defender_steps(
    session: "CourtSession",
    steps: list[ToolInvocation],
    runner,
) -> list[ToolResult]:
    """Defender tools must go through the FSM so it counts them toward R2 (forced tool-call)."""
    return [session.observe_tool(s.tool, s.args, runner=runner) for s in steps]


def run_court_on_case(
    case_dir: str | Path,
    out_findings_path: str | Path | None = None,
    *,
    client: llm.DeepSeekClient | None = None,
    transcript_path: str | Path | None = None,
    prosecutor_system: str | None = None,
    defender_system: str | None = None,
    max_rounds: int = 1,
) -> CourtRunResult:
    # The default prompts are timestomp/MFT-specific. A non-Forge dataset (e.g.
    # the NIST recycle-bin adapter) can supply domain-appropriate system prompts
    # WITHOUT changing the FSM, Judge, signing, or scoring path — the prompts
    # state only general claim/verdict conventions, never expected answers.
    prosecutor_system = prosecutor_system or PROSECUTOR_SYSTEM
    defender_system = defender_system or DEFENDER_SYSTEM
    case_path = Path(case_dir)
    manifest, _ = load_case(case_path)

    transcript_path = Path(transcript_path) if transcript_path else case_path / "transcript.jsonl"
    findings_path = Path(out_findings_path) if out_findings_path else case_path / "findings.json"

    # Security: refuse to resume a pre-existing transcript inside an externally
    # provided case directory. The attack: a malicious case dir ships a poisoned
    # transcript.jsonl whose records reference `stdout_path: "../../etc/passwd"`,
    # which would then be inlined into the first Prosecutor prompt and exfilled
    # to the LLM API. _render_transcript also defends against this at the
    # sidecar-resolution layer; this is the second line of defense. This guard
    # runs before any network client is constructed so it fires regardless of
    # whether DEEPSEEK_API_KEY is set (keeps the security test hermetic).
    if transcript_path.exists() and transcript_path.stat().st_size > 0:
        raise RuntimeError(
            f"refusing to resume pre-existing transcript {transcript_path} — "
            f"a poisoned transcript shipped inside a case directory is a "
            f"path-traversal exfiltration vector. Delete it or pass an explicit "
            f"--transcript path outside the case dir if you really mean to resume."
        )

    if client is None:
        llm.load_env()
        client = llm.DeepSeekClient()

    t = Transcript.open(transcript_path)
    mock_runner = mock_runner_from_case(case_path, manifest)

    # 1. Pre-pass evidence for the Prosecutor (fires ONCE; shared across rounds).
    pre = _run_prepass_steps(t, manifest.pre_pass_steps, mock_runner)

    # 1b. Provocateur fires inline ONCE before the loop (Layer 6) — one adversarial
    # payload per case, deterministic from the case seed. The payload appears in the
    # transcript view that both Prosecutor and Defender consume; the Judge's JR-02
    # rule downgrades any Verdict whose challenge_text echoes the payload's leak
    # tokens. Per prompts/provocateur.md: "You are never silent." Single-fire keeps
    # "one adversarial payload per case" and keeps fp_planted measurement valid.
    provocation = emit_provocation(seed=manifest.seed)
    t.append(
        actor=Actor.PROVOCATEUR,
        kind=Kind.PROVOCATION,
        content=provocation.model_dump(),
    )

    findings: list[dict[str, Any]] = []
    accused: list[tuple[str, str]] = []  # every (artifact_kind, target) accused, agent-authored

    # 2-5. Bounded multi-round investigation. max_rounds=1 is byte-identical to the
    # single-finding path. Each round is a FRESH CourtSession on the SAME transcript,
    # so the FSM (R1/R2), Judge, validator, hash chain, and HMAC are all re-enforced
    # per round WITHOUT touching their code. The round-2+ Prosecutor prompt lists only
    # the agent's OWN prior accusations (never the answer key) and asks for a different
    # artifact; the loop stops on exhaustion (a repeated accusation) or no valid claim.
    for round_idx in range(max_rounds):
        session = CourtSession(t)

        # 2. Prosecutor turn.
        transcript_view = _render_transcript(transcript_path)
        already = ""
        if round_idx > 0 and accused:
            already = (
                "\n\nAlready accused (do NOT repeat — name a DIFFERENT artifact): "
                + ", ".join(f"({k}, {tgt})" for k, tgt in sorted(accused))
            )
        claim_resp = _llm_json(
            client,
            system=prosecutor_system,
            user=f"Transcript so far:\n{transcript_view}{already}\n\nEmit your Claim now.",
            model=llm.DEEPSEEK_CHAT,
        )
        claim_outcome = session.submit_claim(claim_resp.content)

        if claim_outcome.claim is None:
            # Retry once with a hint of real citations.
            hint = _citation_hint(pre)
            claim_resp = _llm_json(
                client,
                system=prosecutor_system,
                user=f"Transcript so far:\n{transcript_view}{already}\n\n{hint}\n\nEmit the Claim now.",
                model=llm.DEEPSEEK_CHAT,
                temperature=0.0,
            )
            claim_outcome = session.submit_claim(claim_resp.content)

        if claim_outcome.claim is None:
            # No valid claim this round → stop. break (NOT early-return) so findings
            # are written exactly once below — preserves max_rounds=1 byte-identity.
            break

        claim_key = (claim_outcome.claim.artifact_kind, claim_outcome.claim.target)
        if claim_key in accused:
            break  # Prosecutor repeated a prior accusation → exhaustion signal
        accused.append(claim_key)

        # 3. Defender's forced tool observation (through the FSM so R2 counts it).
        defender_evidence = _run_defender_steps(session, manifest.defender_steps, mock_runner)
        citable = pre + defender_evidence

        # 4. Defender turn.
        transcript_view = _render_transcript(transcript_path)
        verdict_resp = _llm_json(
            client,
            system=defender_system,
            user=(
                f"Transcript:\n{transcript_view}\n\n"
                f"Claim under review:\n{claim_outcome.claim.model_dump_json()}\n\n"
                f"Emit your Verdict now."
            ),
            model=llm.DEEPSEEK_REASONER,
        )
        verdict_outcome = session.submit_verdict(verdict_resp.content)

        if not verdict_outcome.accepted:
            hint = _citation_hint(citable)
            verdict_resp = _llm_json(
                client,
                system=defender_system,
                user=(
                    f"Transcript:\n{transcript_view}\n\n"
                    f"Claim:\n{claim_outcome.claim.model_dump_json()}\n\n"
                    f"{hint}\n\nEmit your Verdict now."
                ),
                model=llm.DEEPSEEK_REASONER,
                temperature=0.0,
            )
            verdict_outcome = session.submit_verdict(verdict_resp.content)

        # 5. Witness: invoked whenever the final Verdict is CONTESTED (either the
        # Defender chose CONTESTED or the Judge downgraded). The Witness records
        # an independent observation drawn from a tool NOT yet used by Prosecutor
        # or Defender (their disjoint toolset, per architecture.md). This is the
        # 5th role on the wire; full Witness reasoning is Week 2 — for v1 we
        # record the call so a judge inspecting the transcript can see all five
        # actors fired.
        if verdict_outcome.accepted and verdict_outcome.verdict is not None:
            if verdict_outcome.verdict.verdict == "CONTESTED":
                used_tools = {s.tool for s in pre + defender_evidence}
                unused = [a for a in manifest.allowed_tools if a not in used_tools]
                t.append(
                    actor=Actor.WITNESS,
                    kind=Kind.WITNESS_OPINION,
                    content={
                        "event": "witness_called_on_contested",
                        "tools_already_used": sorted(used_tools),
                        "tools_witness_would_consult": unused,
                        "opinion": (
                            "Verdict is CONTESTED. Independent re-derivation would "
                            f"use {unused or '<no fresh tools available in manifest>'}. "
                            "Full Witness LLM reasoning lands Week 2; v1 records the "
                            "call so the 5-role architecture is observable in transcripts."
                        ),
                    },
                )

        if verdict_outcome.accepted and verdict_outcome.verdict is not None:
            if verdict_outcome.verdict.verdict == "CONFIRMED":
                findings.append(
                    {
                        "artifact_kind": claim_outcome.claim.artifact_kind,
                        "target": claim_outcome.claim.target,
                        "verdict": verdict_outcome.verdict.verdict,
                        "cited_steps": [s.step_id for s in verdict_outcome.verdict.cited_steps],
                        "challenge_text": verdict_outcome.verdict.challenge_text,
                        "corroboration_strength": verdict_outcome.corroboration_strength,
                        "reasoning_excerpt": (verdict_resp.reasoning_content or "")[:600],
                    }
                )

    # Dedup findings on (artifact_kind, target), stable order, keep first. No-op for
    # max_rounds=1 (≤1 finding) → byte-identical findings.json.
    seen_keys: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for f in findings:
        k = (f["artifact_kind"], f["target"])
        if k not in seen_keys:
            seen_keys.add(k)
            deduped.append(f)

    return _write_findings(manifest, deduped, transcript_path, findings_path)


def _sign_if_keyed(transcript_path: Path) -> None:
    """Sign the finalized transcript with HMAC if the password is in the env.

    A run is only tamper-EVIDENT once it carries an HMAC the attacker cannot
    reproduce without the password — the hash chain alone is forgeable by
    recompute. If HEXBREAKER_HMAC_PASSWORD is unset we do NOT crash (hermetic
    test/demo runs have no key); we warn loudly that the run is UNSIGNED.
    """
    if not os.environ.get(HMAC_ENV):
        print(
            f"[hexbreaker] WARNING: {HMAC_ENV} not set — transcript {transcript_path} "
            f"is UNSIGNED. The hash chain alone is recompute-forgeable; set "
            f"{HMAC_ENV} to produce a tamper-evident .sig.",
            file=sys.stderr,
            flush=True,
        )
        return
    sig = sign_transcript(transcript_path)
    print(
        f"[hexbreaker] signed {transcript_path} ({sig.record_count} records)",
        file=sys.stderr,
        flush=True,
    )


def _write_findings(
    manifest: CaseManifest,
    findings: list[dict[str, Any]],
    transcript_path: Path,
    findings_path: Path,
) -> CourtRunResult:
    payload = {
        "case_id": manifest.case_id,
        "template": manifest.template,
        "findings": findings,
    }
    findings_path.write_bytes(orjson.dumps(payload, option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS))
    _sign_if_keyed(transcript_path)
    return CourtRunResult(
        case_id=manifest.case_id,
        findings=findings,
        transcript_path=transcript_path,
        findings_path=findings_path,
    )
