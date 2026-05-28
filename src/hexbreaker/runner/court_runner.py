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

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import orjson

from .. import llm
from ..court.orchestrator import CourtSession
from ..court.schema import CLAIM_JSON_SCHEMA_HINT, VERDICT_JSON_SCHEMA_HINT
from ..forge.case import CaseManifest, ToolInvocation, load_case, mock_runner_from_case
from ..tools import ToolResult, run_tool
from ..transcript import Transcript, read


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
    """
    transcript_dir = Path(path).parent
    lines: list[str] = []
    for r in read(path):
        header = f"{r.step_id} | {r.actor.value} | {r.kind.value}"
        if r.kind.value == "tool_call" and "stdout_path" in r.content:
            sidecar = transcript_dir / r.content["stdout_path"]
            try:
                stdout = sidecar.read_text(errors="replace")
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
) -> CourtRunResult:
    case_path = Path(case_dir)
    manifest, _ = load_case(case_path)

    if client is None:
        llm.load_env()
        client = llm.DeepSeekClient()

    transcript_path = Path(transcript_path) if transcript_path else case_path / "transcript.jsonl"
    findings_path = Path(out_findings_path) if out_findings_path else case_path / "findings.json"

    t = Transcript.open(transcript_path)
    session = CourtSession(t)
    mock_runner = mock_runner_from_case(case_path, manifest)

    # 1. Pre-pass evidence for the Prosecutor.
    pre = _run_prepass_steps(t, manifest.pre_pass_steps, mock_runner)

    # 2. Prosecutor turn.
    transcript_view = _render_transcript(transcript_path)
    claim_resp = _llm_json(
        client,
        system=PROSECUTOR_SYSTEM,
        user=f"Transcript so far:\n{transcript_view}\n\nEmit your Claim now.",
        model=llm.DEEPSEEK_CHAT,
    )
    claim_outcome = session.submit_claim(claim_resp.content)

    if claim_outcome.claim is None:
        # Retry once with a hint of real citations.
        hint = _citation_hint(pre)
        claim_resp = _llm_json(
            client,
            system=PROSECUTOR_SYSTEM,
            user=f"Transcript so far:\n{transcript_view}\n\n{hint}\n\nEmit the Claim now.",
            model=llm.DEEPSEEK_CHAT,
            temperature=0.0,
        )
        claim_outcome = session.submit_claim(claim_resp.content)

    if claim_outcome.claim is None:
        return _write_findings(manifest, [], transcript_path, findings_path)

    # 3. Defender's forced tool observation (through the FSM so R2 counts it).
    defender_evidence = _run_defender_steps(session, manifest.defender_steps, mock_runner)
    citable = pre + defender_evidence

    # 4. Defender turn.
    transcript_view = _render_transcript(transcript_path)
    verdict_resp = _llm_json(
        client,
        system=DEFENDER_SYSTEM,
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
            system=DEFENDER_SYSTEM,
            user=(
                f"Transcript:\n{transcript_view}\n\n"
                f"Claim:\n{claim_outcome.claim.model_dump_json()}\n\n"
                f"{hint}\n\nEmit your Verdict now."
            ),
            model=llm.DEEPSEEK_REASONER,
            temperature=0.0,
        )
        verdict_outcome = session.submit_verdict(verdict_resp.content)

    findings: list[dict[str, Any]] = []
    if verdict_outcome.accepted and verdict_outcome.verdict is not None:
        if verdict_outcome.verdict.verdict == "CONFIRMED":
            findings.append(
                {
                    "artifact_kind": claim_outcome.claim.artifact_kind,
                    "target": claim_outcome.claim.target,
                    "verdict": verdict_outcome.verdict.verdict,
                    "cited_steps": [s.step_id for s in verdict_outcome.verdict.cited_steps],
                    "challenge_text": verdict_outcome.verdict.challenge_text,
                    "reasoning_excerpt": (verdict_resp.reasoning_content or "")[:600],
                }
            )

    return _write_findings(manifest, findings, transcript_path, findings_path)


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
    return CourtRunResult(
        case_id=manifest.case_id,
        findings=findings,
        transcript_path=transcript_path,
        findings_path=findings_path,
    )
