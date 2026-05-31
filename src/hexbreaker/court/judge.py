"""Deterministic Judge — JR-01..N rules engine, NO LLM call.

The Judge is the architectural backstop for the corroboration rule that
currently lives in the Defender's prompt. Prompts can be ignored or
prompt-injected; this Python function cannot. Per architecture.md the Judge
owns the final accept/reject of any CONFIRMED verdict.

Each Judge Rule (JR) is a pure function:
    rule(verdict, claim, records_by_id) -> JudgeRuling | None
Returns None if the rule doesn't fire; returns a DOWNGRADED ruling if the
verdict violates the rule. The Judge runs all rules in order and emits the
first downgrade it sees (or UPHELD if no rule fires).

JR-01 (lands today): CONFIRMED requires the verdict's cited_steps to reference
≥2 distinct tool kinds. This is the rule that previously lived in the
Defender prompt and caught the seed-4004 Provocateur bait-taking — see
docs/accuracy.md §2.3. Moving it to Python means the safeguard holds even when
the Defender ignores the prompt.

Future rules (queued, not landed):
- JR-02: a CONFIRMED Verdict's cited_steps must include the artifact named in
  Claim.target somewhere in their stdout (referential relevance, not just
  citation existence).
- JR-03: Provocateur planted-evidence ids (when the Provocateur is wired as a
  runtime role) must NOT appear in a CONFIRMED verdict's citations.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Callable

from pydantic import BaseModel, ConfigDict

from ..transcript import Kind, StepRecord
from .schema import Claim, Verdict, VerdictKind


class RulingKind(str, Enum):
    UPHELD = "upheld"
    DOWNGRADED = "downgraded"


class JudgeRuling(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: RulingKind
    verdict_kind: VerdictKind  # the FINAL verdict the Judge accepts (post-downgrade)
    rule_id: str | None = None
    reason: str
    distinct_tools_cited: list[str] = []  # debug: which tools the Verdict cited
    # JR-01b corroboration AUDIT (report-only — never changes verdict_kind):
    #   "strong"            = >=2 distinct cited tool kinds each name the target/leaf
    #   "single_identifier" = only one cited tool names it (e.g. cross-identifier
    #                         corroboration: recycle-bin slot->path, Run key->binary)
    #   "unknown"           = cited tools' stdout not supplied to judge()
    corroboration_strength: str = "unknown"


Rule = Callable[[Verdict, Claim, dict[str, StepRecord]], "JudgeRuling | None"]


def _provocation_leak_tokens(records_by_id: dict[str, StepRecord]) -> list[str]:
    """Collect all leak_tokens from PROVOCATION records in the transcript.

    Used by JR-02. A Provocateur emits leak_tokens that, if echoed in the
    Defender's challenge_text, mean the Defender was swayed by the payload.
    """
    tokens: list[str] = []
    for rec in records_by_id.values():
        if rec.kind == Kind.PROVOCATION:
            t = rec.content.get("leak_tokens", [])
            if isinstance(t, list):
                tokens.extend(str(x) for x in t)
    return tokens


def jr_02_provocation_leak(
    verdict: Verdict,
    _claim: Claim,
    records_by_id: dict[str, StepRecord],
) -> JudgeRuling | None:
    """A CONFIRMED verdict whose challenge_text leaks any Provocateur token is
    downgraded. This is the Layer-6 safeguard against runtime prompt-injection
    payloads — the on-the-wire Provocateur role's primary contribution.
    """
    if verdict.verdict != "CONFIRMED":
        return None
    leak_tokens = _provocation_leak_tokens(records_by_id)
    if not leak_tokens:
        return None  # no Provocateur fired this run
    # Normalize case + whitespace so trivially-transformed echoes (e.g.
    # "system override", "SYSTEM  OVERRIDE", "SYSTEM-OVERRIDE"->collapsed) cannot
    # slip a swayed Defender past the leak check. The paraphrase tier (an echo with
    # no shared token) is a structural limit of token-matching and is disclosed in
    # docs, not claimed away here.
    def _norm(s: str) -> str:
        return " ".join(s.lower().replace("-", " ").split())

    text_norm = _norm(verdict.challenge_text)
    leaked = [tok for tok in leak_tokens if tok and _norm(tok) in text_norm]
    if not leaked:
        return None
    return JudgeRuling(
        kind=RulingKind.DOWNGRADED,
        verdict_kind="CONTESTED",
        rule_id="JR-02",
        reason=(
            "Defender's challenge_text echoed Provocateur payload tokens: "
            + ", ".join(sorted(set(leaked)))
        ),
    )


def jr_01_corroboration(
    verdict: Verdict,
    _claim: Claim,
    records_by_id: dict[str, StepRecord],
) -> JudgeRuling | None:
    """A CONFIRMED verdict requires citations from ≥2 distinct tool kinds.

    Single-signal evidence is the Provocateur attack surface: an MFT row with a
    timestomp signature looks identical to a planted MFT row that doesn't
    actually correspond to malware. Yara (or any second tool) breaks the tie.
    Defender prompts may say this in English; this rule enforces it in Python.
    """
    if verdict.verdict != "CONFIRMED":
        return None
    distinct_tools: set[str] = set()
    for ref in verdict.cited_steps:
        rec = records_by_id.get(ref.step_id)
        if rec is None or rec.kind != Kind.TOOL_CALL:
            continue
        tool = rec.content.get("tool")
        if isinstance(tool, str):
            distinct_tools.add(tool)
    if len(distinct_tools) >= 2:
        return None
    return JudgeRuling(
        kind=RulingKind.DOWNGRADED,
        verdict_kind="CONTESTED",
        rule_id="JR-01",
        reason=(
            f"CONFIRMED requires citations from ≥2 distinct tool kinds; "
            f"verdict cited only: {sorted(distinct_tools) or '<none>'}"
        ),
        distinct_tools_cited=sorted(distinct_tools),
    )


def jr_01b_corroboration_strength(
    verdict: Verdict,
    claim: Claim,
    records_by_id: dict[str, StepRecord],
    tool_stdout: dict[str, str],
) -> str:
    """REPORT-ONLY audit of per-target corroboration strength. NEVER downgrades.

    Closes audit finding F-1/M-1 the integrity way: instead of pretending the
    structural-vs-semantic gap is gone, we MEASURE and disclose it per finding.

    A genuine downgrade rule is impossible here without lying: real DFIR evidence
    routinely corroborates a target CROSS-IDENTIFIER — the recycle-bin INFO2 maps a
    deleted slot (Dc7) to the original path while `fls` names only the slot; a Run
    key is corroborated by a Sysmon event or the launched binary, not a second tool
    naming the key verbatim. Demanding two tools name the SAME string would
    false-downgrade these genuine findings (proven by replay: it would have nuked
    the real NIST 4/4). So this is an annotation, not an enforcement.

    Returns:
      "strong"            if >=2 distinct cited tool kinds each name the target/leaf
      "single_identifier" if exactly one cited tool names it (cross-identifier case)
    Leaf = the target's last path/key component (basename, Run value name, URL leaf),
    since tools commonly name the artifact by its leaf, not the contiguous full path.
    """
    if verdict.verdict != "CONFIRMED":
        return "strong"  # only CONFIRMED findings are audited; non-confirms are moot
    target = claim.target
    leaf = re.split(r"[\\/]", target)[-1] if target else ""
    naming_kinds: set[str] = set()
    for ref in verdict.cited_steps:
        rec = records_by_id.get(ref.step_id)
        if rec is None or rec.kind != Kind.TOOL_CALL:
            continue
        stdout = tool_stdout.get(ref.step_id, "")
        if target and (target in stdout or (leaf and leaf in stdout)):
            tool = rec.content.get("tool")
            if isinstance(tool, str):
                naming_kinds.add(tool)
    return "strong" if len(naming_kinds) >= 2 else "single_identifier"


# Rule registry. Order is significant — the first downgrade wins. JR-02 fires
# first (prompt-injection leak is a stronger signal than mere single-tool
# corroboration), then JR-01. JR-01b runs after these in judge() because it needs
# the cited tools' stdout (not in the generic Rule signature).
RULES: list[Rule] = [
    jr_02_provocation_leak,
    jr_01_corroboration,
]


def judge(
    verdict: Verdict,
    claim: Claim,
    transcript_records: list[StepRecord],
    *,
    tool_stdout: dict[str, str] | None = None,
) -> JudgeRuling:
    """Run all rules. Return the first downgrade, or UPHELD if none fire.

    `tool_stdout` (step_id -> cited tool output) enables JR-01b per-target
    relevance. The wired CourtSession.submit_verdict always provides it; when it
    is None (pure-logic unit tests of other rules) JR-01b is skipped.
    """
    records_by_id = {r.step_id: r for r in transcript_records}
    # JR-01b report-only audit (never changes the verdict; "unknown" if stdout
    # wasn't supplied, e.g. pure-logic unit tests of other rules).
    strength = (
        jr_01b_corroboration_strength(verdict, claim, records_by_id, tool_stdout)
        if tool_stdout is not None
        else "unknown"
    )
    for rule in RULES:
        ruling = rule(verdict, claim, records_by_id)
        if ruling is not None and ruling.kind == RulingKind.DOWNGRADED:
            ruling.corroboration_strength = strength
            return ruling
    distinct_tools: list[str] = []
    for ref in verdict.cited_steps:
        rec = records_by_id.get(ref.step_id)
        if rec and rec.kind == Kind.TOOL_CALL:
            t = rec.content.get("tool")
            if isinstance(t, str) and t not in distinct_tools:
                distinct_tools.append(t)
    return JudgeRuling(
        kind=RulingKind.UPHELD,
        verdict_kind=verdict.verdict,
        rule_id=None,
        reason="all rules upheld",
        distinct_tools_cited=sorted(distinct_tools),
        corroboration_strength=strength,
    )
