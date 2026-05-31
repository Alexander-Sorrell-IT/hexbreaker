# Autonomy: an honest characterization (criterion C1)

Criterion 1 — **Autonomous Execution Quality** — asks, verbatim
([official rules](https://findevil.devpost.com/rules)):

> *"Does the agent reason about next steps, handle failures, and self-correct in real time?"*

This document answers each of those three sub-questions for Hexbreaker's Court,
and draws the boundary explicitly: **exactly where the LLM reasons, and exactly
where deterministic Python takes over.** We state the bounds ourselves rather
than wait for a skeptical judge to find them, because understating the autonomy
claim is the same discipline that the whole project exists to enforce — cite
only what the orchestrator can prove.

Everything below is grounded in the shipping code paths
(`src/hexbreaker/runner/court_runner.py`, `court/orchestrator.py`,
`court/judge.py`, `tools.py`, `forge/case.py`) and the committed sweep
`sweeps/2026-05-29_C2_multi.json`. Where a number is not measured, it says so.

---

## 1. The two-LLM-reasoning-point model

In the shipping runner (`run_court_on_case`, `court_runner.py`), an LLM is
invoked for reasoning at **exactly two points per Court bout**:

| # | Role | Model | What it reasons about | Code |
|---|---|---|---|---|
| 1 | **Prosecutor** | `deepseek-chat` | Read the rendered transcript; pick ONE suspicious artifact; emit a structured `Claim` citing real step_ids | `court_runner.py:307-313` (`_llm_json(... model=llm.DEEPSEEK_CHAT)`) |
| 2 | **Defender** | `deepseek-reasoner` | Read the Claim + transcript; decide CONFIRMED / CONTESTED / REJECTED; emit a `Verdict` citing real step_ids | `court_runner.py:343-353` (`model=llm.DEEPSEEK_REASONER`) |

**Everything else in a Court run is deterministic Python — no model call:**

- **Judge** (`court/judge.py`) — pure rule functions, no LLM. Its module
  docstring is explicit: *"Deterministic Judge ... NO LLM call."* The Judge owns
  the final accept/reject of any CONFIRMED verdict.
- **Provocateur** (`court/provocateur.py::emit_provocation`) — selects one of
  five fixed payloads via `random.Random(f"hexbreaker.provocateur:{seed}")`. It
  is seeded and deterministic; **no LLM is involved** in choosing or generating
  the payload.
- **Witness** (`court_runner.py:370-395`) — in the shipping runner this writes a
  **stub record**, not an LLM opinion. The code says so in-line: *"Full Witness
  LLM reasoning lands Week 2; v1 records the call so the 5-role architecture is
  observable in transcripts."* We do **not** claim the Witness reasons today.
- **Tool execution, hashing, step-ID allocation, hash chain, HMAC** — all
  deterministic (`tools.py`, `transcript.py`, `court/hmac_chain.py`).

> A note on `src/hexbreaker/llm.py`: its module docstring lists Witness and
> Provocateur as `deepseek-chat` roles. That is aspirational/planned wiring. The
> authoritative description of what runs today is `court_runner.py`, which calls
> the model only for the Prosecutor and the Defender. This doc describes the
> code path, not the docstring.

So the honest one-line characterization is: **the LLM reasons at two points
(accuse, adjudicate); a deterministic scaffold forces, validates, and can
override that reasoning.**

---

## 2. "Reason about next steps" — bounded by a forced FSM, not free-form planning

The Court is **not** a free-form ReAct-style agent that decides on its own which
tool to run next. It is a finite-state machine that *forces* a fixed
investigative sequence, and lets the LLM reason **inside** that sequence.

### 2.1 The FSM forces the loop

`court/orchestrator.py::CourtSession` is a 4-state machine
(`AWAITING_CLAIM → AWAITING_TOOL → TOOL_OBSERVED → VERDICT_ACCEPTED`) with three
hard rules stated in its module docstring:

- **R1** — a Claim must be submitted before any tool is observed.
- **R2** — the Defender cannot emit a verdict before at least one tool has been
  observed since the claim (`submit_verdict` returns a rejection if
  `_tools_observed_since_claim == 0`, `orchestrator.py:152-170`).
- **R3** — an invalid Verdict is logged as a `SYSTEM_EVENT` and the session
  **stays open**; the FSM does not terminate on rejection. Termination happens
  only on an accepted Verdict.

The FSM deliberately **does not call an LLM** (docstring lines 13-15). That is
what makes the loop forced rather than suggested: the model cannot skip the
tool-observation step by being told not to in a prompt — the Python state
machine refuses the verdict.

### 2.2 Tool *selection* is manifest-driven, not agent-chosen

This is the most important bound to state plainly. **The LLM never chooses which
tool to run.** The runner executes a fixed list of tools defined in the case
manifest:

- Pre-pass evidence for the Prosecutor: `manifest.pre_pass_steps`, run
  programmatically (`court_runner.py:272`, `_run_prepass_steps`).
- Defender's forced evidence: `manifest.defender_steps`, run through the FSM so
  R2 counts them (`court_runner.py:338`, `_run_defender_steps`).

Both are iterated directly in Python (`forge/case.py::ToolInvocation` entries);
the model is shown the *results* and reasons about them, but it does not emit
tool calls. (`mock_runner_from_case` in `forge/case.py:146` contains an
"if the agent tries a tool the case doesn't have a mock for" branch — that is a
defensive guard for a code path the shipping runner does not exercise, not
evidence of LLM-initiated tool selection.)

The autonomy here is **interpretive**: given fixed tool output, the model
decides *what it means* (which artifact to accuse, whether corroboration holds)
— not *what action to take next*. We claim the former and explicitly disclaim
the latter.

### 2.3 The tool surface itself is a closed enum

Even if the architecture were extended to let the model name tools,
`tools.py::run_tool` validates the tool name against a `SUPPORTED_TOOLS`
frozenset (`tools.py:28-43, 110-113`) and raises `ValueError` on anything else.
There is no path by which an LLM string becomes an arbitrary subprocess.

---

## 3. "Handle failures" — a bounded single retry with a citation hint

The runner's one real recovery mechanism is the **retry-on-fabrication** loop,
and it is bounded to a single retry per turn — not free-form replanning.

The live model is known to fabricate `step_id`s on its first attempt (the smoke
test on 2026-05-26 caught this; see `court/validator.py`'s module docstring).
The runner handles it deterministically:

1. The Prosecutor (or Defender) emits a Claim/Verdict.
2. The deterministic validator (`court/validator.py`) checks every cited
   `step_id` exists in the transcript **and** the cited `stdout_hash` matches
   what the tool actually emitted. A fabricated or hash-mismatched citation is
   rejected.
3. On rejection, the runner retries **exactly once**, this time appending a
   `_citation_hint` built from the *actual* tool results — the real step_ids and
   hashes — and drops temperature to 0.0
   (Prosecutor: `court_runner.py:315-325`; Defender: `court_runner.py:355-368`).
4. If the retry still fails to produce a valid Claim, the round simply `break`s
   with no finding (`court_runner.py:327-330`).

This is honest "failure handling": a deterministic detect → narrow → retry-once
→ give-up cycle. It is **not** an agent that diagnoses an arbitrary error and
devises a novel multi-step recovery plan. The bound (one retry, then stop) is
intentional and is what the doc claims.

---

## 4. "Self-correct in real time" — runtime Judge downgrade, replayable

This is the criterion's strongest verbatim phrase, and we map it to a real,
in-run, deterministic mechanism — **not** to free-form replanning by the model.

### 4.1 The mechanism

When a Verdict passes schema + citation-integrity checks, the orchestrator runs
the deterministic **Judge** before the verdict becomes a finding
(`orchestrator.py:186-216`). The Judge applies rules in order:

- **JR-02** (`judge.py::jr_02_provocation_leak`) — a CONFIRMED verdict whose
  `challenge_text` echoes any Provocateur leak token (case/whitespace-normalized
  match) is downgraded to CONTESTED.
- **JR-01** (`judge.py::jr_01_corroboration`) — a CONFIRMED verdict must cite
  **≥2 distinct tool kinds**; a single-signal CONFIRM is downgraded to CONTESTED.

If a rule fires, the orchestrator writes a `judge_downgrade` `SYSTEM_EVENT` to
the transcript and stores the **post-Judge** verdict (`orchestrator.py:192-207`).
A downgraded CONFIRMED becomes CONTESTED, so it never reaches the findings list
(`court_runner.py:397-408` only emits findings for CONFIRMED). That is the
self-correction: the model's over-confident CONFIRM is corrected at runtime by
Python, and the correction is recorded in the signed transcript.

### 4.2 Why this is "self-correction" and not just "a gate"

The corroboration rule originally lived only in the Defender's *prompt*. Prompts
can be ignored or prompt-injected. JR-01 moves the rule into Python so the
safeguard holds even when the Defender ignores the prompt (judge.py docstring,
lines 14-19). The system corrects its own output in the same run, with no human
in the loop, and the override is part of the agent's autonomous execution — it
is the agent catching and fixing its own mistake before emitting a finding.

> The earlier commit-history self-correction (the seed-4004 Provocateur
> bait-taking that motivated moving the rule from prompt to Judge) is attributed
> to `docs/accuracy.md §2.3`; this doc verifies the in-run Judge downgrade and
> the sweep below, which are the claims we measured directly.

### 4.3 It is replayable — `scripts/demo_self_correction.py`

The self-correction is a committed, re-derivable artifact, not a narrated
anecdote. Run:

```bash
PYTHONPATH=src python scripts/demo_self_correction.py
```

Verified output (deterministic, no network):

```
Defender emitted     : CONFIRMED (citing only S-001, a single tool kind)
Judge final verdict  : CONTESTED
Self-correction      : JR-01 downgraded CONFIRMED -> CONTESTED
  reason             : CONFIRMED requires citations from ≥2 distinct tool kinds; verdict cited only: ['MFTECmd']
Findings emitted     : 0 (bait rejected)
Chain verify         : ok=True reason=None
HMAC verify          : ok=True (chain_ok=True hmac_ok=True)

RESULT: PASS — runtime self-correction demonstrated + artifact verified
```

**Honest scope of the demo (a judge will open the script — so we say it first):**
the script does **not** run a live model. It runs the real `CourtSession` FSM
and the real deterministic Judge, but the bait verdict is a **hardcoded JSON
literal** (`demo_self_correction.py:73-78`) — specifically, the exact
single-tool-CONFIRMED shape the live model produced under the seed-4004 failure
mode. We inject that fixture and show the Judge downgrade it via JR-01. The
value of the demo is that **the Judge code path is byte-identical whether the
verdict arrives from a live Defender or from this fixture** — so it isolates and
proves the deterministic override without burning an API call or depending on
non-deterministic model output. The transcript it writes
(`samples/self_correction/transcript.jsonl` + `.sig`) is hash-chain- and
HMAC-verifiable.

---

## 5. The multi-finding loop — bounded re-accusation, opt-in

A single Court bout produces at most one finding. The multi-finding capability
is a **bounded** loop, and it is **opt-in** (`max_rounds` defaults to `1` in
`run_court_on_case`, `court_runner.py:234`; `max_rounds=1` is byte-identical to
the single-finding path).

When `max_rounds > 1` (`court_runner.py:296-408`):

- Each round is a **fresh `CourtSession` on the same transcript**, so the FSM
  (R1/R2), Judge, validator, hash chain, and HMAC are **re-enforced per round**
  without changing their code.
- The round-2+ Prosecutor prompt lists only **the agent's own prior
  accusations** (never the answer key) and asks for a *different* artifact
  (`court_runner.py:302-306`).
- The loop **stops on exhaustion**: if the Prosecutor repeats a prior accusation
  (`claim_key in accused`, line 333) or fails to produce a valid claim
  (line 327), the loop `break`s.

This is bounded re-accusation, not unbounded autonomous exploration: a hard
round cap, a deterministic dedup on `(artifact_kind, target)`
(`court_runner.py:410-418`), and a termination condition the agent cannot talk
its way past.

### 5.1 Measured evidence (`sweeps/2026-05-29_C2_multi.json`)

This sweep exercises the multi-finding loop on the `multi_artifact` template
(`sweep.py` exposes `--max-rounds`, line 145, and passes it through to
`run_court_on_case`, line 168; the `n_findings: 2` rows confirm `max_rounds > 1`
was used). Every per-run row carries `chain_ok: true` and `hmac_ok: true` — the
sweep is signed.

| Mode | n_runs | f1_mean | f1_stdev | precision_mean | recall_mean | total_fp_planted |
|---|---|---|---|---|---|---|
| normal | 10 | **0.8933** | 0.1447 | 0.9333 | 0.9 | **0** |
| provocateur | 10 | **0.9** | 0.161 | 1.0 | 0.85 | **0** |

`total_fp_planted: 0` in both modes is the safeguard result that matters for
C1: across 20 signed multi-finding runs, the agent confirmed **zero** of the
deliberately-planted bait artifacts. (Figures are this committed sweep's
`summary` block; broader-template generalization beyond `multi_artifact` is to
be measured.)

---

## 6. Summary table — where reasoning lives vs where Python enforces

| Capability the criterion asks about | LLM does | Deterministic Python does | Honest bound |
|---|---|---|---|
| Reason about next steps | Interprets tool output; chooses which artifact to accuse and how to adjudicate | FSM forces tool→observe→verdict order; tool **selection** is manifest-driven; tool name is a closed enum | The model does **not** choose investigative actions; it interprets fixed evidence |
| Handle failures | Re-emits a Claim/Verdict after a citation hint | Validator detects fabricated/hash-mismatched citations; runner retries **once** then stops | Single bounded retry, not free-form recovery |
| Self-correct in real time | Emits the verdict that gets corrected | Judge JR-01/JR-02 downgrade weak/baited CONFIRMs to CONTESTED in-run; recorded in signed transcript | Correction is a **deterministic runtime override**, not the model replanning |
| Multi-step autonomy | Proposes a different artifact each round | Per-round FSM/Judge re-enforcement; bounded `max_rounds`; dedup; exhaustion stop | Bounded re-accusation (opt-in), not unbounded exploration |

**The principle, restated for C1:** the model is allowed to reason freely; it is
only allowed to have its reasoning *become a finding* when a deterministic
scaffold can prove the citations exist and the corroboration rule holds. That is
the autonomy we claim — strong on adjudication and self-correction, deliberately
bounded on planning and tool selection, and honest about both.
