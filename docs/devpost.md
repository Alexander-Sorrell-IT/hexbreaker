# Hexbreaker — Devpost submission

*Two products in one repo:* **Hexbreaker Forge** — the **Accuracy Benchmarking Framework** the Find Evil! brief asks for ([starter idea #5](https://findevil.devpost.com/)) — and **Hexbreaker Court**, the 5-role adversarial DFIR agent built on top, graded by Forge like any other agent. Forge lets the community honestly measure ANY DFIR agent on cases the agent has never seen.

---

## Inspiration

The Find Evil! brief is blunt about why this hackathon exists: *"Protocol SIFT works. It also hallucinates more than we'd like. (That's exactly why this hackathon exists.)"* And in the starter ideas, the organizers name the missing piece outright — **idea #5, the Accuracy Benchmarking Framework:**

> *"Create a test harness that runs … against known-good data with documented ground truth, then scores accuracy, false positive rates, and hallucination frequency. **The community needs this benchmark to measure progress.**"* — Find Evil! starter idea #5

**Hexbreaker Forge IS that framework.** We built it because the field's accuracy problem is structural, and we could prove it: every DFIR-agent paper, repo, and demo we read for this hackathon scored 100% F1 on the **same one dataset** — NIST's CFReDS "Mr. Evil" Hacking Case. We independently re-measured the strongest visible competitor (`dhyabi2/findevil`) and found their 100% holds **only on their original (model, OS, scaffolding) tuple** (Gemma 4 31B + SIFT VM + 400 lines of NIST-specific extraction code). Swap any axis — to DeepSeek, to Ubuntu — and the same code returns 0% F1.

That's not a methodology indictment; it's a **dataset saturation problem.** When a community converges on one ground-truth corpus, agents converge on its idiosyncrasies, and "F1 = 100%" stops meaning what people think it means. You cannot measure progress on a benchmark everyone has overfit. So idea #5 needs two things at once:

1. **infrastructure that generates new cases on demand**, so no agent — author, judge, or future researcher — has seen the case before (that's **Forge**); and
2. **an agent worth measuring on it** — one whose accuracy survives the move to a new (model, OS, case) combination (that's the **Court**).

## What it does

**Hexbreaker Forge — the benchmarking framework (starter idea #5).** Forge synthesizes Windows DFIR cases from a 32-bit integer seed: `seed → manifest.json + answer_key.json + mock_outputs/`, deterministic and byte-identical across hosts. Six artifact templates ship (timestomp via MFTECmd CSV, registry_persistence via RECmd Run-key dump, multi_artifact for multi-finding load, browser, prefetch, amcache), each with genuine 2-tool per-target corroboration. Every case ships a documented ground truth — an `answer_key.json` with `expected_findings`, `decoys`, and optional `planted` (adversarial) entries — and a strict scorer: `(artifact_kind, target)` exact-tuple match. That is precisely idea #5's "known-good data with documented ground truth, then scores accuracy, false positive rates, and hallucination frequency": **anyone can `hexbreaker generate --seed N`, point any DFIR agent at the case, and score it** — false positives, planted-bait confirmations (the hallucination-frequency metric), and missed findings all fall out of the same exact-tuple match. Forge does not replace NIST; it complements it. NIST measures whether your scaffolding is correct on one famous case. Forge measures whether your *architecture* is robust to inputs no scaffolding can foresee.

**Hexbreaker Court — the agent built on top, graded by Forge like any other.** The Court is the agentic execution engine: it investigates synthetic *and* real Windows forensic evidence (Forge cases and the genuine NIST `.E01`) and emits structured findings `{artifact_kind, target, verdict ∈ {CONFIRMED, CONTESTED, REJECTED}}` as an investigative narrative, with every finding traceable to the exact tool execution that produced it. Five roles cooperate and adversarially check each other:

| Role | Job |
|---|---|
| Prosecutor | Reads tool output, identifies one artifact, files a structured Claim |
| Defender | Investigates, demands corroboration, files a structured Verdict |
| Witness | Called whenever the FINAL verdict is CONTESTED — whether the Defender contested it or the Judge downgraded a CONFIRMED; independent toolset |
| Judge | **Deterministic Python** (no LLM): rules JR-01..N gate final accept/reject |
| Provocateur | Adversarial: fires one prompt-injection payload per case (Judge JR-02 checks every round's verdict against it) |

Self-correction is architectural, not prompt-based: the corroboration rule lives in the deterministic Judge (JR-01), so a CONFIRMED verdict citing a single tool kind is **downgraded to CONTESTED in code at runtime**, regardless of what the LLM emits — replayable via `scripts/demo_self_correction.py`. Every step writes to a **SHA-256 hash-chained JSONL transcript** with **HMAC-SHA256** signing (PBKDF2 600,000 iterations, MIT-licensed pattern ported from AppliedIR/Valhuntir with attribution). Cited evidence references both `step_id` and `stdout_hash`; the citation validator (Layer 1) and the chain verifier (Layer 4) reject any Verdict that cites fabricated or tampered steps. Six hallucination safeguards in total — all in code, none in prompt.

The Court is one agent. The point of Forge is that it grades *any* agent the same way — which is how we benchmarked the Court honestly, and how we re-measured `dhyabi2` under hackathon constraints rather than citing their self-reported number.

## Measured results

| Run | F1 | Source |
|---|---|---|
| ~~Hexbreaker Court on NIST Hacking Case (batched)~~ **WITHDRAWN** — the batched `court_on_nist.py` run injected literal ground-truth answers into the prompt, so this measured string-copying, not forensics. Injection removed; number not reproducible. | ~~95.08%~~ withdrawn | — |
| **Hexbreaker Court on NIST Hacking Case (real `.E01`, multi-round FSM, signed)** — the genuine adversarial Court, no injection | **4/4 deleted recycle-bin exes recovered; P/R/F1 = 1.0; fp_planted=0; 5/5 runs** | [`samples/nist_fsm_run/`](../samples/nist_fsm_run/SUMMARY.md) — chain+HMAC verified, E01 SHA256 matches docs. Scope: recycle-bin Q (~1 of ~31), `artifact_kind='other'` |
| dhyabi2 IABF on NIST (Gemma 4 31B + SIFT, **their original stack**, **their self-reported number**) | 100% | dhyabi2/findevil ACCURACY.md |
| dhyabi2 IABF on NIST (DeepSeek + Ubuntu, **our independent re-measurement**) | **0.0%** | `sweeps/competitors/score_deepseek.json` |
| marez8505 on NIST under DeepSeek constraint | **not runnable** | competitor briefing — hardcoded to Anthropic `claude --print` |
| Hexbreaker Court on Forge (both templates, 40 runs/mode, normal) | **F1 ≈ 0.95–0.975** (0.975±0.158 and 0.95±0.221, two signed sweeps) | `sweeps/2026-05-28_N40_signed_audit.json` + `sweeps/2026-05-29_N40_signed_audit.json` (HMAC-signed) |
| Hexbreaker Court on Forge (both templates, 40 runs/mode, **max attack**: planted artifacts + runtime prompt injection) | **F1 ≈ 0.475–0.525** (0.525 and 0.475) — high variance, "miss not lie" | same two sweeps |
| Provocateur bait-taking | **0 planted artifacts confirmed** (across 40 provocateur runs the agent confirmed a finding in 21, none planted; 19 found nothing) | same sweep |

**Head-to-head on NIST:** our independent re-measurement of dhyabi2 under hackathon constraints (DeepSeek-only, no SIFT VM) scored **0.0%**, vs their self-reported 100% on Gemma+SIFT. (We previously claimed a 95.08% Hexbreaker number here; it is withdrawn — see the table note above.)

**Adversarial robustness:** across 40 provocateur runs/mode with maximum attack pressure (planted MFT rows + runtime prompt injection on every round, all six safeguard layers firing), the agent **never once** confirmed a planted artifact. The architecture trades recall-under-attack for precision-under-attack — better to miss than to lie.

## How we built it

13+ commits in 2 build days, deliberately staged to keep the safeguard story testable at each step:

1. Hash-chained transcript with orchestrator-owned `S-NNN` step_id namespace (Layer 1 + 4)
2. DeepSeek adapter (httpx + tenacity, 429-aware retry, OpenAI-compatible)
3. Pydantic Claim/Verdict schemas with `extra="forbid"` and citation cross-checks (Layer 3)
4. CourtSession FSM with forced tool-call rule R2 (Layer 2)
5. Forge case template #1 (timestomp) + scorer + runner + CLI
6. Friday-gate executed 3 days early (3/3 checks pass)
7. Independent NIST head-to-head measurement
8. Provocateur (Layer 6) + iterative sweep with measured self-correction (`fp_planted`: 1 bait taken → 0 after the corroboration rule moved from Defender prompt to Judge JR-01)
9. 9-angle code review + security review (parallel agents); 15 findings + 2 confirmed HIGH/MEDIUM path-traversal CVEs; both CVEs closed with 10 regression tests
10. Witness wired (5th actor on the wire); HMAC signing (Layer 5) via MIT-licensed Valhuntir port

## Challenges we ran into

- **The audit caught a 50-percentage-point measurement artifact.** The code-review angle revealed the timestomp template was always emitting the evil MFT row at index 0. After `rng.shuffle()`, the Provocateur F1 dropped 1.0 → 0.7 — the prior number was partially "agent picks row 1," not "agent reasons about $SI/$FN." Honest re-measurement is in `docs/accuracy.md §2.2.1`.
- **dhyabi2's 100% F1 doesn't transfer.** When we swapped DeepSeek into their pipeline on our Ubuntu host (instead of Gemma 4 31B on a SIFT VM), the pipeline returned 0% F1: their LLM-tool-chaining prompt expected Gemma's output format, and their `_pre_extract_hives` hardcoded a SIFT-only RECmd path. Documented in `docs/accuracy.md §3.2`.
- **The Provocateur runtime role wasn't real until late.** The architecture doc claimed a "5-role adversarial system," but for most of the build only 2 actors (Prosecutor + Defender) appeared in transcripts. The code-review Altitude angle surfaced the gap; we closed it by building a 5-payload Provocateur taxonomy + JR-02 leak detector in the Judge. Now the transcript shows TOOL → PROVOCATEUR → PROSECUTOR → TOOL → DEFENDER (+ JUDGE on downgrade + WITNESS on CONTESTED).

## Accomplishments we're proud of

- **Independent measurement of every named competitor under hackathon constraints.** marez8505 documented as unrunnable (Anthropic-locked); Valhuntir documented as human-in-loop (different category, MIT HMAC pattern borrowed with attribution); dhyabi2 measured at 0% with DeepSeek on Ubuntu. (A previously claimed 95.08% Hexbreaker NIST number is withdrawn — it relied on prompt-injected answers.)
- **All six hallucination safeguards are in code, not prompt.** Step-ID referential integrity, forced tool-call FSM, strict JSON schema, hash chain, HMAC signing, Provocateur runtime — every layer demonstrably rejects bad input via a paired unit test.
- **Adversarial audit caught real bugs.** Code review + security review found 15 cleanups, 2 path-traversal CVEs (both closed with regression tests), and the position-bias measurement artifact. The audits caught more than the unit tests — that's the safeguard architecture working at the development layer too.
- **Self-correction is in code, and replayable.** The corroboration rule moved from the Defender's prompt into a deterministic Judge (JR-01); a CONFIRMED verdict that cites a single tool kind is overridden to CONTESTED at runtime. This is a committed, re-derivable artifact — `PYTHONPATH=src python scripts/demo_self_correction.py` drives the real Court + Judge and verifies the signed transcript. (The earlier "iterative NIST 45.9% → 95.08%" story is withdrawn — prompt-injected answers, not forensic improvement.)

## What we learned

- **"Generative benchmark" is necessary infrastructure**, not a feature. When NIST is the only public ground-truth case, scaffolding overfits and "F1=100%" stops meaning what people think it means. Forge lets anyone test ANY DFIR agent on cases nobody — agent, author, judge — has seen before.
- **Architectural guardrails beat prompt guardrails.** When the corroboration rule lived in the Defender's prompt, the LLM could ignore it and confirm on a single signal. Moving it into the deterministic Judge (JR-01) makes the override happen in code — demonstrated, committed, and replayable via `scripts/demo_self_correction.py` (CONFIRMED → CONTESTED, 0 findings). Across the signed sweep's 40 provocateur runs, 0 planted artifacts were confirmed.
- **Independent measurement is more important than higher numbers.** Citing dhyabi2's published 100% would have been "ok." Re-running their pipeline ourselves and measuring 0% under hackathon constraints is the more honest — and frankly more useful to the community — number.

## What's next

- Wider real-disk NIST coverage beyond the recycle-bin question (currently 1 of ~31), via the FSM path
- N=50 sweeps for tight stdev intervals
- Multi-template leaderboard (Court vs naive-LLM baseline)
- Witness LLM reasoning (v1 records the call; v2 does the independent investigation)
- Open the Forge benchmark to the community post-hackathon

## Built by

Alexander Sorrell (Alexander-Sorrell-IT), with Claude Opus 4.8 (1M context) as collaborator. All commits are MIT-licensed; the HMAC primitive carries upstream attribution to AppliedIR/Valhuntir.
