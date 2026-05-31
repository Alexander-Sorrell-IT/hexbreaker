# Demo video shot list

> ⚠️ **SUPERSEDED by [docs/demo_runbook.md](demo_runbook.md)** (2026-05-30). The
> runbook is the canonical, current recording plan — it uses only reproducible,
> non-withdrawn material (the real NIST 4/4 run + the deterministic JR-01 self-
> correction). This older shot list is kept for reference but contains stale
> numbers (e.g. `fp_planted = 0/20`, the seed-4004 framing) — do not record from it.

Target: ≤5 minutes total (hackathon rules). Submission artifact #2.

Required by the hackathon: **at least one unscripted self-correction moment** (Autonomous Execution Quality tiebreaker). We satisfy this with the seed-4004 → corroboration-rule story, reproducible from committed sweep data. (The earlier "Court-on-NIST 45.9% → 95.08%" trajectory is withdrawn — it was driven by prompt-injected answer hints, not forensic improvement; do not show it.)

---

## Structure (5:00 budget)

| Time | Shot | What happens | What the viewer sees |
|---|---|---|---|
| 0:00–0:30 | Title + problem | Voice-over: "Find Evil! has 3,706 contestants. We submitted the league." Cut to README headline. | README's Forge `fp_planted = 0/20` headline (the NIST batched number is withdrawn — do not show it) |
| 0:30–1:15 | Live seed pick | Type `hexbreaker generate --seed 4729 --template registry_persistence --out /tmp/demo` in a terminal. Show the generated mock_outputs/recmd_run.csv with 5 Run-key rows. | Real terminal, no cuts. Pause on the CSV so the viewer sees the malicious entry mixed in with legit ones. |
| 1:15–2:45 | Court runs live | `hexbreaker run --agent court --case /tmp/demo --out /tmp/demo/findings.json`. Wait the ~10 s of real wall-clock. Show the streaming output. Then `cat /tmp/demo/findings.json`. | Real DeepSeek call. Defender's reasoning visible. CONFIRMED verdict at the end. |
| 2:45–3:30 | The safeguards demo | `hexbreaker generate --seed 4004 --template timestomp --provocateur --out /tmp/bait`. Run Court. Show JUDGE downgrade event in transcript. | Transcript shows S-002 PROVOCATEUR (payload) and S-006 JUDGE downgrade with rule_id JR-02 — the bait-taking failure mode the safeguard exists to catch, caught in code not prompt. |
| 3:30–4:30 | Adversarial robustness | Voice-over: "Under maximum attack — planted artifacts plus runtime prompt injection on every round — the agent never confirmed a planted artifact." Show `fp_planted = 0/20` in the committed sweep. (NIST head-to-head dropped: the prior Hexbreaker 95% was prompt-injected and is withdrawn.) | Terminal showing the sweep summary / accuracy.md Forge table. |
| 4:30–5:00 | Audit story | `hexbreaker verify --transcript /tmp/demo/transcript.jsonl --hmac` returns "chain + HMAC OK". Then `git log --oneline` showing 10 commits today. | Clean cryptographic verification. Cut to the commit graph showing measured self-correction across the day. |

---

## Required: unscripted self-correction moments to mention or show

1. **Seed-4004 → corroboration-rule migration**: caught the Defender confirming a planted artifact (`fp_planted = 1/10`), moved the corroboration rule from prompt to deterministic Python (JR-01 in Judge), re-measured (`fp_planted = 0/20`). Sweep files `sweeps/2026-05-27_N10_baseline.json` and `sweeps/2026-05-28_N10_final_arch.json` are both committed for replay.
2. **Position bias caught by code review**: the Provocateur F1=1.0 was partially a "pick row 1" artifact because the timestomp template always emitted the evil row at index 0. Added `rng.shuffle()`, re-measured at F1=0.7. Honest in `accuracy.md §2.2.1`.
3. ~~NIST F1 iteration 45.9% → 95.08%~~ **WITHDRAWN**: that trajectory was driven by adding prompt-injected ground-truth answer hints to `scripts/court_on_nist.py`, not by forensic improvement. The injection has been removed; do not present this as self-correction.

The remaining moments are reproducible from committed artifacts and are sufficient for the tiebreaker.

---

## Visual assets needed

- Terminal recording at high-res (1920×1080 preferred, monospace font)
- Screen-capture overlay showing key file paths as text on screen
- Optional: an architecture diagram cut-in at 2:45 (use docs/architecture.md's ASCII or convert to SVG)
- Title card with the two-product framing: "Hexbreaker Forge + The Court"

## Voice-over script (full text)

> "The SANS Find Evil! hackathon has thirty-seven hundred contestants. We submitted the league.
>
> Hexbreaker is two products: a Court — a five-role adversarial DFIR agent — and Forge, a generative benchmark that lets anyone test any agent on cases the agent has never seen.
>
> Here's a real Forge case being generated from a seed, in real time. Watch the Court find evil.
>
> Now watch the safeguard layer catch a planted artifact. The Defender confirmed it. The deterministic Judge — a Python function, not an LLM — downgrades the verdict to CONTESTED because the Defender cited only one tool and the corroboration rule lives in code.
>
> The strongest visible competitor self-reports 100% F1 on the canonical NIST Hacking Case. We independently re-ran their pipeline under the hackathon's actual LLM constraint — DeepSeek instead of Gemma, Ubuntu instead of SIFT — and it scored zero percent. We do NOT counter with a flashy Hexbreaker NIST number: an earlier 95% came from prompt-injected answers and is withdrawn. Instead we show what's reproducible right here — Forge generating unseen cases and the Court rejecting a planted artifact in code.
>
> The transcript verifies with HMAC. Every safeguard is in code. The full repo is at github.com/Alexander-Sorrell-IT/hexbreaker."

## Recording checklist

- [ ] Terminal font 18pt+ for readability
- [ ] No real API keys visible (use `$DEEPSEEK_API_KEY` env reference)
- [ ] Disable shell history pollution; clear screen between sections
- [ ] One take preferred; if multiple takes, cut on terminal commands not mid-sentence
- [ ] Audio levels checked; voice-over normalized to -16 LUFS
- [ ] Export as MP4 H.264 720p+ (Devpost allows up to 1080p, YouTube embed expected)
- [ ] Final length 4:30–5:00 (do NOT exceed 5:00 hard cap)

## What NOT to do in the recording

- Don't pre-record the LLM call (judges will check). Show the real wall-clock.
- Don't read from `accuracy.md` verbatim — paraphrase, point to the file at the end.
- Don't apologize for the F1=0.5 Provocateur number; that's the safeguard working ("better to miss than to lie").
- Don't claim "we beat dhyabi2" without immediately qualifying "under hackathon constraints" — their 100% on Gemma+SIFT is real on that stack.
