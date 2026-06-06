# Submission Checklist — Find Evil! Hackathon

Target submission: **Fri 2026-06-13 17:00 CDT** (48-hour safety margin to the
2026-06-15 hard deadline).

## The 8 mandatory submission artifacts

Each row points to where the artifact lives in this repo + verifies it's complete.

| # | Artifact | Where it lives | Status |
|---|---|---|---|
| 1 | **GitHub repo (MIT or Apache)** | https://github.com/Alexander-Sorrell-IT/hexbreaker (currently private; flip to public before submit). [LICENSE](LICENSE) = MIT. | ✅ ready (visibility flip on submit day) |
| 2 | **≤5 min demo video** | **Committed:** [docs/demo.mp4](docs/demo.mp4) (1:47) — a real **live-terminal screencast** (asciinema capture of the actual tool, no slides) with neural-TTS narration: Forge generate → the self-correction CONFIRMED→CONTESTED beat → `hexbreaker verify --hmac` proving the **committed signed NIST 4/4** on-screen → the brittleness close. Fully no-API; regenerable via `AGG_BIN=/tmp/agg python scripts/build_screencast_demo.py --out docs/demo.mp4`. Recording plan: [docs/demo_runbook.md](docs/demo_runbook.md). | ⏳ **Built + committed; needs the human gate.** Live terminal execution is genuine and every number shown is committed-backed; narration is synthetic TTS (rules require "audio narration", not a specific voice). Alex: accept this take OR record a voiced take per the runbook → then **upload public** + put the URL on Devpost. (Promo trailer `docs/trailer.mp4` is a separate Devpost-gallery asset, NOT #2.) |
| 3 | **Architecture diagram (security boundaries)** | [docs/architecture.md](docs/architecture.md). ASCII data-flow diagram + per-boundary "architectural vs prompt-based" table. SVG conversion is optional polish. | ✅ ready (Markdown); SVG = optional |
| 4 | **Written description (Devpost story)** | [docs/devpost.md](docs/devpost.md). Full Inspiration / What it does / Measured results / How we built it / Challenges / Accomplishments / What we learned / What's next narrative. | ✅ ready (paste into Devpost form) |
| 5 | **Dataset documentation** | [docs/dataset.md](docs/dataset.md). Documents Forge synthetic schema, the 6 case templates, NIST Hacking Case acquisition + hashes + extraction commands, attribution. | ✅ ready |
| 6 | **Accuracy report with evidence-integrity section** | [docs/accuracy.md](docs/accuracy.md). Per-method F1 table, head-to-head vs dhyabi2 / marez / Valhuntir, the 6 safeguards each tied to a specific code path + test. (The earlier NIST 95.08% batched number is withdrawn — it used prompt-injected answers; see §3.2.1.) | ✅ ready |
| 7 | **Try-it-out instructions tested on SIFT** | [README.md §"Try it out"](README.md) + [docs/sift_verification.md](docs/sift_verification.md) — full walkthrough run **live** in the Docker image (generate → Court → score → verify, 17 s, F1=1.0, chain OK). Docker is `python:3.12-slim`, so it is SIFT-version-proof and runs on both SIFT bases (22.04 / 24.04). | ✅ Docker path verified end-to-end (the SIFT-safe route); native path needs Python ≥3.11 (stock SIFT 22.04 ships 3.10 → use Docker). **Also run inside a booted SANS SIFT 24.04 VM** (CONFIRMED with MFTECmd+yara corroboration; evidence `samples/sift_vm_run/`). Only the literal distributed-`.ova`-file import was not done (the qcow2 is the same SIFT build; Docker removes the failure class). |
| 8 | **Structured agent execution logs** | every Court run produces hash-chained JSONL at `<case_dir>/transcript.jsonl` + per-tool sidecar files at `<case_dir>/transcript.outputs/`. HMAC signature optional via `hexbreaker sign`. Validator: `hexbreaker verify --transcript X.jsonl --hmac`. **Committed sample:** `samples/self_correction/transcript.jsonl` (+ `.sig` + sidecars) — chain-verifiable via `hexbreaker verify --transcript samples/self_correction/transcript.jsonl` (HMAC too with `HEXBREAKER_HMAC_PASSWORD=demo-self-correction`); regenerate via `python scripts/demo_self_correction.py`. | ✅ ready |

**Current state (post adversarial audit + Wave 1 integrity fixes, 2026-05-28):** the demo (#2) is NON-COMPLIANT (slides, not a screencast) and is the one hard-open artifact. Integrity holes are now fixed (sidecar-byte verification + HMAC wired into runs); the answer-injected NIST 95.08% is withdrawn. Court is proven to run on a genuine SANS SIFT 24.04 workstation VM (booted KVM guest; provocateur-mode run CONFIRMED with MFTECmd+yara corroboration; evidence at `samples/sift_vm_run/`) AND via Docker on the host (F1=1.0). Remaining build work tracked as Waves 2–3 (honest flagship measurement, real SIFT-tool integration, doc/narrative truth pass). The six-criteria table below was corrected (2026-05-29) to the official rubric verified against findevil.devpost.com/rules.

## Six judging criteria + how Hexbreaker addresses each

The six criteria are **equally weighted** (verbatim, [official rules](https://findevil.devpost.com/rules)). There is no single tiebreaker axis: ties break by the highest score in the **first applicable criterion in the listed order below** — so Autonomous Execution Quality (listed first) is the effective tiebreaker. Listed in official order, with honest evidence — including where we are genuinely weak:

| # | Criterion (verbatim) | Where we show it | Honest read |
|---|---|---|---|
| 1 | **Autonomous Execution Quality** — *"reason about next steps, handle failures, self-correct in real time?"* | Runtime self-correction is in the data, not the prompt: seed-4004 bait taken → corroboration rule moved from Defender prompt to deterministic Judge JR-01 → 0 planted confirmed in the signed sweep; position-bias caught in code review, fixed, re-measured. Runtime Judge JR-01/JR-02 downgrade weak/baited CONFIRMs to CONTESTED on live evidence. All replayable from committed sweeps. | **Strong, but honest scope:** the FSM forces the tool→observe→verdict loop and the Judge is deterministic; DeepSeek does the reasoning within that scaffold. Self-correction is demonstrated across commits + in-run (Judge downgrades), not as free-form agent replanning. |
| 2 | **IR Accuracy** — *"findings correct? hallucinations caught and flagged? confirmed vs inferred distinguished?"* | Forge (two signed sweeps): **F1 ≈ 0.95–0.975 normal / ≈ 0.475–0.525 max-attack**, **0 planted confirmed (0/80)** (~19–21 of 40 provoc. runs confirmed a finding each, 0 planted; 160/160 chain+HMAC verified). Hallucination handling is architectural: validator rejects fabricated step_ids/hashes; JR-01/JR-02 downgrade unsupported CONFIRMs; CONFIRMED vs CONTESTED vs REJECTED separates confirmed from contested. | **Mixed — stated plainly.** Strong on our synthetic benchmark (F1 ≈0.95–0.975). On the real NIST disk the single-finding path caps recall at ~0.25, but the **multi-round Court lifts it to 4/4 (P/R/F1 = 1.0, signed, [samples/nist_fsm_run/](samples/nist_fsm_run/SUMMARY.md))** on the recycle-bin question (~1 of ~31). Caveat: that NIST case has **no planted decoys**, so its precision 1.0 is *recovery* accuracy, **not** bait-resistance — bait-resistance is the Forge `fp_planted=0/80` left of this column. The honest soft spot is the prefetch/amcache target-format gap (accuracy.md). We still lead with the honesty machinery over any single number. |
| 3 | **Breadth and Depth of Analysis** — *"how much case data? depth on fewer types beats shallow coverage."* | Court does deep multi-role adjudication (Prosecutor/Defender/Witness/Provocateur/Judge); **6 Forge templates** (timestomp, registry_persistence, multi_artifact, browser, prefetch, amcache) + the real NIST recycle-bin case (4/4, signed). | **Still our weakest axis, stated honestly.** Breadth now spans 6 synthetic classes + one real NIST question-family — but on the breadth sweep browser scores F1≈0.9 while prefetch/amcache score ≈0 from a target-format scoring gap (the agent confirms the right artifact but emits a short name vs the answer-key's full path; disclosed in accuracy.md), and real-case coverage is still 1 of ~31 NIST questions. We lean on depth-over-breadth (the rubric's stated preference). |
| 4 | **Constraint Implementation** — *"guardrails architectural or prompt-based? tested for bypass?"* | All 6 hallucination safeguards live in code, not prompt. Each was **tested for bypass by execution** (see `AUDIT_WAVE3.md`): sidecar-byte tamper → `verify()` fails; full chain recompute → HMAC catches it; single-tool CONFIRM → JR-01 downgrades. Each has a paired test that fails on the violating input. | **Strongest axis.** Maps almost word-for-word to the criterion ("architectural" + "tested for bypass"). Honest caveat: bare SHA chain is forgeable by recompute — tamper-evidence depends on the HMAC layer. |
| 5 | **Audit Trail Quality** — *"trace any finding back to the specific tool execution that produced it?"* | Every Verdict cites step_ids resolving to TOOL_CALL records whose stored stdout hash must match the cited hash; hash-chained JSONL + per-tool sidecar files + optional HMAC signature. `hexbreaker verify --hmac` validates chain + signature (80/80 in the signed sweep). | **Strong and direct.** A finding that doesn't trace to a real tool execution is rejected before it can be confirmed. |
| 6 | **Usability and Documentation** — *"can another practitioner deploy and build on this?"* | One-shot Docker path verified end-to-end on SIFT (generate→Court→score→verify); README "Try it out"; 169 unit tests pass (5 skipped); clean module separation (transcript / FSM / Judge / Provocateur / Forge). | **Solid.** Docker removes the Python-version failure class. Gap: bare `pytest` needs `pip install -e` first; native path needs Python ≥3.11. |

## Pre-flight checklist (Thu 6/12 evening)

- [ ] `git pull && git status` clean
- [ ] `PYTHONPATH=src python -m pytest -q` passes 169 tests (5 skipped: 4 live without `HEXBREAKER_RUN_LIVE=1` + the MCP suite without the `[mcp]` extra; `.[test,deepseek,mcp]` → 178 pass / 4 skip)
- [ ] `hexbreaker --help` lists 5 subcommands (generate / run / score / verify / sign + leaderboard stub)
- [ ] `docker build -t hexbreaker -f docker/Dockerfile .` succeeds
- [ ] Docker smoke: `generate → run → score` works inside the container (one-shot reproducibility for judges)
- [ ] `hexbreaker generate --seed 4729 --out /tmp/x` deterministic across re-runs (sha256 of manifest.json matches)
- [ ] ~~`python scripts/court_on_nist.py` reproduces the F1=95.08% NIST headline~~ WITHDRAWN — that number came from prompt-injected answers (now removed); the batched path no longer produces a claimed F1
- [ ] `python scripts/sweep.py --seeds 20 --templates timestomp,registry_persistence --modes normal,provocateur` produces a Forge sweep comparable to the two signed sweeps (F1 ≈ 0.95–0.975 normal / ≈ 0.475–0.525 max-attack, 0 planted confirmed; exact F1 varies — DeepSeek is non-deterministic)
- [ ] Demo video recorded + uploaded (Tue 6/10 target per plan)
- [ ] **Repo visibility flipped to PUBLIC** (currently private)
- [ ] Devpost form filled with content from [docs/devpost.md](docs/devpost.md)
- [ ] All 8 artifact links in the Devpost form resolve

## Submission-day commands

```bash
# 0. PUT THE REAL WORK ON THE DEFAULT BRANCH FIRST.
#    All 27 commits live on `wave3-honesty-multifinding`; `main` is the stale
#    scaffold. `git push origin main` ALONE would publish nothing real. Local
#    `main` fast-forwards cleanly to wave3 (verified: `git merge-base --is-ancestor
#    main wave3-honesty-multifinding`), so:
git checkout main
git merge --ff-only wave3-honesty-multifinding   # main -> 57aeadf (or latest), no merge commit
git log --oneline -1                              # confirm main == wave3 head

# 1. Push the real work to origin/main (repo can still be PRIVATE for this push)
git status                                        # must be clean
git push origin main                              # publishes all 27 commits

# 2. Flip repo visibility to PUBLIC (the irreversible, judge-facing step)
gh repo edit Alexander-Sorrell-IT/hexbreaker --visibility public
#    Verify in a logged-out browser: repo loads, default branch shows all commits,
#    About panel shows "MIT License", anonymous `git clone` works.

# 3. Tag the submission commit
git tag -a v1.0.0-findevil-submission -m "Find Evil! 2026 submission"
git push origin v1.0.0-findevil-submission

# 4. Submit on Devpost (https://findevil.devpost.com/) using docs/devpost.md as the story
```

## Risk + mitigation snapshot

| Risk | Status | Mitigation |
|---|---|---|
| Demo video not recorded by 6/13 | mitigated | A live-terminal screencast is **committed** (`docs/demo.mp4`, 1:47, no-API, regenerable via `scripts/build_screencast_demo.py`); needs only Alex's accept-or-rerecord decision + public upload. |
| DeepSeek rate-limit during demo | low | 429 retry wired in code (commit `29ddf2a`); $35 balance |
| Docker fails on a clean judge machine | mitigated | verified on host build + smoke; image is python-slim base, fits in ~200MB |
| SIFT-specific "tested-on-SIFT" requirement | mitigated | Docker path (`python:3.12-slim`) verified live end-to-end and is SIFT-version-proof — runs on both SIFT bases. Native (no-Docker) install needs Python ≥3.11, which stock SIFT 22.04 lacks; README leads with Docker for SIFT. Evidence: [docs/sift_verification.md](docs/sift_verification.md) |
| Repo private at submission | mitigated | checklist above includes the visibility flip command |

## Builder

Alexander Sorrell ([@Alexander-Sorrell-IT](https://github.com/Alexander-Sorrell-IT))
Collaborator: Claude Opus 4.8 (1M context)
