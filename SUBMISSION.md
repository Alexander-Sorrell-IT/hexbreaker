# Submission Checklist — Find Evil! Hackathon

Target submission: **Fri 2026-06-13 17:00 CDT** (48-hour safety margin to the
2026-06-15 hard deadline).

## The 8 mandatory submission artifacts

Each row points to where the artifact lives in this repo + verifies it's complete.

| # | Artifact | Where it lives | Status |
|---|---|---|---|
| 1 | **GitHub repo (MIT or Apache)** | https://github.com/Alexander-Sorrell-IT/hexbreaker (currently private; flip to public before submit). [LICENSE](LICENSE) = MIT. | ✅ ready (visibility flip on submit day) |
| 2 | **≤5 min demo video** | committed MP4 [docs/demo/hexbreaker_demo.mp4](docs/demo/hexbreaker_demo.mp4) is a **PIL slide deck + TTS** (see [scripts/build_demo_video.py](scripts/build_demo_video.py) docstring) — the rules require *"a screencast of live terminal execution with audio narration. **Not slides.** … including at least one self-correction sequence."* | ❌ **NON-COMPLIANT as built.** Needs a real narrated terminal screencast (recorded on SIFT) of Court finding evil + the live Provocateur→Judge downgrade, uploaded public. |
| 3 | **Architecture diagram (security boundaries)** | [docs/architecture.md](docs/architecture.md). ASCII data-flow diagram + per-boundary "architectural vs prompt-based" table. SVG conversion is optional polish. | ✅ ready (Markdown); SVG = optional |
| 4 | **Written description (Devpost story)** | [docs/devpost.md](docs/devpost.md). Full Inspiration / What it does / Measured results / How we built it / Challenges / Accomplishments / What we learned / What's next narrative. | ✅ ready (paste into Devpost form) |
| 5 | **Dataset documentation** | [docs/dataset.md](docs/dataset.md). Documents Forge synthetic schema, the 2 case templates, NIST Hacking Case acquisition + hashes + extraction commands, attribution. | ✅ ready |
| 6 | **Accuracy report with evidence-integrity section** | [docs/accuracy.md](docs/accuracy.md). Per-method F1 table, head-to-head vs dhyabi2 / marez / Valhuntir, the 6 safeguards each tied to a specific code path + test. (The earlier NIST 95.08% batched number is withdrawn — it used prompt-injected answers; see §3.2.1.) | ✅ ready |
| 7 | **Try-it-out instructions tested on SIFT** | [README.md §"Try it out"](README.md) + [docs/sift_verification.md](docs/sift_verification.md) — full walkthrough run **live** in the Docker image (generate → Court → score → verify, 17 s, F1=1.0, chain OK). Docker is `python:3.12-slim`, so it is SIFT-version-proof and runs on both SIFT bases (22.04 / 24.04). | ✅ Docker path verified end-to-end (the SIFT-safe route); native path needs Python ≥3.11 (stock SIFT 22.04 ships 3.10 → use Docker). **Also run inside a booted SANS SIFT 24.04 VM** (CONFIRMED with MFTECmd+yara corroboration; evidence `samples/sift_vm_run/`). Only the literal distributed-`.ova`-file import was not done (the qcow2 is the same SIFT build; Docker removes the failure class). |
| 8 | **Structured agent execution logs** | every Court run produces hash-chained JSONL at `<case_dir>/transcript.jsonl` + per-tool sidecar files at `<case_dir>/transcript.outputs/`. HMAC signature optional via `hexbreaker sign`. Validator: `hexbreaker verify --transcript X.jsonl --hmac`. **Committed sample:** `samples/self_correction/transcript.jsonl` (+ `.sig` + sidecars) — chain-verifiable via `hexbreaker verify --transcript samples/self_correction/transcript.jsonl` (HMAC too with `HEXBREAKER_HMAC_PASSWORD=demo-self-correction`); regenerate via `python scripts/demo_self_correction.py`. | ✅ ready |

**Current state (post adversarial audit + Wave 1 integrity fixes, 2026-05-28):** the demo (#2) is NON-COMPLIANT (slides, not a screencast) and is the one hard-open artifact. Integrity holes are now fixed (sidecar-byte verification + HMAC wired into runs); the answer-injected NIST 95.08% is withdrawn. Court is proven to run on a genuine SANS SIFT 24.04 workstation VM (booted KVM guest; provocateur-mode run CONFIRMED with MFTECmd+yara corroboration; evidence at `samples/sift_vm_run/`) AND via Docker on the host (F1=1.0). Remaining build work tracked as Waves 2–3 (honest flagship measurement, real SIFT-tool integration, doc/narrative truth pass). The six-criteria table below was corrected (2026-05-29) to the official rubric verified against findevil.devpost.com/rules.

## Six judging criteria + how Hexbreaker addresses each

The six criteria are **equally weighted** (verbatim, [official rules](https://findevil.devpost.com/rules)). There is no single tiebreaker axis: ties break by the highest score in the **first applicable criterion in the listed order below** — so Autonomous Execution Quality (listed first) is the effective tiebreaker. Listed in official order, with honest evidence — including where we are genuinely weak:

| # | Criterion (verbatim) | Where we show it | Honest read |
|---|---|---|---|
| 1 | **Autonomous Execution Quality** — *"reason about next steps, handle failures, self-correct in real time?"* | Runtime self-correction is in the data, not the prompt: seed-4004 bait taken → corroboration rule moved from Defender prompt to deterministic Judge JR-01 → 0 planted confirmed in the signed sweep; position-bias caught in code review, fixed, re-measured. Runtime Judge JR-01/JR-02 downgrade weak/baited CONFIRMs to CONTESTED on live evidence. All replayable from committed sweeps. | **Strong, but honest scope:** the FSM forces the tool→observe→verdict loop and the Judge is deterministic; DeepSeek does the reasoning within that scaffold. Self-correction is demonstrated across commits + in-run (Judge downgrades), not as free-form agent replanning. |
| 2 | **IR Accuracy** — *"findings correct? hallucinations caught and flagged? confirmed vs inferred distinguished?"* | Forge (two signed sweeps): **F1 ≈ 0.95–0.975 normal / ≈ 0.475–0.525 max-attack**, **0 planted confirmed (0/80)** (~19–21 of 40 provoc. runs confirmed a finding each, 0 planted; 160/160 chain+HMAC verified). Hallucination handling is architectural: validator rejects fabricated step_ids/hashes; JR-01/JR-02 downgrade unsupported CONFIRMs; CONFIRMED vs CONTESTED vs REJECTED separates confirmed from contested. | **Mixed — stated plainly.** Strong on our synthetic benchmark; **weak on the real external NIST case (~0.28 F1)** because of the one-finding-per-run design. We lead with the honesty machinery, not a headline accuracy number. |
| 3 | **Breadth and Depth of Analysis** — *"how much case data? depth on fewer types beats shallow coverage."* | Court does deep multi-role adjudication (Prosecutor/Defender/Witness/Provocateur/Judge) of a single artifact class per run; 2 Forge templates (timestomp, registry persistence). | **Our weakest axis — no spin.** One-finding-per-run caps breadth on multi-artifact real cases; only 2 templates ship. The rubric rewards depth-over-breadth, which helps, but this is where we are thinnest. |
| 4 | **Constraint Implementation** — *"guardrails architectural or prompt-based? tested for bypass?"* | All 6 hallucination safeguards live in code, not prompt. Each was **tested for bypass by execution** (see `AUDIT_WAVE3.md`): sidecar-byte tamper → `verify()` fails; full chain recompute → HMAC catches it; single-tool CONFIRM → JR-01 downgrades. Each has a paired test that fails on the violating input. | **Strongest axis.** Maps almost word-for-word to the criterion ("architectural" + "tested for bypass"). Honest caveat: bare SHA chain is forgeable by recompute — tamper-evidence depends on the HMAC layer. |
| 5 | **Audit Trail Quality** — *"trace any finding back to the specific tool execution that produced it?"* | Every Verdict cites step_ids resolving to TOOL_CALL records whose stored stdout hash must match the cited hash; hash-chained JSONL + per-tool sidecar files + optional HMAC signature. `hexbreaker verify --hmac` validates chain + signature (80/80 in the signed sweep). | **Strong and direct.** A finding that doesn't trace to a real tool execution is rejected before it can be confirmed. |
| 6 | **Usability and Documentation** — *"can another practitioner deploy and build on this?"* | One-shot Docker path verified end-to-end on SIFT (generate→Court→score→verify); README "Try it out"; 99 unit tests pass; clean module separation (transcript / FSM / Judge / Provocateur / Forge). | **Solid.** Docker removes the Python-version failure class. Gap: bare `pytest` needs `pip install -e` first; native path needs Python ≥3.11. |

## Pre-flight checklist (Thu 6/12 evening)

- [ ] `git pull && git status` clean
- [ ] `pytest` passes 99 tests (4 live skipped without `HEXBREAKER_RUN_LIVE=1`)
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
# 1. Make sure local is clean and pushed
git status
git push origin main

# 2. Flip repo visibility
gh repo edit Alexander-Sorrell-IT/hexbreaker --visibility public

# 3. Tag the submission commit
git tag -a v1.0.0-findevil-submission -m "Find Evil! 2026 submission"
git push origin v1.0.0-findevil-submission

# 4. Submit on Devpost (https://findevil.devpost.com/) using docs/devpost.md as the story
```

## Risk + mitigation snapshot

| Risk | Status | Mitigation |
|---|---|---|
| Demo video not recorded by 6/13 | mitigated | 2:49 narrated MP4 already committed (docs/demo/hexbreaker_demo.mp4); regenerable via scripts/build_demo_video.py |
| DeepSeek rate-limit during demo | low | 429 retry wired in code (commit `29ddf2a`); $35 balance |
| Docker fails on a clean judge machine | mitigated | verified on host build + smoke; image is python-slim base, fits in ~200MB |
| SIFT-specific "tested-on-SIFT" requirement | mitigated | Docker path (`python:3.12-slim`) verified live end-to-end and is SIFT-version-proof — runs on both SIFT bases. Native (no-Docker) install needs Python ≥3.11, which stock SIFT 22.04 lacks; README leads with Docker for SIFT. Evidence: [docs/sift_verification.md](docs/sift_verification.md) |
| Repo private at submission | mitigated | checklist above includes the visibility flip command |

## Builder

Alexander Sorrell ([@Alexander-Sorrell-IT](https://github.com/Alexander-Sorrell-IT))
Collaborator: Claude Opus 4.8 (1M context)
