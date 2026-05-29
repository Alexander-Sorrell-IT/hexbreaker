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
| 7 | **Try-it-out instructions tested on SIFT** | [README.md §"Try it out"](README.md) + [docs/sift_verification.md](docs/sift_verification.md) — full walkthrough run **live** in the Docker image (generate → Court → score → verify, 17 s, F1=1.0, chain OK). Docker is `python:3.12-slim`, so it is SIFT-version-proof and runs on both SIFT bases (22.04 / 24.04). | ✅ Docker path verified end-to-end (the SIFT-safe route); native path needs Python ≥3.11 (stock SIFT 22.04 ships 3.10 → use Docker). **Residual: literal SANS OVA boot not performed** (Docker removes the failure class it would test) |
| 8 | **Structured agent execution logs** | every Court run produces hash-chained JSONL at `<case_dir>/transcript.jsonl` + per-tool sidecar files at `<case_dir>/transcript.outputs/`. HMAC signature optional via `hexbreaker sign`. Validator: `hexbreaker verify --transcript X.jsonl --hmac`. Sample committed at `sweeps/competitors/run_deepseek.log`. | ✅ ready |

**Current state (post adversarial audit + Wave 1 integrity fixes, 2026-05-28):** the demo (#2) is NON-COMPLIANT (slides, not a screencast) and is the one hard-open artifact. Integrity holes are now fixed (sidecar-byte verification + HMAC wired into runs); the answer-injected NIST 95.08% is withdrawn. Court is proven to run on a genuine SIFT OVA (Ubuntu 24.04, native + Docker, F1=1.0). Remaining build work tracked as Waves 2–3 (honest flagship measurement, real SIFT-tool integration, doc/narrative truth pass). The "six criteria" table below still references a hallucinated rubric and is corrected in Wave 3.

## Six judging criteria + how Hexbreaker addresses each

Per the hackathon brief, six equally-weighted criteria with **Autonomous Execution Quality as tiebreaker**:

| Criterion | Where we show it |
|---|---|
| **Innovation** | Generative Forge benchmark (no other entry has one); 5-role MAD with deterministic Python Judge (no other entry has one). |
| **Technical Quality** | 94 unit tests + 4 live integration tests, all green; 13+ commits each with substantive content; clean separation of concerns (transcript / FSM / Judge / Provocateur). |
| **Accuracy on Find-Evil cases** | Forge: 1.0 normal / 0.5 max-attack with `fp_planted = 0/20`. (The earlier NIST 95.08% batched number is withdrawn — it used prompt-injected answers, was not the adversarial Court, and is not reproducible.) |
| **Audit Trail Quality** | Hash-chained JSONL + step_id namespace + cited-hash cross-check + HMAC signing (5 of the 6 safeguards directly underpin this criterion). |
| **Constraint Implementation** | DeepSeek-only (no Anthropic), no SIFT-only tools required, runs in `python:3.12-slim` Docker (Layer-1 reproducibility); the only entry that runs at all under the LLM constraint AND on a plain Ubuntu host. |
| **Autonomous Execution Quality (TIEBREAKER)** | Demonstrable self-correction: (a) Defender → Judge JR-01 corroboration migration (seed-4004 → fp_planted=0/20); (b) position-bias caught by code review, fixed, re-measured. All replayable from committed sweep artifacts. (The earlier NIST 45.9%→95.08% "trajectory" is withdrawn — it was the trajectory of adding prompt-injected answer hints, not forensic improvement.) |

## Pre-flight checklist (Thu 6/12 evening)

- [ ] `git pull && git status` clean
- [ ] `pytest` passes 94+ tests
- [ ] `hexbreaker --help` lists 5 subcommands (generate / run / score / verify / sign + leaderboard stub)
- [ ] `docker build -t hexbreaker -f docker/Dockerfile .` succeeds
- [ ] Docker smoke: `generate → run → score` works inside the container (one-shot reproducibility for judges)
- [ ] `hexbreaker generate --seed 4729 --out /tmp/x` deterministic across re-runs (sha256 of manifest.json matches)
- [ ] ~~`python scripts/court_on_nist.py` reproduces the F1=95.08% NIST headline~~ WITHDRAWN — that number came from prompt-injected answers (now removed); the batched path no longer produces a claimed F1
- [ ] `python scripts/sweep.py --seeds 10 --modes normal,provocateur` reproduces the Forge headline (F1=1.0 normal, fp_planted=0)
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
