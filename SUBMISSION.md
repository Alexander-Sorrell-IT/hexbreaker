# Submission Checklist — Find Evil! Hackathon

Target submission: **Fri 2026-06-13 17:00 CDT** (48-hour safety margin to the
2026-06-15 hard deadline).

## The 8 mandatory submission artifacts

Each row points to where the artifact lives in this repo + verifies it's complete.

| # | Artifact | Where it lives | Status |
|---|---|---|---|
| 1 | **GitHub repo (MIT or Apache)** | https://github.com/Alexander-Sorrell-IT/hexbreaker (currently private; flip to public before submit). [LICENSE](LICENSE) = MIT. | ✅ ready (visibility flip on submit day) |
| 2 | **≤5 min demo video** | [docs/demo/hexbreaker_demo.mp4](docs/demo/hexbreaker_demo.mp4) — **2:49 narrated MP4, committed** (built programmatically by [scripts/build_demo_video.py](scripts/build_demo_video.py) from [docs/demo_shot_list.md](docs/demo_shot_list.md), per-shot TTS voice-over). | ✅ ready (2:49 < 5 min); a hand-recorded screencast is optional polish, not required |
| 3 | **Architecture diagram (security boundaries)** | [docs/architecture.md](docs/architecture.md). ASCII data-flow diagram + per-boundary "architectural vs prompt-based" table. SVG conversion is optional polish. | ✅ ready (Markdown); SVG = optional |
| 4 | **Written description (Devpost story)** | [docs/devpost.md](docs/devpost.md). Full Inspiration / What it does / Measured results / How we built it / Challenges / Accomplishments / What we learned / What's next narrative. | ✅ ready (paste into Devpost form) |
| 5 | **Dataset documentation** | [docs/dataset.md](docs/dataset.md). Documents Forge synthetic schema, the 2 case templates, NIST Hacking Case acquisition + hashes + extraction commands, attribution. | ✅ ready |
| 6 | **Accuracy report with evidence-integrity section** | [docs/accuracy.md](docs/accuracy.md). Per-method F1 table, head-to-head vs dhyabi2 / marez / Valhuntir, the 6 safeguards each tied to a specific code path + test, the iteration trajectory (45.9% → 95.08% on NIST). | ✅ ready |
| 7 | **Try-it-out instructions tested on SIFT** | [README.md §"Try it out"](README.md) + [docs/sift_verification.md](docs/sift_verification.md) — full walkthrough run **live** in the Docker image (generate → Court → score → verify, 17 s, F1=1.0, chain OK). Docker is `python:3.12-slim`, so it is SIFT-version-proof and runs on both SIFT bases (22.04 / 24.04). | ✅ Docker path verified end-to-end (the SIFT-safe route); native path needs Python ≥3.11 (stock SIFT 22.04 ships 3.10 → use Docker). **Residual: literal SANS OVA boot not performed** (Docker removes the failure class it would test) |
| 8 | **Structured agent execution logs** | every Court run produces hash-chained JSONL at `<case_dir>/transcript.jsonl` + per-tool sidecar files at `<case_dir>/transcript.outputs/`. HMAC signature optional via `hexbreaker sign`. Validator: `hexbreaker verify --transcript X.jsonl --hmac`. Sample committed at `sweeps/competitors/run_deepseek.log`. | ✅ ready |

**Current state: 8/8 artifacts have a satisfying deliverable committed.** Residuals are submit-day actions or optional polish, not open artifacts: flip repo to public (#1), optional hand-recorded demo (#2, the committed 2:49 MP4 already satisfies the requirement), and booting the literal SANS OVA for #7 (Docker makes it unnecessary — try-it-out is verified live via the Docker path).

## Six judging criteria + how Hexbreaker addresses each

Per the hackathon brief, six equally-weighted criteria with **Autonomous Execution Quality as tiebreaker**:

| Criterion | Where we show it |
|---|---|
| **Innovation** | Generative Forge benchmark (no other entry has one); 5-role MAD with deterministic Python Judge (no other entry has one). |
| **Technical Quality** | 94 unit tests + 4 live integration tests, all green; 13+ commits each with substantive content; clean separation of concerns (transcript / FSM / Judge / Provocateur). |
| **Accuracy on Find-Evil cases** | NIST: 95.08% under hackathon constraints (vs dhyabi2's 0% same constraints); Forge: 1.0 normal / 0.5 max-attack with `fp_planted = 0/20`. |
| **Audit Trail Quality** | Hash-chained JSONL + step_id namespace + cited-hash cross-check + HMAC signing (5 of the 6 safeguards directly underpin this criterion). |
| **Constraint Implementation** | DeepSeek-only (no Anthropic), no SIFT-only tools required, runs in `python:3.12-slim` Docker (Layer-1 reproducibility); the only entry that runs at all under the LLM constraint AND on a plain Ubuntu host. |
| **Autonomous Execution Quality (TIEBREAKER)** | Demonstrable self-correction at three levels: (a) Defender → Judge JR-01 corroboration migration (seed-4004 → fp_planted=0/20); (b) position-bias caught by code review, fixed, re-measured; (c) NIST extraction 45.9% → 95.08% over 5 iterations. All replayable from committed sweep artifacts. |

## Pre-flight checklist (Thu 6/12 evening)

- [ ] `git pull && git status` clean
- [ ] `pytest` passes 94+ tests
- [ ] `hexbreaker --help` lists 5 subcommands (generate / run / score / verify / sign + leaderboard stub)
- [ ] `docker build -t hexbreaker -f docker/Dockerfile .` succeeds
- [ ] Docker smoke: `generate → run → score` works inside the container (one-shot reproducibility for judges)
- [ ] `hexbreaker generate --seed 4729 --out /tmp/x` deterministic across re-runs (sha256 of manifest.json matches)
- [ ] `python scripts/court_on_nist.py` reproduces the F1=95.08% NIST headline (needs the NIST extracts under /tmp/nist-extracts)
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
