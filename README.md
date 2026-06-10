# Hexbreaker

> Adversarial DFIR triage + generative benchmark for AI forensic agents.
> SANS **Find Evil!** hackathon, 2026.

**Headline measurement (Hexbreaker Forge synthetic cases):**

Across **two** HMAC-signed Forge sweeps (40 runs/mode each): **F1 ≈ 0.95–0.975 normal / ≈ 0.475–0.525 under maximum adversarial pressure** (planted artifacts + runtime prompt injection on every round, all 6 safeguard layers firing). **0 planted artifacts confirmed across all 80 provocateur runs** (160/160 chain+HMAC verified). Honest caveat: in each sweep the agent confirmed a finding in ~19–21 of 40 provocateur runs (0 planted) and found nothing in the rest — bait-resistance is shown on the runs where it actually had the opportunity, not robustly across all 40. Exact F1 varies run-to-run (DeepSeek is non-deterministic); both committed JSONs are the artifacts of record.

**Real-disk measurement (NIST CFReDS Hacking Case, `.E01`):**

The adversarial FSM Court, run on the genuine seized disk image, recovered **all 4
deleted recycle-bin executables** (lalsetup, netstumbler, WinPcap, ethereal) via
`fls`+`INFO2` cross-corroboration — **4/4, precision/recall/F1 = 1.0, `fp_planted = 0`,
across 5/5 signed runs**, every transcript chain+HMAC verified
([`samples/nist_fsm_run/`](samples/nist_fsm_run/SUMMARY.md)). Scope, stated plainly:
the recycle-bin question (NIST Q28) — ~1 of the case's ~31 question families;
`artifact_kind = "other"` (deletion proven, not execution); `max_rounds = 4` is the
count of deleted-exe slots visible in the real INFO2 index, not a peek at the answer
key (enforced by `tests/test_court_on_nist_fsm_honesty.py`).

> **NIST batched-Q&A number withdrawn (do not confuse with the above).** A *different*,
> earlier `scripts/court_on_nist.py` run reported 95.08% F1, but that batched pipeline
> injected literal ground-truth answers into the prompt, so the number measured
> string-copying, not forensics. The injection has been removed; the batched path is
> NOT the adversarial Court (no Defender, no FSM, no hash chain) and is not labeled
> "Court" or "verifiable". The signed multi-round result above replaces it.

Full numbers + per-question breakdown: [docs/accuracy.md](docs/accuracy.md).

---

## What it is

Two products in one repo:

1. **Hexbreaker Forge** — generative DFIR case synthesizer. `seed: int → manifest.json + answer_key.json + mock_outputs/`. Deterministic, adversarial-mode (`--provocateur`) supported. **Six artifact-type templates**: timestomp, registry_persistence, multi_artifact (multi-finding), browser, prefetch, amcache — each with genuine 2-tool per-target corroboration.
2. **Hexbreaker Court** — 5-role adversarial agent. Prosecutor + Defender + Witness + **deterministic Python Judge (NO LLM)** + Provocateur (runtime prompt-injection role). Six layered hallucination safeguards (all in code, none in prompt). Hash-chained JSONL transcripts with HMAC-SHA256 signing (PBKDF2 600K, MIT-licensed primitive ported from AppliedIR/Valhuntir with attribution).

The Forge is the headline product — it lets the community honestly measure any DFIR agent on cases the agent has never seen. The Court is one agent built on top, graded by Forge like any other.

## Why this exists

The Find Evil! hackathon exists because Protocol SIFT (the organizer's reference framework) hallucinates without human review. Of the visible submissions we reviewed, none ship a generative benchmark. Hexbreaker's premise: **when a community converges on one ground-truth dataset (NIST Hacking Case), agents converge on its idiosyncrasies** — dhyabi2's 400-line `_pre_extract_hives` pipeline scores 100% F1 on NIST and 0% F1 on the same NIST under different (model, host) conditions. The community needs cases nobody — agent, author, judge — has seen before.

## Try it out (5 minutes, no SIFT VM needed)

**On SIFT (or any host with Docker) — the version-proof route.** The image is a
self-contained `python:3.12-slim`, so it runs identically on both SIFT bases
(Ubuntu 22.04 ships Python 3.10; 24.04 ships 3.12) — see
[docs/sift_verification.md](docs/sift_verification.md) (verified end-to-end, 17 s):

```bash
docker build -t hexbreaker -f docker/Dockerfile .
mkdir -p /tmp/case && docker run --rm -e DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY \
    -v /tmp/case:/case hexbreaker generate --seed 4729 --template timestomp --out /case
docker run --rm -e DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY -v /tmp/case:/case \
    hexbreaker run --agent court --case /case --out /case/findings.json
docker run --rm -v /tmp/case:/case hexbreaker score \
    --findings /case/findings.json --answer-key /case/answer_key.json
```

**Native (no Docker) — requires Python 3.11+.** Stock SIFT on Ubuntu 22.04 ships
Python 3.10 and the install will fail there (`requires a different Python`); use
Docker above, or install Python 3.11+ first.

```bash
# 1. Install (Python 3.11+ required — 3.10 will not install)
git clone https://github.com/Alexander-Sorrell-IT/hexbreaker.git
cd hexbreaker
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"

# 2. Configure DeepSeek (any OpenAI-compatible endpoint works; see .env.example)
cp .env.example .env  # then edit to set DEEPSEEK_API_KEY

# 3. Generate a case + run Court + score
hexbreaker generate --seed 4729 --template timestomp --out /tmp/case-4729
hexbreaker run --agent court --case /tmp/case-4729 --out /tmp/case-4729/findings.json
hexbreaker score --findings /tmp/case-4729/findings.json --answer-key /tmp/case-4729/answer_key.json

# 4. Verify the transcript chain
hexbreaker verify --transcript /tmp/case-4729/transcript.jsonl
# add --hmac to also verify the HMAC signature (needs HEXBREAKER_HMAC_PASSWORD)

# 5. Run a full N=10 sweep with mean F1 / variance / fp_planted
python scripts/sweep.py --seeds 10 --modes normal,provocateur --out /tmp/my_sweep.json
```

For the NIST Hacking Case head-to-head: see [docs/dataset.md §2](docs/dataset.md) for the download + extraction + scoring commands.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full data-flow diagram + security boundaries.

Six hallucination safeguards, all in code:

| Layer | What | Code |
|---|---|---|
| 1 | Step-ID referential integrity (orchestrator owns `S-NNN` namespace) | `src/hexbreaker/transcript.py` + `court/validator.py` |
| 2 | Forced tool-call FSM (Defender can't verdict before observing a tool) | `src/hexbreaker/court/orchestrator.py` |
| 3 | Strict Pydantic schema (`extra="forbid"`, regex on hash & step_id) | `src/hexbreaker/court/schema.py` |
| 4 | SHA-256 hash chain (per-record `prev_hash + this_hash`) | `src/hexbreaker/transcript.py` |
| 5 | HMAC-SHA256 signing (PBKDF2 600K, Valhuntir MIT pattern) | `src/hexbreaker/court/hmac_chain.py` |
| 6 | Provocateur runtime role + Judge JR-02 leak detector | `src/hexbreaker/court/provocateur.py` + `judge.py` |

Plus a deterministic Python Judge (`src/hexbreaker/court/judge.py`) with JR-01 (corroboration requires ≥2 distinct tool kinds) and JR-02 (challenge_text echoing a Provocateur leak token downgrades to CONTESTED).

## Repository layout

```
src/hexbreaker/
├── transcript.py        # hash-chained JSONL + step_id namespace
├── llm.py               # DeepSeek adapter (httpx + tenacity, 429-aware)
├── tools.py             # SIFT subprocess wrappers + sidecars + hash
├── court/
│   ├── schema.py        # Pydantic Claim / Verdict / StepReference
│   ├── validator.py     # citation cross-check (Layers 1 + 4)
│   ├── orchestrator.py  # CourtSession FSM (Layer 2)
│   ├── judge.py         # deterministic JR-01 / JR-02 rules
│   ├── provocateur.py   # Layer 6 runtime payloads
│   └── hmac_chain.py    # Layer 5 signing
├── forge/
│   ├── case.py          # CaseManifest + AnswerKey + mock_runner
│   ├── template_timestomp.py
│   ├── template_registry_persistence.py
│   ├── template_multi_artifact.py   # multi-finding (timestomp + persistence)
│   ├── template_browser.py
│   ├── template_prefetch.py
│   └── template_amcache.py
├── scorer/exact_match.py
├── runner/court_runner.py
└── cli.py               # hexbreaker generate / run / score / verify / sign / trace

tests/                   # 173 pass + 5 skipped (4 live + MCP); ~182 pass with the [mcp] extra (derived from the 169→173 base; re-measure after `pip install -e .[mcp]`)
docs/
├── architecture.md      # security boundaries + data flow
├── accuracy.md          # measured numbers + methodology
├── competitors.md       # independent briefings on dhyabi2 / marez / Valhuntir
├── dataset.md           # Forge + NIST documentation
├── benchmark_datasheet.md  # "Datasheet for Datasets" — Forge as a benchmark
├── brittleness.md       # robustness / failure-mode study (miss-not-lie)
├── autonomy.md          # honest C1 autonomy characterization
├── repro.md             # clean-room Docker reproduction guide
└── devpost.md           # Devpost submission narrative
sweeps/                  # committed sweep results (replayable)
scripts/
├── sweep.py             # multi-seed Court harness
├── brittleness.py       # robustness / failure-mode harness (--from-sweep | --vary)
├── demo_self_correction.py  # replayable JR-01 self-correction artifact
├── court_on_nist_fsm.py # genuine FSM Court on the real NIST .E01 (no injection)
└── court_on_nist.py     # WITHDRAWN batched adapter (prompt-injected; do not cite)
```

## Tests

```bash
PYTHONPATH=src python -m pytest -q      # 173 pass, 5 skipped (4 live + MCP suite), ~7 s
HEXBREAKER_RUN_LIVE=1 pytest            # also runs the 4 live DeepSeek integration tests (needs API key)
```

Every safeguard has a paired test that proves it **rejects** bad input as well as accepts good input. Examples:

- `tests/test_transcript.py::test_verify_detects_content_tampering` — hash chain catches edits
- `tests/test_validator.py::test_verdict_rejected_on_fabricated_step_id` — Layer 1 catches step_id fabrication
- `tests/test_validator.py::test_verdict_rejected_on_hash_substitution` — Layer 4 catches hash substitution
- `tests/test_security_transcript.py::test_render_transcript_refuses_traversal_stdout_path` — path-traversal CVE regression
- `tests/test_judge.py::test_jr01_downgrades_confirmed_with_single_tool` — JR-01 corroboration in code
- `tests/test_provocateur.py::test_jr02_downgrades_when_challenge_text_echoes_leak_token` — JR-02 leak detection

## Reproducing the headline numbers

| Number | Command |
|---|---|
| dhyabi2 on NIST F1=0% under DeepSeek+Ubuntu | `bash /tmp/competitors/findevil/run_nist_deepseek.sh` after `git clone https://github.com/dhyabi2/findevil.git` |
| Forge sweep — two signed runs (20 seeds × 2 templates = 40 runs/mode each): F1 ≈ 0.95–0.975 / 0.475–0.525, 0 planted confirmed (`sweeps/2026-05-28_N40_signed_audit.json`, `sweeps/2026-05-29_N40_signed_audit.json`). Exact F1 varies run-to-run (DeepSeek is non-deterministic); the committed JSONs are the artifacts of record. | `python scripts/sweep.py --seeds 20 --templates timestomp,registry_persistence --modes normal,provocateur --out sweeps/X.json` |
| Friday gate (generate / score / Court transcript) | `hexbreaker generate ... && hexbreaker run ... && hexbreaker score ...` |

## License

MIT. See [LICENSE](LICENSE). The HMAC primitive at `src/hexbreaker/court/hmac_chain.py` was ported from MIT-licensed [AppliedIR/Valhuntir](https://github.com/AppliedIR/Valhuntir) `src/vhir_cli/verification.py` (Copyright (c) 2026 AppliedIncidentResponse.com) with attribution preserved in the module docstring.

## Author

Alexander Sorrell ([@Alexander-Sorrell-IT](https://github.com/Alexander-Sorrell-IT)), 2026.
