# Clean-Room Reproduction Guide

> How to reproduce Hexbreaker's committed headline numbers from a **fresh
> machine**, step by step, copy-pasteable, pinned. Every command below is
> grounded in `docker/Dockerfile`, `scripts/sweep.py`, `src/hexbreaker/cli.py`,
> and the committed sweep JSONs — not aspirational.

**Pin used to write this guide:** commit `548ec88`
(`Alexander-Sorrell-IT/hexbreaker`, branch state at 2026-05-29). Re-clone at this
commit for a byte-faithful clean room; later commits may change defaults.

**Verification status of the commands below (at pin `548ec88`):** the Docker
build, and the `generate` / `score` / `verify` subcommands **through the
container**, were executed and confirmed at this commit (build smoke step plus a
live `docker run … generate/score/verify`). The one stage **not** re-run here is
`run --agent court` (it needs a live DeepSeek key and is the non-deterministic
LLM stage); its documented single-case reference result is from
`docs/sift_verification.md` (dated 2026-05-28, an earlier commit). So: Docker
plumbing for the three deterministic stages is executed-verified at HEAD; the
Court LLM result is cited from the earlier end-to-end run, not re-executed here.

---

## 0. What is deterministic vs. LLM-nondeterministic (read this first)

Three of the four pipeline stages are **pure Python with no network call** and
reproduce **byte-for-byte**. One stage calls a hosted LLM and is therefore
**not** bit-reproducible. This is the single most important honesty boundary in
this repo, so it is stated up front.

| Stage | Command | Deterministic? | Needs `DEEPSEEK_API_KEY`? | Evidence |
|---|---|---|---|---|
| **generate** | `hexbreaker generate` | **Yes** — same seed → identical `manifest.json` + `answer_key.json` | No | `cli.py:54` calls `TEMPLATES[template](seed, …)`; no client constructed. Verified: two `--seed 4729` generations produced byte-identical `answer_key.json` and `manifest.json`. |
| **run (Court)** | `hexbreaker run --agent court` | **No** — calls DeepSeek; output varies run-to-run | **Yes** | `cli.py:73` → `run_court_on_case(case, out)` → `client is None` branch → `llm.load_env()` + `DeepSeekClient()` (`court_runner.py:264-266`), which raises if `DEEPSEEK_API_KEY` is unset (`llm.py:97-99`). Empirical proof of non-determinism: the two committed N40 sweeps run the *same* command yet differ (normal 0.975 vs 0.95; provocateur 0.525 vs 0.475). |
| **score** | `hexbreaker score` | **Yes** — pure set arithmetic over findings vs. answer key | No | `cli.py:84-90` reads two JSON files and calls `score(...)`; no client. Verified: scoring the committed `samples/sift_vm_run/` twice produced identical output (`tp=1, fp=0, fn=0, fp_planted=0, F1=1.0`). |
| **verify** | `hexbreaker verify` | **Yes** — recomputes SHA-256 hash chain (+ optional HMAC) | No | `cli.py:111-129` → `transcript.verify()` / `verify_signature()`; no client. |
| **trace** | `hexbreaker trace` | **Yes** — re-joins findings → cited steps → re-hashed sidecar bytes | No | `cli.py` `trace_cmd` → `court/trace.py:trace_findings()`; no client. Verified: `--findings samples/nist_fsm_run/run1/findings.json --transcript …/transcript.jsonl` traces 4/4 findings to the `fls`/`icat` output that produced them; a one-byte sidecar edit flips it to `sidecar_mismatch` and exit 1 (`tests/test_trace.py`). |

**Therefore:**

- The **Friday gate** (generate → run → score → verify on a single self-generated
  case) reproduces the *shape* of the result deterministically except for the one
  Court LLM round-trip. On the committed `--seed 4729 --template timestomp` case
  the documented Court result is a single CONFIRMED finding scoring **F1=1.0**
  (see `docs/sift_verification.md §1`), but because Court calls a non-deterministic
  LLM, an individual replay can land elsewhere on any given run.
- The **sweep F1** (the headline `≈0.95–0.975 normal / ≈0.475–0.525 provocateur`)
  is an **aggregate over 40 LLM-driven runs per mode** and will **not** reproduce
  to the exact decimal. The committed JSONs are the **artifacts of record**; a
  re-run reproduces the *pattern* (normal ≫ provocateur, `fp_planted` total = 0),
  not the literal mean. This is stated verbatim in the README headline and in
  `sweep.py`'s own caveat ("honest F1 numbers", concurrency=1 to respect rate
  limits).

---

## 1. Prerequisites (fresh machine)

- **Docker** (any recent version; this guide was validated structurally against
  Docker 29.1.3). Docker is the supported route because the image is a
  self-contained `python:3.12-slim` (`Dockerfile:20`) and runs identically on both
  SANS SIFT bases — Ubuntu 22.04 (Python 3.10) and 24.04 (Python 3.12). See
  `docs/sift_verification.md`.
- A **DeepSeek API key** for any step that runs Court (the `run` and `sweep`
  stages). `generate`, `score`, and `verify` need no key.
- `git`.

```bash
git clone https://github.com/Alexander-Sorrell-IT/hexbreaker.git
cd hexbreaker
git checkout 548ec88           # pin to the commit this guide was written against
export DEEPSEEK_API_KEY=sk-...  # your DeepSeek key (needed only for Court/sweep)
```

> **`.env.example` caveat (honest):** the committed `.env.example` shows
> `ANTHROPIC_API_KEY` and lists `DEEPSEEK_API_KEY` only as a commented "optional"
> line. The **load-bearing** key for the Court agent is `DEEPSEEK_API_KEY`
> (`llm.py:97`) — the adapter is DeepSeek, not Anthropic. Set `DEEPSEEK_API_KEY`
> regardless of what `.env.example` implies. (Reported as an integration note, not
> edited here.)

---

## 2. Build the container (deterministic-ish; pinned base)

```bash
docker build -t hexbreaker -f docker/Dockerfile .
```

- Base is pinned to `python:3.12-slim` (`Dockerfile:20`). Forensic CLIs
  (`sleuthkit`, `ewf-tools`, `yara`) and `git`/`curl`/`ca-certificates` are
  apt-installed unpinned-by-version (`Dockerfile:33-40`) — so the apt layer is
  *not* bit-reproducible across rebuild dates, but the Python environment and the
  hexbreaker code are.
- The build runs a **self-smoke-test** (`Dockerfile:59-61`): `hexbreaker --help`
  plus a `generate --seed 999` that must succeed, so a broken image fails at build
  time, not first run.
- The `ENTRYPOINT` is `["hexbreaker"]` (`Dockerfile:63`) — every `docker run …
  hexbreaker <args>` below appends a subcommand to the CLI.

---

## 3. Friday gate — generate / run / score / verify (one case)

This is the README "Try it out" path (`README.md:42-50`) plus the verify step
from `docs/sift_verification.md:103`. It exercises all four stages on one case.

```bash
mkdir -p /tmp/case

# 3a. generate  — DETERMINISTIC, no API key. Same seed → identical case files.
docker run --rm -v /tmp/case:/case hexbreaker \
    generate --seed 4729 --template timestomp --out /case

# 3b. run Court — LLM, NON-DETERMINISTIC, NEEDS DEEPSEEK_API_KEY.
docker run --rm -e DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY -v /tmp/case:/case hexbreaker \
    run --agent court --case /case --out /case/findings.json

# 3c. score  — DETERMINISTIC, no API key.
docker run --rm -v /tmp/case:/case hexbreaker \
    score --findings /case/findings.json --answer-key /case/answer_key.json

# 3d. verify the hash chain — DETERMINISTIC, no API key.
docker run --rm -v /tmp/case:/case hexbreaker \
    verify --transcript /case/transcript.jsonl
```

**Expected, with honesty boundaries:**

- **3a** emits `generated case case-004729-timestomp …` and writes
  `manifest.json`, `answer_key.json`, `mock_outputs/` into `/tmp/case`. These are
  identical on every run (verified byte-for-byte).
- **3b** prints the findings the live LLM produced. The committed reference run on
  this exact case is **1 finding, CONFIRMED,
  `\Windows\System32\drivers\mssecsvc2.exe`** (`docs/sift_verification.md:30`).
  Your run *may* differ — this is the one non-deterministic stage.
- **3c** prints a scorecard. On the reference run it is
  `tp=1, fp=0, fn=0, fp_planted=0, precision=1.0, recall=1.0, f1=1.0`
  (`docs/sift_verification.md:31`). Because 3b varies, your F1 can vary; what does
  **not** vary is the scorer's arithmetic given a fixed findings file.
- **3d** prints `chain OK: …`. The chain check recomputes every record's
  `prev_hash + this_hash` and re-hashes the `transcript.outputs/` sidecars, so it
  only passes when the sidecars produced by 3b are present alongside the
  transcript (they are, inside `/tmp/case`). To also check the HMAC signature, add
  `--hmac` **and** pass `-e HEXBREAKER_HMAC_PASSWORD=…` (`cli.py:110`,
  `hmac_chain.py:45`); without that env var Court runs **unsigned** and emits a
  warning (`court_runner.py:431-435`).

> **Known caveat about the committed `samples/sift_vm_run/` bundle:** running
> `verify` on *that* sample reports `chain INVALID: sidecar missing …` — by
> design. Only the JSON bundle was scp'd out of the SIFT VM; the
> `transcript.outputs/` sidecars stayed inside the guest
> (`docs/sift_verification.md:88-90`). The record-link chain is intact; the
> sidecar-byte re-hash needs files that weren't exported. A *self-generated* case
> (3a–3d above) has its sidecars and verifies clean.

---

## 4. Reproduce the headline sweep numbers

### 4.1 What the committed numbers are

The README headline (`README.md:8`) is two HMAC-signed N=40-per-mode sweeps. Both
are committed and are the artifacts of record:

| File | normal `f1_mean` | provocateur `f1_mean` | `total_fp_planted` | runs/mode |
|---|---|---|---|---|
| `sweeps/2026-05-28_N40_signed_audit.json` | **0.975** | **0.525** | **0** | 40 |
| `sweeps/2026-05-29_N40_signed_audit.json` | **0.95** | **0.475** | **0** | 40 |

(These are the `summary` blocks inside each JSON, read directly — not transcribed
from prose.) Both used **seeds 5000–5019** (start-seed 5000, 20 seeds) across
**two templates** (`timestomp`, `registry_persistence`), giving 20 × 2 = 40
runs/mode. **Independently re-counted from the JSONs for this guide:** every run
in both files has `chain_ok=true` **and** `hmac_ok=true` — 80/80 in each file,
**160/160** chain+HMAC across the two.

Honest sub-claim (matches README): the agent confirmed a finding in only
**21/40** (5-28) and **19/40** (5-29) of the provocateur runs and found nothing in
the rest — bait-resistance (`fp_planted=0`) is demonstrated on the runs where the
agent actually engaged, not robustly across all 40.

### 4.2 The exact command that maps to the committed seeds

The README "reproducing" table (`README.md:154`) gives:

```
python scripts/sweep.py --seeds 20 --templates timestomp,registry_persistence \
    --modes normal,provocateur --out sweeps/X.json
```

**This omits `--start-seed`, which defaults to 4000 (`sweep.py:142`).** The
committed audit JSONs used seeds **5000–5019**, so to hit the *same seeds* you
must pass `--start-seed 5000`:

```bash
# Native multi-seed sweep path (Python 3.11+).
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"          # Python 3.11+ required (pyproject.toml:11)
export DEEPSEEK_API_KEY=sk-...
export HEXBREAKER_HMAC_PASSWORD='choose-a-strong-passphrase'   # needed for hmac_ok=true

python scripts/sweep.py \
    --start-seed 5000 --seeds 20 \
    --templates timestomp,registry_persistence \
    --modes normal,provocateur \
    --out sweeps/repro.json
```

- `--start-seed 5000` and `--seeds 20` reproduce seeds 5000–5019 (`sweep.py:155`).
- Without `HEXBREAKER_HMAC_PASSWORD`, every run records `hmac_ok=null` /
  `"… unset — run UNSIGNED"` (`sweep.py:71-77`) and the result is **not** a signed
  artifact. Set it to get the `hmac_ok=true` the committed JSONs carry.
- Concurrency is 1 by design to respect the DeepSeek rate limit
  (`sweep.py:8-9`); wall time on the committed runs was ≈ 380–480 s total per file
  (from the `wall_s_total` in each JSON).

### 4.3 What you should — and should not — expect to match

- **WILL match (deterministic invariants):** `total_fp_planted = 0`; both
  `chain_ok` and `hmac_ok` true on every run (when `HEXBREAKER_HMAC_PASSWORD` is
  set); the same case files per seed/template; the normal mode meaningfully higher
  than provocateur mode.
- **WILL NOT match to the decimal (LLM-nondeterministic):** the exact `f1_mean`,
  `f1_stdev`, and the count of provocateur runs that confirmed a finding. DeepSeek
  is non-deterministic; the committed JSONs span 0.95 ↔ 0.975 (normal) and
  0.475 ↔ 0.525 (provocateur) across just two runs of the *same* command — that
  divergence is itself the proof, and is exactly the run-to-run variance the
  README warns about.

### 4.4 Running the sweep inside the container (optional, structural)

The image contains `scripts/` (`Dockerfile:51`) and all sweep dependencies
(`orjson` and the `hexbreaker` package), but the `ENTRYPOINT` is the CLI, not
`python`, so you must override it:

```bash
docker run --rm \
    -e DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY \
    -e HEXBREAKER_HMAC_PASSWORD='choose-a-strong-passphrase' \
    -v "$PWD/sweeps":/opt/hexbreaker/sweeps \
    --entrypoint python hexbreaker \
    scripts/sweep.py --start-seed 5000 --seeds 20 \
        --templates timestomp,registry_persistence \
        --modes normal,provocateur --out sweeps/repro.json
```

**Honest scope:** I did not run the full sweep here (it needs ~40 live LLM calls
per mode), and the committed JSONs carry no host-vs-container marker, so I do
**not** claim how they were produced. The native path (§4.2) is the one that
matches the committed command. The in-container invocation above is structurally
valid (the script and its imports resolve in the image; `load_env` is a harmless
no-op when no `.env` is present because the key comes from `-e`), but it is
presented as an option, not as a measured artifact. A container-produced sweep
JSON is **to be measured** if you need one to compare.

---

## 5. The NIST head-to-head number (status: withdrawn / future work)

For completeness, because the README references NIST: the earlier 95.08% F1 on the
NIST CFReDS Hacking Case was produced by `scripts/court_on_nist.py`, **withdrawn**
because that batched pipeline injected ground-truth answers into the prompt
(`README.md:10-16`). It is **not** part of the headline and is **not** reproducible
as a forensics result. A real Court-on-NIST measurement is explicitly future work.
Do not include the 95.08% number in any reproduction.

---

## 6. One-screen checklist

```text
[ ] git clone … && git checkout 548ec88
[ ] export DEEPSEEK_API_KEY=…            # for run/sweep only
[ ] docker build -t hexbreaker -f docker/Dockerfile .
[ ] generate (det.)  → manifest.json + answer_key.json   (no key)
[ ] run court (LLM)  → findings.json + transcript.jsonl   (NEEDS key)
[ ] score (det.)     → scorecard                          (no key)
[ ] verify (det.)    → chain OK on a self-generated case  (no key)
[ ] sweep            → native path, --start-seed 5000 --seeds 20,
                        DEEPSEEK_API_KEY + HEXBREAKER_HMAC_PASSWORD set;
                        expect fp_planted=0 and the normal≫provocateur pattern,
                        NOT the exact f1_mean.
```

If your sweep reproduces `total_fp_planted = 0`, signed chains on every run, and
the normal-mode-much-higher-than-provocateur pattern, you have reproduced the
*claim*. The exact F1 decimal is, and is documented to be, LLM-nondeterministic —
the committed `sweeps/*_N40_signed_audit.json` files are the artifacts of record.
