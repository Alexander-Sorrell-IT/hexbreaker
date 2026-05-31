# Datasheet for Hexbreaker Forge

A "Datasheet for Datasets"–style description of **Hexbreaker Forge**, the generative
benchmark that produces the synthetic DFIR cases Hexbreaker (and, by design, any other
DFIR agent) is graded on.

This document follows the structure of Gebru et al., *Datasheets for Datasets* (2021):
Motivation → Composition → Collection / Generation Process → Recommended Uses →
Limitations → Maintenance → Distribution & License.

**Scope note.** This datasheet is about the *dataset generator* (`src/hexbreaker/forge/`)
and the cases it emits. It is not the accuracy report. Measured agent numbers live in
`docs/accuracy.md` and the committed `sweeps/*.json`; this datasheet cites them but does
not restate the full methodology. Where a number is not yet measured, it is labelled
**"to be measured"** rather than estimated.

---

## 1. Motivation

**Why was this benchmark created?**

The Find Evil! hackathon's premise is that AI forensic agents hallucinate, and that
existing public ground truth cannot reliably distinguish a robust agent from an overfit
one. There is essentially one public, labelled DFIR exam in common use — the **NIST
CFReDS Hacking Case** (documented in `docs/dataset.md` §2). When a whole community
converges on a single fixed case, agents converge on *that case's idiosyncrasies*
instead of on general forensic reasoning. `docs/accuracy.md` §4 documents the concrete
failure mode: a competitor agent that scaffolds heavily around the NIST disk
(`_pre_extract_hives` / `_pre_extract_artefacts`, hundreds of lines) self-reports 100%
F1 on NIST, yet the same pipeline scores 0% F1 when only the (model, host) conditions
change (re-measured in `sweeps/competitors/score_deepseek.json`).

Forge exists to provide the missing axis: **a stream of adversarial cases that no agent,
author, or judge has seen before**, generated on demand from a seed, each shipping its
own withheld ground-truth answer key. NIST measures whether your case-specific
*scaffolding* is correct; Forge measures whether your *architecture* is robust to inputs
no scaffolding can foresee. Forge complements NIST; it does not replace it.

**Who created it / funded it?** Built for the Find Evil! hackathon as part of the
Hexbreaker repository (MIT-licensed, see `LICENSE`).

**What gap does it fill that NIST does not?**

| Property | NIST CFReDS Hacking Case | Hexbreaker Forge |
|---|---|---|
| Number of distinct cases | 1 (fixed) | unbounded (one per seed × template × mode) |
| Agent has seen it before | almost always | never (novel per seed) |
| Ground truth | 31 free-form investigator Q&A | machine-checkable `(artifact_kind, target)` tuples |
| Real disk image | yes (the moat artifact — real evidence) | **no — synthetic tool output (see §5)** |
| Adversarial planted bait | no | yes (`--provocateur`) |
| Reproducible from a seed | n/a (a fixed image) | byte-identical from `(seed, template, provocateur)` |

The honest division of labour: **NIST is the only real-disk evidence in this project.**
Forge is synthetic infrastructure for measuring robustness, not a claim of real-world
ground truth.

---

## 2. Composition

### 2.1 What is an instance?

One Forge *case* is a directory produced by `hexbreaker generate`:

```
case-<seed>-<template>[-provoked]/
├── manifest.json      # what the case is; the tool calls; where mock outputs live — the agent reads this
├── answer_key.json    # ground truth; WITHHELD from the agent at run time, used only by the scorer
└── mock_outputs/
    ├── <tool>.csv / .txt   # pre-baked forensic-tool stdout the manifest references
    └── ...
```

The schemas are Pydantic models in `src/hexbreaker/forge/case.py`
(`CaseManifest`, `AnswerKey`, `ExpectedFinding`, `ToolInvocation`). An `AnswerKey`
carries three disjoint lists: `expected_findings` (must CONFIRM), `decoys`
(must REJECT — benign artifacts that share surface features with the real one), and
`planted` (must REJECT — adversarial bait; non-empty only in `--provocateur` mode).

### 2.2 Artifact-type templates

Forge ships **six template generators** (registered identically in
`src/hexbreaker/cli.py` and `scripts/sweep.py`). Five emit a single artifact kind; the
sixth (`multi_artifact`) is a **composite** that fuses two of the single-artifact legs
onto one host. The distinct `artifact_kind` values exercised are therefore **five**
(`timestomp`, `persistence`, `prefetch`, `amcache`, `browser`), drawn from the enum in
`src/hexbreaker/court/schema.py`.

Every template synthesizes the stdout of a real DFIR tool (Eric Zimmerman's MFTECmd /
PECmd / AmcacheParser / RECmd / EvtxECmd, `bulk_extractor`, `log2timeline.py`/plaso,
`yara`) — *not* a real disk image. Each has the **same honesty contract**: the one true
finding is corroborated by a *second, distinct tool* whose stdout literally names the
*same* target string, so the agent's "CONFIRMED requires ≥2 distinct tool kinds" rule
(Judge rule JR-01) is genuinely satisfiable. Decoys and planted entries deliberately
lack that second signal.

| Template id | `artifact_kind` | Primary tool (pre-pass) | Corroborator (defender step) | True finding target | Source |
|---|---|---|---|---|---|
| `timestomp` | `timestomp` | MFTECmd CSV — one row with divergent `$SI`/`$FN` created timestamps | `yara` hit on the same file | full Windows path of the backdated binary, e.g. `\Windows\System32\drivers\svchosts.exe` | `forge/template_timestomp.py` |
| `registry_persistence` | `persistence` | RECmd dump of `HKLM\…\CurrentVersion\Run` — one value in a user-writable path | `yara` hit on the binary | full `Run`-key path incl. value name | `forge/template_registry_persistence.py` |
| `prefetch` | `prefetch` | PECmd CSV — one executed binary in a user-writable path | `yara` hit on the same `FullPath` | the binary's `FullPath` | `forge/template_prefetch.py` |
| `amcache` | `amcache` | AmcacheParser CSV (`InventoryApplicationFile`) — one present/executed binary in a user-writable path, with SHA1 | `yara` hit on the same `FullPath` | the binary's `FullPath` | `forge/template_amcache.py` |
| `browser` | `browser` | `bulk_extractor` `url` feature file — a malicious URL carved from disk | `log2timeline.py` (plaso) web-history timeline naming the same URL | the malicious URL string | `forge/template_browser.py` |
| `multi_artifact` | `timestomp` **+** `persistence` (composite) | MFTECmd **and** RECmd (two primaries) | `yara` (timestomp leg) **and** EvtxECmd Sysmon EventID-13 (registry leg) | **two** distinct targets, one per leg | `forge/template_multi_artifact.py` |

Per-case composition (counts come straight from the generators):

- **Single-artifact templates** (`timestomp`, `registry_persistence`, `prefetch`,
  `amcache`, `browser`): 1 true finding + 4 decoys; `--provocateur` adds plants
  (1 plant for `prefetch`/`amcache`/`browser`; up to 2 for `timestomp`;
  up to 2 for `registry_persistence`).
- **`multi_artifact`**: 2 true findings + 3 timestomp decoys + 3 persistence decoys;
  `--provocateur` adds up to 2 plants (one per leg).

### 2.3 The `--provocateur` flag (dataset-level adversarial mode)

`--provocateur` is the *data composition* knob: when set, the generator adds entries to
`answer_key.json["planted"]` and the corresponding rows to the synthetic tool output.
A plant carries the **same primary signal** as the true finding (a suspicious path, a
timestomp signature, a carved URL) but **lacks the corroborating second-tool hit** — it
is engineered to look exactly like the real evidence to a careless reader. Confirming a
plant is the single strongest signal of safeguard failure, because the bait was designed
to be confirmed; the scorer tracks it separately as `FP_PLANTED`
(`src/hexbreaker/scorer/exact_match.py`, `FindingClass.FP_PLANTED`).

> **Two different "provocateurs" — do not conflate them.** This `--provocateur` *flag*
> is dataset-side (it changes what is in the case files). There is a separate,
> *Court-harness-side* runtime adversary, `src/hexbreaker/court/provocateur.py`, which
> emits one of five prompt-injection payload categories per round
> (`base64_injection`, `false_mitre`, `timestamp_swap`, `authority_impersonation`,
> `anchored_false_positive`) and is policed by Judge rule JR-02. That runtime injector
> is **not part of the dataset**; it is part of how the Court agent is stress-tested.
> A different agent consuming Forge cases sees only the planted *data*, not the Court's
> runtime payloads.

### 2.4 Labels / ground truth

The label for each instance is its `answer_key.json`. Labels are exact strings the agent
must reproduce verbatim from tool output; the scorer
(`src/hexbreaker/scorer/exact_match.py`) does **strict, case-sensitive
`(artifact_kind, target)` tuple equality** — any deviation is counted as a defect, not
forgiven. There is no held-out/test split: every case is freshly generated, so "unseen"
is guaranteed by construction rather than by partitioning.

### 2.5 Is anything in the data real / sensitive?

No. All paths, hashes, URLs, and timestamps are synthetic and generated from a seeded
RNG. SHA1/SHA-256 values are derived from the synthetic path strings, not from real
files (`forge/template_amcache.py::_sha1`). The data contains no PII and no real malware.
The "malicious" names (typosquats, homoglyph URLs) are fictional constructions.

---

## 3. Collection / Generation Process

### 3.1 How a case is produced

```bash
hexbreaker generate --seed 4729 --template timestomp --out ./case_a
hexbreaker generate --seed 4729 --template timestomp --provocateur --out ./case_b
```

Each generator is a pure function of `(seed, provocateur)`: it constructs a
`random.Random(seed)`, draws an evil artifact, decoys, and (optionally) plants from fixed
pools, synthesizes the tool-output CSV/feature files, **shuffles row order** so position
is not a confound, and writes `manifest.json` / `answer_key.json` via `orjson` with
sorted keys. No network, no external state, no real disk.

### 3.2 Determinism contract (verified)

The contract is: `generate(seed, …)` must produce **byte-identical** files across runs.
This is what makes a Forge result reproducible and citable. It is enforced by
per-template tests and re-verified here:

- **Five** dedicated determinism test modules pass (`65 passed` across
  `tests/test_template_{timestomp,prefetch,amcache,browser,multi_artifact}.py`).
- **`registry_persistence` has no dedicated determinism test module.** Its
  byte-determinism is spot-checked in this datasheet instead (below), and it is
  exercised end-to-end by the N40 signed sweeps (§4.2).
- Independent spot checks (this datasheet): two `browser` generations from
  `--seed 4729` produced identical `sha256(manifest.json)` (`01ffb480…9d5ee2`), with
  the `--provocateur` run flipping `answer_key.json["planted"]` from 0 → 1 entry as
  designed; two `registry_persistence` generations from `--seed 4729` likewise produced
  identical `sha256` of both `manifest.json` (`c6887d11…ffd0ef`) and `answer_key.json`
  (`7bcde25f…6bc35b`), with `--provocateur` adding 2 plants.

### 3.3 Why the position-shuffle matters (a real bug that was fixed)

Early `timestomp` cases always placed the evil row at index 0. An agent biased toward
"pick row #1" scored F1 = 1.0 *without doing forensic reasoning*. The generators now
shuffle row order (see the `rng.shuffle(rows)` comments in each template), removing row
position as a shortcut. This is documented in `docs/dataset.md` §3 (the
pre-/post-shuffle sweep pair) and is why the honest baseline differs from the first run.

---

## 4. Recommended Uses

### 4.1 What Forge is for

- **Robustness measurement on unseen cases.** Generate N seeds the agent has never seen,
  run the agent, score against the withheld answer key. The headline use in this repo:
  `scripts/sweep.py` runs Court across seeds × templates × `{normal, provocateur}` modes
  and emits per-run + aggregate F1, precision, recall, and `fp_planted`.
- **Bait-resistance measurement.** `--provocateur` + the `FP_PLANTED` counter directly
  quantify whether an agent confirms engineered bait.
- **Accuracy-under-load measurement.** `multi_artifact` + `max_rounds > 1` measures
  whether an agent still gets *both* findings right on a noisier two-attack host.

### 4.2 Measured results in this repo (what is actually graded today)

The honest measured/unmeasured split — **"6 templates" does not mean "6 measured
templates."** Determinism is verified for all six; *agent F1* has only been swept for
three.

| Template | Determinism test passing? | Court F1 swept? | Where |
|---|---|---|---|
| `timestomp` | yes | **yes** — N40 signed, two sweeps | `sweeps/2026-05-28_N40_signed_audit.json`, `sweeps/2026-05-29_N40_signed_audit.json` |
| `registry_persistence` | yes (spot-checked; no dedicated test module) | **yes** — included in the same N40 signed sweeps | same as above |
| `multi_artifact` | yes | **yes** — N20 (`max_rounds=3`) | `sweeps/2026-05-29_C2_multi.json` |
| `prefetch` | yes | **no — to be measured** | (determinism only: `tests/test_template_prefetch.py`) |
| `amcache` | yes | **no — to be measured** | (determinism only: `tests/test_template_amcache.py`) |
| `browser` | yes | **no — to be measured** | (determinism only: `tests/test_template_browser.py`) |

Measured numbers (DeepSeek is non-deterministic, so the two N40 sweeps are reported as a
**range**, and both are artifacts of record):

- **`timestomp` + `registry_persistence`, N40 each mode, HMAC-signed:**
  F1 ≈ **0.95–0.975** normal / ≈ **0.475–0.525** under maximum adversarial pressure,
  with **`fp_planted = 0` across all 80 provocateur runs** and **160/160 chain+HMAC
  verified** (`2026-05-28_N40_signed_audit.json` reports 0.975/0.525;
  `2026-05-29_N40_signed_audit.json` reports 0.95/0.475).
  **Caveat preserved from the README/accuracy report:** in each sweep the agent
  confirmed *something* in only ~19–21 of 40 provocateur runs (and found nothing in the
  rest); bait-resistance (0 planted confirmed) is demonstrated on the runs where the
  agent actually had the opportunity to take bait, not robustly across all 40 runs.
- **`multi_artifact`, N20 (10 seeds × 2 modes), `max_rounds=3`, HMAC-signed**
  (`sweeps/2026-05-29_C2_multi.json`, 20/20 chain+HMAC verified): both true artifacts
  surfaced in 13/20 runs; provocateur arm **precision 1.0 / recall 0.85 / F1 0.9 /
  `fp_planted = 0/10`**; normal arm F1 0.893.

### 4.3 Reusability — design intent vs. what is wired today

Forge is *designed* to grade any DFIR agent, not just Hexbreaker's Court. The properties
that make that real and honest are already in the code: deterministic generation from
`(seed, template, provocateur)`, a `answer_key.json` withheld at run time, and a strict
`(artifact_kind, target)` scorer that is agent-agnostic (it scores a list of findings, it
does not care who produced them).

**What is not yet wired (stated plainly so the reuse claim is not overstated):**
- `hexbreaker run --agent <x>` currently rejects every agent except `court`
  (`src/hexbreaker/cli.py`: *"agent … not implemented yet — only 'court'"*). A general
  agent adapter is not implemented.
- `hexbreaker leaderboard` raises `not implemented … (planned post-submission)`.
- To grade a third-party agent today, you must produce a findings list in the scorer's
  shape yourself and call `hexbreaker score --findings … --answer-key …`. The contract
  is reusable; the turnkey multi-agent harness is future work.

---

## 5. Limitations

1. **Synthetic, not a real disk.** This is the single most important limitation. Forge
   emits *pre-baked tool stdout*, not a mountable disk image. It therefore measures an
   agent's *reasoning over tool output* and its *bait-resistance*, **not** its ability to
   acquire, mount, carve, or parse real evidence. An agent that is excellent on Forge has
   not been shown to handle a real `.E01`. **Only the NIST CFReDS Hacking Case
   (`docs/dataset.md` §2) is real-disk evidence in this project.**

2. **Forge is not real-world ground truth.** A high Forge F1 is evidence of robustness on
   *this synthetic distribution*, not of real-world DFIR accuracy. Do not report a Forge
   number as a real-evidence accuracy claim. (The repository's only attempted
   Court-on-real-NIST F1, the former "95.08%", is **withdrawn** — see
   `docs/accuracy.md` §3.2.1 — because that pipeline injected ground-truth answers into
   the prompt; it measured string-copying, not forensics. This datasheet quotes **no**
   Hexbreaker NIST F1.)

3. **Pools are small and curated.** Each template draws from ~8–10 hand-written
   suspicious/benign names per pool. An agent could in principle memorize the pools.
   The shuffle defeats *position* shortcuts but not *vocabulary* shortcuts; novelty is in
   the combination and corroboration structure, not in an unbounded vocabulary.

4. **Three templates are unmeasured against an agent (§4.2).** `prefetch`, `amcache`, and
   `browser` have a verified determinism contract but **no Court F1 sweep yet** — their
   agent-difficulty is *to be measured*. Treat them as generators that are known to
   produce valid, reproducible cases, not as templates with established difficulty.

5. **Single LLM, non-deterministic.** All measured numbers used DeepSeek; F1 varies
   run-to-run, which is why ranges are reported. Forge itself is deterministic; the agent
   under test is not.

6. **Corroboration is by tool *kind*, not per-target relevance.** The Court's JR-01
   counts ≥2 distinct tool kinds cited; the per-target referential-relevance rule
   (JR-02-relevance) is queued (`docs/accuracy.md` §2.4 final bullet). Forge cases are
   *constructed* so that the honest answer satisfies JR-01, but the scorer/judge do not
   independently verify that each citation is about the specific target.

---

## 6. Maintenance

- **Where it lives.** `src/hexbreaker/forge/` (generators + `case.py` schema); registered
  in `src/hexbreaker/cli.py` and `scripts/sweep.py`. Tests in `tests/test_template_*.py`.
- **Adding a template.** Implement `generate(seed, out_dir, *, provocateur=False) ->
  CaseManifest` following the honesty contract in §2.2 (one true finding with a genuine
  second-tool corroborator; decoys and plants lacking it), register it in the two
  `TEMPLATES` dicts, and add a determinism test. Run `pytest tests/test_template_*.py`.
- **Versioning.** Cases embed `seed`, `template`, and the `case_id`
  (`case-<seed>-<template>[-provoked]`). Reproducibility is the contract: a committed
  sweep JSON + the generator code regenerates the exact cases.
- **Errata.** `docs/dataset.md` §1.2 is *stale* — it lists only 2 templates and
  "three more planned." The current authoritative template list is the table in §2.2 of
  this datasheet (6 templates, all implemented). The withdrawn NIST 95.08% (see §5 item 2)
  is the other known erratum and is already corrected in `docs/accuracy.md`.
- **Contact / owner.** Hexbreaker repository maintainers (Find Evil! hackathon
  submission).

---

## 7. Distribution & License

- **License.** MIT (the Forge generator is part of the Hexbreaker repo; see `LICENSE`).
  Generated cases inherit MIT.
- **Distribution.** The generator is distributed as source; cases are generated on
  demand, not shipped as a fixed corpus. A handful of sweep outputs are committed under
  `sweeps/` as replayable artifacts of record.
- **External dependency.** The NIST CFReDS Hacking Case referenced for the real-disk
  comparison is a US-Government public-domain forensic sample (NIST CFReDS); attribution
  and acquisition steps are in `docs/dataset.md` §2 and §4.

---

## 8. Provenance of every claim in this datasheet

| Claim | Grounded in |
|---|---|
| 6 templates, 5 distinct artifact kinds, `multi_artifact` is composite | `src/hexbreaker/cli.py` + `scripts/sweep.py` `TEMPLATES`; `forge/template_*.py`; `court/schema.py::ArtifactKind` |
| Per-case decoy/plant counts | the generator bodies in `forge/template_*.py` |
| Honesty contract (≥2 distinct tools, same target) | module docstrings in each `forge/template_*.py`; `court/judge.py` JR-01 |
| `--provocateur` plants tracked as `FP_PLANTED` | `forge/case.py::AnswerKey.planted`; `scorer/exact_match.py::FindingClass.FP_PLANTED` |
| Runtime provocateur ≠ dataset provocateur (5 payload categories) | `court/provocateur.py` |
| Strict `(artifact_kind, target)` scoring | `scorer/exact_match.py` |
| Determinism verified (5 dedicated test modules pass; browser + registry_persistence sha256 spot-checked) | `pytest tests/test_template_{timestomp,prefetch,amcache,browser,multi_artifact}.py` (65 passed); spot checks in this datasheet (§3.2) |
| Measured F1 ranges + `fp_planted=0` | `sweeps/2026-05-28_N40_signed_audit.json`, `sweeps/2026-05-29_N40_signed_audit.json`, `sweeps/2026-05-29_C2_multi.json`; `docs/accuracy.md` §2.4 |
| `prefetch`/`amcache`/`browser` agent-unmeasured | absence from all committed `sweeps/*.json` (verified) |
| NIST is the only real-disk evidence; 95.08% withdrawn | `docs/dataset.md` §2; `docs/accuracy.md` §1.2, §3.2.1 |
| `run --agent` non-court rejected; `leaderboard` unimplemented | `src/hexbreaker/cli.py` |
