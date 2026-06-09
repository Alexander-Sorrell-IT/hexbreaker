# PLAN — Hexbreaker Registry v1 (the un-gameable neutral DFIR agent scoreboard)

**Goal.** Turn the existing Forge (case generator) + Court (adversarial runner) + scorer +
HMAC/validator into a **neutral registry**: issue freshly-generated, *un-memorizable* cases to
any agent, score the returned run against a *withheld* answer key with cryptographic receipt
validation, and publish a 3-column scorecard — then reveal the seeds so anyone can replay the
result by math, not trust.

This is the one genuinely-unowned cell from `IPHONE_IDEA_BRIEF.md`: *fresh-per-run tasks +
score bound to signed receipts + deterministic (no-LLM) judge.* v1 is local-CLI; hosting is
deferred. Build happens on branch `registry-v1` — **`main` + the submission tag stay untouched.**

## The load-bearing correctness problem (read first)

The benchmark is worthless if the submitter can derive the answer key from what we hand them.
Two leaks to seal:

1. **`answer_key.json`** — already a separate file `court_runner` refuses to read. Sealing =
   *don't copy it into the issued bundle.* (trivial; verified in code.)
2. **`manifest.seed`** — the Forge is open-source (MIT), so a leaked seed lets the submitter
   run `generate --seed N` locally and reconstruct `expected_findings` exactly. **The seed must
   not appear in the issued bundle.** But `run_court_on_case` calls
   `emit_provocation(seed=manifest.seed)` *during the submitter's run* — so we cannot simply
   delete the seed or the Provocateur (Layer 6, the integrity column) breaks.

   **Design: precompute + ship the provocation, strip the seed.**
   - `CaseManifest.seed` → `int | None` (generation still sets the real int; issued bundles set
     `None`). Loader must tolerate `None`.
   - `run_court_on_case(...)` gains `provocation: Provocation | None = None`. If a case dir
     contains `provocation.json`, registry-mode loads it and passes it in; the runner uses it
     **instead of** `emit_provocation(seed=...)`. Non-registry path is byte-identical (param
     defaults to None → falls back to `emit_provocation(seed=manifest.seed)`).
   - The issued `provocation.json` is the *attack payload only*; it must contain **no**
     `expected_findings` target string. The Phase-1 verify agent proves this.

   **Cheat-resistance invariant (the test that defines v1 correctness):** given only an issued
   bundle (manifest with `seed=None`, mock_outputs, provocation.json; NO answer_key.json), there
   is no path to reconstruct `answer_key.expected_findings`. Prove by: (a) bundle contains no
   seed and no answer_key; (b) no `expected_findings` target substring appears anywhere in the
   issued files; (c) re-running `generate` is impossible without the seed.

## Module layout (new: `src/hexbreaker/registry/`)

- `bundle.py` — `issue(seeds, templates, provocateur_frac, out_dir) -> SubmissionId`. For each
  (seed, template): `forge.generate(seed, tmp, provocateur=…)`; precompute `provocation =
  emit_provocation(seed)`; write SEALED bundle dir `case_<idx>/` = manifest(seed=None) +
  mock_outputs/ + provocation.json; record `(seed, template, answer_key, provocation)`
  server-side via store. Returns submission id.
- `store.py` — SQLite at `--store` (default `./registry.db`). Tables:
  `submissions(id TEXT PK, created_ts, status)`,
  `cases(submission_id, idx, seed, template, answer_key_json, provocation_json)`,
  `results(submission_id, scorecard_json, revealed INT)`. (datetime/uuid from stdlib — fine in
  Python; only the JS orchestration script forbids Date.now.)
- `score.py` — `score_submission(submission_id, transcripts_dir, store) -> Scorecard`. Per case:
  locate the submitter's `transcript.jsonl` + findings; run `verify` (chain + HMAC if signed),
  `validator` (every cited step resolves to a TOOL_CALL whose stored stdout hash matches the
  cited hash — receipt validation), then `scorer.score(findings, answer_key)`. A finding whose
  citation fails validation is dropped BEFORE scoring (fabrication ≠ finding). Aggregate.
- `scorecard.py` — `Scorecard` model + `to_markdown()` + `to_html()`:
  - **Capability** = F1 mean ± sd over the K cases (never a single number).
  - **Integrity** = `fp_planted` rate (planted baits taken / planted offered) + chain-verify pass %.
  - **Verifiability** = % of CONFIRMED findings that survive receipt validation.
- `cli.py` (extend existing): `hexbreaker registry issue|score|board|reveal`.

## CLI surface

```
hexbreaker registry issue  --k 8 --templates timestomp,registry_persistence,prefetch,amcache,browser,multi_artifact \
                           --provocateur-frac 0.5 --out ./bundle_<id>/ --store ./registry.db
hexbreaker registry score  --submission <id> --transcripts ./submitted/ --store ./registry.db
hexbreaker registry board  --store ./registry.db --out ./board.html        # all scored submissions
hexbreaker registry reveal --submission <id> --store ./registry.db          # writes revealed seeds; enables replay
```

## Build phases (each: implement → run tests to GREEN → commit on registry-v1)

- **P1 — Seed-strip core + cheat-resistance.** `CaseManifest.seed: int|None`; `run_court_on_case`
  `provocation=` param + `provocation.json` fallback; sealed-bundle writer. New tests:
  `test_registry_cheat_resistance.py` (the invariant above) + provocation-injection parity
  (registry-mode run == seeded run for the same case). **Gate:** determinism tests still pass,
  full suite green, cheat test green.
- **P2 — Store + issue.** `store.py` + `bundle.issue()` + `registry issue` CLI. **Gate:** issuing
  K cases creates K sealed bundles (no answer_key.json, manifest.seed null) + store rows; a test
  asserts the seal.
- **P3 — Score.** `score.py` + `registry score` CLI. **Gate:** hermetic test (NO live API) using
  crafted/committed transcripts proves: a correct submission scores F1>0; a **fabricated-citation**
  submission has those findings dropped by validation; a **bait-taking** submission shows
  `fp_planted>0`. Verify agent confirms validation actually gates scoring.
- **P4 — Scorecard + board + reveal + replay.** `scorecard.py` render (md + html), `registry board`,
  `registry reveal`, replay check. **Gate:** board renders the 3 columns; a revealed seed re-run
  through `generate` reproduces a byte-identical case (sha256 match).
- **P5 — The launch teardown.** `scripts/registry_teardown.py`: issue a bundle, run the house Court
  through `registry score` (live API only if `HEXBREAKER_RUN_LIVE=1`; otherwise score committed
  sample transcripts), and if `dhyabi2` is runnable reproduce the **100% static → 0% fresh**
  collapse as two scorecards. **Gate:** emits a committed `samples/registry_demo/` scorecard;
  clearly labels what is live-measured vs deferred. Best-effort on dhyabi2 — report honestly.

## Constraints
- **No live API in tests.** Use committed sample transcripts + crafted findings. The LLM is not
  needed to test issue/seal/score/validate/scorecard logic.
- **Receipts are emitted at the tool-execution boundary** by our harness, never self-reported by
  the submitter. v1 keeps HMAC (we are the verifier); Ed25519 is a gated milestone *before* any
  public board (symmetric HMAC can't support independent third-party verification).
- **Surgical.** New code in `registry/`; the only edits to existing files are the two contained
  seed/provocation changes (`forge/case.py`, `runner/court_runner.py`) + CLI registration.
  Do not refactor unrelated code. Keep existing 175 tests green.

## Definition of done (v1)
`registry issue` → seal verified → a submission scored into a 3-column scorecard → `board` renders
it → `reveal` enables byte-identical replay → cheat-resistance + validation-gating proven by test →
full suite green → teardown artifact committed. All on `registry-v1`; `main`/tag untouched.

---

## Decision log

**2026-06-08 — v1 plumbing built; Capability axis flagged; Option 1 chosen.**
- v1 built & green (280 pass/5 skip): seed-strip, issue, store, receipt-gated score,
  3-column scorecard, board, reveal, byte-identical replay. Seed-replay cheat vector
  CLOSED; fabrication gated by receipt validation (skeptic-confirmed). Commits
  89efbd5→957326c on registry-v1.
- Adversarial P1 gate found the **Capability axis is non-discriminative**: secondary
  signals (yara/sysmon) fire only on the answer (self-labeling), and only the answer
  row carries the tell ($SI≠$FN) while decoys are clean (regex-able). The invariant
  "target never in evidence" is unsatisfiable; the real property is **answer
  indistinguishable from decoys except by the intended reasoning** (every signal that
  fires on the answer also fires on ≥1 decoy; decoys carry benign near-miss tells).
  Integrity + Verifiability axes are sound; only Capability needs the fix.
- **Alex chose Option 1 (reasoning-only / strict).** Next: the evidence-design pass
  across all 6 templates, gated by a CHEATER-GAP PROOF (a label/regex cheater must
  score ≈chance while an oracle applying the intended rule scores high). HARD-STOP on
  that gate — no "tests pass so it's done." Tracked in `BUILD_CHEATRESIST_PLAN` below
  / the build-cheat-resist workflow.
