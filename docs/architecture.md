# Hexbreaker Architecture

Submission artifact #3 — the architecture with security boundaries.

## At a glance

Two products in one repo:

1. **Forge** — generative DFIR case synthesizer. `seed: int → manifest.json + answer_key.json + mock_outputs/`. Deterministic (same seed → byte-identical files); supports adversarial Provocateur mode at generation time.
2. **Court** — 5-role adversarial agent. Prosecutor + Defender + Witness + deterministic Judge (NO LLM) + Provocateur. Six layered safeguards prevent fabrication.
3. **Scorer** — deterministic strict-tuple match `(artifact_kind, target)` against the answer key. Sort-stable output JSON.
4. **Runner** — invokes Court on a generated Forge case OR on real disk evidence (see `scripts/court_on_nist.py` for the NIST adapter).
5. **HMAC chain** — PBKDF2 600K + HMAC-SHA256 per-transcript signature, MIT-licensed primitive ported from AppliedIR/Valhuntir.

## Pattern

**Find Evil! starter #3 — Multi-Agent Frameworks**, with the load-bearing twist: **the Judge is a deterministic Python function, not an LLM.** The Judge cannot hallucinate because the Judge cannot generate text. Every CONFIRMED verdict passes through `court/judge.py` rules JR-01..JR-N before becoming a finding.

## The 6 hallucination safeguards (all in code, none in prompt)

| Layer | What | Where in code | Test |
|---|---|---|---|
| 1. Step-ID referential integrity | Orchestrator owns the `S-NNN` namespace; cited IDs must exist in the transcript | `transcript.py` (assigns) + `court/validator.py` (checks) | `test_validator.py::test_verdict_rejected_on_fabricated_step_id` |
| 2. Forced tool-call FSM | Defender cannot emit a verdict before observing at least one tool since the claim | `court/orchestrator.py::CourtSession` state machine | `test_orchestrator.py::test_premature_verdict_is_rejected_but_session_stays_open` |
| 3. Strict JSON schema | Pydantic with `extra="forbid"`, regex on step_id (`^S-\d{3,}$`) and hash (`^sha256:[0-9a-f]{64}$`); parse failure auto-rejects | `court/schema.py` | `test_schema.py` (9 cases) |
| 4. SHA-256 hash chain | Every record's `this_hash` covers `prev_hash + canonical(content)`; tampering breaks the chain | `transcript.py::Transcript.append + verify` | `test_transcript.py::test_verify_detects_content_tampering` |
| 4+. Cited-hash cross-check | Verdicts cite both step_id AND stdout_hash; hash substitution attack rejected | `court/validator.py::_validate_reference` | `test_validator.py::test_verdict_rejected_on_hash_substitution` |
| 5. HMAC-SHA256 signing | PBKDF2 600K → 32-byte key → per-transcript HMAC over (chain_head, record_count). Detects append and truncation directly; a non-tail content edit is caught by the Layer-4 hash chain — `verify_signature` returns ok only if chain AND HMAC both pass. (The bare SHA chain alone is recompute-forgeable; tamper-evidence requires the HMAC.) | `court/hmac_chain.py` (Valhuntir MIT port) | `test_hmac_chain.py` (9 cases) |
| 6. Provocateur runtime role | One prompt-injection payload fired once per case; Judge JR-02 downgrades any Verdict (in any round) whose `challenge_text` echoes the payload's leak tokens (case/whitespace-insensitive match) | `court/provocateur.py` + `court/judge.py::jr_02_provocation_leak` | `test_provocateur.py` (7 cases) + `test_judge.py` (JR-02 evasion) |

**The principle**: *The model is allowed to think anything. It is only allowed to cite what the orchestrator can prove exists.*

## Security boundaries

| Boundary | Enforced by | Architectural or prompt-based? |
|---|---|---|
| Evidence read-only | A run writes only NEW artifacts (`transcript.jsonl` + `<transcript>.outputs/`) into the case dir; it never overwrites existing evidence files (manifest / answer_key / mock_outputs) | **Architectural** |
| MCP tool exposure | `hexbreaker.mcp.server` exposes one tool, `run_sift_tool`, whose `tool` arg is an enum of `SUPPORTED_TOOLS`; `run_tool` re-enforces the same gate server-side and returns hash-chained chain-of-custody, never raw output as "verified" | **Architectural** |
| Destructive command isolation | `SUPPORTED_TOOLS` frozenset; `subprocess.run(shell=False)`; tool name validated before exec | **Architectural** |
| Path traversal in case dirs | `CaseManifest.mock_outputs` field_validator rejects absolute / `..` / drive-letter paths; runtime `is_relative_to(case_path.resolve())` containment check | **Architectural** |
| Path traversal in transcript resume | `run_court_on_case` refuses pre-existing transcript.jsonl in case dirs; `_render_transcript` validates each sidecar path is `is_relative_to(transcript_dir)` | **Architectural** |
| Hallucination detection | Citation validator + deterministic Judge rules JR-01..JR-N + adversarial Provocateur (all 3 in code) | **Architectural** |
| Final accept/reject of finding | `court/judge.py::judge()` — pure Python function, no LLM | **Architectural** |
| Tamper detection on transcript | SHA-256 hash chain + per-transcript HMAC-SHA256 via PBKDF2-derived key | **Architectural** |
| Role-attributed reasoning | `Actor` enum on every StepRecord (Pydantic-enforced); each role writes its own transcript record | **Architectural** |

No prompt-based safety boundaries. Every guardrail is enforceable in Python.

### Tested for bypass

Each boundary above has a paired test that *attempts the bypass and asserts it fails*
(the criterion's "tested for bypass" prong). Full index: [`tests/bypass/README.md`](../tests/bypass/README.md).

| Boundary / guardrail | Bypass test (attempt → rejected) |
|---|---|
| Fabricated step_id citation | `test_validator.py::test_verdict_rejected_on_fabricated_step_id` |
| Hash-substitution on a cited step | `test_validator.py::test_verdict_rejected_on_hash_substitution` |
| Verdict before observing a tool (FSM) | `test_orchestrator.py::test_premature_verdict_is_rejected_but_session_stays_open` |
| Transcript content tampering | `test_transcript.py::test_verify_detects_content_tampering` |
| Sidecar-byte tampering | `test_transcript.py::test_verify_detects_sidecar_byte_tampering` |
| Full-chain recompute forgery | `test_hmac_chain.py::test_hmac_detects_full_chain_recompute_forgery` |
| Single-tool CONFIRM (corroboration) | `test_judge.py::test_jr01_downgrades_confirmed_with_single_tool` |
| Provocateur leak echoed in a verdict | `test_provocateur.py::test_jr02_downgrades_when_challenge_text_echoes_leak_token` |
| Path traversal in case `mock_outputs` | `test_forge_case.py::test_mock_outputs_rejects_dot_dot_traversal` |
| Path traversal via transcript sidecar | `test_security_transcript.py::test_render_transcript_refuses_traversal_stdout_path` |
| Poisoned pre-existing transcript in case dir | `test_security_transcript.py::test_run_court_refuses_preexisting_transcript_in_case_dir` |
| Unsupported/destructive tool name | `test_tools.py::test_run_tool_rejects_unsupported_tool` |
| Schema bypass (extra fields / bad ids) | `test_schema.py::test_verdict_extras_rejected` |

## Data flow on a single Court round

```
                            ┌────────────────────────────────────┐
                            │      HEXBREAKER FORGE              │
                            │   seed: int ─►                     │
                            │     manifest.json                  │
                            │     answer_key.json   ──[withheld] │
                            │     mock_outputs/*.csv             │
                            └─────────────────┬──────────────────┘
                                              │
                                              ▼  (analyst: `hexbreaker run --case ...`)
                            ┌────────────────────────────────────┐
                            │           RUNNER                   │
                            │   loads manifest, opens transcript │
                            │   refuses pre-existing transcript  │ ◄── Vuln 2 defense
                            │   builds mock_runner (containment) │ ◄── Vuln 1 defense
                            └─────────────────┬──────────────────┘
                                              │
   ┌──────────────────────────────────────────┼───────────────────────────────────────────┐
   │                                          │                                           │
   │   ┌──────────┐    ┌────────────┐   ┌─────▼──────┐    ┌──────────┐    ┌───────────┐  │
   │   │   TOOL   │───►│PROVOCATEUR │──►│ PROSECUTOR │───►│   TOOL   │───►│  DEFENDER │  │
   │   │ pre-pass │    │  Layer 6   │   │   Claim    │    │ defender │    │  Verdict  │  │
   │   │  MFTECmd │    │  payload   │   │  + cites   │    │   yara   │    │  + cites  │  │
   │   └──────────┘    └────────────┘   └────────────┘    └──────────┘    └─────┬─────┘  │
   │                                                                            │        │
   │                                                                            ▼        │
   │                                                                ┌───────────────────┐│
   │                                                                │      JUDGE        ││
   │                                                                │ JR-01 corroborate ││ ◄── deterministic
   │                                                                │ JR-02 leak detect ││     Python (NO LLM)
   │                                                                │ ─► UPHELD         ││
   │                                                                │ ─► DOWNGRADED     ││
   │                                                                └─────────┬─────────┘│
   │                                                                          │          │
   │                                                              CONTESTED?  │          │
   │                                                                  ┌───────▼────────┐ │
   │                                                                  │     WITNESS    │ │
   │                                                                  │ disjoint tools │ │
   │                                                                  └────────────────┘ │
   └─────────────────────────────────────────────┬──────────────────────────────────────┘
                                                 │
                                                 ▼  every step writes:
                            ┌────────────────────────────────────┐
                            │   transcript.jsonl                 │
                            │   • S-NNN step_id (orchestrator)   │
                            │   • prev_hash + this_hash (Layer 4)│
                            │   • Actor + Kind + content         │
                            │   • per-tool sidecar files         │
                            │                                    │
                            │   transcript.jsonl.sig             │
                            │   • PBKDF2 600K + HMAC-SHA256      │
                            │   • binds chain_head + record_count│
                            │   • hexbreaker verify --hmac       │
                            └────────────────────────────────────┘
```

## What runs where (deployment)

| Component | Where | Why |
|---|---|---|
| `hexbreaker generate/run/score/verify/sign` | Analyst's host (Linux/macOS/Windows with Python 3.11+) | No SIFT VM required for Forge cases; everything is in-process |
| `scripts/court_on_nist.py` | Analyst's host | Uses host's `fls/icat/mmls` + `python-registry` for hive parsing; no Zimmerman tools needed |
| DeepSeek API | `api.deepseek.com/v1/chat/completions` | OpenAI-compatible; httpx + tenacity 429-aware retry |
| SIFT VM | Not required for v1 | Real SIFT-tool integration (MFTECmd / vol / log2timeline) is supported but not used by the shipping configs |

## CLI surface

```
hexbreaker generate --seed N --template {timestomp,registry_persistence} [--provocateur] --out DIR
hexbreaker run --agent court --case DIR --out FINDINGS.json
hexbreaker score --findings FINDINGS.json --answer-key ANS.json
hexbreaker verify --transcript T.jsonl [--hmac]      # --hmac needs HEXBREAKER_HMAC_PASSWORD
hexbreaker sign --transcript T.jsonl                  # needs HEXBREAKER_HMAC_PASSWORD
```

## Reproducibility

Every Forge case is `byte-identical(seed) -> manifest.json + answer_key.json + mock_outputs/`. Every Court run is `(case, model, prompt_version) -> findings.json + transcript.jsonl + transcript.jsonl.sig`, all chain-validating. The scorer iterates sorted-set order so the score JSON is byte-stable across runs (post the Tier B fix in commit `29ddf2a`).

```bash
# Cross-host reproducibility check
hexbreaker generate --seed 4729 --out /tmp/a
hexbreaker generate --seed 4729 --out /tmp/b
sha256sum /tmp/{a,b}/manifest.json  # must match
sha256sum /tmp/{a,b}/answer_key.json  # must match
```
