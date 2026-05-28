# Competitor analysis

Independent research, 2026-05-27. Spawned `general-purpose` agents to read each competitor's repo cold and report architecture + threat assessment + recommended response.

## dhyabi2/findevil

**Architecture:** IABF (Iterative Assumption-Based Framework). 4 phases per iteration: narrative → hypothesis → parallel investigation → feedback loop. Uses MCP server wrapping ~30+ SIFT tools.

**LLM:** Configurable (openrouter, openai, anthropic, ollama). Tested against Gemma 4 31B as default.

**Eval methodology:** 31-question token-substring scorer (`scripts/score.py`) against `reports/ground_truth/hacking_case.json`. Generous matching (substring in `root_cause + confirmed_findings + final_narrative`).

**Published number:** F1=100% (31/31 confirmed, 0 hallucinations) on NIST Hacking Case with Gemma 4 31B on SIFT.

**Our independent measurement (this report, §3 of accuracy.md):** F1=0% with DeepSeek V4-flash on Ubuntu 24.04 host. 90 LLM calls, 353K tokens, 15 iterations, zero confirmed findings. Root cause: `_pre_extract_hives` hardcodes `dotnet /opt/zimmermantools/RECmd/RECmd.dll` (SIFT path) AND DeepSeek's tool-command output contained unresolved `<INODE>` placeholders.

**Differentiator vs Hexbreaker:** their NIST-specific pre-pass scaffolding (`_pre_extract_hives`, `_pre_extract_artefacts`, iabf.py:997-1400, ~400 LOC) vs our generative Forge.

**Threat level:** High (only competitor with a published 100% number) but architecturally orthogonal. Different optimization targets.

**Action:** Cited as the benchmark target. Their NIST methodology is reused via `scripts/competitors/dhyabi2_score.py` for cross-comparison.

---

## marez8505/find-evil

**Architecture:** Phase scheduler (`agent/loop.py`) firing `claude --print --output-format json` subprocess for each of 5 fixed phases (triage, disk timeline, memory, persistence, correlation). Flask web GUI (`web/app.py`) for case mgmt. Claude subprocess talks to stdio MCP server wrapping SIFT tools.

**LLM:** **Hardcoded to Anthropic Claude via `claude` CLI binary + `~/.claude/.credentials.json`.** Not swappable to DeepSeek/Gemma without rewriting `run_claude_phase()` and reimplementing MCP tool-calling.

**Input:** Mounted `.E01` + optional `.raw` memory dump + per-case `CLAUDE.md` context file.

**Eval methodology:** `validator/score.py` with SequenceMatcher fuzzy match (>=0.70) against ground-truth JSON. **Shipped ground truth is a stub with `REPLACE_WITH_ACTUAL_SHA1` placeholders** — no published benchmark case.

**Differentiator:** Operational/security hardening. MCP server physically blocks `rm/dd/curl/ssh`, parses all tool output to JSON before LLM ingest, SHA256-logs every call, hardened Flask GUI with bcrypt+CSRF+CSP+rate-limiting on 127.0.0.1.

**Threat level:** Medium, on orthogonal axes. They compete on hardening polish; we compete on architectural audit guarantees + generative benchmark.

**Action:** **Cannot run head-to-head** — they're locked to Anthropic, so a DeepSeek bake-off is impossible. Hedge by ensuring our submission explicitly documents (a) read-only evidence handling, (b) per-tool audit log with output hashes, (c) usability/CLI story — so "Constraint Implementation" and "Audit Trail Quality" judging criteria don't see marez8505 as the only entry that took those criteria seriously.

---

## AppliedIR/Valhuntir (organizer reference)

**Architecture:** Examiner-driven IR. CLI (`vhir`) orchestrates LLM via MCP gateway (`sift-gateway:4508`) to 7-8 stdio backends (forensic-mcp, case-mcp, report-mcp, sift-mcp, forensic-rag, windows-triage, opencti, optional opensearch-mcp). Findings stage DRAFT, only become APPROVED via human commit (Examiner Portal UI or `vhir approve`), HMAC ledger entry written at approval time.

**HMAC `verification.py`:** **MIT-licensed** (Copyright 2026 AppliedIncidentResponse.com). Clean to port with attribution.
- **Algorithm**: `pbkdf2_hmac("sha256", password.encode(), salt, 600_000)` → 32-byte key; per-entry `hmac.new(key, content.encode("utf-8"), sha256).hexdigest()`
- **What's signed**: per-finding `content_snapshot` only — NOT whole transcript / NOT Merkle chain
- **Validation**: `hmac.compare_digest()` (constant-time, lines 95/138)
- **Storage**: `/var/lib/vhir/verification/{case_id}.jsonl`, mode 0o700/0o600, fsync'd, atomic temp+rename
- **Path traversal**: guarded via `_validate_case_id`
- **Key rotation**: `rehmac_entries` (re-verify under old key then re-sign with new)

**LLM:** Fully swappable. Discipline at gateway/MCP layer, not in prompts.

**Input:** Not disk-image-in/report-out. `vhir case init` + `vhir register-evidence` (hashes files); LLM drives ingest via MCP (15 parsers: evtx, EZ Tools, Volatility 3, Plaso, etc.). Requires SIFT VM (16-32 GB).

**Eval methodology:** None. Zero hits on `scoring|ground_truth|NIST|nps|m57|hacking-case`. Examiner tool, not a benchmark.

**Differentiator vs Hexbreaker:** Massive parser library (15 parsers, 73-100 MCP tools), real OpenSearch indexing at 50M-record scale, Hayabusa+Sigma auto-detection, 22K-record forensic RAG, 2.6M-record Windows triage baseline, polished Examiner Portal UI, full SIFT/REMnux deployment.

**Threat level:** Highest production-feel polish; lowest direct competition (different category — they're examiner-tooling, we're autonomous agent).

**Actions:**
- **Port HMAC pattern**: YES. MIT-licensed, exact match to our Layer 5 spec, surgical 165-line module, drop-in with attribution. Note: per-finding only — extend if we want whole-transcript signing.
- **Run head-to-head**: NO. No ground truth, no scorer, fundamentally examiner-driven.
- **Borrow**: their forensic-knowledge YAML reminders pattern (per-tool caveats injected at MCP response time, not system prompt) for our Forge prompts. Their 15-parser list as Hexbreaker ingest-scope coverage checklist.
