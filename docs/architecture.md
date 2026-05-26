# Hexbreaker Architecture

**Status:** STUB. Full diagram + writeup lands Week 2 (Fri 6/6).

This document is **submission artifact #3** — the architecture diagram with security boundaries that judges read first.

## At a glance

Two products, one repo:

1. **Forge** — generative DFIR case synthesizer. Seed → synthetic disk image + answer key.
2. **Court** — 5-role adversarial agent. Prosecutor + Defender + Witness + deterministic Judge (non-LLM) + Provocateur.
3. **Scorer** — deterministic exact-match grading agent findings against the answer key.
4. **Runner** — invokes any DFIR agent (Court, dhyabi2/findevil, marez8505/find-evil, Valhuntir baseline, raw Protocol SIFT) on a generated case.
5. **Leaderboard** — aggregates ScoreReports across seeds × agents.

## Architectural pattern (per Find Evil! brief)

**#3 — Multi-Agent Frameworks**, with one important addition: the Judge is a **deterministic Python function**, not an LLM. The Judge cannot hallucinate because the Judge cannot generate text.

## Security boundaries (judges read this carefully)

| Boundary | Enforced by | Architectural or prompt-based? |
|---|---|---|
| Evidence read-only | Bubblewrap RO bind mount + OS file perms | **Architectural** |
| Destructive command isolation | CLI allowlist (Protocol SIFT's `settings.json` model) | **Architectural** |
| Hallucination detection | Adversarial Defender + Provocateur + deterministic Judge rules | **Architectural** |
| Final accept/reject of finding | Non-LLM `judge.evaluate(claim, evidence)` Python function | **Architectural** |
| Tamper detection on transcript | SHA-256 hash chain + HMAC-SHA256 per verdict | **Architectural** |
| Token-budget safety | Output truncation at MCP layer before LLM ingest | **Architectural** |
| Role-attributed reasoning | Schema-enforced `role` field on every CourtRecord turn | **Architectural** |

No prompt-based guardrails for any safety boundary.

## Diagram

ASCII placeholder; SVG version lands Week 2.

```
   ┌────────────────────────────────────────────────┐
   │                  HEXBREAKER FORGE              │
   │      seed → case manifest + answer key         │
   └───────────────────┬────────────────────────────┘
                       │
            ┌──────────┴──────────┐
            ▼                     ▼
   ┌────────────────┐    ┌────────────────┐
   │  RUNNER        │    │  SCORER        │
   │  invoke agents │    │  exact match   │
   └────────┬───────┘    └────────┬───────┘
            │                     │
   ┌────────┴──────────────────┐  │
   │        AGENTS              │ │
   │  - Hexbreaker Court        │ │
   │  - dhyabi2/findevil        │ │
   │  - marez8505/find-evil     │ │
   │  - Valhuntir baseline      │ │
   │  - Raw Protocol SIFT       │ │
   └────────┬──────────────────┘  │
            │                     │
            └────────┬────────────┘
                     ▼
            ┌────────────────┐
            │  LEADERBOARD   │
            └────────────────┘
```

Pending: full SVG with security boundaries colored, role contracts annotated, hash chain visible.
