# Hexbreaker

> Adversarial DFIR triage and benchmark for AI forensic agents.
> SANS **Find Evil!** hackathon submission, 2026.

**Status:** Work in progress. Build window 2026-05-26 → 2026-06-15.

---

## What it is

Two products, one submission:

1. **Hexbreaker Forge** — a generative DFIR benchmark. Synthesizes adversarial Find-Evil cases with provable ground truth from a seed, then deterministically scores any agent against the answer key.
2. **Hexbreaker Court** — a five-role adversarial forensic agent. Prosecutor, Defender, Witness, deterministic Judge (non-LLM), Provocateur (live prompt-injection red-team). Findings ship as CONFIRMED / CONTESTED / REJECTED, hash-chained and HMAC-signed.

The Forge is the headline product. The Court is the agent that runs on it — and gets graded by it like every other agent.

## Why this exists

The SANS Find Evil! hackathon exists because Protocol SIFT (the existing AI DFIR framework) hallucinates. Every submission claims accuracy. None ship ground truth. Hexbreaker is the oracle that grades the field.

## Try it out

```bash
# Coming soon. Target try-it surface:
docker run -v $(pwd)/case:/case hexbreaker run-all
```

## Architecture

See [`docs/architecture.md`](docs/architecture.md) — pending diagram.

## License

MIT. See [LICENSE](LICENSE).
