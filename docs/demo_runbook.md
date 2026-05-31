# Demo Runbook — live terminal screencast (≤5 min)

**Rules (official):** a screencast of **live terminal execution with audio
narration**. Not slides. Public on YouTube/Vimeo/Youku. Must show the agent
against **real evidence** with **at least one self-correction sequence**.

Everything below is real and reproducible — no withdrawn numbers, no slides. Two
load-bearing beats: (1) the Court finding evil on the **real NIST disk** (4/4),
and (2) the **deterministic Judge self-correcting** a single-tool CONFIRM in code.

## Pre-flight (do OFF camera)

```bash
cd hexbreaker
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test,deepseek]"
export DEEPSEEK_API_KEY=...            # your key
export HEXBREAKER_HMAC_PASSWORD=demo   # so transcripts are signed on camera
# Confirm the NIST extracts are staged (the real-disk beat depends on them):
ls /tmp/nist-extracts/      # expect fls_recycler.txt + INFO2
```

Have two terminals: one clean for recording, one scratch. Font ≥ 16pt.

## Beat 1 — the problem (0:00–0:30, voice only over a clean prompt)

> "Find Evil! asks an AI agent to triage a forensic image without hallucinating.
> The hard part isn't finding artifacts — it's *not inventing them*. Hexbreaker is
> two things: Forge, a generative benchmark that makes cases no agent has seen, and
> Court, a five-role adversarial agent whose anti-hallucination guarantees live in
> Python, not in a prompt."

## Beat 2 — Forge generates an unseen case (0:30–1:15)

```bash
hexbreaker generate --seed 4729 --template timestomp --provocateur --out /tmp/case
ls /tmp/case /tmp/case/mock_outputs
```

> "One seed deterministically produces a full case: tool outputs, an answer key,
> and — because I passed --provocateur — a *planted* artifact designed to bait the
> agent into a false confirmation. Six artifact types ship: timestomp, registry
> persistence, browser, prefetch, amcache, and a multi-finding case."

## Beat 3 — the self-correction (THE required sequence) (1:15–2:45)

```bash
PYTHONPATH=src python scripts/demo_self_correction.py
```

This runs the real CourtSession + Judge (deterministic, no API). Narrate the output:

> "Watch the safeguard fire. The Defender — the LLM — CONFIRMS the artifact citing
> a single tool. That's exactly the bait-taking failure mode. But the verdict isn't
> final until the **Judge** sees it: a deterministic Python function, not a model.
> JR-01 requires two independent tool kinds to corroborate. It **downgrades the
> CONFIRMED to CONTESTED** — in code — and no finding is emitted. The model tried to
> over-claim; the architecture stopped it. That correction is recorded in the
> hash-chained transcript, and it verifies."

```bash
hexbreaker verify --transcript samples/self_correction/transcript.jsonl --hmac
```

> "Chain plus HMAC: valid. Every finding traces to the exact tool execution that
> produced it — and tampering breaks the signature."

## Beat 4 — real evidence: the NIST Hacking Case (2:45–4:15)

```bash
PYTHONPATH=src python scripts/court_on_nist_fsm.py --case-dir /tmp/nist_court/case
```

Narrate the summary it prints:

> "Now the real thing — the NIST CFReDS Hacking Case, an actual seized disk image.
> The Court runs on the real recycle-bin evidence and recovers all four of the
> attacker's deleted tools — WinPcap, Ethereal, LAL, NetStumbler — four of four,
> zero false positives. Honestly scoped: this is the recycle-bin question family,
> one of roughly thirty-one in the full case, reported as kind 'other'. No injected
> answers — an earlier ninety-five-percent number that came from prompt-injected
> hints is withdrawn. This is the genuine agent on genuine evidence."

## Beat 5 — the honesty close (4:15–4:50)

```bash
PYTHONPATH=src python scripts/brittleness.py --from-sweep sweeps/2026-05-30_N40_jr01b_signed.json
```

> "And when it fails, it fails the right way. Across eighty adversarial runs, every
> failure is a *miss* — zero false confirmations, zero baits taken. It would rather
> say nothing than lie. That's the whole thesis: an agent you can trust because it's
> built to be caught when it's wrong. Repo and full reproduction:
> github.com/Alexander-Sorrell-IT/hexbreaker."

## Recording checklist

- [ ] Pre-flight done off-camera; `DEEPSEEK_API_KEY` + `HEXBREAKER_HMAC_PASSWORD` set
- [ ] `/tmp/nist-extracts/` staged (Beat 4)
- [ ] One self-correction sequence shown live (Beat 3) — **the required element**
- [ ] Real evidence shown (Beat 4, NIST) — **the required element**
- [ ] Total ≤ 5:00
- [ ] No slides; terminal only; audio narration throughout
- [ ] Upload public to YouTube/Vimeo/Youku; put the URL in the Devpost form
- [ ] No copyrighted music / third-party trademarks

## Honesty guardrails (do NOT say on camera)
- Do **not** claim a Hexbreaker NIST F1 of 95% — it is withdrawn (prompt-injected).
- Do **not** present the Forge F1 as a single number — it's a range (≈0.95–0.975
  normal / ≈0.475–0.525 max-attack); say "around 0.95" or show the sweep.
- Beat 4's "4/4" is the recycle-bin family only — always say "1 of ~31 questions."
