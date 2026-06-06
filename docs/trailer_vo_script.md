# Trailer voiceover script — record over `docs/trailer.mp4`

The trailer is **voice-ready**: no baked narration, a low music bed with headroom.
Record these lines to picture (timestamps are where each beat is on screen) and lay
your voice on top. Total runtime **50.6s** — aim to finish the close line by ~0:49.

**Delivery:** calm, low, certain. You're not selling — you're stating facts a skeptic
can check. Slow down on the proof beats; let the terminal breathe. The on-screen text
is *not* what you say — it's punch-words; your voice expands them, never reads them
verbatim.

| Time | On screen | Say (VO) |
|------|-----------|----------|
| 0:00–0:05 | a confident ✓ "CONFIRMED" finding flips to a red ✗ | "Every AI tool says it finds evil. None of them tell you when they're making it up." |
| 0:05–0:08 | "AI forensics has a trust problem." | *(beat — let it land)* |
| 0:08–0:13 | "A made-up finding isn't a miss. / It's a false accusation." | "In forensics, a confident wrong answer isn't a missed finding. It's a false accusation." |
| 0:13–0:16 | "What if it were built to catch itself?" | "So we built the opposite —" |
| 0:16–0:18 | **HEXBREAKER** forms | "Hexbreaker." |
| 0:18–0:28 | PROOF · self-correction (real terminal) | "Watch it confirm a finding on a single signal — then overrule itself, in code, before that finding ever reaches you. The judge is deterministic. The model never gets the last word." |
| 0:28–0:37 | PROOF · NIST .E01 4/4 (real terminal, verified) | "On the real NIST hacking-case disk, it recovers all four of the attacker's deleted tools. Four of four — and every step is hash-chained and signed, so you can verify it yourself." |
| 0:37–0:45 | stat wall (4/4 · 0/80 · F1 · 169 · 6 · 100%) | "Six case types. Zero baits taken across eighty adversarial runs. Every number committed and reproducible." |
| 0:45–0:50 | "Miss, don't lie." → repo | "Hexbreaker. Miss — don't lie." |

## Notes
- The music dips (has headroom) under the proof beats; your voice should sit comfortably.
- If a line runs long, cut words from the *middle*, never the claim. The numbers
  (4/4, 0/80, six) are load-bearing — keep them exact (they match the committed
  evidence; do not round or embellish).
- Honesty guardrails (same as the demo): never say "95%", never imply NIST precision
  is bait-resistance (it's a no-decoy recovery case), never claim free-form autonomy
  (the Judge is deterministic; tool selection is manifest-driven).
- Regenerate the trailer anytime: `AGG_BIN=/tmp/agg python3 scripts/build_trailer.py --out docs/trailer.mp4`
