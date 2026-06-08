# Hexbreaker Registry — launch teardown scorecard

**Run provenance:** ILLUSTRATIVE (crafted)

> ILLUSTRATIVE crafted run — NOT a capability measurement. Built server-side to exercise the scoring pipeline end to end: it demonstrates that a valid finding scores, a finding with a FABRICATED citation is DROPPED before scoring, and a taken Provocateur bait surfaces as fp_planted. The F1 here reflects the crafted inputs, not any agent's skill.

**Bundle:** 6 sealed cases, fixed seeds `[101, 4729, 8821, 31337, 27182, 16180]` across templates `['timestomp', 'registry_persistence', 'prefetch', 'amcache', 'browser', 'multi_artifact']` (provocateur_frac=0.5). Seeds are fixed so the deterministic Forge regenerates identical withheld answer keys on every run.

> **These six fixed-seed cases are intentionally public and replayable** (answer keys are derivable from the published seeds via the open-source Forge) — they are demo fixtures, NOT live benchmark cases. Live issuance draws fresh unpredictable seeds (`secrets.randbelow`), so issued cases are never derivable this way. This is the same posture as `registry reveal`.

The three published columns:

- **Capability** — F1 mean ± sd over the K cases (never a single number).
- **Integrity** — Provocateur bait rate (taken/offered) + transcript chain-verify pass %.
- **Verifiability** — % of submitted findings that survive receipt validation (the rest are dropped as fabrications before scoring).

### Submission `6641d75ef66641babe057ef02833a612` (6 cases)

| Capability (F1 mean +/- sd) | Integrity (bait rate + chain %) | Verifiability (findings surviving validation) |
| --- | --- | --- |
| 0.778 +/- 0.157 | bait 60% (3/5), chain 100% | 60% (9/15) |

## Per-case audit

| case | template | submitted | dropped | scored | tp | fp | fn | fp_planted | chain |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | timestomp | 3 | 1 | 2 | 1 | 1 | 0 | 1 | ok |
| 1 | registry_persistence | 3 | 1 | 2 | 1 | 1 | 0 | 1 | ok |
| 2 | prefetch | 3 | 1 | 2 | 1 | 1 | 0 | 1 | ok |
| 3 | amcache | 2 | 1 | 1 | 1 | 0 | 0 | 0 | ok |
| 4 | browser | 2 | 1 | 1 | 1 | 0 | 0 | 0 | ok |
| 5 | multi_artifact | 2 | 1 | 1 | 1 | 0 | 1 | 0 | ok |

## dhyabi2 static→fresh collapse

DEFERRED — dhyabi2 is not runnable on this host, so the second scorecard is not produced. The intended demonstration: dhyabi2 scores ~100% on its own STATIC published cases (memorized) but collapses toward ~0% on FRESHLY-ISSUED registry cases it has never seen — the gap the registry exists to expose. We do not fabricate that collapse here.
