# Dataset Documentation

Submission artifact #5. Documents every dataset Hexbreaker generates or consumes during evaluation.

---

## 1. Hexbreaker Forge — generative synthetic cases

| Field | Value |
|---|---|
| **Type** | Synthetic Windows DFIR artifacts |
| **Generation** | `hexbreaker generate --seed N --template T [--provocateur] --out DIR` |
| **Determinism** | byte-identical from `(seed, template, provocateur_flag)` |
| **License** | MIT (the Forge generator is part of the Hexbreaker repo) |
| **Ground truth** | `<case_dir>/answer_key.json` (Pydantic schema in `src/hexbreaker/forge/case.py`) |
| **Scorer** | `src/hexbreaker/scorer/exact_match.py` — strict `(artifact_kind, target)` tuple equality |

### 1.1 Case directory layout

```
case-<seed>-<template>/
├── manifest.json          # what the case contains; agent reads this
├── answer_key.json        # ground truth; WITHHELD from agent at run time
└── mock_outputs/
    ├── <tool>_<args>.csv  # pre-baked forensic tool output (CSV / text)
    └── ...
```

### 1.2 Case template registry (6 templates ship)

| Template id | Artifact kind | Synthesizes | Expected finding |
|---|---|---|---|
| `timestomp` | `timestomp` | MFTECmd CSV with one row whose `$STANDARD_INFORMATION.Created` (`Created0x10`) diverges from `$FILE_NAME.Created` (`Created0x30`) by 5+ years, plus 4 decoy entries with matching timestamps. Optional Provocateur mode plants 2 additional rows with timestomp signatures but no yara confirmation. | full Windows path of the timestomped binary, e.g. `\Windows\System32\drivers\mssecsvc2.exe` |
| `registry_persistence` | `persistence` | RECmd dump of `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` with one malicious value pointing at a user-writable path, 4 legitimate decoys (Adobe Updater, OneDrive, MSEdge, etc.), Provocateur mode adds 2 plants. | full HKLM path including value name, e.g. `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\svchosts_loader` |
| `multi_artifact` | `timestomp` + `persistence` | fuses a timestomp leg (MFTECmd) and a registry Run-key leg (RECmd + EvtxECmd Sysmon EventID-13 naming the same key) into one case for multi-finding load; Provocateur adds a corroborator-less plant. | both leg targets (full MFT path **and** full HKLM Run-key path) |
| `browser` | `browser` | bulk_extractor + log2timeline both naming the same malicious URL. | full URL of the malicious browser artifact |
| `prefetch` | `execution` | PECmd + yara on the same executed binary. | full path of the executed binary |
| `amcache` | `execution` | AmcacheParser + yara on the same path. | full path of the amcache-recorded binary |

Each true artifact has genuine per-target corroboration from two distinct tool kinds.
**Honest scoring caveat:** on the breadth sweep (`sweeps/2026-05-30_breadth3_signed.json`)
`browser` scores F1≈0.9, but `prefetch`/`amcache` score ≈0 — a *target-format* gap
(the agent confirms the correct artifact but emits a short name vs the answer-key's full
path), not a detection failure. Per-template prompt tuning to close it is post-submission
work; see [accuracy.md](accuracy.md).

### 1.3 Answer-key schema

```json
{
  "case_id": "case-004729-timestomp",
  "template": "timestomp",
  "expected_findings": [
    {"artifact_kind": "timestomp", "target": "\\Windows\\System32\\drivers\\mssecsvc2.exe",
     "must_have_verdict": "CONFIRMED",
     "note": "$SI=2019-... $FN=2026-..."}
  ],
  "decoys": [
    {"artifact_kind": "timestomp", "target": "\\Windows\\System32\\ntoskrnl.exe",
     "must_have_verdict": "REJECTED",
     "note": "normal entry with matching $SI/$FN"}
  ],
  "planted": [  // key always present; non-empty iff --provocateur
    {"artifact_kind": "timestomp", "target": "\\Windows\\System32\\wininit.exe",
     "must_have_verdict": "REJECTED",
     "note": "planted: timestomp signature but no yara hit"}
  ]
}
```

### 1.4 Determinism check (reproducibility)

```bash
hexbreaker generate --seed 4729 --template timestomp --out /tmp/a
hexbreaker generate --seed 4729 --template timestomp --out /tmp/b
sha256sum /tmp/{a,b}/manifest.json     # must be identical
sha256sum /tmp/{a,b}/answer_key.json   # must be identical
```

Verified by `tests/test_template_timestomp.py::test_generate_is_deterministic_from_seed`.

---

## 2. NIST CFReDS Hacking Case (external public dataset)

Used for the head-to-head measurement vs `dhyabi2/findevil` under hackathon constraints.

| Field | Value |
|---|---|
| **Source** | https://cfreds-archive.nist.gov/Hacking_Case.html |
| **Owner / publisher** | NIST CFReDS (US National Institute of Standards and Technology) |
| **License** | NIST CFReDS public-domain forensic samples |
| **Image format** | EnCase EWF (`.E01` + `.E02`) |
| **Image file 1** | `4Dell_Latitude_CPi.E01` — 671,094,597 bytes |
| **Image file 2** | `4Dell_Latitude_CPi.E02` — 419,384,951 bytes |
| **SHA256 E01** | `96bebe80f00541bf28fbc2ef0b02b580082ee6ad58837e991852ae66f077ec31` |
| **SHA256 E02** | `46bd09821dbb64675e5877d0ad7ec544a571fad5a3fd7fc3f0c3a16278887db5` |
| **Embedded MD5 (per ewfverify)** | `aee4fcd9301c03b3b054623ca261959a` |
| **Scenario** | Dell Latitude CPi notebook abandoned with PCMCIA wireless card + homemade 802.11b antenna. Suspected wardriving by "Mr. Evil" / Greg Schardt. |
| **Ground truth** | 31 investigator Q&A pairs, sourced from `dhyabi2/findevil/reports/ground_truth/hacking_case.json` (MIT, used with attribution; their question list is the canonical NIST exam) |
| **Scorer** | `dhyabi2/findevil/scripts/score.py` (MIT) — token-substring match against expected-answer strings, per-question TP/TP_inferred/FN/FP |

### 2.1 Acquisition

```bash
mkdir -p datasets/nist-hacking-case && cd datasets/nist-hacking-case
curl -L -o 4Dell_Latitude_CPi.E01 'https://cfreds-archive.nist.gov/images/4Dell%20Latitude%20CPi.E01'
curl -L -o 4Dell_Latitude_CPi.E02 'https://cfreds-archive.nist.gov/images/4Dell%20Latitude%20CPi.E02'
sha256sum 4Dell_Latitude_CPi.E0?    # match published values above
```

Total download: ~1.1 GB. Verified via `ewfverify 4Dell_Latitude_CPi.E01` (the E01 carries the original embedded MD5).

### 2.2 Extraction

```bash
# Mount EWF as a raw image (no SIFT VM required; libewf-tools on Ubuntu/Debian)
sudo apt install ewf-tools
mkdir -p /tmp/nist-ewf-mount
ewfmount datasets/nist-hacking-case/4Dell_Latitude_CPi.E01 /tmp/nist-ewf-mount

# Partition layout: single NTFS at offset 63 sectors
mmls /tmp/nist-ewf-mount/ewf1

# Extract registry hives + irunin.ini + Mr. Evil's NTUSER (no Zimmerman tools needed)
mkdir -p /tmp/nist-extracts
icat -o 63 /tmp/nist-ewf-mount/ewf1 336   > /tmp/nist-extracts/SOFTWARE
icat -o 63 /tmp/nist-ewf-mount/ewf1 334   > /tmp/nist-extracts/SYSTEM
icat -o 63 /tmp/nist-ewf-mount/ewf1 3667  > /tmp/nist-extracts/SAM
icat -o 63 /tmp/nist-ewf-mount/ewf1 345   > /tmp/nist-extracts/NTUSER_MrEvil.DAT
icat -o 63 /tmp/nist-ewf-mount/ewf1 11776 > /tmp/nist-extracts/irunin.ini
icat -o 63 /tmp/nist-ewf-mount/ewf1 10080 > /tmp/nist-extracts/mirc.ini
icat -o 63 /tmp/nist-ewf-mount/ewf1 12264 > /tmp/nist-extracts/interception
icat -o 63 /tmp/nist-ewf-mount/ewf1 11850 > /tmp/nist-extracts/INFO2
```

`scripts/court_on_nist.py` handles all of the above; the manual commands above are documented for transparency / replay.

### 2.3 Score

```bash
python scripts/court_on_nist.py --out sweeps/competitors/hacking_case_court_v5.json
python /tmp/competitors/findevil/scripts/score.py \
    sweeps/competitors/hacking_case_court_v5.json \
    /tmp/competitors/findevil/reports/ground_truth/hacking_case.json \
    --label 'Hexbreaker-Court-on-NIST'
```

The earlier "F1 = 95.08%" from this batched path is **withdrawn** — that pipeline
injected literal ground-truth answers into the prompt (now removed), so the
number measured string-copying, not forensics. This batched script is not the
adversarial Court and is not labeled "verifiable". See `docs/accuracy.md §3.2.1`.

---

## 3. Sample / pre-generated cases (committed for replay)

| Path | What |
|---|---|
| `sweeps/2026-05-27_N10_baseline.json` | First N=10 sweep (timestomp, normal + Provocateur), recorded pre-position-bias-fix |
| `sweeps/2026-05-27_N10_shuffled.json` | Same N=10 post-shuffle (honest baseline) |
| `sweeps/2026-05-28_N10_judge.json` | After Judge JR-01 wired |
| `sweeps/2026-05-28_N10_final_arch.json` | Full architecture (Judge + Provocateur + HMAC + Tier B), canonical submission run |
| `sweeps/competitors/hacking_case_court_v5.json` | Batched NIST Q&A output — **withdrawn** (was produced with prompt-injected answers; not Court, not verifiable) |
| `sweeps/competitors/score_court_on_nist_v5.json` | dhyabi2's scorer applied to the withdrawn batched NIST output |
| `sweeps/competitors/hacking_case_deepseek.json` | dhyabi2 on NIST with DeepSeek (0% F1 — independent re-measurement) |
| `sweeps/competitors/score_deepseek.json` | dhyabi2's scorer applied to dhyabi2's own DeepSeek run |
| `sweeps/competitors/run_deepseek.log` | 60KB transcript of the dhyabi2 run that produced the above |

All sweep JSON files are committed and reproducible from `scripts/sweep.py` + `scripts/court_on_nist.py` + the run script at `/tmp/competitors/findevil/run_nist_deepseek.sh`.

---

## 4. Attribution

- `dhyabi2/findevil/reports/ground_truth/hacking_case.json` — MIT-licensed (Copyright dhyabi2/findevil contributors), used with attribution as the canonical NIST question list.
- `dhyabi2/findevil/scripts/score.py` — MIT-licensed (same), used as the canonical NIST scorer for methodological parity.
- `AppliedIR/Valhuntir/src/vhir_cli/verification.py` — MIT-licensed (Copyright (c) 2026 AppliedIncidentResponse.com), HMAC primitive (PBKDF2 600K + HMAC-SHA256 + hmac.compare_digest) ported to `src/hexbreaker/court/hmac_chain.py` with attribution preserved in the module docstring + `__valhuntir_attribution__` constant.
- NIST CFReDS Hacking Case — US Government public-domain forensic sample.
