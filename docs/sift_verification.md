# Try-it-out Verification (Submission Artifact #7)

The hackathon requires the try-it-out instructions to be **tested on SIFT**. This
document records exactly what was tested, on what, and what was *not* — so a judge
can reproduce it and trust the claim.

**Date:** 2026-05-28 · **Verified by:** Claude Opus 4.8 (1M context), on Alex's
Ubuntu host via Docker.

## TL;DR

Hexbreaker's thesis is **SIFT-independence** — dhyabi2's pipeline scored 100% F1
on SIFT and 0% off-SIFT because it silently depended on SIFT-VM paths
(see [accuracy.md](accuracy.md)). Artifact #7 is where we prove we don't have that
failure mode: the **Docker path is SIFT-version-proof by construction** and was
verified end-to-end. The native (no-Docker) path needs Python ≥3.11, which the
SANS-recommended SIFT base (Ubuntu 22.04) does **not** ship — so on SIFT, Docker is
the supported route.

## 1. Docker path — verified end-to-end (the SIFT-safe route)

The image is self-contained `python:3.12-slim` (Dockerfile pins Python and the
forensic CLIs), so it runs identically on any host that has Docker — including both
SIFT bases. Full documented walkthrough, run live against DeepSeek:

| Step | Command (inside `hexbreaker` image) | Result |
|---|---|---|
| python | `python --version` | `Python 3.12.13` |
| 1. generate | `generate --seed 4729 --template timestomp --out /case` | `case-004729-timestomp`, deterministic |
| 2. run (live LLM) | `run --agent court --case /case --out /case/findings.json` | 1 finding: `timestomp … mssecsvc2.exe` verdict=CONFIRMED |
| 3. score | `score --findings … --answer-key …` | **tp=1, fp=0, fn=0, fp_planted=0, F1=1.0** |
| 4. verify | `verify --transcript /case/transcript.jsonl` | `chain OK` |

- **Total wall time: 13–17 s** across runs (dominated by the single live Court LLM
  round-trip) — well inside the spec's ≤5 min on an 8 GB SIFT VM
  ([SPEC_VERIFIER §"≤ 5 minutes on a SIFT VM"]). Re-verified on the image rebuilt
  from HEAD (including the `court_runner` security-guard reorder).
- Image size 303 MB; produces the full audit bundle (`transcript.jsonl` +
  `transcript.outputs/` sidecars + `manifest.json`).

**Honest scope:** this §1 result ran via Docker on Alex's host. The image is
environment-independent, so "runs on SIFT" follows from "SIFT has Docker." We did
not stop there — Court was **also run inside a booted SANS SIFT 24.04 VM** with the
audit bundle pulled out (see §3 + `samples/sift_vm_run/`).

## 2. Native (no-Docker) path — version-gated on stock SIFT

SANS's standard SIFT install is **Ubuntu 22.04** (Cast also supports 24.04).
Stock 22.04 ships **Python 3.10**; hexbreaker declares `requires-python = ">=3.11"`.
So the documented `pip install` fails on a stock 22.04 SIFT box:

```
# Ubuntu 22.04 (stock SIFT base) — Python 3.10.x
$ pip install .
ERROR: Package 'hexbreaker' requires a different Python: 3.10.20 not in '>=3.11'
```

Failure mode depends on the box's pip/setuptools:

- **Current pip (build isolation, PyPI reachable):** clean
  `requires a different Python: 3.10.x not in '>=3.11'` error (shown above, on
  `python:3.10-slim`).
- **Older system pip/setuptools (`pip 22.0.2` as shipped on 22.04):** the build
  falls back and produces a **silent no-op `UNKNOWN-0.0.0`** wheel — `pip install`
  appears to succeed but `hexbreaker` is not on `PATH` and `import hexbreaker`
  raises `ModuleNotFoundError` (observed in our run).

Either way the CLI does not install on stock 22.04 SIFT. **Scope it correctly:**
SIFT-on-24.04 (Cast) ships Python 3.12 and the native path works there. The point
is that **only the Docker path works on *both* SIFT bases** — which is why the
README leads with it for SIFT.

## 3. Booted SIFT VM run (residual gap closed)

The §1 result ran via Docker on the host. We subsequently ALSO ran Court **inside a
booted SANS SIFT workstation VM** — Ubuntu **24.04.4** (the Cast SIFT image
`sift.qcow2`), booted as a KVM/libvirt guest (serial-console login banner captured:
`Ubuntu 24.04.4 LTS siftworkstation … siftworkstation login:`). The hexbreaker
package was pushed into the guest over scp, a **provocateur-mode** Court run executed
inside SIFT, and the audit bundle was pulled back out. Committed evidence:
[`samples/sift_vm_run/`](../samples/sift_vm_run/) — the run **CONFIRMED**
`\Windows\System32\drivers\mssecsvc2.exe` with genuine two-tool corroboration
(MFTECmd S-001 + yara S-004); `findings.json` + `transcript.jsonl` are the verbatim
pull, plus `sift_boot_serial.log`.

Precise caveats (no overclaim): it was the SIFT **`.qcow2`** image booted as a KVM
guest, not a literal distributed-`.ova`-file import (same SIFT build); and the
transcript's `transcript.outputs/` sidecars stayed inside the VM (only the JSON
bundle was scp'd out), so the chain's RECORD links verify while the sidecar-byte
re-hash would need the in-VM outputs. Net: **"Court runs on a genuine SIFT
workstation" is demonstrated, not assumed.** The only thing not done is importing
the distributed `.ova` file specifically — which the Docker path makes unnecessary.

## Reproduce

```bash
# Docker path (the verified, SIFT-version-proof route)
docker build -t hexbreaker -f docker/Dockerfile .
mkdir -p /tmp/judge-case
docker run --rm -v /tmp/judge-case:/case hexbreaker generate --seed 4729 --template timestomp --out /case
docker run --rm -e DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY -v /tmp/judge-case:/case hexbreaker run --agent court --case /case --out /case/findings.json
docker run --rm -v /tmp/judge-case:/case hexbreaker score --findings /case/findings.json --answer-key /case/answer_key.json
docker run --rm -v /tmp/judge-case:/case hexbreaker verify --transcript /case/transcript.jsonl

# Native version gate (reproduces the stock-SIFT failure)
docker run --rm -v "$PWD":/src:ro python:3.10-slim bash -c 'cp -r /src /tmp/hb && cd /tmp/hb && pip install .'
```
