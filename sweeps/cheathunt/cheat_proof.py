"""Prove the cheater is genuinely cheaper than the oracle and still perfect.

1. Show the TS cheap predicate (backward-gap>30d) differs from is_timestomped's
   internal threshold on at least some plausible rows (it is strictly weaker).
2. Show per-leg: PERS cheat reads ONLY evtx; TS cheat needs no 'years' notion.
3. Confirm cheater==1.0 on the NON-provocateur case too (weaker decoys).
4. Print the actual is_timestomped source to document the gap.
"""
from __future__ import annotations
import csv, io, inspect
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from hexbreaker.forge import template_multi_artifact as M
from hexbreaker.forge.case import load_case
from hexbreaker.forge.template_multi_artifact import is_timestomped
from hexbreaker.scorer.exact_match import score

RUN_KEY=M.RUN_KEY_PATH; DRIVER_PARENT=M.DRIVER_PARENT
def _piso(s): return datetime.fromisoformat(s.replace("Z","+00:00")).astimezone(timezone.utc)
def _rows(cd,n): return list(csv.DictReader(io.StringIO((cd/"mock_outputs"/n).read_text())))
def _mft(cd): return _rows(cd,"mft.csv")
def _evtx(cd): return _rows(cd,"evtx_registry.csv")
def _yara(cd):
    t=(cd/"mock_outputs"/"yara.txt").read_text()
    return [l.split(":",1)[0].strip() for l in t.splitlines() if l.strip()]
def _ts(n): return f"{DRIVER_PARENT}\\{n}"
def _f1(f,cd):
    _m,a=load_case(cd); return score(f,a).f1
VENDOR=["microsoft","spotify","discord","zoom","teams","adobe","google","utorrent"]

def cheater(cd):
    out=[]
    for r in _evtx(cd):
        if not any(w in r["Image"].lower() for w in VENDOR):
            out.append({"artifact_kind":"persistence","target":r["TargetObject"]})
    y=set(_yara(cd))
    for r in _mft(cd):
        if r["FileName"] in y and (_piso(r["Created0x30"])-_piso(r["Created0x10"])).days>30:
            out.append({"artifact_kind":"timestomp","target":_ts(r["FileName"])})
    return out

print("=== is_timestomped source (the ORACLE threshold the cheat avoids) ===")
print(inspect.getsource(is_timestomped))

# non-provocateur perfect?
tmp=Path(tempfile.mkdtemp()); s=0.0; seeds=list(range(90000,90024))
for seed in seeds:
    cd=tmp/f"c{seed}"; M.generate(seed=seed,out_dir=cd,provocateur=False)
    s+=_f1(cheater(cd),cd)
print(f"Cheater F1 on NON-provocateur (weaker decoys), K={len(seeds)}: {s/len(seeds):.4f}")
