"""Decompose: per-leg F1 of the strongest cheats, and even cheaper variants.

A finding set covering both legs gets F1 over 2 expected. To see what each leg
contributes, we score single-leg findings sets too. We also test the CHEAPEST
possible corroborator-only and 'echo evtx image' style attacks.
"""
from __future__ import annotations
import csv, io
from datetime import datetime, timezone
from pathlib import Path
import tempfile

from hexbreaker.forge import template_multi_artifact as M
from hexbreaker.forge.case import load_case
from hexbreaker.scorer.exact_match import score

RUN_KEY = M.RUN_KEY_PATH
DRIVER_PARENT = M.DRIVER_PARENT
SEEDS = list(range(50000, 50024))

def _piso(s): return datetime.fromisoformat(s.replace("Z","+00:00")).astimezone(timezone.utc)
def _rows(cd,n): return list(csv.DictReader(io.StringIO((cd/"mock_outputs"/n).read_text())))
def _mft(cd): return _rows(cd,"mft.csv")
def _recmd(cd): return _rows(cd,"recmd_run.csv")
def _evtx(cd): return _rows(cd,"evtx_registry.csv")
def _yara(cd):
    t=(cd/"mock_outputs"/"yara.txt").read_text()
    return [l.split(":",1)[0].strip() for l in t.splitlines() if l.strip()]
def _evtx_t(cd): return [r["TargetObject"] for r in _evtx(cd)]
def _ts(n): return f"{DRIVER_PARENT}\\{n}"
def _pers(v): return f"{RUN_KEY}\\{v}"
def _f1(f,cd):
    _m,a=load_case(cd); return score(f,a).f1

VENDOR=["microsoft","spotify","discord","zoom","teams","adobe","google","utorrent"]

# ---- single-leg cheats ----
def ts_yara_backward(cd):
    """timestomp: yara-hit AND $SI<$FN (any magnitude). CHEAP: no years threshold."""
    y=set(_yara(cd)); out=[]
    for r in _mft(cd):
        if r["FileName"] in y and _piso(r["Created0x10"])<_piso(r["Created0x30"]):
            out.append({"artifact_kind":"timestomp","target":_ts(r["FileName"])})
    return out

def ts_yara_only(cd):
    """timestomp: just yara basenames (all of them)."""
    return [{"artifact_kind":"timestomp","target":_ts(b)} for b in _yara(cd)]

def ts_yara_and_old_si(cd):
    """timestomp: yara-hit AND $SI year < 2022 (cheap 'old' threshold, no FN logic)."""
    y=set(_yara(cd)); out=[]
    for r in _mft(cd):
        if r["FileName"] in y and int(r["Created0x10"][:4])<2022:
            out.append({"artifact_kind":"timestomp","target":_ts(r["FileName"])})
    return out

def pers_evtx_nonvendor(cd):
    """persistence: evtx-corroborated AND no vendor word in path (substring)."""
    evt=set(_evtx_t(cd)); out=[]
    for r in _recmd(cd):
        low=r["ValueData"].lower()
        if _pers(r["ValueName"]) in evt and not any(w in low for w in VENDOR):
            out.append({"artifact_kind":"persistence","target":_pers(r["ValueName"])})
    return out

def pers_evtx_image_nonvendor(cd):
    """persistence: among evtx rows, pick the one whose Image path has no vendor
    word. Reads ONLY the corroborator file."""
    out=[]
    for r in _evtx(cd):
        low=r["Image"].lower()
        if not any(w in low for w in VENDOR):
            out.append({"artifact_kind":"persistence","target":r["TargetObject"]})
    return out

def pers_nonvendor_only(cd):
    """persistence: recmd rows with no vendor word (ignores evtx entirely).
    Should also flag the plant -> 2 findings -> ~0.5 F1 single-leg... let's see."""
    out=[]
    for r in _recmd(cd):
        low=r["ValueData"].lower()
        if not any(w in low for w in VENDOR):
            out.append({"artifact_kind":"persistence","target":_pers(r["ValueName"])})
    return out

def main():
    tmp=Path(tempfile.mkdtemp())
    legs={
        "TS: yara+backward(any-mag)":ts_yara_backward,
        "TS: yara-only(all)":ts_yara_only,
        "TS: yara+old-SI(<2022)":ts_yara_and_old_si,
        "PERS: evtx+nonvendor-substr":pers_evtx_nonvendor,
        "PERS: evtx-image-nonvendor":pers_evtx_image_nonvendor,
        "PERS: nonvendor-only(no evtx)":pers_nonvendor_only,
    }
    sums={k:0.0 for k in legs}
    # also the BEST combined = TS yara+backward  +  PERS evtx+nonvendor
    combo=0.0
    for seed in SEEDS:
        cd=tmp/f"c{seed}"; M.generate(seed=seed,out_dir=cd,provocateur=True)
        for name,fn in legs.items():
            sums[name]+=_f1(fn(cd),cd)
        combo+=_f1(ts_yara_backward(cd)+pers_evtx_nonvendor(cd),cd)
    k=len(SEEDS)
    print("Single-leg F1 (max over 2 expected, so a perfect single leg ≈0.667):")
    for name in legs:
        print(f"  {sums[name]/k:.4f}  {name}")
    print(f"\nBEST COMBINED (TS yara+backward + PERS evtx+nonvendor) F1 = {combo/k:.4f}")

if __name__=="__main__":
    main()
