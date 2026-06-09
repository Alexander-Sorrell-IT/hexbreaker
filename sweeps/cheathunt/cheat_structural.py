"""Pin down the cheapest structural leaks and whether they are universal.

Claim A: in evtx_registry.csv, the answer key is the UNIQUE row whose Image path
         lacks a vendor directory. (corroborator self-isolates the answer)
Claim B: 'recmd row that is in evtx AND is the rarest by some surface token'.
Claim C: timestomp answer = unique yara-hit row whose $SI<$FN by >1yr is not the
         only thing... measure cheapest timestomp tell.

Also: properly measure F1 of a 2-finding cheater that uses ONLY the two
corroborator files (yara.txt + evtx) with the dumbest possible filters.
"""
from __future__ import annotations
import csv, io
from datetime import datetime, timezone
from pathlib import Path
import tempfile

from hexbreaker.forge import template_multi_artifact as M
from hexbreaker.forge.case import load_case
from hexbreaker.scorer.exact_match import score

RUN_KEY=M.RUN_KEY_PATH; DRIVER_PARENT=M.DRIVER_PARENT
SEEDS=list(range(60000,60040))  # 40 fresh seeds
def _piso(s): return datetime.fromisoformat(s.replace("Z","+00:00")).astimezone(timezone.utc)
def _rows(cd,n): return list(csv.DictReader(io.StringIO((cd/"mock_outputs"/n).read_text())))
def _mft(cd): return _rows(cd,"mft.csv")
def _recmd(cd): return _rows(cd,"recmd_run.csv")
def _evtx(cd): return _rows(cd,"evtx_registry.csv")
def _yara(cd):
    t=(cd/"mock_outputs"/"yara.txt").read_text()
    return [l.split(":",1)[0].strip() for l in t.splitlines() if l.strip()]
def _ts(n): return f"{DRIVER_PARENT}\\{n}"
def _pers(v): return f"{RUN_KEY}\\{v}"
def _f1(f,cd):
    _m,a=load_case(cd); return score(f,a).f1

VENDOR=["microsoft","spotify","discord","zoom","teams","adobe","google","utorrent"]

def claim_A_universal():
    """Is the answer the UNIQUE non-vendor Image in evtx, every seed?"""
    tmp=Path(tempfile.mkdtemp())
    uniq=0; total=0; correct=0
    for seed in SEEDS:
        cd=tmp/f"c{seed}"; M.generate(seed=seed,out_dir=cd,provocateur=True)
        _m,ans=load_case(cd)
        pers_ans=next(f.target for f in ans.expected_findings if f.artifact_kind=="persistence")
        nonvendor=[r for r in _evtx(cd) if not any(w in r["Image"].lower() for w in VENDOR)]
        total+=1
        if len(nonvendor)==1:
            uniq+=1
            if nonvendor[0]["TargetObject"]==pers_ans:
                correct+=1
    print(f"Claim A: evtx non-vendor Image is UNIQUE in {uniq}/{total} seeds; "
          f"and equals the answer in {correct}/{total} seeds.")

def best_corroborator_only():
    """Dumbest 2-leg cheat using ONLY corroborator files + a trivial filter.
    timestomp: yara-hit basename whose MFT $SI<$FN (need mft for ts gap, but the
               cheapest pure-corroborator timestomp pick is ambiguous -> we still
               read mft just for the < test). To stay 'cheap' use raw <, any mag.
    persistence: the unique non-vendor Image in evtx -> its TargetObject."""
    tmp=Path(tempfile.mkdtemp())
    s=0.0
    for seed in SEEDS:
        cd=tmp/f"c{seed}"; M.generate(seed=seed,out_dir=cd,provocateur=True)
        out=[]
        # persistence: evtx unique non-vendor
        for r in _evtx(cd):
            if not any(w in r["Image"].lower() for w in VENDOR):
                out.append({"artifact_kind":"persistence","target":r["TargetObject"]})
        # timestomp: yara-hit AND $SI<$FN (raw)
        y=set(_yara(cd))
        for r in _mft(cd):
            if r["FileName"] in y and _piso(r["Created0x10"])<_piso(r["Created0x30"]):
                out.append({"artifact_kind":"timestomp","target":_ts(r["FileName"])})
        s+=_f1(out,cd)
    print(f"Best corroborator-only 2-leg cheat F1 = {s/len(SEEDS):.4f} over {len(SEEDS)} seeds")

def cheapest_timestomp():
    """Find the cheapest timestomp filter that maximizes single-leg F1.
    Variants combined with yara-hit."""
    tmp=Path(tempfile.mkdtemp())
    variants={
        "yara & backward(raw <)":lambda r: _piso(r["Created0x10"])<_piso(r["Created0x30"]),
        "yara & SI<2024":lambda r: int(r["Created0x10"][:4])<2024,
        "yara & SI<2022":lambda r: int(r["Created0x10"][:4])<2022,
        "yara & FN==2026 & SI<2024":lambda r: r["Created0x30"][:4]=="2026" and int(r["Created0x10"][:4])<2024,
        "yara & gap>30d":lambda r: abs((_piso(r["Created0x30"])-_piso(r["Created0x10"])).days)>30,
        "yara & backward-gap>30d":lambda r: (_piso(r["Created0x30"])-_piso(r["Created0x10"])).days>30,
    }
    sums={k:0.0 for k in variants}
    for seed in SEEDS:
        cd=tmp/f"c{seed}"; M.generate(seed=seed,out_dir=cd,provocateur=True)
        y=set(_yara(cd)); mft=[r for r in _mft(cd) if r["FileName"] in y]
        for name,pred in variants.items():
            out=[{"artifact_kind":"timestomp","target":_ts(r["FileName"])} for r in mft if pred(r)]
            sums[name]+=_f1(out,cd)
    k=len(SEEDS)
    print("Cheapest timestomp single-leg (perfect single-leg ≈0.667):")
    for name in variants:
        print(f"  {sums[name]/k:.4f}  {name}")

if __name__=="__main__":
    claim_A_universal()
    print()
    cheapest_timestomp()
    print()
    best_corroborator_only()
