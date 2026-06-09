"""Final: the strongest cheap 2-leg cheater vs oracle, with correct chance.

Cheater = TS(yara & backward-gap>30d) + PERS(evtx unique non-vendor Image).
Both are cheap surface filters that do NOT implement the intended reasoning:
  - TS: a backward gap of merely >30 days + a yara hit (oracle needs YEARS magnitude
    via is_timestomped, and the per-leg comment explicitly says the magnitude /
    'years-vs-minutes' distinction is the load-bearing reasoning).
  - PERS: reads ONLY the corroborator (evtx) Image column with a substring vendor
    filter; never checks user-writable, never applies segment-bounded vendor
    reasoning, never cross-references recmd. The answer is the unique non-vendor
    Image in evtx (universal, 40/40).

Run on the SAME seed set the in-repo suite uses (1011..1042) AND fresh seeds, on
the provocateur case, to be apples-to-apples.
"""
from __future__ import annotations
import csv, io
from datetime import datetime, timezone
from pathlib import Path
import tempfile

from hexbreaker.forge import template_multi_artifact as M
from hexbreaker.forge.case import load_case
from hexbreaker.forge.template_multi_artifact import is_evil_run_value, is_timestomped
from hexbreaker.scorer.exact_match import score

RUN_KEY=M.RUN_KEY_PATH; DRIVER_PARENT=M.DRIVER_PARENT
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

def cheater(cd):
    out=[]
    # PERS: unique non-vendor Image in evtx
    for r in _evtx(cd):
        if not any(w in r["Image"].lower() for w in VENDOR):
            out.append({"artifact_kind":"persistence","target":r["TargetObject"]})
    # TS: yara-hit AND backward gap > 30 days
    y=set(_yara(cd))
    for r in _mft(cd):
        if r["FileName"] in y:
            gap_days=(_piso(r["Created0x30"])-_piso(r["Created0x10"])).days
            if gap_days>30:
                out.append({"artifact_kind":"timestomp","target":_ts(r["FileName"])})
    return out

def oracle(cd):
    out=[]; y=set(_yara(cd))
    for r in _mft(cd):
        if is_timestomped(_piso(r["Created0x10"]),_piso(r["Created0x30"])) and r["FileName"] in y:
            out.append({"artifact_kind":"timestomp","target":_ts(r["FileName"])})
    evt=set(_evtx_t(cd))
    for r in _recmd(cd):
        if is_evil_run_value(r["ValueName"],r["ValueData"]) and _pers(r["ValueName"]) in evt:
            out.append({"artifact_kind":"persistence","target":_pers(r["ValueName"])})
    return out

def ncand(cd):
    _m,a=load_case(cd); per={}
    for f in a.expected_findings+a.decoys+a.planted:
        per[f.artifact_kind]=per.get(f.artifact_kind,0)+1
    return min(per.values())

def run(seeds,label):
    tmp=Path(tempfile.mkdtemp())
    cs=os=0.0; nc=None
    for seed in seeds:
        cd=tmp/f"c{seed}"; M.generate(seed=seed,out_dir=cd,provocateur=True)
        if nc is None: nc=ncand(cd)
        cs+=_f1(cheater(cd),cd); os+=_f1(oracle(cd),cd)
    k=len(seeds)
    cf,of=cs/k,os/k
    print(f"[{label}] K={k} chance≈{1/nc:.3f} cheater={cf:.4f} oracle={of:.4f} gap={of-cf:.4f}")
    return cf,of

if __name__=="__main__":
    run(list(range(1011,1043)),"in-repo seeds 1011-1042")
    run(list(range(70000,70024)),"fresh seeds 70000-70023")
    run(list(range(80000,80012)),"fresh K=12 80000-80011")
