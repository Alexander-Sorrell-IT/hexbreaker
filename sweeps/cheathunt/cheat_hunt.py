"""Independent adversarial cheater harness for multi_artifact.

Generates K fresh PROVOCATEUR cases (strongest decoys) and runs a large battery
of NEW cheap shortcuts not (all) covered by the in-repo suite. Each strategy
consumes ONLY the issued evidence bytes (mock_outputs), never answer_key.json.
F1 is computed by the production scorer against the withheld key.

Reports best cheater F1, oracle F1, gap, and per-strategy breakdown.
"""
from __future__ import annotations

import collections
import csv
import io
from datetime import datetime, timezone
from pathlib import Path
import tempfile

from hexbreaker.forge import template_multi_artifact as M
from hexbreaker.forge.case import load_case
from hexbreaker.forge.template_multi_artifact import is_evil_run_value, is_timestomped
from hexbreaker.scorer.exact_match import score

RUN_KEY = M.RUN_KEY_PATH
DRIVER_PARENT = M.DRIVER_PARENT

# Fresh seeds distinct from the in-repo suite's 1011-1042. K=24.
SEEDS = list(range(50000, 50024))


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def _read_rows(case_dir: Path, name: str):
    text = (case_dir / "mock_outputs" / name).read_text()
    return list(csv.DictReader(io.StringIO(text)))


def _mft(cd): return _read_rows(cd, "mft.csv")
def _recmd(cd): return _read_rows(cd, "recmd_run.csv")
def _evtx(cd): return _read_rows(cd, "evtx_registry.csv")
def _yara(cd):
    text = (cd / "mock_outputs" / "yara.txt").read_text()
    return [ln.split(":", 1)[0].strip() for ln in text.splitlines() if ln.strip()]
def _evtx_targets(cd): return [r["TargetObject"] for r in _evtx(cd)]
def _evtx_images(cd): return [r["Image"] for r in _evtx(cd)]

def _ts(name): return f"{DRIVER_PARENT}\\{name}"
def _pers(value): return f"{RUN_KEY}\\{value}"


# ===================== NEW CHEATER STRATEGIES =========================

def c_evtx_image_evil(cd):
    """PERSISTENCE: among EvtxECmd Image paths, pick the value whose Image is
    user-writable AND lacks a vendor subdir -- BUT keyed off the corroborator
    file alone, applying only the surface 'no vendor dir' string test (no
    timestomp-style reasoning). This is essentially half the oracle but driven
    purely by string tokens in evtx. Tests if evtx Image leaks the answer."""
    out = []
    for r in _evtx(cd):
        img = r["Image"]
        low = img.lower()
        if M._is_userwritable(img) and not any(v in low for v in M._VENDOR_SUBDIRS):
            out.append({"artifact_kind": "persistence", "target": r["TargetObject"]})
    return out


def c_recmd_minus_evtx(cd):
    """PERSISTENCE: keys in RECmd but NOT in EvtxECmd (the plant lacks an evtx
    row). Naive 'the registry entry with no logged write is suspicious'. This
    isolates the PLANT, not the answer -- check it scores ~0."""
    rec_keys = {_pers(r["ValueName"]) for r in _recmd(cd)}
    evt = set(_evtx_targets(cd))
    extra = rec_keys - evt
    return [{"artifact_kind": "persistence", "target": k} for k in extra]


def c_recmd_and_evtx(cd):
    """PERSISTENCE: keys in BOTH RECmd and EvtxECmd. Answer + all 6 vendor
    decoys qualify (plant excluded). Big FP set -> low F1."""
    rec_keys = {_pers(r["ValueName"]) for r in _recmd(cd)}
    evt = set(_evtx_targets(cd))
    return [{"artifact_kind": "persistence", "target": k} for k in (rec_keys & evt)]


def c_path_depth_min(cd):
    """PERSISTENCE: pick the Run value whose ValueData has the FEWEST backslash
    segments (the bare AppData drop is shallower than vendor subdirs). Naive
    'shortest/shallowest path is the dropped binary'."""
    rc = _recmd(cd)
    if not rc:
        return []
    def depth(r):
        # count path separators in the binary path portion (strip args)
        p = r["ValueData"].split(" ")[0]
        return p.count("\\")
    chosen = min(rc, key=depth)
    return [{"artifact_kind": "persistence", "target": _pers(chosen["ValueName"])}]


def c_path_depth_min_all(cd):
    """PERSISTENCE: flag ALL rows tied for the minimum path depth."""
    rc = _recmd(cd)
    if not rc:
        return []
    def depth(r):
        return r["ValueData"].split(" ")[0].count("\\")
    mind = min(depth(r) for r in rc)
    return [{"artifact_kind": "persistence", "target": _pers(r["ValueName"])}
            for r in rc if depth(r) == mind]


def c_no_args(cd):
    """PERSISTENCE: pick rows whose ValueData has NO command-line args (no space).
    Some vendor decoys carry --processStart / /background. Naive 'bare exe'."""
    rc = _recmd(cd)
    out = [r for r in rc if " " not in r["ValueData"]]
    return [{"artifact_kind": "persistence", "target": _pers(r["ValueName"])} for r in out]


def c_basename_eq_valuename_mismatch(cd):
    """PERSISTENCE: pick the row where the exe basename does NOT match a known
    vendor word in the value name. Too fuzzy; approximate: value name not a
    common app. Skip -- use token rarity instead."""
    return []


def c_rarest_pathtoken_dir(cd):
    """PERSISTENCE: split each ValueData binary path into directory segments,
    count global frequency of each segment, pick the row whose RAREST segment is
    globally rarest. The vendor decoys share AppData/Local/Roaming; the answer's
    distinctive segment is its unique exe. Naive 'most unusual directory'."""
    rc = _recmd(cd)
    if not rc:
        return []
    seg_counts = collections.Counter()
    rows_segs = []
    for r in rc:
        p = r["ValueData"].split(" ")[0]
        segs = [s for s in p.split("\\") if s]
        rows_segs.append((r, segs))
        for s in segs:
            seg_counts[s] += 1
    def min_seg_freq(item):
        r, segs = item
        return min(seg_counts[s] for s in segs) if segs else 999
    chosen = min(rows_segs, key=min_seg_freq)[0]
    return [{"artifact_kind": "persistence", "target": _pers(chosen["ValueName"])}]


def c_valuename_underscore_or_typo(cd):
    """PERSISTENCE: pick value names containing an underscore or digit (the evil
    binaries are typosquats like svchosts_loader, ChromeUpdater_2). Naive
    'weird-looking name'."""
    rc = _recmd(cd)
    out = [r for r in rc if ("_" in r["ValueName"] or any(c.isdigit() for c in r["ValueName"]))]
    return [{"artifact_kind": "persistence", "target": _pers(r["ValueName"])} for r in out]


def c_evtx_image_lacks_vendor_token(cd):
    """PERSISTENCE: just string match: among ALL recmd rows, pick those whose
    ValueData has none of the vendor *words* anywhere (not segment-bounded).
    Naive token-presence cheat that ignores segment semantics."""
    VENDOR_WORDS = ["microsoft", "spotify", "discord", "zoom", "teams",
                    "adobe", "google", "utorrent"]
    rc = _recmd(cd)
    out = []
    for r in rc:
        low = r["ValueData"].lower()
        if not any(w in low for w in VENDOR_WORDS):
            out.append({"artifact_kind": "persistence", "target": _pers(r["ValueName"])})
    return out


# ---- timestomp NEW strategies ----

def c_mft_entrynumber_extreme(cd):
    """TIMESTOMP: pick the row with the min/max EntryNumber (byte/structural tell)."""
    mft = _mft(cd)
    if not mft:
        return []
    chosen = max(mft, key=lambda r: int(r["EntryNumber"]))
    return [{"artifact_kind": "timestomp", "target": _ts(chosen["FileName"])}]


def c_mft_entrynumber_min(cd):
    mft = _mft(cd)
    if not mft:
        return []
    chosen = min(mft, key=lambda r: int(r["EntryNumber"]))
    return [{"artifact_kind": "timestomp", "target": _ts(chosen["FileName"])}]


def c_si_lm_eq_and_old(cd):
    """TIMESTOMP: rows where LastModified == $SI (timestomp tool sets LM=backdated
    $SI) AND $SI is old (<2022). Naive combo. Skew decoys have LM==$FN(recent),
    old-clean decoys have LM != $SI. Does this isolate the answer?"""
    mft = _mft(cd)
    out = []
    for r in mft:
        if r["LastModified0x10"] == r["Created0x10"] and int(r["Created0x10"][:4]) < 2022:
            out.append({"artifact_kind": "timestomp", "target": _ts(r["FileName"])})
    return out


def c_si_old_and_fn_recent(cd):
    """TIMESTOMP: rows where $SI year < 2022 AND $FN year == 2026. The naive
    'created-old-but-truename-recent' combo. Tests whether decoys dilute it."""
    mft = _mft(cd)
    out = []
    for r in mft:
        if int(r["Created0x10"][:4]) < 2022 and r["Created0x30"][:4] == "2026":
            out.append({"artifact_kind": "timestomp", "target": _ts(r["FileName"])})
    return out


def c_yara_and_si_ne_fn(cd):
    """TIMESTOMP: yara-hit AND $SI != $FN (raw inequality, NOT directional/magnitude).
    Cheaper than oracle (no is_timestomped). Does the yara-FP-on-a-skew-decoy
    dilute it?"""
    yara = set(_yara(cd))
    mft = _mft(cd)
    out = []
    for r in mft:
        if r["FileName"] in yara and r["Created0x10"] != r["Created0x30"]:
            out.append({"artifact_kind": "timestomp", "target": _ts(r["FileName"])})
    return out


def c_yara_and_si_before_fn(cd):
    """TIMESTOMP: yara-hit AND $SI < $FN (directional, any magnitude). Cheaper
    than is_timestomped (which needs YEARS gap). The GAP-forward decoy is yara?
    skew decoys $SI<$FN by minutes -- are any yara-hit?"""
    yara = set(_yara(cd))
    mft = _mft(cd)
    out = []
    for r in mft:
        if r["FileName"] in yara and _parse_iso(r["Created0x10"]) < _parse_iso(r["Created0x30"]):
            out.append({"artifact_kind": "timestomp", "target": _ts(r["FileName"])})
    return out


def c_yara_oldest_si(cd):
    """TIMESTOMP: among yara-hit rows only, pick the one with the oldest $SI.
    Combines corroborator + naive 'oldest'."""
    yara = set(_yara(cd))
    mft = [r for r in _mft(cd) if r["FileName"] in yara]
    if not mft:
        return []
    chosen = min(mft, key=lambda r: _parse_iso(r["Created0x10"]))
    return [{"artifact_kind": "timestomp", "target": _ts(chosen["FileName"])}]


def c_yara_biggest_gap(cd):
    """TIMESTOMP: among yara-hit rows, pick the largest |$SI-$FN| gap."""
    yara = set(_yara(cd))
    mft = [r for r in _mft(cd) if r["FileName"] in yara]
    if not mft:
        return []
    def gap(r):
        return abs((_parse_iso(r["Created0x30"]) - _parse_iso(r["Created0x10"])).total_seconds())
    chosen = max(mft, key=gap)
    return [{"artifact_kind": "timestomp", "target": _ts(chosen["FileName"])}]


def c_yara_backward_biggest(cd):
    """TIMESTOMP: among yara-hit rows with $SI<$FN (backward), pick the biggest
    backward gap. This is closest to oracle but uses ranking not threshold."""
    yara = set(_yara(cd))
    mft = [r for r in _mft(cd) if r["FileName"] in yara
           and _parse_iso(r["Created0x10"]) < _parse_iso(r["Created0x30"])]
    if not mft:
        return []
    def gap(r):
        return (_parse_iso(r["Created0x30"]) - _parse_iso(r["Created0x10"])).total_seconds()
    chosen = max(mft, key=gap)
    return [{"artifact_kind": "timestomp", "target": _ts(chosen["FileName"])}]


# ---- CROSS-LEG / combined strategies (2 findings) ----

def c_combined_corroborator_intersect(cd):
    """Both legs: yara-hit basenames (timestomp) + evtx-AND-recmd keys minus the
    one with the most... no. Just: yara basenames + the recmd row whose path is
    non-vendor (string). A 'corroborated + suspicious-name' combo across both."""
    out = []
    yara = set(_yara(cd))
    mft = _mft(cd)
    # timestomp: yara-hit & backward
    for r in mft:
        if r["FileName"] in yara and _parse_iso(r["Created0x10"]) < _parse_iso(r["Created0x30"]):
            out.append({"artifact_kind": "timestomp", "target": _ts(r["FileName"])})
    # persistence: evtx-corroborated & non-vendor-token
    VENDOR = ["microsoft","spotify","discord","zoom","teams","adobe","google","utorrent"]
    evt = set(_evtx_targets(cd))
    for r in _recmd(cd):
        low = r["ValueData"].lower()
        if _pers(r["ValueName"]) in evt and not any(w in low for w in VENDOR):
            out.append({"artifact_kind": "persistence", "target": _pers(r["ValueName"])})
    return out


def c_suspicious_name_both(cd):
    """Both legs by NAME ONLY: timestomp -> driver name in the suspicious pool;
    persistence -> value name with underscore/digit. Pure label-pattern on names.
    This is the strongest naive 'looks malicious by name' cheat -- but the answer
    DRIVER uses a NORMAL name (timestomp leg picks SUSPICIOUS_DRIVER_NAMES as the
    evil one). Wait: check both directions."""
    out = []
    # timestomp evil driver IS from SUSPICIOUS_DRIVER_NAMES
    for r in _mft(cd):
        if r["FileName"] in M.SUSPICIOUS_DRIVER_NAMES:
            out.append({"artifact_kind": "timestomp", "target": _ts(r["FileName"])})
    # persistence evil value names look typo'd
    for r in _recmd(cd):
        vn = r["ValueName"]
        if "_" in vn or any(c.isdigit() for c in vn):
            out.append({"artifact_kind": "persistence", "target": _pers(vn)})
    return out


STRATS = [
    c_evtx_image_evil,
    c_recmd_minus_evtx,
    c_recmd_and_evtx,
    c_path_depth_min,
    c_path_depth_min_all,
    c_no_args,
    c_rarest_pathtoken_dir,
    c_valuename_underscore_or_typo,
    c_evtx_image_lacks_vendor_token,
    c_mft_entrynumber_extreme,
    c_mft_entrynumber_min,
    c_si_lm_eq_and_old,
    c_si_old_and_fn_recent,
    c_yara_and_si_ne_fn,
    c_yara_and_si_before_fn,
    c_yara_oldest_si,
    c_yara_biggest_gap,
    c_yara_backward_biggest,
    c_combined_corroborator_intersect,
    c_suspicious_name_both,
]


def _oracle(cd):
    out = []
    yara = set(_yara(cd))
    for r in _mft(cd):
        si = _parse_iso(r["Created0x10"]); fn = _parse_iso(r["Created0x30"])
        if is_timestomped(si, fn) and r["FileName"] in yara:
            out.append({"artifact_kind": "timestomp", "target": _ts(r["FileName"])})
    evt = set(_evtx_targets(cd))
    for r in _recmd(cd):
        tgt = _pers(r["ValueName"])
        if is_evil_run_value(r["ValueName"], r["ValueData"]) and tgt in evt:
            out.append({"artifact_kind": "persistence", "target": tgt})
    return out


def _f1(findings, cd):
    _m, ans = load_case(cd)
    return score(findings, ans).f1


def main():
    tmp = Path(tempfile.mkdtemp())
    sums = {s.__name__: 0.0 for s in STRATS}
    oracle_sum = 0.0
    ncand = None
    for seed in SEEDS:
        cd = tmp / f"c{seed}"
        M.generate(seed=seed, out_dir=cd, provocateur=True)
        if ncand is None:
            _m, ans = load_case(cd)
            per = {}
            for f in ans.expected_findings + ans.decoys + ans.planted:
                per[f.artifact_kind] = per.get(f.artifact_kind, 0) + 1
            ncand = min(per.values())
        for s in STRATS:
            sums[s.__name__] += _f1(s(cd), cd)
        oracle_sum += _f1(_oracle(cd), cd)
    k = len(SEEDS)
    print(f"K={k} seeds, num_candidates/leg={ncand}, chance≈{1/ncand:.3f}")
    print(f"ORACLE f1 = {oracle_sum/k:.4f}")
    print("-"*60)
    ranked = sorted(((sums[n]/k, n) for n in sums), reverse=True)
    for f1, n in ranked:
        flag = "  <<< BEATS CHANCE" if f1 > 1/ncand + 0.05 else ""
        print(f"{f1:.4f}  {n}{flag}")
    best = ranked[0][0]
    print("-"*60)
    print(f"BEST cheater F1 = {best:.4f}  gap = {oracle_sum/k - best:.4f}")


if __name__ == "__main__":
    main()
