"""Adversarial re-hunt of registry_persistence after the cross-bundle frequency repair.

Reads ONLY mock_outputs/{recmd_run,sysmon_registry}.csv across fresh bundles.
Truth (answer_key) is used ONLY to compute F1, NEVER to select. Fresh seed range.
"""
from __future__ import annotations
import csv, io, random, re, tempfile
from collections import Counter
from pathlib import Path

from hexbreaker.forge import template_registry_persistence as RP
from hexbreaker.forge.case import load_case

RUN_KEY = RP.RUN_KEY_PATH
SEEDS = list(range(91001, 91017))  # K=16 FRESH seeds, disjoint from test suite (90001-90016)


def recmd_rows(d): return list(csv.DictReader(io.StringIO((d/"mock_outputs"/"recmd_run.csv").read_text())))
def sysmon_rows(d): return list(csv.DictReader(io.StringIO((d/"mock_outputs"/"sysmon_registry.csv").read_text())))
def target_of(r): return f"{RUN_KEY}\\{r['ValueName']}"

def f1(selected, truth):
    tp = len(selected & truth); fp = len(selected - truth); fn = len(truth - selected)
    if tp == 0: return 0.0
    p = tp/(tp+fp); r = tp/(tp+fn)
    return 2*p*r/(p+r)


def gen(seed, prov, tmp):
    d = Path(tmp)/f"c_{seed}_{int(prov)}"
    RP.generate(seed=seed, out_dir=d, provocateur=prov)
    return d


def build_corpus(prov, tmp):
    """Return list of (dir, recmd, sysmon, truth) for all seeds."""
    out = []
    for s in SEEDS:
        d = gen(s, prov, tmp)
        _m, answer = load_case(d)
        truth = {ef.target for ef in answer.expected_findings}
        out.append((d, recmd_rows(d), sysmon_rows(d), truth))
    return out


# ---- Cross-bundle frequency histogram (the headline attack) ----
def cross_bundle_recurrence(corpus):
    """For each ValueData (uw only), count how many bundles it appears in."""
    counts = Counter()
    for d, recmd, sysmon, truth in corpus:
        seen = {r["ValueData"] for r in recmd if RP.is_user_writable(r["ValueData"])}
        for vd in seen:
            counts[vd] += 1
    return counts


def freq_attack(corpus, threshold, rng):
    """Cheater: in each bundle, pick uw rows whose ValueData is corpus-RARE
    (recurs in < threshold bundles) AND Sysmon-corroborated in THIS bundle.
    Pure counting; no path knowledge; no answer_key reads."""
    counts = cross_bundle_recurrence(corpus)
    f1s = []
    for d, recmd, sysmon, truth in corpus:
        syskeys = {r["TargetObject"] for r in sysmon}
        sel = {target_of(r) for r in recmd
               if RP.is_user_writable(r["ValueData"])
               and counts[r["ValueData"]] < threshold
               and target_of(r) in syskeys}
        f1s.append(f1(sel, truth))
    return sum(f1s)/len(f1s)


def freq_attack_single(corpus, rng):
    """Pick the single rarest uw+corroborated row per bundle (rng tie-break)."""
    counts = cross_bundle_recurrence(corpus)
    f1s = []
    for d, recmd, sysmon, truth in corpus:
        syskeys = {r["TargetObject"] for r in sysmon}
        cand = [r for r in recmd
                if RP.is_user_writable(r["ValueData"]) and target_of(r) in syskeys]
        if not cand: f1s.append(0.0); continue
        m = min(counts[r["ValueData"]] for r in cand)
        rare = [r for r in cand if counts[r["ValueData"]] == m]
        f1s.append(f1({target_of(rng.choice(rare))}, truth))
    return sum(f1s)/len(f1s)


# ---- basename casing tell ----
def basename_tell(corpus, rng):
    """Pick rows whose exe basename is lowercase+underscore (msedge_health.exe...)."""
    def is_tell(vd):
        base = vd.split("\\")[-1]
        return base.islower() and "_" in base
    f1s = []
    for d, recmd, sysmon, truth in corpus:
        cand = [r for r in recmd if is_tell(r["ValueData"])]
        if not cand: f1s.append(0.0); continue
        f1s.append(f1({target_of(rng.choice(cand))}, truth))
    return sum(f1s)/len(f1s)


def basename_lower_tell(corpus, rng):
    """Pick rows whose exe basename is all-lowercase (any)."""
    def is_tell(vd):
        return vd.split("\\")[-1].islower()
    f1s = []
    for d, recmd, sysmon, truth in corpus:
        cand = [r for r in recmd if is_tell(r["ValueData"])]
        if not cand: f1s.append(0.0); continue
        f1s.append(f1({target_of(rng.choice(cand))}, truth))
    return sum(f1s)/len(f1s)


# ---- honest multi-select (no domain knowledge) ----
def multiselect(corpus, rng):
    f1s = []
    recalls = []
    for d, recmd, sysmon, truth in corpus:
        syskeys = {r["TargetObject"] for r in sysmon}
        sel = {target_of(r) for r in recmd
               if RP.is_user_writable(r["ValueData"]) and target_of(r) in syskeys}
        f1s.append(f1(sel, truth))
        recalls.append(1.0 if truth <= sel else 0.0)
    return sum(f1s)/len(f1s), sum(recalls)/len(recalls)


# ---- oracle (intended rule) ----
def oracle(corpus, rng):
    f1s = []
    for d, recmd, sysmon, truth in corpus:
        syskeys = {r["TargetObject"] for r in sysmon}
        sel = {target_of(r) for r in recmd
               if RP.is_malicious_run_entry(r["ValueData"]) and target_of(r) in syskeys}
        f1s.append(f1(sel, truth))
    return sum(f1s)/len(f1s)


def avg_cands(corpus):
    return sum(len(recmd) for _, recmd, _, _ in corpus)/len(corpus)


def report_histogram(corpus, label):
    counts = cross_bundle_recurrence(corpus)
    # which ValueData are evil vs decoy? use truth to LABEL (post-hoc, not for selection)
    evil_vd, decoy_vd = set(), set()
    for d, recmd, sysmon, truth in corpus:
        for r in recmd:
            if not RP.is_user_writable(r["ValueData"]): continue
            if target_of(r) in truth: evil_vd.add(r["ValueData"])
            else: decoy_vd.add(r["ValueData"])
    decoy_vd -= evil_vd
    ev = [counts[v] for v in evil_vd]
    dc = [counts[v] for v in decoy_vd]
    print(f"\n[{label}] cross-bundle recurrence over {len(SEEDS)} bundles:")
    print(f"  evil pool  ({len(evil_vd)} distinct): recurrence {sorted(ev)}  min={min(ev)} max={max(ev)}")
    print(f"  decoy pool ({len(decoy_vd)} distinct): recurrence {sorted(dc)}  min={min(dc)} max={max(dc)}")
    moat = min(dc) - max(ev)
    print(f"  MOAT (min_decoy - max_evil) = {moat}  -> {'separable' if moat>0 else 'OVERLAP (no moat)'}")
    return moat


def main():
    for prov in (True, False):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = build_corpus(prov, tmp)
            rng = random.Random(12345)
            ac = avg_cands(corpus)
            chance = 1.0/ac
            print("="*72)
            print(f"PROVOCATEUR={prov}   seeds={SEEDS[0]}..{SEEDS[-1]}  avg_candidates={ac:.2f}  chance={chance:.3f}")
            moat = report_histogram(corpus, f"prov={prov}")
            counts = cross_bundle_recurrence(corpus)
            mn = min(counts.values()); mx = max(counts.values())
            print(f"\n  Strategy F1 (mean over {len(SEEDS)} fresh bundles):")
            # frequency attack: sweep thresholds across observed range
            best_freq = 0.0
            for th in range(mn+1, mx+2):
                f = freq_attack(corpus, th, random.Random(1))
                best_freq = max(best_freq, f)
                print(f"    freq_attack(threshold<{th:2d})         F1={f:.4f}")
            fs = freq_attack_single(corpus, random.Random(2))
            print(f"    freq_attack_single_rarest      F1={fs:.4f}")
            bt = basename_tell(corpus, random.Random(3))
            print(f"    basename_lower_underscore_tell F1={bt:.4f}")
            blt = basename_lower_tell(corpus, random.Random(4))
            print(f"    basename_lowercase_tell        F1={blt:.4f}")
            ms, ms_recall = multiselect(corpus, random.Random(5))
            print(f"    honest_multiselect             F1={ms:.4f}  recall={ms_recall:.3f}")
            orc = oracle(corpus, random.Random(6))
            print(f"    ORACLE (intended rule)         F1={orc:.4f}")
            cheater_best = max(best_freq, fs, bt, blt, ms)
            print(f"\n  cheater_best_F1={cheater_best:.4f}  oracle_F1={orc:.4f}  gap={orc-cheater_best:.4f}")
            print(f"  (freq_attack best={best_freq:.4f}, multiselect={ms:.4f})")


if __name__ == "__main__":
    main()
