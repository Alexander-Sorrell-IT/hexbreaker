"""Independent adversarial re-hunt of the prefetch template.

Generates K>=12 FRESH bundles (seeds outside the repo test's 2011-2042 range),
reads the raw artifact files directly, and attempts:
  - Shortcut A "malware_rule_label"
  - Shortcut B "masqname_AND_yarahit"
  - a battery of NEW surface/membership shortcuts
Computes mean-F1 per strategy vs the single true target from answer_key.json.
No reliance on the repo's own test helpers for scoring.
"""
from __future__ import annotations

import collections
import itertools
import json
import tempfile
from pathlib import Path

from hexbreaker.forge import template_prefetch as P

MALWARE_RULES = set(P.MALWARE_YARA_RULES)
MASQ_NAMES = set(P.MASQUERADE_NAMES)
DUAL_HOME = set(P.DUAL_HOME_NAMES)
PF_SYS = set(P.PROGRAMFILES_SYSTEM_NAMES)
DROPPERS = set(P.MALWARE_NONMASQ_DROPPERS)
STAGING_PREFIXES = tuple(P.STAGING_DIRS) + ("C:\\Windows\\Temp",)

# Canonical home map (this is OMNISCIENT domain knowledge = oracle territory; only
# used for the oracle strategy, not the cheaters).
CANON = {}
for n, dirs in P.MASQUERADE_NAMES.items():
    CANON[n] = list(dirs)
for n in P.DUAL_HOME_NAMES:
    CANON[n] = [P.SYSTEM32, P.SYSWOW64]
for n, dirs in P.PROGRAMFILES_SYSTEM_NAMES.items():
    CANON[n] = list(dirs)


def gen(seed, tmp, provocateur=True):
    d = Path(tmp) / f"c{seed}"
    P.generate(seed=seed, out_dir=d, provocateur=provocateur)
    rows = [
        r.split(",")
        for r in (d / "mock_outputs" / "prefetch.csv").read_text().splitlines()[1:]
    ]  # name, full, runcount, lastrun
    yara_lines = [
        ln.strip()
        for ln in (d / "mock_outputs" / "yara.txt").read_text().splitlines()
        if ln.strip()
    ]
    yara_leaves = {ln.split(":", 1)[0].strip() for ln in yara_lines}
    rule_of = {ln.split(":", 1)[0].strip(): ln.split(":", 1)[1].strip() for ln in yara_lines}
    signed = {
        ln.split(":", 1)[0].strip()
        for ln in (d / "mock_outputs" / "catalog.txt").read_text().splitlines()
        if ln.strip()
    }
    ans = json.loads((d / "answer_key.json").read_bytes())
    target = ans["expected_findings"][0]["target"]
    return rows, yara_lines, yara_leaves, rule_of, signed, target, len(rows)


def f1(picked, target):
    picked = set(p for p in picked if p)
    if not picked:
        return 0.0
    tp = 1 if target in picked else 0
    prec = tp / len(picked)
    rec = float(tp)
    if prec + rec == 0:
        return 0.0
    return 2 * prec * rec / (prec + rec)


def oracle(rows, rule_of, signed):
    mal_leaves = {leaf for leaf, r in rule_of.items() if r in MALWARE_RULES}
    picks = []
    for name, full, *_ in rows:
        parent = full.rsplit("\\", 1)[0]
        masq = name in CANON and parent not in CANON[name]
        if masq and name in mal_leaves and name not in signed:
            picks.append(full)
    return picks


def strategies(rows, yara_lines, yara_leaves, rule_of, signed):
    paths = [r[1] for r in rows]
    mal_leaves = {leaf for leaf, r in rule_of.items() if r in MALWARE_RULES}
    out = {}

    def rows_for(leaf):
        return sorted(r[1] for r in rows if r[0] == leaf)

    # ---- Shortcut A verbatim: pick rows whose yara rule is in MALWARE_YARA_RULES.
    malrule_rows = sorted(r[1] for r in rows if r[0] in mal_leaves)
    out["A_malrule_flagall"] = malrule_rows            # flag every malware-rule hit
    out["A_malrule_first"] = malrule_rows[:1]
    out["A_malrule_last"] = malrule_rows[-1:]

    # ---- Shortcut B verbatim: basename in MASQUERADE_NAMES AND appears in yara.
    masq_yara = sorted(r[1] for r in rows if r[0] in MASQ_NAMES and r[0] in yara_leaves)
    out["B_masqYara_flagall"] = masq_yara
    out["B_masqYara_first"] = masq_yara[:1]
    out["B_masqYara_last"] = masq_yara[-1:]

    # ---- NEW shortcuts ----

    # N1: malrule AND masqname (membership pair)
    s = sorted(r[1] for r in rows if r[0] in mal_leaves and r[0] in MASQ_NAMES)
    out["N_malrule_masq_flagall"] = s
    out["N_malrule_masq_first"] = s[:1]
    out["N_malrule_masq_last"] = s[-1:]

    # N2: malrule AND staging dir
    s = sorted(r[1] for r in rows if r[0] in mal_leaves and r[1].startswith(STAGING_PREFIXES))
    out["N_malrule_staging_flagall"] = s
    out["N_malrule_staging_first"] = s[:1]
    out["N_malrule_staging_last"] = s[-1:]

    # N3: malrule AND unsigned
    s = sorted(r[1] for r in rows if r[0] in mal_leaves and r[0] not in signed)
    out["N_malrule_unsigned_flagall"] = s
    out["N_malrule_unsigned_first"] = s[:1]
    out["N_malrule_unsigned_last"] = s[-1:]

    # N4: masqname AND staging
    s = sorted(r[1] for r in rows if r[0] in MASQ_NAMES and r[1].startswith(STAGING_PREFIXES))
    out["N_masq_staging_flagall"] = s
    out["N_masq_staging_first"] = s[:1]
    out["N_masq_staging_last"] = s[-1:]

    # N5: masqname AND unsigned
    s = sorted(r[1] for r in rows if r[0] in MASQ_NAMES and r[0] not in signed)
    out["N_masq_unsigned_flagall"] = s
    out["N_masq_unsigned_first"] = s[:1]
    out["N_masq_unsigned_last"] = s[-1:]

    # N6: yara AND staging AND unsigned (3 surface legs, no rule semantics)
    s = sorted(r[1] for r in rows if r[0] in yara_leaves and r[1].startswith(STAGING_PREFIXES) and r[0] not in signed)
    out["N_yara_staging_unsigned_flagall"] = s
    out["N_yara_staging_unsigned_first"] = s[:1]
    out["N_yara_staging_unsigned_last"] = s[-1:]

    # N7: masqname AND staging AND unsigned (NOT using rule semantics) — closest
    #     non-rule approximation of the answer
    s = sorted(r[1] for r in rows if r[0] in MASQ_NAMES and r[1].startswith(STAGING_PREFIXES) and r[0] not in signed)
    out["N_masq_staging_unsigned_flagall"] = s
    out["N_masq_staging_unsigned_first"] = s[:1]
    out["N_masq_staging_unsigned_last"] = s[-1:]

    # N8: basename NOT in DUAL_HOME/PF_SYS/DROPPERS but in MASQ_NAMES, yara-hit,
    #     unsigned (try to exclude known decoy classes by their PUBLIC list membership)
    #     Note: SYS and SMQ and MASQB are ALSO drawn from MASQ_NAMES, so this won't
    #     distinguish — but DROPPERS/DUAL/PF are separate lists, test anyway.
    s = sorted(r[1] for r in rows if r[0] in MASQ_NAMES and r[0] in yara_leaves
               and r[0] not in signed and r[0] not in DROPPERS and r[0] not in DUAL_HOME and r[0] not in PF_SYS)
    out["N_masq_yara_unsigned_notdropper_flagall"] = s
    out["N_masq_yara_unsigned_notdropper_first"] = s[:1]
    out["N_masq_yara_unsigned_notdropper_last"] = s[-1:]

    # N9: rule-string lexicographic outlier among MALWARE rules only
    mal_hit = [r for r in rows if r[0] in mal_leaves]
    if mal_hit:
        by_rule = sorted(mal_hit, key=lambda r: (rule_of[r[0]], r[1]))
        out["N_malrule_minrule"] = [by_rule[0][1]]
        out["N_malrule_maxrule"] = [by_rule[-1][1]]

    # N10: malware-rule hit AND basename NOT in droppers list (droppers are the
    #      explicit non-masq malware decoys). Removes MAL_lo/hi but keeps SYS/SMQ/DEF.
    s = sorted(r[1] for r in rows if r[0] in mal_leaves and r[0] not in DROPPERS)
    out["N_malrule_notdropper_flagall"] = s
    out["N_malrule_notdropper_first"] = s[:1]
    out["N_malrule_notdropper_last"] = s[-1:]

    # N11: malware-rule hit AND masqname AND unsigned but NOT in PF_SYS
    #      (this is essentially masq∩malrule∩unsigned = approaches oracle via labels;
    #      SMQ is unsigned? No SMQ is signed. SYS is signed. So this = masq∩mal∩unsigned)
    s = sorted(r[1] for r in rows if r[0] in mal_leaves and r[0] in MASQ_NAMES and r[0] not in signed)
    out["N_masq_malrule_unsigned_flagall"] = s
    out["N_masq_malrule_unsigned_first"] = s[:1]
    out["N_masq_malrule_unsigned_last"] = s[-1:]

    # N12: the row whose basename is a MASQ_NAME and that basename appears NOWHERE
    #      in System32 in the rows (i.e. masqname with no canonical-dir occurrence
    #      anywhere in CSV) — a pure-string canonical-absence proxy without the map
    sys32_names = {r[0] for r in rows if r[1].startswith("C:\\Windows\\System32")}
    s = sorted(r[1] for r in rows if r[0] in MASQ_NAMES and r[0] in yara_leaves
               and r[0] not in signed and r[0] not in sys32_names)
    out["N_masq_yara_unsigned_noSys32twin_flagall"] = s
    out["N_masq_yara_unsigned_noSys32twin_first"] = s[:1]
    out["N_masq_yara_unsigned_noSys32twin_last"] = s[-1:]

    return out


def main():
    SEEDS = list(range(70001, 70017))  # 16 fresh seeds, outside test range
    cheater = collections.defaultdict(list)
    oracle_scores = []
    ncands = set()
    with tempfile.TemporaryDirectory() as tmp:
        for seed in SEEDS:
            rows, yl, yleaves, rule_of, signed, target, n = gen(seed, tmp)
            ncands.add(n)
            oracle_scores.append(f1(set(oracle(rows, rule_of, signed)), target))
            for name, picked in strategies(rows, yl, yleaves, rule_of, signed).items():
                cheater[name].append(f1(set(picked), target))
    print(f"K = {len(SEEDS)} fresh seeds {SEEDS[0]}..{SEEDS[-1]}")
    print(f"num_candidates seen = {sorted(ncands)}  chance = {1/max(ncands):.4f}")
    oracle_f1 = sum(oracle_scores) / len(oracle_scores)
    print(f"ORACLE mean-F1 = {oracle_f1:.4f}")
    print()
    ranked = sorted(((sum(v)/len(v), k) for k, v in cheater.items()), reverse=True)
    print("All cheater strategies (mean-F1, sorted desc):")
    for score, name in ranked:
        print(f"  {score:.4f}  {name}")
    best_f1, best_name = ranked[0]
    print()
    print(f"BEST CHEATER: {best_name}  F1={best_f1:.4f}")
    print(f"GAP = oracle - best_cheater = {oracle_f1 - best_f1:.4f}")
    verdict = "clean" if (best_f1 <= 1/max(ncands) + 0.12 and oracle_f1 - best_f1 >= 0.6) else "leaky"
    print(f"VERDICT (gap>=0.6 & cheater near chance): {verdict}")


if __name__ == "__main__":
    main()
