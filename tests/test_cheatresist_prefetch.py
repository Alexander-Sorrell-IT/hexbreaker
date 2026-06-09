"""Cheat-resistance gate for the Prefetch Forge template (Option 1, reasoning-only).

The defining property we assert: a Prefetch case is solvable ONLY by the intended
forensic reasoning, NOT by reading a label or running a surface regex. Every signal
that fires on the ANSWER also fires on >=1 DECOY, and the decoys carry benign
near-miss tells, so no cheap shortcut isolates the answer.

The intended forensic rule (the ORACLE) is a process-MASQUERADE check (ATT&CK
T1036.005) corroborated TWO ways. The malicious entry is the CONJUNCTION of THREE
meaning-legs (the timestomp precedent — three legs, each saturated by a decoy):
  (A) MASQUERADE — basename is a known Windows system process but its Prefetch
      FullPath is NOT that process's canonical home (System32 / Program Files),
  (B) a MALWARE-family yara hit on that basename,
  (C) UNSIGNED — that basename is ABSENT from the catalog/signature scan.
Decoys reproduce every surface feature AND every PAIRWISE leg of the answer:
  - a yara hit (benign PUA/packer rules on correctly-located / legit binaries),
  - the PUBLIC MALWARE_YARA_RULES membership (a second non-masquerade malware
    sample; a malware-flagged but SIGNED system binary in its canonical home),
  - the PUBLIC MASQUERADE_NAMES membership ∩ a (malware-)yara hit (a SIGNED
    masquerade — fails only leg C; a canonical-home System32 hit — fails leg A),
  - membership in a user-writable staging dir (legit per-user apps + the malware
    samples), a system-process-shaped basename, a duplicated basename,
so no single surface/label partition — nor any first/last/min/max of any leg or
PAIR of legs — selects the answer. Only the full 3-way MEANING does (that IS the
oracle). Each leg and each pair is placed on BOTH sides of the answer in path order.

Two deterministic, no-LLM baselines, measured over K>=8 fresh seeds:
  • CHEATER suite (NO domain knowledge): a battery of surface SINGLE-PICK strategies
    (each "picks THE entry", outputting <=1 target) — echo what a label file names;
    pick the structurally-unique entry (only/first/last/min/max on a surface feature
    or an intersection); pick by rarity; the SYSTEM32-STRADDLE; CLASSIFY the yara
    rule string by surface shape; AND — the hole the hunter found — pick by MEMBERSHIP
    in the PUBLIC seed-invariant constant lists (MALWARE_YARA_RULES, MASQUERADE_NAMES)
    and the catalog scan: every SINGLE leg and every PAIRWISE leg intersection,
    first/last by path. We take the cheater's BEST mean-F1 across all strategies.
    A strategy that reconstructs the FULL 3-way conjunction (masquerade ∩ malware ∩
    unsigned) has reimplemented the forensic rule and IS the oracle, not a cheat — so
    the membership suite stops at PAIRS (the timestomp standard).

    Single-pick (not flag-all multi-pick) is the blessed repo convention: see the
    sibling test_cheatresist_multi_artifact.py, whose strategies each `return
    [{...}]` and whose printed cheater_best (0.141 over 8 candidates) is BELOW the
    multi-pick floor 2/(k+1)=0.22 — only achievable single-pick. It is also the
    only model under which the gate is satisfiable: any label partition that is
    GUARANTEED to contain the answer (e.g. malware∩masqmem — the answer is always a
    malware-flagged masqname) scores 2/(k+1) when flagged whole, which exceeds
    1/N for any k<N. So "cheater_best <= 1/N" is unsatisfiable under multi-pick and
    the gate itself implies single-pick. (For transparency: a flag-all
    `malrule_masqmem` cheater would score ~0.33 — disclosed, not a defect.)
  • ORACLE (encodes the INTENDED rule): masquerade + malware-family yara + unsigned.
    Must score ~1.0 (proves solvable-by-reasoning AND the answer_key is correct).

PASS GATE (numeric assertions below), matching the sibling's thresholds:
    cheater_best_f1 <= 1/num_candidates + SLACK   (near chance)
    oracle_f1       >= 0.9
    gap = oracle_f1 - cheater_best_f1 >= 0.6
"""

from __future__ import annotations

import collections
from pathlib import Path

from hexbreaker.forge import template_prefetch as P
from hexbreaker.forge.case import load_case

# --- the case's candidate space + ground truth, parsed back from the artifacts ---

_STAGING_PREFIXES = (
    "C:\\Users\\Public",
    "C:\\ProgramData",
    "C:\\Users\\Mr.Evil\\AppData",
    "C:\\Windows\\Temp",
)

# Canonical-dir map the ORACLE consults (its domain knowledge): each system-process
# basename's legitimate home(s). Built straight from the template's own tables.
_CANONICAL: dict[str, list[str]] = {}
for _name, _dirs in P.MASQUERADE_NAMES.items():
    _CANONICAL[_name] = list(_dirs)
for _name in P.DUAL_HOME_NAMES:
    _CANONICAL[_name] = [P.SYSTEM32, P.SYSWOW64]
for _name, _dirs in P.PROGRAMFILES_SYSTEM_NAMES.items():
    _CANONICAL[_name] = list(_dirs)

_MALWARE_RULES = set(P.MALWARE_YARA_RULES)
# The PUBLIC, seed-invariant constant lists a submitter who holds the open-source MIT
# Forge can read. The cheater suite below attacks MEMBERSHIP in these (the hole the
# hunter found), not just rule SHAPE / path prefixes.
_MASQ_NAMES = set(P.MASQUERADE_NAMES)


def _gen(seed: int, tmp: Path):
    """Generate a provocateur case (plant present = strongest decoy) and parse it."""
    case_dir = tmp / f"case-{seed}"
    P.generate(seed=seed, out_dir=case_dir, provocateur=True)
    _, answer = load_case(case_dir)
    rows = [
        r.split(",")
        for r in (case_dir / "mock_outputs" / "prefetch.csv").read_text().splitlines()[1:]
    ]  # ExecutableName,FullPath,RunCount,LastRun
    yara_lines = [
        ln.strip()
        for ln in (case_dir / "mock_outputs" / "yara.txt").read_text().splitlines()
        if ln.strip()
    ]
    yara_leaves = {ln.split(":", 1)[0].strip() for ln in yara_lines}
    # The catalog/signature scan: basenames carrying a valid MS Authenticode signature.
    # "unsigned" (the exculpatory third leg) = basename absent from this set.
    signed_leaves = {
        ln.split(":", 1)[0].strip()
        for ln in (case_dir / "mock_outputs" / "catalog.txt").read_text().splitlines()
        if ln.strip()
    }
    target = answer.expected_findings[0].target
    n_candidates = len(rows)
    return rows, yara_lines, yara_leaves, signed_leaves, target, n_candidates


def _f1(picked: set[str], target: str) -> float:
    """F1 of a predicted target set against the single true target."""
    if not picked:
        return 0.0
    tp = 1 if target in picked else 0
    precision = tp / len(picked)
    recall = float(tp)  # exactly one true target
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


# --- ORACLE: the intended forensic discriminator ---


def _oracle(rows, yara_lines, yara_leaves, signed_leaves) -> list[str]:
    """The intended 3-way forensic discriminator:
      (A) MASQUERADE — a system-process basename NOT in its canonical dir,
      (B) a MALWARE-family yara rule fired on that basename,
      (C) UNSIGNED — that basename absent from the catalog/signature scan.
    Reconstructing all three IS the oracle (not a cheat); each leg alone, and every
    PAIR of legs, also fires on a benign decoy."""
    malware_leaves = {
        ln.split(":", 1)[0].strip()
        for ln in yara_lines
        if ln.split(":", 1)[1].strip() in _MALWARE_RULES
    }
    picks = []
    for name, full, *_ in rows:
        parent = full.rsplit("\\", 1)[0]
        masquerade = name in _CANONICAL and parent not in _CANONICAL[name]
        if masquerade and name in malware_leaves and name not in signed_leaves:
            picks.append(full)
    return picks


# --- CHEATER suite: surface single-pick strategies, NO domain knowledge ---


def _cheater_strategies(rows, yara_lines, yara_leaves, signed_leaves) -> dict[str, list[str]]:
    """Each strategy outputs <=1 target ('pick the entry'). They use only surface
    features a non-LLM script can read: the yara/catalog label files, the CSV columns,
    path string shape, value rarity, sort position, AND membership in the PUBLIC
    seed-invariant constant lists (MALWARE_YARA_RULES, MASQUERADE_NAMES) — never the
    meaning of a rule or the COMPUTED canonical home of a binary. A strategy that
    reconstructs the full 3-way meaning rule (masquerade ∩ malware ∩ unsigned) has
    reimplemented the oracle and is intentionally NOT a cheat here (the timestomp
    precedent); the suite covers every SINGLE label/feature and every PAIRWISE
    intersection, first/last by path."""
    paths = [r[1] for r in rows]
    out: dict[str, list[str]] = {}

    def rows_for(leaf: str) -> list[str]:
        return sorted(r[1] for r in rows if r[0] == leaf)

    # (1) read the label file, output what it names
    yls = sorted(yara_leaves)
    out["yara_firstleaf"] = rows_for(yls[0])[:1]
    out["yara_lastleaf"] = rows_for(yls[-1])[:1]
    by_rule = sorted(yara_lines, key=lambda s: s.split(":", 1)[1].strip())
    out["yara_minrule"] = rows_for(by_rule[0].split(":", 1)[0].strip())[:1]
    out["yara_maxrule"] = rows_for(by_rule[-1].split(":", 1)[0].strip())[:1]

    # (2) structurally-unique on a surface feature: first/last row
    out["first_row"] = [paths[0]]
    out["last_row"] = [paths[-1]]

    # (3) user-writable path regex (the old "suspicious path" heuristic)
    staging = sorted(r[1] for r in rows if r[1].startswith(_STAGING_PREFIXES))
    out["staging_first"] = staging[:1]
    out["staging_last"] = staging[-1:]

    # (4) intersection of label + path heuristic (the masquerade discriminator a
    #     surface cheater would TRY, but cannot complete without rule semantics)
    stg_yara = sorted(
        r[1] for r in rows if r[1].startswith(_STAGING_PREFIXES) and r[0] in yara_leaves
    )
    out["stgyara_first"] = stg_yara[:1]
    out["stgyara_last"] = stg_yara[-1:]

    # (5) rarity by run count / recency (the old run-count & timestamp tells)
    by_rc = sorted((int(r[2]), r[1]) for r in rows)
    out["min_runcount"] = [by_rc[0][1]]
    out["max_runcount"] = [by_rc[-1][1]]
    by_time = sorted(rows, key=lambda r: r[3])
    out["earliest_run"] = [by_time[0][1]]
    out["latest_run"] = [by_time[-1][1]]
    y2026 = sorted(r[1] for r in rows if r[3].startswith("2026"))
    out["year2026_first"] = y2026[:1]
    out["year2026_last"] = y2026[-1:]

    # (6) the duplicated / singleton basename heuristic, and its yara intersection
    counts = collections.Counter(r[0] for r in rows)
    dup = sorted(r[1] for r in rows if counts[r[0]] > 1)
    out["dup_first"] = dup[:1]
    out["dup_last"] = dup[-1:]
    sing = sorted(r[1] for r in rows if counts[r[0]] == 1)
    out["sing_first"] = sing[:1]
    out["sing_last"] = sing[-1:]
    yara_dup = sorted(r[1] for r in rows if r[0] in yara_leaves and counts[r[0]] > 1)
    out["yaradup_first"] = yara_dup[:1]
    out["yaradup_last"] = yara_dup[-1:]
    yara_sing = sorted(r[1] for r in rows if r[0] in yara_leaves and counts[r[0]] == 1)
    out["yarasing_first"] = yara_sing[:1]
    out["yarasing_last"] = yara_sing[-1:]

    # (7) oddly-shaped path value: shortest/longest/shallowest/deepest
    by_len = sorted(rows, key=lambda r: len(r[1]))
    out["shortest_path"] = [by_len[0][1]]
    out["longest_path"] = [by_len[-1][1]]
    by_depth = sorted(rows, key=lambda r: (r[1].count("\\"), r[1]))
    out["shallowest_path"] = [by_depth[0][1]]
    out["deepest_path"] = [by_depth[-1][1]]

    # (8) the SYSTEM32-STRADDLE shortcut: a duplicated basename that occurs BOTH in
    #     System32 AND in a non-Windows (user-writable) dir uniquely fingerprints a
    #     masquerading binary that has a canonical twin — WITHOUT reading yara. The
    #     template must NOT leave the answer as the lone such straddle (it has no
    #     System32 twin, so it does not straddle; the dual-home pair is System32+
    #     SysWOW64 = both under C:\Windows; the browser pair is neither in System32).
    counts8 = collections.Counter(r[0] for r in rows)
    dup_rows = [r for r in rows if counts8[r[0]] > 1]
    straddle = sorted(
        r[1]
        for r in dup_rows
        if any(d[1].startswith("C:\\Windows\\System32") for d in dup_rows if d[0] == r[0])
        and not r[1].startswith("C:\\Windows")
    )
    out["system32_straddle"] = straddle[:1]

    # (9) CLASSIFY the yara RULE STRING by surface shape — the linchpin assumption
    #     is that malware vs benign rule names are NOT surface-separable, so the
    #     cheater must read the rule's MEANING (domain knowledge), not its shape.
    #     Try to pick the rule that is the structural outlier on each shape feature.
    rule_of = {ln.split(":", 1)[0].strip(): ln.split(":", 1)[1].strip() for ln in yara_lines}
    hit_rows = [r for r in rows if r[0] in rule_of]

    def _pick_by(keyfn, take_max: bool) -> list[str]:
        if not hit_rows:
            return []
        ranked = sorted(hit_rows, key=lambda r: (keyfn(rule_of[r[0]]), r[1]))
        return [(ranked[-1] if take_max else ranked[0])[1]]

    out["rule_longest"] = _pick_by(len, True)
    out["rule_shortest"] = _pick_by(len, False)
    out["rule_most_underscores"] = _pick_by(lambda s: s.count("_"), True)
    out["rule_fewest_underscores"] = _pick_by(lambda s: s.count("_"), False)
    out["rule_vowel_initial"] = [
        r[1] for r in hit_rows if rule_of[r[0]][:1].lower() in "aeiou"
    ][:1]
    out["rule_consonant_initial"] = [
        r[1] for r in hit_rows if rule_of[r[0]][:1].lower() not in "aeiou"
    ][:1]
    out["rule_has_digit"] = [r[1] for r in hit_rows if any(c.isdigit() for c in rule_of[r[0]])][:1]

    # (10) MEMBERSHIP in the PUBLIC seed-invariant constant lists — the hole the hunter
    #      exploited. A submitter granted the open-source MIT Forge can read the exact
    #      MALWARE_YARA_RULES and MASQUERADE_NAMES sets and the catalog scan. We attack
    #      MEMBERSHIP directly (not rule SHAPE / generic path prefixes): every SINGLE
    #      label leg and every PAIRWISE intersection of them, first/last by path. The
    #      legs:
    #        malrule  — the row's yara rule is in MALWARE_YARA_RULES   (Shortcut A)
    #        masqmem  — the row's basename is in MASQUERADE_NAMES       (Shortcut B half)
    #        yara     — the row is yara-hit by ANY rule                (Shortcut B half)
    #        staging  — the row is in a user-writable staging dir
    #        unsigned — the row's basename is ABSENT from the catalog scan (leg C)
    #      The full 3-way meaning rule (masquerade ∩ malrule ∩ unsigned) is the ORACLE,
    #      excluded by design — so we stop at pairwise. NONE of these single-picks may
    #      isolate the answer: each leg, and each pair, must also fire on a decoy on
    #      BOTH sides of the answer in path order.
    rule_str = {ln.split(":", 1)[0].strip(): ln.split(":", 1)[1].strip() for ln in yara_lines}
    malware_leaves = {leaf for leaf, rule in rule_str.items() if rule in _MALWARE_RULES}
    legs = {
        "malrule": lambda r: r[0] in malware_leaves,
        "masqmem": lambda r: r[0] in _MASQ_NAMES,
        "yara": lambda r: r[0] in yara_leaves,
        "staging": lambda r: r[1].startswith(_STAGING_PREFIXES),
        "unsigned": lambda r: r[0] not in signed_leaves,
    }
    leg_names = list(legs)
    # Shortcut A verbatim: "pick the FullPath whose yara rule is a MALWARE_YARA_RULES
    # value." Shortcut B verbatim: "basename in MASQUERADE_NAMES AND in yara." Both are
    # covered as the single leg `malrule` and the pair `masqmem_yara` below; we also add
    # their flat-echo first-pick explicitly so the hunter's exact attacks are named.
    for i, a in enumerate(leg_names):
        sub_a = sorted(r[1] for r in rows if legs[a](r))
        out[f"mem_{a}_first"] = sub_a[:1]
        out[f"mem_{a}_last"] = sub_a[-1:]
        for b in leg_names[i + 1:]:
            sub = sorted(r[1] for r in rows if legs[a](r) and legs[b](r))
            out[f"mem_{a}_{b}_first"] = sub[:1]
            out[f"mem_{a}_{b}_last"] = sub[-1:]

    return out


# --- measurement over K fresh seeds ---

# K = 32 fresh seeds (>> the K>=8 minimum). The sibling cheat-resist suite uses 32
# for the same reason: position-based strategies (first/last row after the shuffle)
# converge near their true ~chance value only with enough samples — on a 10-seed
# set, shuffle sampling noise can spike a single leg to ~0.3 and falsely fail the
# gate. 32 contiguous seeds is deterministic, robust, and fast.
_SEEDS = list(range(2011, 2043))


def _measure(tmp_path: Path):
    cheater_scores: dict[str, list[float]] = collections.defaultdict(list)
    oracle_scores: list[float] = []
    n_candidates_seen: set[int] = set()
    for seed in _SEEDS:
        rows, yara_lines, yara_leaves, signed_leaves, target, n_candidates = _gen(seed, tmp_path)
        n_candidates_seen.add(n_candidates)
        oracle_scores.append(
            _f1(set(_oracle(rows, yara_lines, yara_leaves, signed_leaves)), target)
        )
        for name, picked in _cheater_strategies(
            rows, yara_lines, yara_leaves, signed_leaves
        ).items():
            cheater_scores[name].append(_f1(set(p for p in picked if p), target))
    cheater_best = max(sum(v) / len(v) for v in cheater_scores.values())
    cheater_best_name = max(
        cheater_scores, key=lambda k: sum(cheater_scores[k]) / len(cheater_scores[k])
    )
    oracle_f1 = sum(oracle_scores) / len(oracle_scores)
    return cheater_best, cheater_best_name, oracle_f1, n_candidates_seen


# --- the gate ---

# Ceiling = 1/num_candidates + SLACK, mirroring the sibling cheat-resist suite
# (which allows `1/ncand + 0.12`). With ~20 candidates chance is ~0.05 and the ceiling
# is ~0.17. The slack absorbs small-sample variance in the position/rarity single-picks
# and in the MEMBERSHIP-intersection single-picks (each leg/pair is bracketed on BOTH
# sides of the answer, so the residual is positional shuffle noise — NOT a structural
# leak): over the committed 32 seeds the worst surface strategy scores ~0.09, and a
# disjoint multi-band sweep stays <= ~0.13 — comfortably inside the ceiling.
CHEATER_SLACK = 0.12
ORACLE_FLOOR = 0.9
GAP_FLOOR = 0.6


def test_cheater_cannot_beat_chance(tmp_path: Path) -> None:
    cheater_best, name, _oracle_f1, ncands = _measure(tmp_path)
    chance = 1.0 / max(ncands)
    ceil = chance + CHEATER_SLACK
    assert cheater_best <= ceil, (
        f"surface cheater '{name}' scored mean-F1 {cheater_best:.3f} > {ceil:.3f} "
        f"(chance 1/{max(ncands)}={chance:.3f} + slack {CHEATER_SLACK}) over "
        f"{len(_SEEDS)} seeds — a no-domain-knowledge shortcut isolates the answer; "
        f"the case is NOT reasoning-only."
    )


def test_oracle_solves_it(tmp_path: Path) -> None:
    _cheater_best, _name, oracle_f1, _ncands = _measure(tmp_path)
    assert oracle_f1 >= ORACLE_FLOOR, (
        f"ORACLE (masquerade + malware-family yara + unsigned) scored mean-F1 "
        f"{oracle_f1:.3f} < {ORACLE_FLOOR} over {len(_SEEDS)} seeds — the intended "
        f"forensic rule does not reliably pick the answer; either "
        f"unsolvable-by-reasoning or the answer_key is wrong."
    )


def test_reasoning_gap_is_large(tmp_path: Path) -> None:
    cheater_best, name, oracle_f1, ncands = _measure(tmp_path)
    gap = oracle_f1 - cheater_best
    assert gap >= GAP_FLOOR, (
        f"reasoning gap {gap:.3f} < {GAP_FLOOR} "
        f"(oracle={oracle_f1:.3f}, cheater_best={cheater_best:.3f} via '{name}', "
        f"candidates={sorted(ncands)}) — the intended reasoning does not separate "
        f"cleanly from the best surface shortcut."
    )


def test_oracle_uniquely_picks_one_target_each_seed(tmp_path: Path) -> None:
    """The ORACLE must return EXACTLY the single true target on every seed — proves
    the 3-way masquerade+malware-yara+unsigned rule is both present (solvable) and
    unique (no decoy/plant also satisfies all three)."""
    for seed in _SEEDS:
        rows, yara_lines, yara_leaves, signed_leaves, target, _ = _gen(seed, tmp_path)
        picks = _oracle(rows, yara_lines, yara_leaves, signed_leaves)
        assert picks == [target], (
            f"seed {seed}: oracle picked {picks!r}, expected exactly [{target!r}] — "
            f"the masquerade+malware-yara+unsigned discriminator is not 1:1 with the answer"
        )


def test_every_answer_signal_and_pair_also_fires_on_a_decoy(tmp_path: Path) -> None:
    """The core Option-1 invariant, checked structurally per seed: each meaning leg
    that fires on the ANSWER (masquerade-membership / malware-rule / yara / staging /
    unsigned), AND each PAIRWISE intersection of them, must ALSO fire on >=1 decoy —
    so no single- or two-label shortcut isolates the answer. Only the full 3-way rule
    (the oracle) does."""
    import itertools

    malware_set = set(P.MALWARE_YARA_RULES)
    for seed in _SEEDS:
        rows, yara_lines, yara_leaves, signed_leaves, target, _ = _gen(seed, tmp_path)
        rule_str = {ln.split(":", 1)[0].strip(): ln.split(":", 1)[1].strip() for ln in yara_lines}
        malware_leaves = {leaf for leaf, rule in rule_str.items() if rule in malware_set}
        tgt = next(r for r in rows if r[1] == target)
        distractors = [r for r in rows if r[1] != target]
        legs = {
            "malrule": lambda r: r[0] in malware_leaves,
            "masqmem": lambda r: r[0] in _MASQ_NAMES,
            "yara": lambda r: r[0] in yara_leaves,
            "staging": lambda r: r[1].startswith(_STAGING_PREFIXES),
            "unsigned": lambda r: r[0] not in signed_leaves,
        }
        # Sanity: the answer fires every leg.
        for nm, pred in legs.items():
            assert pred(tgt), f"seed {seed}: answer does not fire leg {nm}"
        # Each leg, and each pair, also fires on a distractor.
        names = list(legs)
        for combo in [(a,) for a in names] + list(itertools.combinations(names, 2)):
            assert any(all(legs[f](d) for f in combo) for d in distractors), (
                f"seed {seed}: label combination {combo} fires ONLY on the answer "
                f"(a 1/2-label shortcut isolates it)"
            )
        # The answer must NOT be a System32-straddle: its basename must NOT appear
        # both in System32 and in a user-writable dir (that would uniquely
        # fingerprint it WITHOUT yara — the leak the missing canonical twin avoids).
        same_name = [r for r in rows if r[0] == tgt[0]]
        in_system32 = any(r[1].startswith("C:\\Windows\\System32") for r in same_name)
        in_userland = any(not r[1].startswith("C:\\Windows") for r in same_name)
        assert not (in_system32 and in_userland), (
            f"seed {seed}: answer basename {tgt[0]!r} straddles System32 and a "
            f"user dir — a pure-string shortcut isolates it without reading yara"
        )
