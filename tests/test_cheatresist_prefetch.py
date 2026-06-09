r"""Cheat-resistance gate for the Prefetch Forge template (Option 1, reasoning-only).

The defining property we assert: a Prefetch case is solvable ONLY by the intended
forensic reasoning, NOT by reading a label, running a surface regex, or testing
membership in the PUBLIC open-source constant. Every signal that fires on the
ANSWER also fires on >=1 DECOY, so no cheap shortcut isolates the answer.

The intended forensic rule (the ORACLE) is a process-MASQUERADE check (ATT&CK
T1036.005) corroborated TWO ways. The malicious entry is the CONJUNCTION of THREE
meaning-legs (the timestomp precedent — three legs, each saturated by a decoy):
  (A) MASQUERADE — a system-process basename whose Prefetch FullPath is NOT that
      process's canonical home (read from the SYSTEM_PROCESS_HOMES map),
  (B) a MALWARE-family yara hit on that basename,
  (C) UNSIGNED — that basename is ABSENT from the catalog/signature scan.

CO-LOCATION DEFENCE (cheat-hunt, 2026-06-09). A 30-agent hunt found the answer was
the UNIQUE row satisfying basename∈system-name-list ∧ rule∈MALWARE_YARA_RULES ∧
unsigned — a PUBLIC-MEMBERSHIP conjunction needing ZERO canonical-home reasoning,
because no BENIGN decoy populated that full cell. The fix (see the template): the
answer is a system-process basename dropped into a HOME that legitimately houses
OTHER system processes (e.g. svchost.exe in C:\Windows root next to the real
explorer.exe), CO-LOCATED with >=5 benign canonical residents of that exact dir,
each a heuristic MALWARE-family yara FALSE POSITIVE that is ALSO unsigned. The
answer and its co-residents agree on EVERY public label (system-name ∩ malware-rule
∩ unsigned) AND every path feature (same directory, depth, segments), so only the
per-name canonical-home MAP separates them — that map IS the oracle's reasoning.
The single public constant is the HETEROGENEOUS map SYSTEM_PROCESS_HOMES; it is
deliberately NOT split into homogeneous per-home sublists (an all-System32
MASQUERADE_NAMES leaked "home==System32" as a free KEY test), so KEY-membership
means only "is-a-system-process" (saturated) and recovering a per-home partition
FORCES reading the home VALUES — which is `parent not in SYSTEM_PROCESS_HOMES[name]`,
the ORACLE (the registry precedent: reading KNOWN_VENDOR_PATHS values is oracle-
class, not a cheat).

Two deterministic, no-LLM baselines, measured over K>=24 fresh seeds:
  • CHEATER suite (NO domain knowledge): surface SINGLE-PICK + flag-all strategies
    that use ONLY KEY-membership in the public map, the yara/catalog label files,
    path regexes (user-writable staging, not-Windows, Windows-not-System32), value
    rarity, sort position — never the home VALUES of a basename. INCLUDING the hunted
    PUBLIC-MEMBERSHIP TRIPLE (system-name ∩ malware-rule ∩ unsigned) and its
    intersection with every path regex, first/last/flag-all. We take the cheater's
    BEST mean-F1. A strategy that reads the canonical-home VALUES has reimplemented
    the forensic rule and IS the oracle, not a cheat (see test_home_value_reasoning_
    is_oracle_class: it scores high BY READING THE MAP — the reasoning-only path).
  • ORACLE (encodes the INTENDED rule): masquerade (non-canonical home, read from the
    map) + malware-family yara + unsigned. Must score ~1.0.

PASS GATE (numeric assertions below):
    cheater_best_f1 <= 1/num_candidates + SLACK   (near chance)
    oracle_f1       >= 0.9
    gap = oracle_f1 - cheater_best_f1 >= 0.6
"""

from __future__ import annotations

import collections
import itertools
from pathlib import Path

from hexbreaker.forge import template_prefetch as P
from hexbreaker.forge.case import load_case

# --- the case's candidate space + ground truth, parsed back from the artifacts ---

# User-writable staging prefixes — a path REGEX a surface cheater can run (NOT the
# canonical-home map). The answer lives in a SYSTEM dir, never under these.
_STAGING_PREFIXES = (
    "C:\\Users\\Public",
    "C:\\ProgramData",
    "C:\\Users\\Mr.Evil\\AppData",
    "C:\\Windows\\Temp",
)

# The ORACLE's canonical-home map IS the single public constant SYSTEM_PROCESS_HOMES
# (name -> its legitimate home(s)). Reading its VALUES is the intended reasoning.
_CANONICAL = dict(P.SYSTEM_PROCESS_HOMES)

_MALWARE_RULES = set(P.MALWARE_YARA_RULES)
# KEY-membership in the public map = "is a system-process name" (the full universe).
# This is the strongest membership a no-domain cheater can test WITHOUT reading the
# map's home values. Every candidate row carries one of these basenames.
_ALL_SYSNAMES = set(P.SYSTEM_PROCESS_HOMES)
_MASQ_NAMES = _ALL_SYSNAMES  # the public alias MASQUERADE_NAMES IS the full map


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


def _malware_leaves(yara_lines):
    return {
        ln.split(":", 1)[0].strip()
        for ln in yara_lines
        if ln.split(":", 1)[1].strip() in _MALWARE_RULES
    }


def _win_not_sys32(p: str) -> bool:
    return p.startswith("C:\\Windows\\") and not p.startswith((P.SYSTEM32, P.SYSWOW64))


# --- ORACLE: the intended forensic discriminator (reads the home VALUES) ---


def _oracle(rows, yara_lines, yara_leaves, signed_leaves) -> list[str]:
    """The intended 3-way forensic discriminator:
      (A) MASQUERADE — a system-process basename NOT in its canonical home (read from
          SYSTEM_PROCESS_HOMES — the domain-knowledge map),
      (B) a MALWARE-family yara rule fired on that basename,
      (C) UNSIGNED — that basename absent from the catalog/signature scan.
    Reconstructing all three IS the oracle (not a cheat); each leg alone, and every
    PAIR of legs, also fires on a benign decoy."""
    malware_leaves = _malware_leaves(yara_lines)
    picks = []
    for name, full, *_ in rows:
        parent = full.rsplit("\\", 1)[0]
        masquerade = name in _CANONICAL and parent not in _CANONICAL[name]
        if masquerade and name in malware_leaves and name not in signed_leaves:
            picks.append(full)
    return picks


# --- CHEATER suite: surface single-pick + flag-all, NO home-VALUE reasoning ---


def _cheater_strategies(rows, yara_lines, yara_leaves, signed_leaves) -> dict[str, list[str]]:
    """Each strategy uses only KEY-membership in the public map, the label files, path
    REGEXES, value rarity, and sort position — never the home VALUE of a basename. A
    strategy that reads the canonical-home values has reimplemented the oracle and is
    intentionally NOT a cheat here. We cover every SINGLE label/feature, every PAIRWISE
    intersection, AND the hunted PUBLIC-MEMBERSHIP TRIPLE (system-name ∩ malware-rule ∩
    unsigned) intersected with every cheater-computable path regex, first/last/all."""
    paths = [r[1] for r in rows]
    malware_leaves = _malware_leaves(yara_lines)
    out: dict[str, list[str]] = {}

    def add(name: str, members):
        members = sorted(set(members))
        out[f"{name}_first"] = members[:1]
        out[f"{name}_last"] = members[-1:]
        out[f"{name}_all"] = members

    # membership / label legs (KEY-only, public)
    def masqmem(r): return r[0] in _MASQ_NAMES
    def malrule(r): return r[0] in malware_leaves
    def unsigned(r): return r[0] not in signed_leaves
    def yarahit(r): return r[0] in yara_leaves

    # path REGEXES (cheater-computable; NOT the home-value map)
    locs = {
        "staging": lambda r: r[1].startswith(_STAGING_PREFIXES),
        "notwin": lambda r: not r[1].startswith("C:\\Windows"),
        "winNotSys32": lambda r: _win_not_sys32(r[1]),
    }

    # (1) read the label file, output what it names (yara leaf extremes / rule extremes)
    def rows_for(leaf): return sorted(r[1] for r in rows if r[0] == leaf)
    yls = sorted(yara_leaves)
    if yls:
        add("yara_leaf", rows_for(yls[0]) + rows_for(yls[-1]))
        out["yara_firstleaf"] = rows_for(yls[0])[:1]
        out["yara_lastleaf"] = rows_for(yls[-1])[:1]
    by_rule = sorted(yara_lines, key=lambda s: s.split(":", 1)[1].strip())
    if by_rule:
        out["yara_minrule"] = rows_for(by_rule[0].split(":", 1)[0].strip())[:1]
        out["yara_maxrule"] = rows_for(by_rule[-1].split(":", 1)[0].strip())[:1]

    # (2) structurally-unique on a surface feature: first/last row, path extremes
    out["first_row"] = [paths[0]]
    out["last_row"] = [paths[-1]]
    by_len = sorted(rows, key=lambda r: (len(r[1]), r[1]))
    out["shortest_path"] = [by_len[0][1]]
    out["longest_path"] = [by_len[-1][1]]
    by_depth = sorted(rows, key=lambda r: (r[1].count("\\"), r[1]))
    out["shallowest_path"] = [by_depth[0][1]]
    out["deepest_path"] = [by_depth[-1][1]]

    # (3) single legs
    add("malrule", [r[1] for r in rows if malrule(r)])
    add("masqmem", [r[1] for r in rows if masqmem(r)])
    add("unsigned", [r[1] for r in rows if unsigned(r)])
    add("yara", [r[1] for r in rows if yarahit(r)])
    for ln, lp in locs.items():
        add(f"loc_{ln}", [r[1] for r in rows if lp(r)])

    # (4) the PUBLIC-MEMBERSHIP PAIRS and the hunted TRIPLE, each ∩ every path regex
    add("PAIR_masqmem_malrule", [r[1] for r in rows if masqmem(r) and malrule(r)])
    add("PAIR_masqmem_unsigned", [r[1] for r in rows if masqmem(r) and unsigned(r)])
    add("PAIR_malrule_unsigned", [r[1] for r in rows if malrule(r) and unsigned(r)])
    add("TRIPLE_masqmem_malrule_unsigned",
        [r[1] for r in rows if masqmem(r) and malrule(r) and unsigned(r)])
    for ln, lp in locs.items():
        add(f"TRIPLE_masqmem_malrule_unsigned_{ln}",
            [r[1] for r in rows if masqmem(r) and malrule(r) and unsigned(r) and lp(r)])
        add(f"PAIR_masqmem_malrule_{ln}",
            [r[1] for r in rows if masqmem(r) and malrule(r) and lp(r)])
        add(f"PAIR_malrule_unsigned_{ln}",
            [r[1] for r in rows if malrule(r) and unsigned(r) and lp(r)])

    # (5) rarity / duplication / recency
    counts = collections.Counter(r[0] for r in rows)
    add("singleton_basename", [r[1] for r in rows if counts[r[0]] == 1])
    add("dup_basename", [r[1] for r in rows if counts[r[0]] > 1])
    add("year2026", [r[1] for r in rows if r[3].startswith("2026")])
    by_rc = sorted((int(r[2]), r[1]) for r in rows)
    out["min_runcount"] = [by_rc[0][1]]
    out["max_runcount"] = [by_rc[-1][1]]

    # (6) second path-segment rarity (NON-parameterized structural lens)
    def seg2(p):
        parts = p.split("\\")
        return parts[1] if len(parts) > 1 else ""
    seg_counts = collections.Counter(seg2(r[1]) for r in rows)
    minc = min(seg_counts.values())
    add("rarest_seg2", [r[1] for r in rows if seg_counts[seg2(r[1])] == minc])

    return out


# --- measurement over K fresh seeds ---

# K = 32 fresh seeds (>> the K>=8 minimum). Position-based strategies converge near
# their chance value only with enough samples; 32 contiguous seeds is deterministic.
_SEEDS = list(range(2011, 2043))


def _measure(tmp_path: Path):
    """Returns (single_pick_best, single_pick_name, flagall_best, flagall_name,
    oracle_f1, n_candidates_seen). SINGLE-PICK (<=1 target: the `_first`/`_last`
    variants and the inherently-single strategies) is the chance-gated metric — the
    blessed repo convention (the gate `cheater_best <= 1/N + slack` is satisfiable
    ONLY single-pick; any label partition guaranteed to contain the answer scores
    2/(k+1) flag-all, which exceeds 1/N). FLAG-ALL (`_all`) is gated separately at a
    documented multi-pick-floor bound — it measures DILUTION, not ISOLATION (a true
    isolation leak shows up as a single-pick first/last = 1.0)."""
    single_scores: dict[str, list[float]] = collections.defaultdict(list)
    flagall_scores: dict[str, list[float]] = collections.defaultdict(list)
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
            score = _f1(set(p for p in picked if p), target)
            if name.endswith("_all"):
                flagall_scores[name].append(score)
            else:
                single_scores[name].append(score)
    sp_best = max(sum(v) / len(v) for v in single_scores.values())
    sp_name = max(single_scores, key=lambda k: sum(single_scores[k]) / len(single_scores[k]))
    fa_best = max(sum(v) / len(v) for v in flagall_scores.values())
    fa_name = max(flagall_scores, key=lambda k: sum(flagall_scores[k]) / len(flagall_scores[k]))
    oracle_f1 = sum(oracle_scores) / len(oracle_scores)
    return sp_best, sp_name, fa_best, fa_name, oracle_f1, n_candidates_seen


# --- the gate ---

CHEATER_SLACK = 0.12
ORACLE_FLOOR = 0.9
GAP_FLOOR = 0.6
# Multi-pick floor bound: a flag-all of a benign-saturated cell that is GUARANTEED to
# contain the answer scores 2/(k+1) — disclosed in the docstring, not an isolation
# leak. The task's own bar: "multi-select noise floor ~0.25-0.35 is ACCEPTABLE."
FLAGALL_FLOOR = 0.40


def test_cheater_cannot_beat_chance(tmp_path: Path) -> None:
    sp_best, sp_name, _fa, _fan, _oracle_f1, ncands = _measure(tmp_path)
    chance = 1.0 / max(ncands)
    ceil = chance + CHEATER_SLACK
    assert sp_best <= ceil, (
        f"single-pick cheater '{sp_name}' scored mean-F1 {sp_best:.3f} > {ceil:.3f} "
        f"(chance 1/{max(ncands)}={chance:.3f} + slack {CHEATER_SLACK}) over "
        f"{len(_SEEDS)} seeds — a no-domain-knowledge shortcut isolates the answer; "
        f"the case is NOT reasoning-only."
    )


def test_flagall_stays_below_multipick_floor(tmp_path: Path) -> None:
    """Flag-all (multi-pick) of every membership/label conjunction must stay <= the
    disclosed multi-pick floor — a benign-saturated cell, not an isolation leak."""
    _sp, _spn, fa_best, fa_name, _oracle_f1, _ncands = _measure(tmp_path)
    assert fa_best <= FLAGALL_FLOOR, (
        f"flag-all cheater '{fa_name}' scored mean-F1 {fa_best:.3f} > {FLAGALL_FLOOR} "
        f"over {len(_SEEDS)} seeds — a membership conjunction is under-saturated (cell "
        f"too small); add benign decoys to that cell."
    )


def test_oracle_solves_it(tmp_path: Path) -> None:
    *_rest, oracle_f1, _ncands = _measure(tmp_path)
    assert oracle_f1 >= ORACLE_FLOOR, (
        f"ORACLE (masquerade + malware-family yara + unsigned) scored mean-F1 "
        f"{oracle_f1:.3f} < {ORACLE_FLOOR} over {len(_SEEDS)} seeds — the intended "
        f"forensic rule does not reliably pick the answer; either "
        f"unsolvable-by-reasoning or the answer_key is wrong."
    )


def test_reasoning_gap_is_large(tmp_path: Path) -> None:
    sp_best, name, _fa, _fan, oracle_f1, ncands = _measure(tmp_path)
    gap = oracle_f1 - sp_best
    assert gap >= GAP_FLOOR, (
        f"reasoning gap {gap:.3f} < {GAP_FLOOR} "
        f"(oracle={oracle_f1:.3f}, single-pick cheater_best={sp_best:.3f} via '{name}', "
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


def test_home_value_reasoning_is_oracle_class(tmp_path: Path) -> None:
    """PROOF a reasoning-only discriminator EXISTS (the non-gaming contrast). A
    strategy that READS THE HOME VALUES of the public map — recover the System32-only
    sublist, then require malware ∩ unsigned ∩ a non-canonical (Windows-not-System32)
    location — scores HIGH. The identical strategy using only KEY-membership scores at
    chance (asserted by test_cheater_cannot_beat_chance). The contrast IS the proof:
    only canonical-home reasoning isolates the answer."""
    sys32_names = {n for n, h in P.SYSTEM_PROCESS_HOMES.items() if h == [P.SYSTEM32]}
    scores = []
    for seed in _SEEDS:
        rows, yara_lines, yara_leaves, signed_leaves, target, _ = _gen(seed, tmp_path)
        malware_leaves = _malware_leaves(yara_lines)
        picked = {
            r[1] for r in rows
            if r[0] in sys32_names and r[0] in malware_leaves
            and r[0] not in signed_leaves and _win_not_sys32(r[1])
        }
        scores.append(_f1(picked, target))
    mean = sum(scores) / len(scores)
    assert mean >= 0.40, (
        f"home-VALUE reasoning scored only {mean:.3f} — if the ONLY discriminator that "
        f"beats chance does NOT read the canonical-home map, there is no reasoning-only "
        f"path. Expected it to be the high-scoring (oracle-class) strategy."
    )


def test_answer_basename_is_unique_in_pool(tmp_path: Path) -> None:
    """The answer's basename must occur EXACTLY ONCE across all rows — otherwise a
    duplicated-basename / cross-dir straddle would fingerprint it without the map."""
    for seed in _SEEDS:
        rows, _yl, _yleaves, _signed, target, _ = _gen(seed, tmp_path)
        tgt_base = target.rsplit("\\", 1)[1]
        n = sum(1 for r in rows if r[0] == tgt_base)
        assert n == 1, (
            f"seed {seed}: answer basename {tgt_base!r} appears {n} times — a "
            f"duplicated-basename straddle could isolate the answer without the map"
        )


def test_every_answer_label_leg_and_pair_also_fires_on_a_decoy(tmp_path: Path) -> None:
    """The core Option-1 invariant: each PUBLIC-LABEL leg that fires on the ANSWER
    (system-name membership / malware-rule / yara / unsigned), AND each PAIRWISE
    intersection, AND the full TRIPLE (system-name ∩ malware-rule ∩ unsigned), must
    ALSO fire on >=1 decoy — so no membership shortcut isolates the answer. Location
    is NOT a surface leg here: it is the oracle's axis (the canonical-home map), tested
    separately below."""
    for seed in _SEEDS:
        rows, yara_lines, yara_leaves, signed_leaves, target, _ = _gen(seed, tmp_path)
        malware_leaves = _malware_leaves(yara_lines)
        tgt = next(r for r in rows if r[1] == target)
        distractors = [r for r in rows if r[1] != target]
        legs = {
            "masqmem": lambda r: r[0] in _MASQ_NAMES,
            "malrule": lambda r: r[0] in malware_leaves,
            "yara": lambda r: r[0] in yara_leaves,
            "unsigned": lambda r: r[0] not in signed_leaves,
        }
        for nm, pred in legs.items():
            assert pred(tgt), f"seed {seed}: answer does not fire label leg {nm}"
        names = list(legs)
        combos = (
            [(a,) for a in names]
            + list(itertools.combinations(names, 2))
            + [tuple(names)]  # the full TRIPLE-equivalent (all four labels)
        )
        for combo in combos:
            assert any(all(legs[f](d) for f in combo) for d in distractors), (
                f"seed {seed}: label combination {combo} fires ONLY on the answer "
                f"(a membership shortcut isolates it)"
            )


def test_answer_location_conjunctions_are_bracketed(tmp_path: Path) -> None:
    """The hunted leak structurally: the PUBLIC-MEMBERSHIP TRIPLE (system-name ∩
    malware-rule ∩ unsigned) intersected with EACH cheater-computable path regex must
    contain a benign decoy whenever it contains the answer — so neither a flag-all nor
    a first/last single-pick of the membership conjunction (with or without a location
    regex) isolates the answer. Only the per-name canonical-home map does."""
    locs = {
        "staging": lambda p: p.startswith(_STAGING_PREFIXES),
        "notwin": lambda p: not p.startswith("C:\\Windows"),
        "winNotSys32": _win_not_sys32,
    }
    for seed in _SEEDS:
        rows, yara_lines, yara_leaves, signed_leaves, target, _ = _gen(seed, tmp_path)
        malware_leaves = _malware_leaves(yara_lines)

        def in_triple(r):
            return (r[0] in _MASQ_NAMES and r[0] in malware_leaves
                    and r[0] not in signed_leaves)

        triple = sorted(r[1] for r in rows if in_triple(r))
        assert target in triple
        others = [p for p in triple if p != target]
        assert others, f"seed {seed}: public TRIPLE is a singleton = the answer (LEAK)"
        # bracketed in path order: a decoy sorts below AND a decoy sorts above
        assert any(p < target for p in others), f"seed {seed}: no TRIPLE decoy below answer"
        assert any(p > target for p in others), f"seed {seed}: no TRIPLE decoy above answer"
        # for each location regex the answer fires, a decoy in the same regie+triple cell
        for ln, lp in locs.items():
            if lp(target):
                cell = [p for p in others if lp(p)]
                assert cell, (
                    f"seed {seed}: TRIPLE ∩ {ln} fires ONLY on the answer — a "
                    f"membership+regex shortcut isolates it"
                )


def test_no_system32_straddle(tmp_path: Path) -> None:
    """The answer's basename must NOT appear both in System32 and in another dir — a
    straddle would uniquely fingerprint a masquerade WITHOUT reading the map."""
    for seed in _SEEDS:
        rows, _yl, _yleaves, _signed, target, _ = _gen(seed, tmp_path)
        tgt = next(r for r in rows if r[1] == target)
        same_name = [r for r in rows if r[0] == tgt[0]]
        in_system32 = any(r[1].startswith("C:\\Windows\\System32") for r in same_name)
        in_other = any(not r[1].startswith("C:\\Windows\\System32") for r in same_name)
        assert not (in_system32 and in_other), (
            f"seed {seed}: answer basename {tgt[0]!r} straddles System32 and another dir "
            f"— a pure-string shortcut isolates it without the canonical-home map"
        )
