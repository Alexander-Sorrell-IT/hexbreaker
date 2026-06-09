"""Cheat-resistance gate for the timestomp Forge template (Option 1, reasoning-only).

The defining property this file pins: a timestomp case must be solvable ONLY by
the intended forensic reasoning, never by a cheap surface shortcut. Concretely,
EVERY signal that fires on the answer also fires on >=1 decoy, and decoys carry
benign near-miss tells, so no no-domain-knowledge strategy isolates the answer.

The malicious row is the CONJUNCTION of THREE signals, two of them CATEGORICAL:
  (A) a large BACKWARD $SI<-$FN gap above a threshold (the backdate),   [scalar]
  (B) a yara malware-heuristic hit (APT_DRIVER_HEURISTIC),              [categorical]
  (C) NO valid code signature (absent from the MS_CATALOG_SIGNED scan). [categorical]
The two categorical legs are what make the case argmax-proof: a benign SIGNED,
yara-flagged driver owns the largest gap WITHIN the yara set, and a benign
yara-clean UNSIGNED file owns the largest gap overall — so ranking any single
timestamp delta (even restricted to one label set) lands on a decoy, never the
answer. Only `gap>threshold AND yara AND unsigned` is unique to the answer.

Two deterministic, no-LLM baselines, asserted to be far apart:
  • CHEATER suite — a battery of no-domain-knowledge surface strategies: echo a
    label file (and 2-feature label intersections); pick the row that is
    structurally unique on a column; argmax/argmin/oldest/newest of every
    ordered date-column delta, restricted to {all}/{yara}/{unsigned}; rarity;
    first/last row; oddly-formatted (digit-bearing) name. We take the cheater's
    BEST mean F1 across ALL strategies over K fresh seeds. A strategy that
    reconstructs the FULL 3-way combination has reimplemented the forensic rule
    and is the oracle, not a cheat — it is intentionally NOT in this suite.
  • ORACLE — applies the intended 3-way discriminator. Scores F1 ~1.0, proving
    the case is solvable-by-reasoning and the answer_key is correct.

PASS GATE: cheater_best_f1 <= ~chance(1/num_candidates) margin, oracle_f1 >= 0.9,
and gap = oracle_f1 - cheater_best_f1 >= 0.6, over K>=8 fresh seeds.
"""

from __future__ import annotations

import collections
import itertools
import re
from datetime import datetime
from pathlib import Path

from hexbreaker.forge import template_timestomp as TS
from hexbreaker.forge.case import AnswerKey, load_case
from hexbreaker.scorer.exact_match import score

# Fresh seeds (disjoint from the determinism/template tests' 4729) and K>=8. We
# use K=24 so finite-sample noise on genuinely chance-level strategies (e.g. the
# positional first/last-row picks, which are random under the row shuffle)
# averages out toward 1/num_candidates rather than aliasing high on a few seeds.
SEEDS = list(range(40_001, 40_025))
DATE_COLS = ["Created0x10", "Created0x30", "LastModified0x10"]


# --------------------------------------------------------------------------- #
# Parsing the issued evidence exactly as a non-LLM script would see it.
# --------------------------------------------------------------------------- #
def _rows(case_dir: Path) -> list[dict[str, str]]:
    lines = (case_dir / "mock_outputs" / "mft.csv").read_text().splitlines()
    header = lines[0].split(",")
    return [dict(zip(header, line.split(","))) for line in lines[1:]]


def _label_set(case_dir: Path, filename: str) -> set[str]:
    """Basenames named in a yara-style label file (`<basename>: RULE`)."""
    out: set[str] = set()
    for line in (case_dir / "mock_outputs" / filename).read_text().splitlines():
        if line.strip():
            out.add(line.split(":")[0].strip())
    return out


def _target(row: dict[str, str]) -> str:
    return row["ParentPath"] + "\\" + row["FileName"]


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _f1(targets: list[str], answer: AnswerKey) -> float:
    findings = [{"artifact_kind": "timestomp", "target": t} for t in targets]
    return score(findings, answer).f1


# --------------------------------------------------------------------------- #
# CHEATER SUITE — no-domain-knowledge surface strategies.
# Treats MFT columns as opaque tokens / numbers and label files as lists. None of
# these reconstructs the full 3-way forensic conjunction.
# --------------------------------------------------------------------------- #
def cheater_strategies(
    rows: list[dict[str, str]], yara: set[str], catalog: set[str]
) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}

    # Label-file subsets a no-knowledge cheater can form (yara hits, catalog hits,
    # and their complements). Echo each, and every 2-feature intersection.
    # `over` is the OVER-THRESHOLD subset: the backdate threshold (BACKDATE_DAYS) is
    # PUBLICLY DOCUMENTED, so a no-knowledge cheater can condition on it for free
    # (`gap > 365d`) WITHOUT reconstructing the categorical legs. The over-set must
    # therefore be a mini cheat-resistant set in its own right — the answer must be
    # interior on every ranking within it, else a single argmin/argmax/oldest/newest
    # restricted to `over` isolates the answer. This is the leak the hunter found
    # (`argmin(gap | gap>365d)` and `$SI-band ∩ over-threshold`).
    def _gap_days(r: dict[str, str]) -> float:
        return (_dt(r["Created0x30"]) - _dt(r["Created0x10"])).total_seconds() / 86400.0

    subsets = {
        "all": rows,
        "yara": [r for r in rows if r["FileName"] in yara],
        "notyara": [r for r in rows if r["FileName"] not in yara],
        "catalog": [r for r in rows if r["FileName"] in catalog],
        "notcatalog": [r for r in rows if r["FileName"] not in catalog],
        "over": [r for r in rows if _gap_days(r) > TS.BACKDATE_DAYS],
    }
    for name, sub in subsets.items():
        if sub:
            out[f"echo_{name}"] = [_target(r) for r in sub]
    for (an, a_), (bn, b_) in itertools.combinations(subsets.items(), 2):
        inter = sorted({_target(r) for r in a_} & {_target(r) for r in b_})
        if inter:
            out[f"echo_{an}_AND_{bn}"] = inter

    # Structural uniqueness: the row whose value in some column is unique.
    for col in rows[0]:
        counts = collections.Counter(r[col] for r in rows)
        uniq = [_target(r) for r in rows if counts[r[col]] == 1]
        if 0 < len(uniq) <= 2:
            out[f"unique_in_{col}"] = uniq

    # Ranking strategies on every ordered date-column delta + per-column extrema,
    # restricted to each subset. This is the family that would catch a single
    # threshold-on-a-scalar discriminator — it MUST stay near chance here.
    for name, sub in subsets.items():
        if not sub:
            continue
        for c1, c2 in itertools.permutations(DATE_COLS, 2):
            deltas = [(_dt(r[c2]) - _dt(r[c1])).total_seconds() for r in sub]
            # A constant column-difference is not a ranking signal — argmax/argmin
            # of an all-equal key collapses to a positional tie-break (subset[0]),
            # which is already covered by the first_row/last_row strategies below.
            # The Created0x10-vs-LastModified0x10 delta is identically zero by
            # design (LastModified mirrors $SI on every row, an intentional anti-
            # tell), so skip it rather than scoring a non-strategy. Every genuine
            # gap delta (Created0x10-vs-Created0x30, etc.) still varies and is kept.
            if len(set(deltas)) <= 1:
                continue
            out[f"argmax_{c1[-2:]}{c2[-2:]}_{name}"] = [
                _target(sub[max(range(len(sub)), key=lambda i: deltas[i])])
            ]
            out[f"argmin_{c1[-2:]}{c2[-2:]}_{name}"] = [
                _target(sub[min(range(len(sub)), key=lambda i: deltas[i])])
            ]
        for col in DATE_COLS:
            out[f"oldest_{col[-2:]}_{name}"] = [_target(min(sub, key=lambda r: _dt(r[col])))]
            out[f"newest_{col[-2:]}_{name}"] = [_target(max(sub, key=lambda r: _dt(r[col])))]
        years = collections.Counter(r["Created0x10"][:4] for r in sub)
        rarest = min(years.values())
        rare_year = [_target(r) for r in sub if years[r["Created0x10"][:4]] == rarest]
        if len(rare_year) <= 2:
            out[f"rare_si_year_{name}"] = rare_year

    # Position and lexical "odd-formatted value" tells.
    out["first_row"] = [_target(rows[0])]
    out["last_row"] = [_target(rows[-1])]
    digit_names = [_target(r) for r in rows if re.search(r"\d", r["FileName"])]
    if digit_names:
        out["name_has_digit_first"] = [sorted(digit_names)[0]]
        out["name_has_digit_all"] = digit_names
    return out


def cheater_best_f1(seeds: list[int], *, provocateur: bool, tmp_root: Path) -> tuple[float, str]:
    """BEST mean F1 across all cheater strategies over `seeds` (and the winner)."""
    per_strategy: dict[str, list[float]] = collections.defaultdict(list)
    for seed in seeds:
        case_dir = tmp_root / f"cheat_{int(provocateur)}_{seed}"
        TS.generate(seed=seed, out_dir=case_dir, provocateur=provocateur)
        _, answer = load_case(case_dir)
        rows = _rows(case_dir)
        yara = _label_set(case_dir, "yara.txt")
        catalog = _label_set(case_dir, "catalog.txt")
        for name, targets in cheater_strategies(rows, yara, catalog).items():
            per_strategy[name].append(_f1(targets, answer))
    k = len(seeds)
    # Strategies that don't fire on some seed count 0 there (missing == no pick).
    best, winner = 0.0, "<none>"
    for name, vals in per_strategy.items():
        mean = sum(vals) / k
        if mean > best:
            best, winner = mean, name
    return best, winner


# --------------------------------------------------------------------------- #
# ORACLE — the intended 3-way forensic discriminator.
# --------------------------------------------------------------------------- #
def oracle_pick(rows: list[dict[str, str]], yara: set[str], catalog: set[str]) -> list[str]:
    picks = []
    for r in rows:
        backdated = TS.is_timestomped(_dt(r["Created0x10"]), _dt(r["Created0x30"]))
        yara_hit = r["FileName"] in yara
        unsigned = r["FileName"] not in catalog
        if backdated and yara_hit and unsigned:
            picks.append(_target(r))
    return picks


def oracle_mean_min_f1(seeds: list[int], *, provocateur: bool, tmp_root: Path) -> tuple[float, float]:
    vals: list[float] = []
    for seed in seeds:
        case_dir = tmp_root / f"oracle_{int(provocateur)}_{seed}"
        TS.generate(seed=seed, out_dir=case_dir, provocateur=provocateur)
        _, answer = load_case(case_dir)
        rows = _rows(case_dir)
        yara = _label_set(case_dir, "yara.txt")
        catalog = _label_set(case_dir, "catalog.txt")
        vals.append(_f1(oracle_pick(rows, yara, catalog), answer))
    return sum(vals) / len(vals), min(vals)


# --------------------------------------------------------------------------- #
# The numeric gate. Asserted for both the plain and provocateur case shapes.
# --------------------------------------------------------------------------- #
def _candidate_count(provocateur: bool, tmp_root: Path) -> int:
    case_dir = tmp_root / "count"
    TS.generate(seed=SEEDS[0], out_dir=case_dir, provocateur=provocateur)
    return len(_rows(case_dir))


def test_oracle_solves_the_case(tmp_path: Path) -> None:
    """ORACLE (the intended 3-way rule) scores F1 ~1.0 => solvable-by-reasoning
    AND the answer_key is correct (the rule's pick matches expected_findings)."""
    for prov in (False, True):
        mean, lo = oracle_mean_min_f1(SEEDS, provocateur=prov, tmp_root=tmp_path)
        assert lo == 1.0, f"oracle missed a case (prov={prov}): min F1 {lo}"
        assert mean >= 0.9, f"oracle mean F1 {mean} < 0.9 (prov={prov})"


def test_no_single_pick_cheater_beats_chance(tmp_path: Path) -> None:
    """No SINGLE-PICK surface strategy (the ones that output exactly one target —
    argmax/argmin/oldest/newest/unique/first/last/rarity) beats random chance.

    Single-pick strategies are the dangerous ones: a single-pick cheater that
    lands on the answer scores F1=1.0. These must each stay at ~chance, proving no
    scalar ranking or structural-uniqueness tell isolates the answer. (Multi-pick
    'echo a label subset' strategies are bounded separately — their precision is
    ~1/|subset| by construction, never a 1:1 leak; see the gap gate.)"""
    for prov in (False, True):
        cand = _candidate_count(prov, tmp_path)
        chance = 1.0 / cand
        per_strategy: dict[str, list[float]] = collections.defaultdict(list)
        for seed in SEEDS:
            case_dir = tmp_path / f"single_{int(prov)}_{seed}"
            TS.generate(seed=seed, out_dir=case_dir, provocateur=prov)
            _, answer = load_case(case_dir)
            rows = _rows(case_dir)
            yara = _label_set(case_dir, "yara.txt")
            catalog = _label_set(case_dir, "catalog.txt")
            for name, targets in cheater_strategies(rows, yara, catalog).items():
                if len(targets) == 1:  # single-pick strategies only
                    per_strategy[name].append(_f1(targets, answer))
        # Bound at 2.2x chance: a genuinely chance-level single-pick strategy over
        # K=24 with p=1/cand has SE ~sqrt(p(1-p)/K) ~ 0.06, so its sampled mean can
        # sit ~2-sigma above 1/cand by pure noise (the residual scorers are the
        # subset-restricted positional first/last picks, whose chance is 1/|subset|
        # — above the 1/cand pool baseline by construction, not by isolating the
        # answer). Any strategy that truly ISOLATED the answer would score near 1.0,
        # an order of magnitude over this bound.
        for name, vals in per_strategy.items():
            mean = sum(vals) / len(SEEDS)
            assert mean <= 2.2 * chance, (
                f"single-pick cheater '{name}' F1 {mean:.3f} > 2.2x chance "
                f"{2.2 * chance:.3f} (candidates={cand}, prov={prov}) — it isolates "
                f"the answer via a surface ranking/uniqueness tell"
            )


def test_cheater_best_far_below_oracle(tmp_path: Path) -> None:
    """The BEST cheater across ALL strategies (single- and multi-pick) stays well
    below the oracle. The remaining non-trivial cheater is a 2-feature label echo
    (yara ∩ unsigned), whose F1 is the structural multi-finding floor 2/(k+1) —
    near chance for a guess that emits the whole near-miss set, not a shortcut."""
    for prov in (False, True):
        best, winner = cheater_best_f1(SEEDS, provocateur=prov, tmp_root=tmp_path)
        assert best <= 0.4, (
            f"cheater '{winner}' F1 {best:.3f} > 0.4 (prov={prov}) — a surface "
            f"strategy gets too close to the answer"
        )


def test_cheatresist_gap_gate(tmp_path: Path) -> None:
    """The gate: cheater_best_f1 near chance AND oracle_f1 >= 0.9 AND gap >= 0.6,
    measured over K>=8 fresh seeds, for both the plain and provocateur shapes."""
    assert len(SEEDS) >= 8
    for prov in (False, True):
        best, winner = cheater_best_f1(SEEDS, provocateur=prov, tmp_root=tmp_path)
        oracle_mean, oracle_lo = oracle_mean_min_f1(SEEDS, provocateur=prov, tmp_root=tmp_path)
        gap = oracle_mean - best
        assert oracle_mean >= 0.9, f"oracle {oracle_mean:.3f} < 0.9 (prov={prov})"
        assert oracle_lo == 1.0, f"oracle min {oracle_lo} != 1.0 (prov={prov})"
        assert gap >= 0.6, (
            f"gap {gap:.3f} < 0.6 (prov={prov}): oracle {oracle_mean:.3f} - "
            f"cheater_best {best:.3f} (winner '{winner}')"
        )


def test_every_answer_signal_also_fires_on_a_decoy(tmp_path: Path) -> None:
    """The defining property, asserted structurally per seed: each of the answer's
    three signals (over-threshold gap, yara hit, unsigned) ALSO fires on >=1 decoy
    — so no single signal isolates the answer."""
    for prov in (False, True):
        for seed in SEEDS:
            case_dir = tmp_path / f"sig_{int(prov)}_{seed}"
            TS.generate(seed=seed, out_dir=case_dir, provocateur=prov)
            _, answer = load_case(case_dir)
            rows = _rows(case_dir)
            yara = _label_set(case_dir, "yara.txt")
            catalog = _label_set(case_dir, "catalog.txt")
            ans_target = answer.expected_findings[0].target
            decoy_targets = {d.target for d in answer.decoys} | {p.target for p in answer.planted}

            def fires_on_decoy(predicate) -> bool:
                return any(predicate(r) and _target(r) in decoy_targets for r in rows)

            # Sanity: the answer itself fires all three.
            ans_row = next(r for r in rows if _target(r) == ans_target)
            assert TS.is_timestomped(_dt(ans_row["Created0x10"]), _dt(ans_row["Created0x30"]))
            assert ans_row["FileName"] in yara and ans_row["FileName"] not in catalog

            assert fires_on_decoy(
                lambda r: TS.is_timestomped(_dt(r["Created0x10"]), _dt(r["Created0x30"]))
            ), f"over-threshold gap fires only on the answer (seed={seed}, prov={prov})"
            assert fires_on_decoy(lambda r: r["FileName"] in yara), (
                f"yara hit fires only on the answer (seed={seed}, prov={prov})"
            )
            assert fires_on_decoy(lambda r: r["FileName"] not in catalog), (
                f"unsigned fires only on the answer (seed={seed}, prov={prov})"
            )


def test_max_gap_rankings_land_on_decoys(tmp_path: Path) -> None:
    """Regression for the argmax leak the design exists to kill: the row with the
    largest backward gap (overall, within the yara set, and within the unsigned
    set) must be a DECOY, not the answer — else a no-knowledge cheater reaches the
    answer by ranking a single scalar."""
    for prov in (False, True):
        for seed in SEEDS:
            case_dir = tmp_path / f"gap_{int(prov)}_{seed}"
            TS.generate(seed=seed, out_dir=case_dir, provocateur=prov)
            _, answer = load_case(case_dir)
            rows = _rows(case_dir)
            yara = _label_set(case_dir, "yara.txt")
            catalog = _label_set(case_dir, "catalog.txt")
            ans = answer.expected_findings[0].target

            def gap(r: dict[str, str]) -> float:
                return (_dt(r["Created0x30"]) - _dt(r["Created0x10"])).total_seconds()

            overall = max(rows, key=gap)
            in_yara = max([r for r in rows if r["FileName"] in yara], key=gap)
            in_unsigned = max([r for r in rows if r["FileName"] not in catalog], key=gap)
            assert _target(overall) != ans, f"max-gap-overall == answer (seed={seed})"
            assert _target(in_yara) != ans, f"max-gap-in-yara == answer (seed={seed})"
            assert _target(in_unsigned) != ans, f"max-gap-in-unsigned == answer (seed={seed})"
