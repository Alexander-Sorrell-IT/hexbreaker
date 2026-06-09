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
        # Rarity (rarest) AND frequency (MODE) of the YEAR of EVERY date column,
        # restricted to each subset. The previous suite tested rarest-$SI-year only
        # and never the MODE, and never the $FN ($Created0x30) column at all — the
        # leg the design had left to vary freely. That left a whole order-1 family
        # unmonitored: "among unsigned rows, pick the rows whose $FN year is the
        # most common" landed on {answer + few benign} (F1=0.5) because the evil
        # $FN year (2026) was the unique mode there. We now form BOTH the rarest-
        # year and the most-common-year (mode) selection for $SI and $FN in every
        # subset, so an absolute-date frequency tell on either column trips a named
        # strategy. (rare_si_year_* is kept under its exact old name for the
        # single-pick gate; the new families get distinct names.)
        for col in ("Created0x10", "Created0x30"):
            yc = collections.Counter(r[col][:4] for r in sub)
            # MODE (most-common year): emitted UNGUARDED. The mode of a date-year
            # is a genuine isolation tell when the answer's year is the small
            # plurality bucket (the ROUND-2 $FN leak: F1=0.5 on a {answer + 2}
            # set), and stays self-limiting on large buckets, so we always score it.
            top = max(yc.values())
            mode_rows = [_target(r) for r in sub if yc[r[col][:4]] == top]
            out[f"mode_{col[-2:]}_year_{name}"] = mode_rows
            # RARITY (rarest year): emitted ONLY when it collapses to <=2 rows, the
            # SAME <=2 guard the existing `rare_si_year_*` family uses below. A
            # rarity echo that spans many singleton-year rows (e.g. the 4 ancient
            # singletons in the over-set) is a diffuse low-precision guess dominated
            # by the construction's 1/3 floor, not an isolation tell — the original
            # suite deliberately scopes the rarity family to near-single-pick, and
            # we match that precedent so a 4-row rarity echo isn't scored as a leak.
            rare = min(yc.values())
            rare_rows = [_target(r) for r in sub if yc[r[col][:4]] == rare]
            if len(rare_rows) <= 2:
                out[f"rare_{col[-2:]}_year_{name}"] = rare_rows
        years = collections.Counter(r["Created0x10"][:4] for r in sub)
        rarest = min(years.values())
        rare_year = [_target(r) for r in sub if years[r["Created0x10"][:4]] == rarest]
        if len(rare_year) <= 2:
            out[f"rare_si_year_{name}"] = rare_year

    # Absolute-date MAX-YEAR binning on each date column (a pure frequency/
    # distribution fingerprint that consumes NO forensic leg): bin all rows by the
    # YEAR of the column, take the bucket whose year is the maximum, and pick the
    # 2 rows with the OLDEST and (separately) NEWEST full timestamp inside it.
    # `bottom2_maxyear_30` (oldest-2 in the max-$FN-year bucket) used to land on
    # {answer, D1} (F1=0.667) because the evil row was the older of only two 2026
    # rows; the design now seeds the max-year bucket with several benign rows on
    # both sides of the answer, so this must sit at the floor.
    for col in DATE_COLS:
        max_year = max(r[col][:4] for r in rows)
        bucket = sorted((r for r in rows if r[col][:4] == max_year), key=lambda r: _dt(r[col]))
        out[f"bottom2_maxyear_{col[-2:]}"] = [_target(r) for r in bucket[:2]]
        out[f"top2_maxyear_{col[-2:]}"] = [_target(r) for r in bucket[-2:]]

    # Timestamp SUB-FIELD granularity fingerprint (seconds-of-minute). The evil
    # row used to be the ONLY row with nonzero $SI/$FN seconds (its datetime()
    # constructors passed a seconds argument the decoys omitted), so "rows with
    # nonzero seconds" isolated it at F1=1.0 — a rarity fingerprint the 3-leg floor
    # analysis never accounted for. The generator now draws seconds for EVERY row
    # from one shared pool, so this selects ~every row (near-chance recall) and the
    # answer carries no granularity tell. Asserted both as "nonzero seconds" and
    # as "the structurally-unique seconds value" to catch either framing.
    nz = [_target(r) for r in rows
          if _dt(r["Created0x10"]).second != 0 or _dt(r["Created0x30"]).second != 0]
    if nz:
        out["nz_seconds_either"] = nz
    sec_counts = collections.Counter(
        (_dt(r["Created0x10"]).second, _dt(r["Created0x30"]).second) for r in rows
    )
    uniq_sec = [_target(r) for r in rows
                if sec_counts[(_dt(r["Created0x10"]).second, _dt(r["Created0x30"]).second)] == 1]
    if 0 < len(uniq_sec) <= 2:
        out["unique_seconds_pair"] = uniq_sec

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


def cheater_means(
    seeds: list[int], *, provocateur: bool, tmp_root: Path
) -> dict[str, tuple[float, int]]:
    """Per-strategy (mean F1, max pick-count) across `seeds` for EVERY strategy.

    A strategy that fails to fire on some seed scores 0 there (missing == no
    pick), so the denominator is always len(seeds). Returned so each shortcut can
    be bounded individually at ITS OWN floor — and the per-family gate classifies
    by SHAPE: a SINGLE-pick strategy (max pick-count == 1, e.g. argmax/oldest/
    unique/rare-year-collapsed-to-one) must sit at chance, while a MULTI-pick
    strategy (mode bucket / max-year bin / nonzero-seconds set / label echo) can
    legitimately reach the irreducible 2/(m+1) floor but no higher. The max
    pick-count over seeds is the discriminator (a regression in any single family
    trips a NAMED assertion instead of hiding under the aggregate ceiling).
    """
    per_strategy: dict[str, list[float]] = collections.defaultdict(list)
    max_picks: dict[str, int] = collections.defaultdict(int)
    for seed in seeds:
        case_dir = tmp_root / f"means_{int(provocateur)}_{seed}"
        TS.generate(seed=seed, out_dir=case_dir, provocateur=provocateur)
        _, answer = load_case(case_dir)
        rows = _rows(case_dir)
        yara = _label_set(case_dir, "yara.txt")
        catalog = _label_set(case_dir, "catalog.txt")
        for name, targets in cheater_strategies(rows, yara, catalog).items():
            per_strategy[name].append(_f1(targets, answer))
            max_picks[name] = max(max_picks[name], len(targets))
    k = len(seeds)
    return {name: (sum(vals) / k, max_picks[name]) for name, vals in per_strategy.items()}


# How many of the N=3 forensic legs an `echo_*` label-subset strategy conditions
# on. A no-knowledge cheater can form these single-leg subsets and their pairwise
# intersections WITHOUT reconstructing the forensic rule; their order is the count
# of forensic legs the subset name encodes. The binding shortcut is the highest
# ORDER a cheater can reach without consuming all N legs: order N-1 = 2 here.
# (Intersecting all 3 legs — yara ∩ unsigned ∩ over — IS the oracle, by design,
# so the suite never forms it; see test_intersect_then_rank_is_the_oracle.)
_LEG_TOKENS = {"yara", "notcatalog", "over"}  # the three forensic legs (unsigned == notcatalog)


def _echo_order(name: str) -> int | None:
    """Forensic-leg order of an `echo_*` strategy, or None if it isn't one.

    `echo_all` / `echo_catalog` / `echo_notyara` condition on 0 forensic legs
    (they are NOT positive evidence for any leg of the answer), so they have
    order 0. `echo_yara`, `echo_notcatalog`, `echo_over` are order 1; their
    pairwise intersections are order 2 (the binding (N-1)-feature buckets)."""
    if not name.startswith("echo_"):
        return None
    parts = name[len("echo_"):].split("_AND_")
    return sum(1 for p in parts if p in _LEG_TOKENS)


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


def test_each_shortcut_family_at_its_own_floor(tmp_path: Path) -> None:
    """Per-FAMILY gate: each KNOWN no-domain shortcut bounded at ITS OWN floor, so
    a regression in any single family trips a NAMED assertion instead of hiding
    under the aggregate 0.4 ceiling. The under-detection the previous gate had is
    on the ECHO families specifically: single-picks were already pinned at
    2.2x chance by test_no_single_pick_cheater_beats_chance, but the multi-pick
    label echoes were bounded ONLY by the 0.4 aggregate — so an order-1 echo could
    DRIFT from its 2/(m+1) floor (~0.20) up to ~0.39 and still pass everything
    (0.39 < 0.4, and the gap gate's 1.0 - 0.39 = 0.61 >= 0.6 clears too), leaking
    nearly twice its forensic-leg-order share undetected. Bounding each echo order
    at its own floor (0.25 for order 0/1, 1/3+eps for order 2) is what traps that.
    The floors, confirmed empirically across K=24 fresh seeds:

      • single-pick (argmax/argmin/oldest/newest/unique/first/last/rarity/digit):
        floor = chance = 1/num_candidates. Bounded at 2.2x chance (best observed
        0.125 = first_row, positional noise under the row shuffle, not isolation).
      • order-0 echo (echo_all / echo_catalog / echo_notyara — condition on NO
        forensic leg of the answer): floor = recall-weighted noise; bounded at the
        order-1 floor (strictly below the binding 2-feature echo).
      • order-1 echo (echo_yara / echo_notcatalog / echo_over — ONE forensic leg):
        floor = 2/(m+1) for that leg's bucket size m (~7-9 rows -> 0.18-0.20).
        Bounded strictly below the order-2 floor.
      • order-2 echo (yara∩over, yara∩notcatalog, notcatalog∩over — the (N-1)=2
        binding buckets, each FORCED to size m=5): floor = 2/(5+1) = 1/3. This is
        the IRREDUCIBLE floor — the best shortcut a no-knowledge cheater reaches.

    Intersecting all N=3 legs is NOT in any family here: it consumes every
    forensic bit and IS the oracle (see test_intersect_then_rank_is_the_oracle).
    """
    eps = 1.0 / 15  # one chance unit ~= 0.067
    floor_2feat = 1.0 / 3  # 2/(m+1) with the forced m=5 binding bucket
    floor_1feat = 0.25  # order-1 echoes measured ~0.18-0.20; must stay < order-2
    for prov in (False, True):
        cand = _candidate_count(prov, tmp_path)
        chance = 1.0 / cand
        means = cheater_means(SEEDS, provocateur=prov, tmp_root=tmp_path)

        # Sanity: the suite actually contains a member of each family we bound,
        # so a vacuous-pass (suite silently stopped emitting a family) is caught.
        orders = {n: _echo_order(n) for n in means}
        assert any(o == 2 for o in orders.values()), "no order-2 echo in the suite"
        assert any(o == 1 for o in orders.values()), "no order-1 echo in the suite"
        assert any(
            n.startswith(("argmax_", "argmin_", "oldest_", "newest_", "unique_"))
            or n in ("first_row", "last_row", "name_has_digit_first", "rare_si_year_all")
            for n in means
        ), "no single-pick strategy in the suite"
        # The three KNOWN ROUND-2 shortcuts MUST be present (else this gate would
        # vacuously pass with the leaks restored): $FN-year MODE within a label
        # subset, max-$FN-year binning, and the seconds-granularity fingerprint.
        assert any(n.startswith("mode_30_year_") for n in means), "no $FN-year MODE strategy"
        assert "bottom2_maxyear_30" in means, "no max-$FN-year binning strategy"
        assert "nz_seconds_either" in means, "no seconds-granularity strategy"

        for name, (mean, mpicks) in means.items():
            order = orders[name]
            if order == 2:
                # The binding (N-1)-feature bucket: at most the irreducible 1/3.
                bound = floor_2feat + eps
            elif order == 1:
                # ONE forensic leg: strictly below the binding 2-feature floor.
                bound = floor_1feat
            elif order == 0:
                # Conditions on no forensic leg of the answer: low recall noise.
                bound = floor_1feat
            elif mpicks == 1:
                # SINGLE-pick (argmax/argmin/oldest/newest/unique/positional/rarity
                # or digit) — isolating the answer scores ~1.0, so must be ~chance.
                bound = 2.2 * chance
            else:
                # MULTI-pick non-echo frequency/binning families (mode bucket,
                # max-year bin, nonzero-seconds set): a benign-pooled construction
                # leaves these at the irreducible 2/(m+1) floor or below — NOT at
                # 1.0. This is the bound that traps the three ROUND-2 leaks:
                # mode_30_year_notcatalog (was 0.5), bottom2_maxyear_30 (was 0.667),
                # nz_seconds_either (was 1.0) must each be <= 1/3 + eps now.
                bound = floor_2feat + eps
            assert mean <= bound, (
                f"shortcut '{name}' (order={order}, max_picks={mpicks}) F1 {mean:.3f} "
                f"> floor {bound:.3f} (prov={prov}) — this family exceeds its own "
                f"floor; it leaks more signal than its forensic-leg order permits"
            )


def test_round2_known_shortcuts_at_floor(tmp_path: Path) -> None:
    """ROUND-2 REGRESSION (the three shortcuts the previous gate under-detected).

    Each is recomputed HERE directly (not via the suite) and pinned at the 1/3
    floor, so a regression that restores the leak trips THIS named assertion with
    the historical leaking value in the message. These three families were the
    blind spots: the in-repo suite tested rarest-$SI-year only (never the MODE,
    never the $FN/Created0x30 column) and never any timestamp SUB-field, so all
    three sat unmonitored at F1 0.5 / 0.667 / 1.0 respectively.

      1. mode::30_year::notcatalog — among UNSIGNED rows (absent from the catalog
         scan), select those whose $FN-Created (Created0x30) YEAR is the most
         common. The evil $FN year (2026) used to be the unique mode among
         unsigned rows, so this returned {answer, D3, D10} at F1=0.5. The
         generator now forces the unsigned-$FN-2026 bucket to >=5 members, so the
         mode selects a size->=5 set -> F1 = 2/(m+1) <= 1/3.
      2. bottom2_maxyear_30 — bin all rows by the YEAR of Created0x30, take the
         max-year (2026) bucket, pick the 2 rows with the OLDEST timestamp in it.
         Used to land on {answer, D1} (F1=0.667) because the evil row was the
         older of only two 2026 rows. The 2026 $FN bucket now holds several benign
         rows OLDER than the answer (D1/D9/D10 at months 1-3, evil at 5-8), so the
         oldest-2 are benign -> F1 = 0.
      3. nz_seconds_either — rows whose $SI or $FN seconds-of-minute is nonzero.
         The evil row used to be the UNIQUE nonzero-seconds row (F1=1.0) because
         only its datetime() constructors passed a seconds argument. Seconds are
         now drawn for EVERY row from one shared pool, so this selects ~every row
         (F1 ~ chance).

    The bound is the irreducible floor 1/3 + eps; each shortcut measured well
    below it (0.33 / 0.00 / 0.13). A violation means the bit-table discipline on
    the $FN column or the timestamp sub-fields regressed.
    """
    floor = 1.0 / 3 + 1.0 / 15  # 0.4 — same gate the order-2 echo is held to
    for prov in (False, True):
        m1: list[float] = []
        m2: list[float] = []
        m3: list[float] = []
        for seed in SEEDS:
            case_dir = tmp_path / f"r2_{int(prov)}_{seed}"
            TS.generate(seed=seed, out_dir=case_dir, provocateur=prov)
            _, answer = load_case(case_dir)
            rows = _rows(case_dir)
            catalog = _label_set(case_dir, "catalog.txt")

            # 1. $FN-year MODE among unsigned rows.
            unsigned = [r for r in rows if r["FileName"] not in catalog]
            yc = collections.Counter(r["Created0x30"][:4] for r in unsigned)
            top = max(yc.values())
            m1.append(_f1([_target(r) for r in unsigned if yc[r["Created0x30"][:4]] == top], answer))

            # 2. Oldest-2 within the max-$FN-year bucket.
            max_year = max(r["Created0x30"][:4] for r in rows)
            bucket = sorted((r for r in rows if r["Created0x30"][:4] == max_year),
                            key=lambda r: _dt(r["Created0x30"]))
            m2.append(_f1([_target(r) for r in bucket[:2]], answer))

            # 3. Nonzero-seconds rows.
            nz = [_target(r) for r in rows
                  if _dt(r["Created0x10"]).second != 0 or _dt(r["Created0x30"]).second != 0]
            m3.append(_f1(nz, answer))

        k = len(SEEDS)
        for label, vals, was in (
            ("mode::30_year::notcatalog", m1, 0.5),
            ("bottom2_maxyear_30", m2, 0.667),
            ("nz_seconds_either", m3, 1.0),
        ):
            mean = sum(vals) / k
            assert mean <= floor, (
                f"ROUND-2 shortcut '{label}' F1 {mean:.3f} > floor {floor:.3f} "
                f"(prov={prov}) — regressed toward its historical leak ({was}); the "
                f"$FN-column / timestamp-sub-field bit-table discipline broke"
            )


def test_intersect_then_rank_is_the_oracle(tmp_path: Path) -> None:
    """BOUNDARY (the one objection a reviewer raises). A cheater computing
    argmax(gap) WITHIN yara ∩ unsigned WOULD isolate the answer at F1=1.0 — but
    that consumes ALL THREE forensic legs (yara AND unsigned AND the gap ranking
    that resolves the backdate), which is precisely the INTENDED forensic rule.
    It is the ORACLE, not a cheap shortcut, and is deliberately EXCLUDED from the
    cheater suite. This test pins that classification: (1) argmax-gap within
    yara∩unsigned does land on the answer (so it IS the discriminating reasoning),
    and (2) the cheater suite never forms an order-3 (all-legs) intersection (so it
    is not smuggled in as a 'shortcut'). The 1/3 floor holds CONDITIONAL on this
    exclusion; the scope is single-pick + (k<=N-1)-feature echoes only."""
    for prov in (False, True):
        for seed in SEEDS:
            case_dir = tmp_path / f"boundary_{int(prov)}_{seed}"
            TS.generate(seed=seed, out_dir=case_dir, provocateur=prov)
            _, answer = load_case(case_dir)
            rows = _rows(case_dir)
            yara = _label_set(case_dir, "yara.txt")
            catalog = _label_set(case_dir, "catalog.txt")
            ans = answer.expected_findings[0].target

            def gap(r: dict[str, str]) -> float:
                return (_dt(r["Created0x30"]) - _dt(r["Created0x10"])).total_seconds()

            intersect = [r for r in rows if r["FileName"] in yara and r["FileName"] not in catalog]
            assert intersect, f"yara∩unsigned empty (seed={seed}, prov={prov})"
            picked = _target(max(intersect, key=gap))
            assert picked == ans, (
                f"argmax-gap within yara∩unsigned did NOT isolate the answer "
                f"(seed={seed}, prov={prov}) — the intended oracle reasoning broke"
            )

            # The cheater suite must NOT contain any all-3-legs intersection: such
            # a strategy IS the oracle and would (correctly) score 1.0, so its
            # presence would make the floor unreachable for the wrong reason.
            for name in cheater_strategies(rows, yara, catalog):
                assert _echo_order(name) != 3, (
                    f"cheater suite formed an order-3 (all-legs) echo '{name}' "
                    f"(seed={seed}, prov={prov}) — that is the oracle, not a shortcut"
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
