"""Cheat-resistance gate for the registry_persistence Forge template.

Option-1 ("reasoning-only") contract: a case must be solvable ONLY by the
intended forensic reasoning, never by a label or a surface regex. The defining
property we assert here is the GAP between two deterministic, no-LLM baselines:

  * CHEATER suite — no domain knowledge. Each strategy reads ONLY the issued
    artifacts (mock_outputs) and exploits a SURFACE feature: "echo what the
    Sysmon corroborator names", "pick the structurally-unique row" (newest /
    oldest / first), "pick by rarity" (the lone user-writable entry, the lone
    Sysmon hit). Every such shortcut must collide with >=1 benign decoy, so its
    best F1 across strategies sits at ~chance (1/num_candidates).

  * ORACLE — encodes the INTENDED rule: a Run value is malicious iff its binary
    is in a USER-WRITABLE location AND NOT in the imitated vendor's CANONICAL
    install path (stage 1), corroborated by a Sysmon RegistryEvent on that key
    (stage 2, which rejects the provocateur plants). Scores F1 ~1.0 — proving the
    case is solvable by reasoning and the answer key is correct.

PASS GATE (over K>=12 fresh seeds):
    oracle_f1            >= 0.9
    gap = oracle - cheater >= 0.6
    cheater_best_f1      <= ~chance (with a modest tolerance for single-pick
                            sampling noise over few seeds; the robust asserts are
                            oracle and gap).

Both baselines read mock_outputs only — NEVER answer_key.json. The cheater applies
NO allowlist (it has no domain knowledge); the oracle applies the canonical-path
allowlist (that allowlist IS the domain knowledge a cheater lacks).
"""

from __future__ import annotations

import csv
import io
import random
import re
from pathlib import Path

from hexbreaker.forge import template_registry_persistence as RP
from hexbreaker.forge.case import load_case

RUN_KEY = RP.RUN_KEY_PATH

# K fresh seeds. >=12 per the gate; 16 keeps single-pick hit-rates reasonably
# stable while staying fast.
SEEDS = list(range(90001, 90017))


# --------------------------------------------------------------------------- #
# Parsing helpers — operate on the ISSUED evidence files only.
# --------------------------------------------------------------------------- #


def _recmd_rows(case_dir: Path) -> list[dict[str, str]]:
    txt = (case_dir / "mock_outputs" / "recmd_run.csv").read_text()
    return list(csv.DictReader(io.StringIO(txt)))


def _sysmon_rows(case_dir: Path) -> list[dict[str, str]]:
    txt = (case_dir / "mock_outputs" / "sysmon_registry.csv").read_text()
    return list(csv.DictReader(io.StringIO(txt)))


def _target_of(row: dict[str, str]) -> str:
    return f"{RUN_KEY}\\{row['ValueName']}"


def _f1(selected: set[str], truth: set[str]) -> float:
    """F1 of a selection against the ground-truth positive set."""
    tp = len(selected & truth)
    fp = len(selected - truth)
    fn = len(truth - selected)
    if tp == 0:
        return 0.0
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    return 2 * precision * recall / (precision + recall)


# --------------------------------------------------------------------------- #
# CHEATER suite — single-pick surface strategies, NO domain knowledge.
# Each returns a 1-element selection (the entry it isolates). Single-pick is the
# honest construction: a select-all baseline has a 2/(N+1) precision floor that
# sits above 1/N regardless of decoy design and so cannot gate maliciousness.
#
# ADMISSIBILITY RULE: a cheater's parameters must be choosable WITHOUT the labels.
# A "select rows {with,without} token T" strategy that maximizes F1 over T (single-
# or multi-pick) is choosing T by truth-correlation — a decision stump fit to the
# answer key — which a blind submitter cannot do. Such max-over-tokens strategies
# are EXCLUDED as label-overfit. The parameter-free form of "pick by rarity" (pick
# the rarest-token row, below) IS admissible and is the one we encode.
# --------------------------------------------------------------------------- #


def _path_tokens(value_data: str) -> set[str]:
    """Path-segment + arg word tokens of a binary path (the surface a cheater sees)."""
    return {t for t in re.split(r"[\\ /]+", value_data.lower()) if t}


def _cheat_newest(recmd, sysmon, rng):
    r = max(recmd, key=lambda r: r["LastWriteTimestamp"])
    return {_target_of(r)}


def _cheat_oldest(recmd, sysmon, rng):
    r = min(recmd, key=lambda r: r["LastWriteTimestamp"])
    return {_target_of(r)}


def _cheat_first_row(recmd, sysmon, rng):
    return {_target_of(recmd[0])}


def _cheat_last_row(recmd, sysmon, rng):
    return {_target_of(recmd[-1])}


def _cheat_only_user_writable(recmd, sysmon, rng):
    """Pick a user-writable entry — the surface 'suspicious location' tell.
    Collides with the legit AppData apps, so it cannot isolate the answer."""
    uw = [r for r in recmd if RP.is_user_writable(r["ValueData"])]
    return {_target_of(rng.choice(uw))} if uw else set()


def _cheat_sysmon_named(recmd, sysmon, rng):
    """Echo a key the Sysmon corroborator names (the 'label file' shortcut)."""
    keys = sorted({r["TargetObject"] for r in sysmon})
    return {rng.choice(keys)} if keys else set()


def _cheat_sysmon_user_writable_image(recmd, sysmon, rng):
    """Pick a Sysmon row whose Image is user-writable — refines the label
    shortcut with the 'suspicious binary' tell. Still collides: benign apps
    write from user-writable Images too."""
    suw = [r for r in sysmon if RP.is_user_writable(r["Image"])]
    return {rng.choice(suw)["TargetObject"]} if suw else set()


def _cheat_user_writable_no_sysmon(recmd, sysmon, rng):
    """Pick a user-writable entry that has NO Sysmon event (the 'rare/odd-one-out'
    tell). By design this lands on a provocateur plant (a decoy), never evil."""
    syskeys = {r["TargetObject"] for r in sysmon}
    cand = [r for r in recmd if RP.is_user_writable(r["ValueData"]) and _target_of(r) not in syskeys]
    return {_target_of(rng.choice(cand))} if cand else set()


_MODIFIER_RE = re.compile(r"(?i)(update|updater|helper|health|task|sync|launcher)")


def _cheat_name_modifier(recmd, sysmon, rng):
    """Pick a Run value whose NAME carries an updater/helper-style modifier — the
    'plausible-impersonation name' tell. Collides: legit per-user app updaters
    (OneDriveStandaloneUpdater, ...) carry the same modifier shape."""
    cand = [r for r in recmd if _MODIFIER_RE.search(r["ValueName"])]
    return {_target_of(rng.choice(cand))} if cand else set()


def _cheat_name_modifier_and_sysmon(recmd, sysmon, rng):
    """Name-modifier tell refined by the Sysmon label. Still collides: the
    corroborated user-writable decoys are modifier-named too."""
    syskeys = {r["TargetObject"] for r in sysmon}
    cand = [
        r for r in recmd
        if _MODIFIER_RE.search(r["ValueName"]) and _target_of(r) in syskeys
    ]
    return {_target_of(rng.choice(cand))} if cand else set()


def _cheat_rarest_token(recmd, sysmon, rng):
    """Parameter-free 'pick by rarity': select the row whose rarest path token is
    least frequent across the dump (random tie-break). Admissible — chooses no
    token by hand. It cannot isolate the answer because every folder name and exe
    basename (evil AND decoy) is frequency-1, so ~all rows tie at min-frequency 1."""
    from collections import Counter
    freq = Counter(t for r in recmd for t in _path_tokens(r["ValueData"]))

    def rarity(r):
        toks = _path_tokens(r["ValueData"])
        return min(freq[t] for t in toks) if toks else 1

    m = min(rarity(r) for r in recmd)
    cands = [r for r in recmd if rarity(r) == m]
    return {_target_of(rng.choice(cands))}


CHEAT_STRATEGIES = {
    "newest": _cheat_newest,
    "oldest": _cheat_oldest,
    "first_row": _cheat_first_row,
    "last_row": _cheat_last_row,
    "only_user_writable": _cheat_only_user_writable,
    "sysmon_named": _cheat_sysmon_named,
    "sysmon_user_writable_image": _cheat_sysmon_user_writable_image,
    "user_writable_no_sysmon": _cheat_user_writable_no_sysmon,
    "name_modifier": _cheat_name_modifier,
    "name_modifier_and_sysmon": _cheat_name_modifier_and_sysmon,
    "rarest_token": _cheat_rarest_token,
}


# --------------------------------------------------------------------------- #
# ORACLE — encodes the intended two-stage forensic rule.
# --------------------------------------------------------------------------- #


def _oracle(recmd, sysmon, rng) -> set[str]:
    """Stage 1: user-writable AND not a canonical vendor path (impersonation).
    Stage 2: corroborated by a Sysmon RegistryEvent on that exact key.
    The second stage rejects provocateur plants (path-suspicious, uncorroborated).
    """
    syskeys = {r["TargetObject"] for r in sysmon}
    selected = set()
    for r in recmd:
        if RP.is_malicious_run_entry(r["ValueData"]) and _target_of(r) in syskeys:
            selected.add(_target_of(r))
    return selected


# --------------------------------------------------------------------------- #
# Scoring harness.
# --------------------------------------------------------------------------- #


def _score(strategy, tmp_path: Path, *, provocateur: bool = True) -> tuple[float, float]:
    """Mean F1 of `strategy` over SEEDS, and the mean candidate count (for chance)."""
    f1s: list[float] = []
    n_cands: list[int] = []
    for seed in SEEDS:
        d = tmp_path / f"case_{seed}_{int(provocateur)}"
        RP.generate(seed=seed, out_dir=d, provocateur=provocateur)
        _manifest, answer = load_case(d)
        truth = {ef.target for ef in answer.expected_findings}
        recmd = _recmd_rows(d)
        sysmon = _sysmon_rows(d)
        rng = random.Random(seed * 97 + 3)  # deterministic tie-breaks
        selected = strategy(recmd, sysmon, rng)
        f1s.append(_f1(selected, truth))
        n_cands.append(len(recmd))
    return sum(f1s) / len(f1s), sum(n_cands) / len(n_cands)


# --------------------------------------------------------------------------- #
# Tests.
# --------------------------------------------------------------------------- #


def test_oracle_solves_by_reasoning(tmp_path: Path) -> None:
    """The intended forensic rule scores F1 ~1.0 — proves solvable + key correct."""
    oracle_f1, _ = _score(_oracle, tmp_path)
    assert oracle_f1 >= 0.9, f"oracle F1 {oracle_f1:.3f} < 0.9 — case not solvable by the intended rule, or answer key wrong"


def test_no_cheater_strategy_beats_chance(tmp_path: Path) -> None:
    """Every surface shortcut sits at ~chance — no cheap rule isolates the answer.

    With ~N candidates the chance hit-rate is 1/N. Single-pick F1 == hit-rate, so
    we require each strategy's mean F1 below a generous multiple of chance to
    absorb sampling noise over K=16 seeds. (The robust gate is the gap below.)
    """
    _oracle_f1, avg_cands = _score(_oracle, tmp_path)
    chance = 1.0 / avg_cands
    for name, strat in CHEAT_STRATEGIES.items():
        f1, _ = _score(strat, tmp_path)
        assert f1 <= max(2.5 * chance, 0.30), (
            f"cheater strategy {name!r} F1 {f1:.3f} exceeds tolerance "
            f"(chance={chance:.3f}) — it isolates the answer via a surface feature"
        )


def test_gap_oracle_minus_cheater_at_least_0_6(tmp_path: Path) -> None:
    """The headline gate: oracle - best cheater >= 0.6, oracle >= 0.9."""
    oracle_f1, avg_cands = _score(_oracle, tmp_path)
    cheater_best = max(_score(s, tmp_path)[0] for s in CHEAT_STRATEGIES.values())
    gap = oracle_f1 - cheater_best
    chance = 1.0 / avg_cands
    assert oracle_f1 >= 0.9, f"oracle_f1={oracle_f1:.3f}"
    assert gap >= 0.6, (
        f"gap {gap:.3f} < 0.6  (oracle={oracle_f1:.3f}, cheater_best={cheater_best:.3f}, "
        f"chance={chance:.3f})"
    )


def test_honest_multiselect_baseline_is_below_tolerance(tmp_path: Path) -> None:
    """The baseline a BLIND submitter would actually run with no token games:
    select EVERY user-writable, Sysmon-corroborated entry. tp=1 (evil) against
    ~5 user-writable corroborated decoys → F1 = 2/(N_corroborated+1) ≈ 0.29, the
    precision artifact of any select-all. It stays at/below tolerance and proves
    even the honest multi-select can't isolate the answer (a token-maximized
    variant is excluded as label-overfit; see the sweep test above)."""
    f1s = []
    for seed in SEEDS:
        d = tmp_path / f"ms_{seed}"
        RP.generate(seed=seed, out_dir=d, provocateur=True)
        _m, answer = load_case(d)
        truth = {ef.target for ef in answer.expected_findings}
        syskeys = {r["TargetObject"] for r in _sysmon_rows(d)}
        sel = {
            _target_of(r) for r in _recmd_rows(d)
            if RP.is_user_writable(r["ValueData"]) and _target_of(r) in syskeys
        }
        f1s.append(_f1(sel, truth))
    mean_f1 = sum(f1s) / len(f1s)
    assert mean_f1 <= 0.30, f"honest multi-select baseline F1 {mean_f1:.3f} > 0.30"


def test_path_rule_never_selects_a_decoy(tmp_path: Path) -> None:
    """Stage-1 (non-canonical user-writable) must select exactly {evil} ∪ {plants}
    and NEVER a legitimate decoy — otherwise the rule is not the true discriminator
    and the oracle's correctness would be a coincidence."""
    for seed in SEEDS:
        d = tmp_path / f"pr_{seed}"
        RP.generate(seed=seed, out_dir=d, provocateur=True)
        _m, answer = load_case(d)
        target = answer.expected_findings[0].target
        plant_targets = {p.target for p in answer.planted}
        decoy_targets = {x.target for x in answer.decoys}
        recmd = _recmd_rows(d)
        path_mal = {_target_of(r) for r in recmd if RP.is_malicious_run_entry(r["ValueData"])}
        assert path_mal == {target} | plant_targets, (
            f"seed={seed}: path rule selected {path_mal}, expected evil+plants"
        )
        assert not (path_mal & decoy_targets), f"seed={seed}: path rule hit a decoy"


def test_sysmon_corroborates_a_decoy_too(tmp_path: Path) -> None:
    """The Sysmon file must name >=1 benign decoy key alongside the evil one, so
    'echo the Sysmon corroborator' is not a 1:1 giveaway."""
    for seed in SEEDS:
        d = tmp_path / f"sc_{seed}"
        RP.generate(seed=seed, out_dir=d, provocateur=True)
        _m, answer = load_case(d)
        target = answer.expected_findings[0].target
        decoy_targets = {x.target for x in answer.decoys}
        syskeys = {r["TargetObject"] for r in _sysmon_rows(d)}
        assert target in syskeys, f"seed={seed}: evil not corroborated by Sysmon"
        benign = syskeys - {target}
        assert benign and benign <= decoy_targets, (
            f"seed={seed}: Sysmon benign rows {benign} are not all decoys"
        )
