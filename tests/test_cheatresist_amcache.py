"""Cheat-resistance gate for the Amcache template (Option 1, "reasoning-only").

The defining property we enforce: every surface signal that fires on the ANSWER
also fires on >=1 benign DECOY, and the decoys carry benign near-miss tells, so
no cheap shortcut (read a label, run a surface regex, pick the structurally
unique row) isolates the answer. The answer is identifiable ONLY by the intended
forensic reasoning — the CONJUNCTION (staged in a user-writable / suspicious path
AND flagged by yara). Each leg of that conjunction alone hits a decoy; only their
intersection is the malware.

Two deterministic, no-LLM baselines, scored with the REAL registry scorer
(`hexbreaker.scorer.exact_match.score`) over K fresh seeds:

  CHEATER suite (no domain knowledge): a battery of surface strategies — dump
    everything a label/heuristic file names; pick the structurally-unique row
    (only hit, first/last, oddest value); pick by rarity/frequency; SCORE THE YARA
    RULE STRING by malware-family keywords (the shortcut that broke the prior
    hardening at F1=1.0); pick the row whose rule is UNIQUE; score the BASENAME by
    a scary / system-process token lexicon. We take the cheater's BEST mean F1
    across all strategies. (The rule-content and basename strategies are the
    regression guards: the gate must measure the very leak it is closing.)

  ORACLE (the intended forensic rule): pick the single row that is BOTH in a
    suspicious path AND a yara hit. Must score F1 ~= 1.0 (proves the case is
    solvable-by-reasoning and the answer key is correct).

GATE (asserted numerically below):
  • oracle_f1        >= 0.9
  • gap = oracle - cheater_best >= 0.6        (the substantive guarantee)
  • cheater_best_f1  <= 0.4                    (a measured bound)

NOTE on the "<= ~chance" soft target. With exactly ONE expected finding, the
"dump everything the label names" cheater ALWAYS contains the answer (yara must
name the true target — JR-01 corroboration requires it), so its recall is 1.0 and
its F1 floors at 2/(Y+1) where Y is the yara-hit-set size. No design can push
this all the way to 1/num_candidates (~0.11 here). We size the yara-hit set and
the suspicious-path set to 5 each (1 evil + 4 benign carriers), which puts the
strongest cheater at ~0.33 — comfortably clearing gap >= 0.6, which is the real
guarantee. See the module docstring of template_amcache and the `blockers`
report for this structural floor.
"""

from __future__ import annotations

from pathlib import Path

from hexbreaker.forge import template_amcache as T
from hexbreaker.forge.case import load_case
from hexbreaker.forge.template_amcache import _is_suspicious_path
from hexbreaker.scorer.exact_match import score

# Fixed, well-spread fresh seeds so the gate is reproducible. We use 48 (>> the
# required 8): single-pick cheater strategies are inherently noisy (their F1 is
# the FRACTION of seeds where they happen to land on the answer, true mean 1/5),
# so a small K lets sampling variance push a single-pick strategy artificially
# high. At K=48 the noisy strategies sit near their true ~0.2 mean and the genuine
# ceiling is the DETERMINISTIC dump-all-yara strategy at 2/(Y+1)=1/3 (Y=5). The
# seeds are spread across a wide range (sampled with a fixed RNG seed) rather than
# a contiguous block, which avoids an unlucky local run inflating a single-pick
# strategy.
SEEDS = [
    1030, 10562, 11217, 14523, 16822, 23614, 25015, 27795, 31230, 34714,
    36908, 38875, 42480, 50190, 55562, 61159, 64365, 69038, 76949, 78087,
    91831, 93784, 99528, 101889, 105935, 114177, 116727, 125275, 130375, 137700,
    140029, 147819, 149615, 151707, 158634, 161224, 162270, 166445, 166634, 168430,
    170946, 172269, 175641, 183279, 184412, 190167, 191323, 193831,
]
KIND = "amcache"


# --------------------------------------------------------------------------- #
# Case parsing — exactly the surface a non-LLM cheater would read.
# --------------------------------------------------------------------------- #


def _gen(seed: int, tmp: Path) -> Path:
    d = tmp / f"case-{seed}"
    # provocateur=True is the harder case (one extra suspicious-path bait row);
    # the cheater can never tell the bait from the answer on path alone.
    T.generate(seed=seed, out_dir=d, provocateur=True)
    return d


def _rows(case_dir: Path) -> list[dict]:
    """Parse amcache.csv into row dicts — the raw evidence a cheater sees."""
    lines = (case_dir / "mock_outputs" / "amcache.csv").read_text().splitlines()
    header = lines[0].split(",")
    out = []
    for line in lines[1:]:
        cols = line.split(",")
        out.append(dict(zip(header, cols)))
    return out


def _yara_basenames(case_dir: Path) -> set[str]:
    """Basenames named in yara.txt — the label file a cheater reads."""
    text = (case_dir / "mock_outputs" / "yara.txt").read_text()
    return {ln.split(":", 1)[0].strip() for ln in text.splitlines() if ln.strip()}


def _yara_rule_by_basename(case_dir: Path) -> dict[str, str]:
    """basename -> matched RULE STRING. The cheater that broke the prior hardening
    read the rule content (after the colon), not just membership — so the suite
    MUST expose it or the gate is blind to exactly the leak we're closing."""
    text = (case_dir / "mock_outputs" / "yara.txt").read_text()
    out: dict[str, str] = {}
    for ln in text.splitlines():
        if ":" in ln:
            leaf, rule = ln.split(":", 1)
            out[leaf.strip()] = rule.strip()
    return out


def _basename(path: str) -> str:
    return path.rsplit("\\", 1)[1]


# --------------------------------------------------------------------------- #
# Scoring helper — uses the REAL registry scorer.
# --------------------------------------------------------------------------- #


def _f1_for_targets(targets: list[str], case_dir: Path) -> float:
    """Score a list of guessed FullPaths against the withheld answer key."""
    _, answer = load_case(case_dir)
    findings = [{"artifact_kind": KIND, "target": t} for t in targets]
    return score(findings, answer).f1


# --------------------------------------------------------------------------- #
# CHEATER strategies. Each maps a parsed case -> list of guessed FullPaths,
# using ONLY surface features (no notion of "suspicious path AND yara hit"
# conjunction, which is the intended reasoning the oracle encodes).
# --------------------------------------------------------------------------- #

# Surface "suspicious" substrings a regex-cheater would try, WITHOUT knowing it
# must be conjoined with the yara hit.
_SUSP_TOKENS = ("\\Temp\\", "\\AppData\\", "\\Users\\Public\\", "\\ProgramData\\")


def _surface_suspicious(path: str) -> bool:
    return any(t in path for t in _SUSP_TOKENS)


def _strat_yara_dump_all(rows, yara) -> list[str]:
    return [r["FullPath"] for r in rows if _basename(r["FullPath"]) in yara]


def _strat_yara_first(rows, yara) -> list[str]:
    hits = [r["FullPath"] for r in rows if _basename(r["FullPath"]) in yara]
    return hits[:1]


def _strat_yara_last(rows, yara) -> list[str]:
    hits = [r["FullPath"] for r in rows if _basename(r["FullPath"]) in yara]
    return hits[-1:]


def _strat_suspicious_dump_all(rows, yara) -> list[str]:
    return [r["FullPath"] for r in rows if _surface_suspicious(r["FullPath"])]


def _strat_suspicious_first(rows, yara) -> list[str]:
    hits = [r["FullPath"] for r in rows if _surface_suspicious(r["FullPath"])]
    return hits[:1]


def _strat_suspicious_last(rows, yara) -> list[str]:
    hits = [r["FullPath"] for r in rows if _surface_suspicious(r["FullPath"])]
    return hits[-1:]


def _strat_first_row(rows, yara) -> list[str]:
    return [rows[0]["FullPath"]]


def _strat_last_row(rows, yara) -> list[str]:
    return [rows[-1]["FullPath"]]


def _strat_newest_ts(rows, yara) -> list[str]:
    r = max(rows, key=lambda r: r["FileKeyLastWriteTimestamp"])
    return [r["FullPath"]]


def _strat_oldest_ts(rows, yara) -> list[str]:
    r = min(rows, key=lambda r: r["FileKeyLastWriteTimestamp"])
    return [r["FullPath"]]


def _strat_longest_path(rows, yara) -> list[str]:
    r = max(rows, key=lambda r: len(r["FullPath"]))
    return [r["FullPath"]]


def _strat_shortest_path(rows, yara) -> list[str]:
    r = min(rows, key=lambda r: len(r["FullPath"]))
    return [r["FullPath"]]


def _strat_rarest_year(rows, yara) -> list[str]:
    """Pick the row whose write-year is the least common (rarity heuristic)."""
    years = [r["FileKeyLastWriteTimestamp"][:4] for r in rows]
    counts = {y: years.count(y) for y in years}
    rarest = min(counts, key=lambda y: (counts[y], y))
    for r in rows:
        if r["FileKeyLastWriteTimestamp"][:4] == rarest:
            return [r["FullPath"]]
    return []


def _strat_most_recent_year_dump(rows, yara) -> list[str]:
    """Dump every row in the most recent year (recency heuristic)."""
    maxyear = max(r["FileKeyLastWriteTimestamp"][:4] for r in rows)
    return [r["FullPath"] for r in rows if r["FileKeyLastWriteTimestamp"][:4] == maxyear]


def _strat_dump_everything(rows, yara) -> list[str]:
    """The naive 'flag every recorded binary' cheater (recall 1, precision 1/N)."""
    return [r["FullPath"] for r in rows]


# --- Rule-CONTENT and basename-LEXICON strategies (the leaks that broke the
# prior hardening). These read the yara RULE STRING after the colon and score the
# basename TOKENS — surface signals the membership/position strategies never
# touched, which is exactly why the gate stayed green while the hunter hit F1=1.0.

# The malware-family lexicon the hunter scored rule strings by. If any rule string
# matches one of these, the rule content is acting as a label.
_MALWARE_RULE_TOKENS = (
    "trojan", "backdoor", "malware", "cobalt", "beacon",
    "shellinject", "shell", "inject", "apt", "loader",
)
# Scary basename tokens (the hunter's basename lexicon: EVIL_BINARIES used to have
# malware-y leaf names). The evil pool now masquerades with these legit-looking
# tokens, so a decoy must carry them too.
_SCARY_BASENAME_TOKENS = (
    "svchost", "rundll", "runtimebroker", "securityhealth", "onedrive",
    "edgeupdate", "update", "setup", "service", "crash", "handler",
    "host", "helper", "broker", "telemetry", "cache",
)
# Known Windows system/host process names a "is this a real system process"
# cheater would flag.
_SYSTEM_PROCESS_TOKENS = (
    "svchost", "rundll", "services", "lsass", "csrss", "smss", "wininit",
    "winlogon", "taskhost", "runtimebroker", "dllhost", "securityhealth",
)


def _basenames_for(rows) -> dict[str, str]:
    return {_basename(r["FullPath"]): r["FullPath"] for r in rows}


def _strat_rule_malware_lexicon_pick(rows, yara, rule_map) -> list[str]:
    """The hunter's killer: score each yara line by malware-family keywords in the
    RULE STRING, argmax to one basename, map to its FullPath. If exactly one rule
    sounds malware-y, that is a clean 1:1 label."""
    b2f = _basenames_for(rows)
    hits = [b for b, rule in rule_map.items()
            if any(t in rule.lower() for t in _MALWARE_RULE_TOKENS)]
    if len(hits) == 1:
        return [b2f[hits[0]]] if hits[0] in b2f else []
    return [b2f[b] for b in hits if b in b2f]  # dump-all fallback if 0 or >1


def _strat_rule_unique_pick(rows, yara, rule_map) -> list[str]:
    """Pick the basename whose RULE STRING is unique (appears exactly once). If the
    evil rule is never shared, this isolates the answer."""
    b2f = _basenames_for(rows)
    counts = {}
    for rule in rule_map.values():
        counts[rule] = counts.get(rule, 0) + 1
    uniq = [b for b, rule in rule_map.items() if counts[rule] == 1]
    if len(uniq) == 1:
        return [b2f[uniq[0]]] if uniq[0] in b2f else []
    return [b2f[b] for b in uniq if b in b2f]


def _strat_scary_basename_first(rows, yara, rule_map) -> list[str]:
    """Pick the first row whose BASENAME contains a scary token."""
    hits = [r["FullPath"] for r in rows
            if any(t in _basename(r["FullPath"]).lower() for t in _SCARY_BASENAME_TOKENS)]
    return hits[:1]


def _strat_scary_basename_dump(rows, yara, rule_map) -> list[str]:
    """Dump every row whose BASENAME contains a scary token."""
    return [r["FullPath"] for r in rows
            if any(t in _basename(r["FullPath"]).lower() for t in _SCARY_BASENAME_TOKENS)]


def _strat_system_process_name_first(rows, yara, rule_map) -> list[str]:
    """Pick the first row whose basename looks like a known Windows system process
    (svchost / RuntimeBroker / …) — a classic masquerade hunt."""
    hits = [r["FullPath"] for r in rows
            if any(t in _basename(r["FullPath"]).lower() for t in _SYSTEM_PROCESS_TOKENS)]
    return hits[:1]


def _strat_system_process_name_dump(rows, yara, rule_map) -> list[str]:
    return [r["FullPath"] for r in rows
            if any(t in _basename(r["FullPath"]).lower() for t in _SYSTEM_PROCESS_TOKENS)]


CHEATERS = {
    "yara_dump_all": _strat_yara_dump_all,
    "yara_first": _strat_yara_first,
    "yara_last": _strat_yara_last,
    "suspicious_dump_all": _strat_suspicious_dump_all,
    "suspicious_first": _strat_suspicious_first,
    "suspicious_last": _strat_suspicious_last,
    "first_row": _strat_first_row,
    "last_row": _strat_last_row,
    "newest_ts": _strat_newest_ts,
    "oldest_ts": _strat_oldest_ts,
    "longest_path": _strat_longest_path,
    "shortest_path": _strat_shortest_path,
    "rarest_year": _strat_rarest_year,
    "most_recent_year_dump": _strat_most_recent_year_dump,
    "dump_everything": _strat_dump_everything,
    # Rule-content + basename-lexicon strategies — the leaks that broke the prior
    # hardening (the gate was previously blind to these).
    "rule_malware_lexicon_pick": _strat_rule_malware_lexicon_pick,
    "rule_unique_pick": _strat_rule_unique_pick,
    "scary_basename_first": _strat_scary_basename_first,
    "scary_basename_dump": _strat_scary_basename_dump,
    "system_process_name_first": _strat_system_process_name_first,
    "system_process_name_dump": _strat_system_process_name_dump,
}


# --------------------------------------------------------------------------- #
# ORACLE — encodes the intended forensic rule (the conjunction).
# --------------------------------------------------------------------------- #


def _oracle(rows, yara) -> list[str]:
    """The malware is the UNIQUE entry that is BOTH in a suspicious/user-writable
    path AND a yara hit. Each leg alone also hits a benign decoy — only the
    intersection isolates the answer."""
    return [
        r["FullPath"]
        for r in rows
        if _is_suspicious_path(r["FullPath"]) and _basename(r["FullPath"]) in yara
    ]


# --------------------------------------------------------------------------- #
# Measurement.
# --------------------------------------------------------------------------- #


def _mean_f1(strategy, tmp_path: Path) -> float:
    total = 0.0
    for seed in SEEDS:
        case_dir = _gen(seed, tmp_path)
        rows = _rows(case_dir)
        yara = _yara_basenames(case_dir)
        rule_map = _yara_rule_by_basename(case_dir)
        # Rule-content / basename-lexicon strategies need the rule map; the
        # membership/position strategies take only (rows, yara). Dispatch on the
        # declared parameter count so old strategies stay untouched.
        if strategy.__code__.co_argcount == 3:
            targets = strategy(rows, yara, rule_map)
        else:
            targets = strategy(rows, yara)
        total += _f1_for_targets(targets, case_dir)
    return total / len(SEEDS)


def _cheater_best(tmp_path: Path) -> tuple[float, str]:
    best_f1 = 0.0
    best_name = ""
    for name, strat in CHEATERS.items():
        f1 = _mean_f1(strat, tmp_path)
        if f1 > best_f1:
            best_f1, best_name = f1, name
    return best_f1, best_name


# --------------------------------------------------------------------------- #
# Tests.
# --------------------------------------------------------------------------- #


def test_oracle_solves_the_case(tmp_path: Path) -> None:
    """The intended forensic rule (conjunction) recovers the answer exactly —
    proves the case is solvable-by-reasoning and the answer key is correct."""
    oracle_f1 = _mean_f1(_oracle, tmp_path)
    assert oracle_f1 >= 0.9, f"oracle mean F1={oracle_f1:.4f} < 0.9 — case not solvable"
    assert oracle_f1 == 1.0, f"oracle should be exact; got {oracle_f1:.4f}"


def test_no_cheater_beats_the_threshold(tmp_path: Path) -> None:
    """No surface shortcut isolates the answer: the BEST cheater's mean F1 stays
    well below the oracle. 0.4 is the measured bound (the dump-all-yara strategy
    floors at ~2/(Y+1)=0.33 because, with a single expected finding, any label
    file naming the answer guarantees recall=1)."""
    cheater_best_f1, name = _cheater_best(tmp_path)
    assert cheater_best_f1 <= 0.4, (
        f"cheater '{name}' scored mean F1={cheater_best_f1:.4f} > 0.4 — a surface "
        f"shortcut isolates the answer"
    )


def test_reasoning_gap_is_wide(tmp_path: Path) -> None:
    """The substantive gate: oracle - cheater_best >= 0.6 over K>=8 fresh seeds."""
    oracle_f1 = _mean_f1(_oracle, tmp_path)
    cheater_best_f1, name = _cheater_best(tmp_path)
    gap = oracle_f1 - cheater_best_f1
    assert oracle_f1 >= 0.9, f"oracle_f1={oracle_f1:.4f} < 0.9"
    assert cheater_best_f1 <= 0.4, f"cheater_best_f1={cheater_best_f1:.4f} ({name}) > 0.4"
    assert gap >= 0.6, (
        f"gap={gap:.4f} (oracle={oracle_f1:.4f}, cheater_best={cheater_best_f1:.4f} "
        f"via '{name}') < 0.6 — not enough separation between reasoning and shortcuts"
    )
