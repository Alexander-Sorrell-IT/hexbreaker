"""Cheat-resistance gate for the multi_artifact Forge template (Option 1).

The defining property we enforce: each Forge case must be solvable ONLY by the
intended forensic reasoning, NOT by reading a label or running a surface regex.
Concretely — every signal that fires on the ANSWER also fires on >=1 DECOY, and
decoys carry benign NEAR-MISS tells, so no cheap shortcut isolates the answer.
The malicious entry is distinguished only by the MEANING of the pattern:

  timestomp leg: $SI backdated YEARS before $FN (is_timestomped) AND a yara hit.
  persistence leg: a user-writable path NOT under a recognized vendor subdir
                   (is_evil_run_value) AND a Sysmon EventID-13 corroboration.

We encode two deterministic, no-LLM baselines and assert the gap between them:

  CHEATER suite — NO domain knowledge. Each strategy reads the evidence files
    (and/or the answer-adjacent heuristic file yara.txt) and applies one cheap
    structural rule: "echo what the label file names", "the only mismatch", "the
    only hit", "first/last row", "rarest path token", etc. We take the cheater's
    BEST F1 across ALL strategies over K fresh seeds.

  ORACLE — encodes the INTENDED forensic rule (is_timestomped + yara
    corroboration; is_evil_run_value + EvtxECmd corroboration). Scores ~1.0,
    proving the case is solvable-by-reasoning and the answer key is correct.

PASS GATE (over K>=8 fresh seeds, on the PROVOCATEUR case — strongest decoys):
  cheater_best_f1 <= ~chance (~1/num_candidates)  AND
  oracle_f1       >= 0.9                            AND
  gap = oracle_f1 - cheater_best_f1 >= 0.6

Both baselines consume ONLY the issued evidence (the mock_outputs CSV/txt) — the
same bytes a submitter receives. They never read answer_key.json. F1 is computed
by the production scorer against the (withheld) answer key.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from pathlib import Path

from hexbreaker.forge import template_multi_artifact as M
from hexbreaker.forge.case import load_case
from hexbreaker.forge.template_multi_artifact import is_evil_run_value, is_timestomped
from hexbreaker.scorer.exact_match import score

# K>=8 fresh seeds, distinct from the seeds pinned in other suites. We use 32 so
# the measured cheater_best converges near its true value (a 120-seed sweep gives
# ~0.19); on a 10-seed set, position-cheat sampling noise can spike a single leg
# to ~0.3 and falsely fail the gate. 32 contiguous seeds is deterministic and
# robust without being slow.
_SEEDS = list(range(1011, 1043))

RUN_KEY = M.RUN_KEY_PATH
DRIVER_PARENT = M.DRIVER_PARENT


# --------------------------------------------------------------------------- #
# Evidence parsing — exactly what a submitter (cheater or oracle) can read.
# --------------------------------------------------------------------------- #


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def _read_rows(case_dir: Path, name: str) -> list[dict[str, str]]:
    text = (case_dir / "mock_outputs" / name).read_text()
    return list(csv.DictReader(io.StringIO(text)))


def _mft_rows(case_dir: Path) -> list[dict[str, str]]:
    return _read_rows(case_dir, "mft.csv")


def _recmd_rows(case_dir: Path) -> list[dict[str, str]]:
    return _read_rows(case_dir, "recmd_run.csv")


def _yara_basenames(case_dir: Path) -> list[str]:
    text = (case_dir / "mock_outputs" / "yara.txt").read_text()
    return [ln.split(":", 1)[0].strip() for ln in text.splitlines() if ln.strip()]


def _evtx_targetobjects(case_dir: Path) -> list[str]:
    return [r["TargetObject"] for r in _read_rows(case_dir, "evtx_registry.csv")]


def _evtx_rows(case_dir: Path) -> list[dict[str, str]]:
    return _read_rows(case_dir, "evtx_registry.csv")


# Vendor words the is_evil_run_value rule recognizes (as bare substrings, the way a
# cheater would naively grep the corroborator's Image column).
_VENDOR_WORDS = tuple(v.strip("\\") for v in M._VENDOR_SUBDIRS)


def _ts_target(name: str) -> str:
    return f"{DRIVER_PARENT}\\{name}"


def _pers_target(value: str) -> str:
    return f"{RUN_KEY}\\{value}"


# --------------------------------------------------------------------------- #
# CHEATER suite — NO domain knowledge. Each returns a findings list.
# Strategies that legitimately span both legs return up to 2 findings.
#
# SCOPE: a cheater here applies only CONTENT-AGNOSTIC structural rules — read a
# label/heuristic file, "the only mismatch", first/last row, an oddly-formatted
# value (granularity), rarity/frequency, a raw column comparison ($SI!=$FN,
# $LM!=$FN, year-in-fixed-band). It must NOT reconstruct the forensic rule. The
# line: encoding the MEANING of the pattern (e.g. "$SI predates $FN by a YEAR+",
# "exe in a bare AppData root with NO recognized vendor subdir") is exactly the
# is_timestomped / is_evil_run_value ORACLE discriminator — that is domain
# reasoning, not a surface shortcut, and the ORACLE the task requires is itself a
# deterministic no-LLM script scoring ~1.0. A primary-rule-only script lands on
# {answer + planted bait} (~0.5 per leg) BECAUSE the Provocateur plant is
# engineered to carry the full primary signal; the CORROBORATION step (yara /
# EvtxECmd, which the plant lacks) is the load-bearing reasoning that lifts the
# full oracle to 1.0. So such a script is a *partial oracle*, deliberately out of
# the cheater suite. Every strategy below is a genuine no-domain-knowledge cheat,
# and the gate asserts none of them beats ~chance.
# --------------------------------------------------------------------------- #


def _cheat_echo_label(case_dir: Path) -> list[dict]:
    """Echo what the heuristic/label file (yara.txt) names. The classic
    self-labeling cheat. yara names a basename -> map back to a driver target.
    For the registry leg, echo the only/ first EvtxECmd TargetObject."""
    out = []
    bns = _yara_basenames(case_dir)
    if bns:
        out.append({"artifact_kind": "timestomp", "target": _ts_target(bns[0])})
    tos = _evtx_targetobjects(case_dir)
    if tos:
        out.append({"artifact_kind": "persistence", "target": tos[0]})
    return out


def _cheat_only_mismatch(case_dir: Path) -> list[dict]:
    """Pick the entry that is structurally unique on a surface mismatch:
    timestomp -> the only row whose $SI != $FN; persistence -> the only row whose
    binary path is user-writable. If not unique, fall back to the first match."""
    out = []
    mism = [r for r in _mft_rows(case_dir) if r["Created0x10"] != r["Created0x30"]]
    if mism:
        out.append({"artifact_kind": "timestomp", "target": _ts_target(mism[0]["FileName"])})
    uw = [r for r in _recmd_rows(case_dir) if M._is_userwritable(r["ValueData"])]
    if uw:
        out.append({"artifact_kind": "persistence", "target": _pers_target(uw[0]["ValueName"])})
    return out


def _cheat_only_hit(case_dir: Path) -> list[dict]:
    """Pick the entry named by the corroborator: the (first) yara basename; the
    (first) EvtxECmd TargetObject."""
    out = []
    bns = _yara_basenames(case_dir)
    if bns:
        out.append({"artifact_kind": "timestomp", "target": _ts_target(sorted(bns)[0])})
    tos = _evtx_targetobjects(case_dir)
    if tos:
        out.append({"artifact_kind": "persistence", "target": sorted(tos)[0]})
    return out


def _cheat_first_row(case_dir: Path) -> list[dict]:
    """Pick the first data row of each primary (position cheat)."""
    out = []
    mft = _mft_rows(case_dir)
    if mft:
        out.append({"artifact_kind": "timestomp", "target": _ts_target(mft[0]["FileName"])})
    rc = _recmd_rows(case_dir)
    if rc:
        out.append({"artifact_kind": "persistence", "target": _pers_target(rc[0]["ValueName"])})
    return out


def _cheat_last_row(case_dir: Path) -> list[dict]:
    """Pick the last data row of each primary (position cheat)."""
    out = []
    mft = _mft_rows(case_dir)
    if mft:
        out.append({"artifact_kind": "timestomp", "target": _ts_target(mft[-1]["FileName"])})
    rc = _recmd_rows(case_dir)
    if rc:
        out.append({"artifact_kind": "persistence", "target": _pers_target(rc[-1]["ValueName"])})
    return out


def _cheat_oldest_si(case_dir: Path) -> list[dict]:
    """Timestomp-only: pick the row with the OLDEST $SI (naive 'looks old')."""
    mft = _mft_rows(case_dir)
    if not mft:
        return []
    oldest = min(mft, key=lambda r: _parse_iso(r["Created0x10"]))
    return [{"artifact_kind": "timestomp", "target": _ts_target(oldest["FileName"])}]


def _cheat_biggest_abs_gap(case_dir: Path) -> list[dict]:
    """Timestomp-only: pick the row with the largest |$SI - $FN| gap, IGNORING
    direction (a naive 'most divergent' heuristic — backdate plant trips this)."""
    mft = _mft_rows(case_dir)
    if not mft:
        return []
    def gap(r):
        return abs((_parse_iso(r["Created0x30"]) - _parse_iso(r["Created0x10"])).total_seconds())
    top = max(mft, key=gap)
    return [{"artifact_kind": "timestomp", "target": _ts_target(top["FileName"])}]


def _cheat_old_si_era(case_dir: Path) -> list[dict]:
    """Timestomp-only: flag every row whose $SI year is in the 'backdate era'
    2017-2019 (the era an attacker plants to mimic an old OS file). If only the
    answer (and a planted bait) live in that era, this isolates the answer; a
    benign decoy must also occupy it. Returns ALL such rows (a real cheater would
    accuse the whole era)."""
    out = []
    for r in _mft_rows(case_dir):
        if 2017 <= int(r["Created0x10"][:4]) <= 2019:
            out.append({"artifact_kind": "timestomp", "target": _ts_target(r["FileName"])})
    return out


def _cheat_recent_fn(case_dir: Path) -> list[dict]:
    """Timestomp-only: flag every row whose $FN (true creation) year is the
    current year (2026) — 'recently created'. The backdated file has a recent
    $FN, so if only the answer (+ planted bait) is recent, this isolates it;
    benign recent decoys must also occupy 2026. Accuses the whole set."""
    return [{"artifact_kind": "timestomp", "target": _ts_target(r["FileName"])}
            for r in _mft_rows(case_dir) if r["Created0x30"][:4] == "2026"]


def _cheat_si_before_fn(case_dir: Path) -> list[dict]:
    """Timestomp-only: flag every row whose $SI predates $FN (any magnitude) — a
    naive 'backdate' heuristic that ignores the years-vs-minutes distinction."""
    out = []
    for r in _mft_rows(case_dir):
        if _parse_iso(r["Created0x10"]) < _parse_iso(r["Created0x30"]):
            out.append({"artifact_kind": "timestomp", "target": _ts_target(r["FileName"])})
    return out


def _cheat_lm_ne_fn(case_dir: Path) -> list[dict]:
    """Timestomp-only: flag every row whose $LastModified != $FN. The timestomp
    tool rewrites $LastModified to match the backdated $SI, so the answer trips
    this; benign later-patched decoys must trip it too (else it isolates the
    answer). Accuses the whole set."""
    return [{"artifact_kind": "timestomp", "target": _ts_target(r["FileName"])}
            for r in _mft_rows(case_dir) if r["LastModified0x10"] != r["Created0x30"]]


def _cheat_lm_eq_si(case_dir: Path) -> list[dict]:
    """Timestomp-only: flag every row whose $LastModified == $SI (the timestomp
    tool sets LM to the backdated $SI). Benign clean decoys ($SI==$FN==LM) trip
    this too, so it must not isolate the answer."""
    return [{"artifact_kind": "timestomp", "target": _ts_target(r["FileName"])}
            for r in _mft_rows(case_dir) if r["LastModified0x10"] == r["Created0x10"]]


def _cheat_rarest_si_year(case_dir: Path) -> list[dict]:
    """Timestomp-only: flag rows whose $SI year is the rarest among MFT rows."""
    import collections as _c
    mft = _mft_rows(case_dir)
    if not mft:
        return []
    yrs = [r["Created0x10"][:4] for r in mft]
    cnt = _c.Counter(yrs)
    rare = min(cnt, key=lambda y: cnt[y])
    return [{"artifact_kind": "timestomp", "target": _ts_target(r["FileName"])}
            for r in mft if r["Created0x10"][:4] == rare]


def _cheat_oddly_formatted_time(case_dir: Path) -> list[dict]:
    """Pick the row whose timestamp is 'oddly formatted' relative to the others —
    the classic formatting tell the task calls out. timestomp: the row whose $SI
    or $FN has non-zero SECONDS; persistence: the row whose LastWrite is NOT
    midnight. If the malicious row were the only one built at a finer granularity,
    this trivially isolates it. (First match per leg.)"""
    out = []
    for r in _mft_rows(case_dir):
        if r["Created0x10"][17:19] != "00" or r["Created0x30"][17:19] != "00":
            out.append({"artifact_kind": "timestomp", "target": _ts_target(r["FileName"])})
            break
    for r in _recmd_rows(case_dir):
        if r["LastWriteTimestamp"][11:19] != "00:00:00":
            out.append({"artifact_kind": "persistence", "target": _pers_target(r["ValueName"])})
            break
    return out


def _cheat_unique_granularity(case_dir: Path) -> list[dict]:
    """Stronger formatting cheat: pick the row that is the SOLE one at its
    timestamp granularity. timestomp: if exactly one row has non-zero seconds,
    pick it; persistence: if exactly one row is non-midnight, pick it. Returns
    only the rows that are uniquely formatted (no finding when the tell is absent
    — which is the cheat-resistant state)."""
    out = []
    mft = _mft_rows(case_dir)
    nz = [r for r in mft if r["Created0x10"][17:19] != "00" or r["Created0x30"][17:19] != "00"]
    if len(nz) == 1:
        out.append({"artifact_kind": "timestomp", "target": _ts_target(nz[0]["FileName"])})
    rc = _recmd_rows(case_dir)
    nm = [r for r in rc if r["LastWriteTimestamp"][11:19] != "00:00:00"]
    if len(nm) == 1:
        out.append({"artifact_kind": "persistence", "target": _pers_target(nm[0]["ValueName"])})
    return out


def _cheat_rarest_path_token(case_dir: Path) -> list[dict]:
    """Persistence-only: pick the Run value whose path contains the rarest token
    among {Temp, Public, ProgramData, AppData, Program Files, System32} — a naive
    'unusual location' heuristic."""
    rc = _recmd_rows(case_dir)
    if not rc:
        return []
    tokens = ["\\Temp\\", "\\Public\\", "\\ProgramData\\", "\\AppData\\",
              "Program Files", "System32"]
    counts = {t: sum(1 for r in rc if t in r["ValueData"]) for t in tokens}
    def rarity(r):
        present = [counts[t] for t in tokens if t in r["ValueData"]]
        return min(present) if present else 999
    chosen = min(rc, key=rarity)
    return [{"artifact_kind": "persistence", "target": _pers_target(chosen["ValueName"])}]


# --------------------------------------------------------------------------- #
# Cross-file structural shortcuts a prior cheat-hunt found and that this template
# was reworked to defeat. Each reads the corroborator and exploits a structural
# uniqueness the template now denies. They are pinned here as REGRESSIONS: the gate
# asserts none beats chance+slack.
# --------------------------------------------------------------------------- #


def _cheat_pers_unique_nonvendor_image(case_dir: Path) -> list[dict]:
    """Persistence: read ONLY the corroborator (evtx_registry.csv) and pick every
    row whose Image contains NO recognized vendor word as a plain substring — the
    'unique non-vendor Image' shortcut. Defeated because Sysmon's Image is the
    WRITER PROCESS (a non-vendor installer/shell) for EVERY row, so this fires on
    the whole corroborated set and isolates nothing."""
    return [
        {"artifact_kind": "persistence", "target": r["TargetObject"]}
        for r in _evtx_rows(case_dir)
        if not any(v in r["Image"].lower() for v in _VENDOR_WORDS)
    ]


def _cheat_ts_yara_and_backward_gap(case_dir: Path) -> list[dict]:
    """Timestomp: flag every row that is yara-hit AND has ANY backward $SI<$FN gap
    beyond a 30-day floor (a sub-year-magnitude-blind 'backdate' heuristic). Defeated
    because the whole yara FP set is NEARMISS decoys that carry a benign sub-year
    backward gap, so this fires on answer + all NEARMISS and never isolates the
    answer — only the years-vs-months magnitude (is_timestomped) does."""
    yara = set(_yara_basenames(case_dir))
    out = []
    for r in _mft_rows(case_dir):
        si = _parse_iso(r["Created0x10"])
        fn = _parse_iso(r["Created0x30"])
        if r["FileName"] in yara and (fn - si).days > 30:
            out.append({"artifact_kind": "timestomp", "target": _ts_target(r["FileName"])})
    return out


def _cheat_ts_yara_and_year_substrings_differ(case_dir: Path) -> list[dict]:
    """Timestomp: the dumbest no-parse variant — flag every yara-hit row whose $SI
    and $FN YEAR substrings differ (no datetime parsing at all). Defeated for the
    same reason: NEARMISS decoys cross a year boundary, so this also fires on them."""
    yara = set(_yara_basenames(case_dir))
    out = []
    for r in _mft_rows(case_dir):
        if r["FileName"] in yara and r["Created0x10"][:4] != r["Created0x30"][:4]:
            out.append({"artifact_kind": "timestomp", "target": _ts_target(r["FileName"])})
    return out


def _cheat_combined_two_leg_flood(case_dir: Path) -> list[dict]:
    """The strongest cross-file cheat the hunt combined: the persistence
    non-vendor-Image flood PLUS the timestomp yara&backward-gap flood, in one run.
    It reaches recall 1.0 (it accuses both true findings) but, because both legs now
    flood benign near-miss decoys, its precision — and thus F1 — stays at chance."""
    return _cheat_pers_unique_nonvendor_image(case_dir) + _cheat_ts_yara_and_backward_gap(case_dir)


CHEATER_STRATEGIES = [
    _cheat_echo_label,
    _cheat_only_mismatch,
    _cheat_only_hit,
    _cheat_first_row,
    _cheat_last_row,
    _cheat_oldest_si,
    _cheat_biggest_abs_gap,
    _cheat_old_si_era,
    _cheat_recent_fn,
    _cheat_si_before_fn,
    _cheat_lm_ne_fn,
    _cheat_lm_eq_si,
    _cheat_rarest_si_year,
    _cheat_oddly_formatted_time,
    _cheat_unique_granularity,
    _cheat_rarest_path_token,
    _cheat_pers_unique_nonvendor_image,
    _cheat_ts_yara_and_backward_gap,
    _cheat_ts_yara_and_year_substrings_differ,
    _cheat_combined_two_leg_flood,
]


# --------------------------------------------------------------------------- #
# ORACLE — the intended forensic rule. Reads ONLY the evidence, no answer key.
# --------------------------------------------------------------------------- #


def _oracle(case_dir: Path) -> list[dict]:
    out: list[dict] = []

    # Timestomp leg: the row that is backdated (is_timestomped) AND corroborated
    # by a yara hit on the same file. Both conditions are required: the plant is
    # backdated but NOT yara-hit; the TD3 decoy is yara-hit but NOT backdated.
    yara = set(_yara_basenames(case_dir))
    for r in _mft_rows(case_dir):
        si = _parse_iso(r["Created0x10"])
        fn = _parse_iso(r["Created0x30"])
        if is_timestomped(si, fn) and r["FileName"] in yara:
            out.append({"artifact_kind": "timestomp", "target": _ts_target(r["FileName"])})

    # Persistence leg: a user-writable, non-vendor Run value (is_evil_run_value)
    # AND corroborated by a Sysmon EventID-13 on the same key. Both required: the
    # plant is evil-pathed but has no RegistryEvent; the corroborated vendor decoy
    # is benign under is_evil_run_value.
    evtx_keys = set(_evtx_targetobjects(case_dir))
    for r in _recmd_rows(case_dir):
        tgt = _pers_target(r["ValueName"])
        if is_evil_run_value(r["ValueName"], r["ValueData"]) and tgt in evtx_keys:
            out.append({"artifact_kind": "persistence", "target": tgt})

    return out


# --------------------------------------------------------------------------- #
# Measurement helpers.
# --------------------------------------------------------------------------- #


def _gen(seed: int, tmp_path: Path) -> Path:
    """Generate the PROVOCATEUR case (strongest decoys: planted entries present)."""
    case_dir = tmp_path / f"case-{seed}"
    M.generate(seed=seed, out_dir=case_dir, provocateur=True)
    return case_dir


def _f1(findings: list[dict], case_dir: Path) -> float:
    _man, answer = load_case(case_dir)
    return score(findings, answer).f1


def _num_candidates(case_dir: Path) -> int:
    """Conservative candidate count per leg = answer + decoys (+ plant), taking the
    SMALLER leg. 'chance' = 1/num_candidates; using the smaller leg yields the
    LARGER (more lenient) chance, so the cheater bound we assert is conservative —
    a cheater that beats this would beat the true per-leg chance too. (The two legs
    intentionally differ in size: the timestomp leg carries extra near-miss decoys
    to dilute its intrinsic old-$SI / recent-$FN surface signals.)"""
    _man, answer = load_case(case_dir)
    per_kind: dict[str, int] = {}
    for f in answer.expected_findings + answer.decoys + answer.planted:
        per_kind[f.artifact_kind] = per_kind.get(f.artifact_kind, 0) + 1
    return min(per_kind.values())


def _measure(tmp_path: Path):
    """Return (cheater_best_f1, oracle_f1, num_candidates) averaged over seeds."""
    cheater_means = {fn.__name__: 0.0 for fn in CHEATER_STRATEGIES}
    oracle_sum = 0.0
    ncand = None
    for seed in _SEEDS:
        case_dir = _gen(seed, tmp_path)
        if ncand is None:
            ncand = _num_candidates(case_dir)
        for fn in CHEATER_STRATEGIES:
            cheater_means[fn.__name__] += _f1(fn(case_dir), case_dir)
        oracle_sum += _f1(_oracle(case_dir), case_dir)
    k = len(_SEEDS)
    cheater_best_f1 = max(v / k for v in cheater_means.values())
    oracle_f1 = oracle_sum / k
    return cheater_best_f1, oracle_f1, ncand


# --------------------------------------------------------------------------- #
# Tests.
# --------------------------------------------------------------------------- #


def test_oracle_solves_the_case(tmp_path: Path) -> None:
    """The intended forensic rule scores ~1.0 — proves solvable-by-reasoning AND
    the answer key is correct."""
    cheater_best_f1, oracle_f1, _ = _measure(tmp_path)
    assert oracle_f1 >= 0.9, f"oracle_f1={oracle_f1:.3f} — case not solvable by the intended rule"


def test_cheater_best_at_or_below_chance(tmp_path: Path) -> None:
    """No surface shortcut beats chance (~1/num_candidates per leg)."""
    cheater_best_f1, _oracle_f1, ncand = _measure(tmp_path)
    chance = 1.0 / ncand
    # Allow a small slack above chance for the per-leg averaging granularity.
    assert cheater_best_f1 <= chance + 0.12, (
        f"cheater_best_f1={cheater_best_f1:.3f} exceeds chance "
        f"(1/{ncand}={chance:.3f}) + slack — a surface shortcut leaks the answer"
    )


def test_reasoning_gap_is_large(tmp_path: Path) -> None:
    """The gate: oracle - cheater_best >= 0.6 over K>=8 fresh seeds."""
    cheater_best_f1, oracle_f1, ncand = _measure(tmp_path)
    gap = oracle_f1 - cheater_best_f1
    assert oracle_f1 >= 0.9, f"oracle_f1={oracle_f1:.3f}"
    assert cheater_best_f1 <= 1.0 / ncand + 0.12, f"cheater_best_f1={cheater_best_f1:.3f}"
    assert gap >= 0.6, (
        f"gap={gap:.3f} (oracle={oracle_f1:.3f} cheater_best={cheater_best_f1:.3f}) "
        f"< 0.6 — the case is not reasoning-only"
    )


def test_every_answer_signal_also_fires_on_a_distractor(tmp_path: Path) -> None:
    """Structural invariant behind the gap: for each leg, every surface signal
    that fires on the ANSWER also fires on >=1 decoy/planted entry, so no single
    signal isolates the answer."""
    for seed in _SEEDS:
        case_dir = _gen(seed, tmp_path)
        _man, answer = load_case(case_dir)
        ts_answer = next(f.target for f in answer.expected_findings if f.artifact_kind == "timestomp")
        pers_answer = next(f.target for f in answer.expected_findings if f.artifact_kind == "persistence")
        distractors = {(f.artifact_kind, f.target) for f in answer.decoys + answer.planted}

        # --- timestomp signals ---
        mft = _mft_rows(case_dir)
        si_ne_fn = {_ts_target(r["FileName"]) for r in mft if r["Created0x10"] != r["Created0x30"]}
        backward = {
            _ts_target(r["FileName"]) for r in mft
            if _parse_iso(r["Created0x10"]) < _parse_iso(r["Created0x30"])
        }
        yara_hit = {_ts_target(b) for b in _yara_basenames(case_dir)}
        for sig_name, fired in [("$SI!=$FN", si_ne_fn), ("backward", backward), ("yara_hit", yara_hit)]:
            assert ts_answer in fired, f"seed {seed}: answer missing from {sig_name}"
            others = fired - {ts_answer}
            assert any(("timestomp", t) in distractors for t in others), (
                f"seed {seed}: timestomp signal {sig_name} fires ONLY on the answer"
            )

        # --- persistence signals ---
        rc = _recmd_rows(case_dir)
        userwritable = {_pers_target(r["ValueName"]) for r in rc if M._is_userwritable(r["ValueData"])}
        evtx_hit = set(_evtx_targetobjects(case_dir))
        for sig_name, fired in [("user_writable", userwritable), ("evtx_hit", evtx_hit)]:
            assert pers_answer in fired, f"seed {seed}: answer missing from {sig_name}"
            others = fired - {pers_answer}
            assert any(("persistence", t) in distractors for t in others), (
                f"seed {seed}: persistence signal {sig_name} fires ONLY on the answer"
            )


def test_print_measured_numbers(tmp_path: Path, capsys) -> None:
    """Emit the measured numbers for the report (visible with -s)."""
    cheater_best_f1, oracle_f1, ncand = _measure(tmp_path)
    gap = oracle_f1 - cheater_best_f1
    with capsys.disabled():
        print(
            f"\n[multi_artifact cheat-resist over K={len(_SEEDS)} seeds] "
            f"num_candidates/leg={ncand} chance={1/ncand:.3f} "
            f"cheater_best_f1={cheater_best_f1:.3f} oracle_f1={oracle_f1:.3f} gap={gap:.3f}"
        )
