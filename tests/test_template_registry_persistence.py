"""Tests for the registry_persistence Forge template — determinism + correctness.

Static invariants on the generated case (manifest + answer key + mock outputs).
The cheat-resistance gate (cheater suite + oracle + the numeric gap) lives in
test_cheatresist_registry_persistence.py; here we pin determinism and the
near-miss decoy shape those baselines rely on.
"""

from __future__ import annotations

import csv
import hashlib
import io
from pathlib import Path

from hexbreaker.forge import template_registry_persistence as RP
from hexbreaker.forge.case import load_case

RUN_KEY = RP.RUN_KEY_PATH


def _dir_hash(d: Path) -> str:
    """sha256 across all file bytes in d, sorted by path."""
    h = hashlib.sha256()
    for p in sorted(d.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(d).as_posix().encode())
            h.update(b"\x00")
            h.update(p.read_bytes())
            h.update(b"\x00")
    return h.hexdigest()


def _recmd(case_dir: Path) -> list[dict[str, str]]:
    txt = (case_dir / "mock_outputs" / "recmd_run.csv").read_text()
    return list(csv.DictReader(io.StringIO(txt)))


def _sysmon(case_dir: Path) -> list[dict[str, str]]:
    txt = (case_dir / "mock_outputs" / "sysmon_registry.csv").read_text()
    return list(csv.DictReader(io.StringIO(txt)))


def test_generate_is_deterministic_from_seed(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    RP.generate(seed=4729, out_dir=a)
    RP.generate(seed=4729, out_dir=b)
    assert _dir_hash(a) == _dir_hash(b)


def test_provocateur_is_deterministic_from_seed(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    RP.generate(seed=4729, out_dir=a, provocateur=True)
    RP.generate(seed=4729, out_dir=b, provocateur=True)
    assert _dir_hash(a) == _dir_hash(b)


def test_different_seeds_produce_different_cases(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    RP.generate(seed=1, out_dir=a)
    RP.generate(seed=2, out_dir=b)
    assert _dir_hash(a) != _dir_hash(b)


def test_generated_case_loads_cleanly(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    RP.generate(seed=4729, out_dir=case_dir, provocateur=True)
    manifest, answer = load_case(case_dir)
    assert manifest.template == "registry_persistence"
    assert len(manifest.pre_pass_steps) >= 1
    assert len(manifest.defender_steps) >= 1
    assert len(answer.expected_findings) == 1
    assert len(answer.decoys) >= 1
    assert len(answer.planted) >= 1


def test_evil_and_decoys_appear_in_recmd(tmp_path: Path) -> None:
    """Every candidate (evil + decoys + plants) must be present in the primary so
    the agent could plausibly flag any of them."""
    case_dir = tmp_path / "case"
    RP.generate(seed=4729, out_dir=case_dir, provocateur=True)
    _m, answer = load_case(case_dir)
    names = {r["ValueName"] for r in _recmd(case_dir)}
    for ef in answer.expected_findings + answer.decoys + answer.planted:
        assert ef.target.split("\\")[-1] in names, f"{ef.target} missing from RECmd dump"


def test_user_writable_does_not_isolate_the_answer(tmp_path: Path) -> None:
    """Near-miss invariant: >=2 LEGIT decoys are also user-writable, so a regex on
    'user-writable path' collides with benign entries instead of isolating evil."""
    for seed in (4729, 101, 8821, 31337):
        case_dir = tmp_path / f"uw_{seed}"
        RP.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _m, answer = load_case(case_dir)
        decoy_names = {d.target.split("\\")[-1] for d in answer.decoys}
        uw_decoys = [
            r for r in _recmd(case_dir)
            if r["ValueName"] in decoy_names and RP.is_user_writable(r["ValueData"])
        ]
        assert len(uw_decoys) >= 2, (
            f"seed={seed}: only {len(uw_decoys)} user-writable decoys — "
            f"'pick user-writable' would isolate the answer"
        )


def test_user_writable_decoys_are_canonical(tmp_path: Path) -> None:
    """The discriminator must hold: every user-writable DECOY sits in a canonical
    vendor path (so the path rule selects none of them), and the EVIL entry does
    not (so the rule selects it)."""
    for seed in (4729, 101, 8821, 31337):
        case_dir = tmp_path / f"can_{seed}"
        RP.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _m, answer = load_case(case_dir)
        decoy_names = {d.target.split("\\")[-1] for d in answer.decoys}
        for r in _recmd(case_dir):
            if r["ValueName"] in decoy_names and RP.is_user_writable(r["ValueData"]):
                assert RP.is_canonical_vendor_path(r["ValueData"]), (
                    f"seed={seed}: user-writable decoy {r['ValueName']} not canonical"
                )
        evil_name = answer.expected_findings[0].target.split("\\")[-1]
        evil_row = next(r for r in _recmd(case_dir) if r["ValueName"] == evil_name)
        assert RP.is_malicious_run_entry(evil_row["ValueData"]), (
            f"seed={seed}: evil entry not flagged by the path rule"
        )


def test_name_modifier_does_not_isolate_the_answer(tmp_path: Path) -> None:
    """Near-miss invariant on the NAME channel: a modifier-name regex (/update|
    helper|task/) must fire on >=2 Sysmon-corroborated DECOYS, not just the evil
    entry. Otherwise 'pick the corroborated entry with an updater-style name'
    isolates the answer via a surface regex."""
    import re
    pat = re.compile(r"(?i)(update|updater|helper|health|task)")
    for seed in (4729, 101, 8821, 31337):
        case_dir = tmp_path / f"nm_{seed}"
        RP.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _m, answer = load_case(case_dir)
        target = answer.expected_findings[0].target
        decoy_targets = {d.target for d in answer.decoys}
        syskeys = {r["TargetObject"] for r in _sysmon(case_dir)}
        corroborated_modifier_decoys = {
            f"{RUN_KEY}\\{r['ValueName']}"
            for r in _recmd(case_dir)
            if pat.search(r["ValueName"])
            and f"{RUN_KEY}\\{r['ValueName']}" in syskeys
            and f"{RUN_KEY}\\{r['ValueName']}" in decoy_targets
        }
        assert pat.search(target.split("\\")[-1]), f"seed={seed}: evil name has no modifier"
        assert len(corroborated_modifier_decoys) >= 2, (
            f"seed={seed}: only {len(corroborated_modifier_decoys)} corroborated "
            f"modifier-named decoys — name regex would isolate the answer"
        )


def test_timestamps_do_not_isolate_the_answer(tmp_path: Path) -> None:
    """Recency must not be a tell: across seeds the evil entry is NOT always the
    newest (timestamps are iid from a shared window)."""
    evil_is_newest = 0
    n = 0
    for seed in range(40):
        case_dir = tmp_path / f"ts_{seed}"
        RP.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _m, answer = load_case(case_dir)
        evil_name = answer.expected_findings[0].target.split("\\")[-1]
        rows = _recmd(case_dir)
        newest = max(rows, key=lambda r: r["LastWriteTimestamp"])
        if newest["ValueName"] == evil_name:
            evil_is_newest += 1
        n += 1
    # If recency leaked, evil would be newest ~every seed. With iid timestamps
    # over ~9 candidates it should be roughly 1/9 — well under half.
    assert evil_is_newest < n / 2, (
        f"evil was newest in {evil_is_newest}/{n} seeds — recency leaks the answer"
    )


def test_sysmon_is_not_a_one_to_one_giveaway(tmp_path: Path) -> None:
    """The Sysmon corroborator names the evil key AND >=1 benign decoy key, so
    echoing 'the Sysmon hit' does not extract the answer."""
    for seed in (4729, 101, 8821, 31337):
        case_dir = tmp_path / f"sys_{seed}"
        RP.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _m, answer = load_case(case_dir)
        target = answer.expected_findings[0].target
        decoy_targets = {x.target for x in answer.decoys}
        syskeys = {r["TargetObject"] for r in _sysmon(case_dir)}
        assert target in syskeys
        benign = syskeys - {target}
        assert benign and benign <= decoy_targets, (
            f"seed={seed}: Sysmon does not name a benign decoy alongside evil"
        )


def test_plants_have_no_sysmon_corroboration(tmp_path: Path) -> None:
    """Provocateur plants look persistence-like by the path rule but carry NO
    Sysmon event — the second signal the defender requires."""
    for seed in (4729, 101, 8821, 31337):
        case_dir = tmp_path / f"pl_{seed}"
        RP.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _m, answer = load_case(case_dir)
        syskeys = {r["TargetObject"] for r in _sysmon(case_dir)}
        for p in answer.planted:
            assert p.target not in syskeys, f"seed={seed}: plant {p.target} has Sysmon"


def test_evil_row_not_always_first(tmp_path: Path) -> None:
    """Regression: the evil row must not sit at a fixed RECmd position."""
    positions = []
    for seed in range(10):
        case_dir = tmp_path / f"pos_{seed}"
        RP.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _m, answer = load_case(case_dir)
        evil_name = answer.expected_findings[0].target.split("\\")[-1]
        for i, r in enumerate(_recmd(case_dir)):
            if r["ValueName"] == evil_name:
                positions.append(i)
                break
    assert len(set(positions)) >= 2, f"evil row positions across seeds: {positions}"
