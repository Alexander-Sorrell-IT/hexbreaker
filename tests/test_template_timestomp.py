"""Tests for the timestomp Forge template — determinism + correctness."""

from __future__ import annotations

import hashlib
from pathlib import Path

from hexbreaker.forge import template_timestomp
from hexbreaker.forge.case import load_case


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


def test_generate_is_deterministic_from_seed(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    template_timestomp.generate(seed=4729, out_dir=a)
    template_timestomp.generate(seed=4729, out_dir=b)
    assert _dir_hash(a) == _dir_hash(b)


def test_different_seeds_produce_different_cases(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    template_timestomp.generate(seed=1, out_dir=a)
    template_timestomp.generate(seed=2, out_dir=b)
    assert _dir_hash(a) != _dir_hash(b)


def test_generated_case_loads_cleanly(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_timestomp.generate(seed=4729, out_dir=case_dir)
    manifest, answer = load_case(case_dir)
    assert manifest.template == "timestomp"
    assert len(manifest.pre_pass_steps) >= 1
    assert len(manifest.defender_steps) >= 1
    assert len(answer.expected_findings) == 1
    assert len(answer.decoys) >= 1


def _path_parts(target: str) -> tuple[str, str]:
    """Split \\dir\\name target into (parent, name) so we can match MFT columns."""
    idx = target.rfind("\\")
    return target[:idx], target[idx + 1:]


def test_evil_target_appears_in_mock_mft(tmp_path: Path) -> None:
    """The expected target's name and parent path must literally appear in the MFT."""
    case_dir = tmp_path / "case"
    template_timestomp.generate(seed=4729, out_dir=case_dir)
    _, answer = load_case(case_dir)
    parent, name = _path_parts(answer.expected_findings[0].target)
    mft = (case_dir / "mock_outputs" / "mft.csv").read_text()
    assert name in mft, f"expected name {name!r} missing from MFT"
    assert parent in mft, f"expected parent {parent!r} missing from MFT"


def test_decoys_appear_in_mock_mft(tmp_path: Path) -> None:
    """Decoys must be in the MFT so the agent could plausibly flag them."""
    case_dir = tmp_path / "case"
    template_timestomp.generate(seed=4729, out_dir=case_dir)
    _, answer = load_case(case_dir)
    mft = (case_dir / "mock_outputs" / "mft.csv").read_text()
    for decoy in answer.decoys:
        _parent, name = _path_parts(decoy.target)
        assert name in mft, f"decoy name {name!r} missing from MFT"


def test_evil_row_not_always_at_position_zero(tmp_path: Path) -> None:
    """Regression: the evil row must not be at MFT index 0 every time.

    Without `rng.shuffle(rows)` in the template, the evil row was always rows[0]
    and any agent that picks the first MFT data row scored F1=1.0 without doing
    forensic reasoning. This test confirms the shuffle is actually scrambling
    position across seeds — if all 10 seeds put evil at row 0, the shuffle is
    broken and the F1 measurement is a position artifact.
    """
    positions = []
    for seed in range(10):
        case_dir = tmp_path / f"case-{seed}"
        template_timestomp.generate(seed=seed, out_dir=case_dir)
        _, answer = load_case(case_dir)
        _parent, evil_name = _path_parts(answer.expected_findings[0].target)
        mft = (case_dir / "mock_outputs" / "mft.csv").read_text().splitlines()
        for i, row in enumerate(mft[1:]):  # skip header
            if row.split(",")[1] == evil_name:
                positions.append(i)
                break
    # Across 10 seeds, at LEAST 2 distinct positions for the evil row.
    assert len(set(positions)) >= 2, f"evil row positions across seeds: {positions} — shuffle is broken or has insufficient variance"


def test_evil_row_has_divergent_si_fn_timestamps(tmp_path: Path) -> None:
    """The signature of timestomp — the row for the evil file must have $SI ≠ $FN."""
    case_dir = tmp_path / "case"
    template_timestomp.generate(seed=4729, out_dir=case_dir)
    _, answer = load_case(case_dir)
    _parent, name = _path_parts(answer.expected_findings[0].target)
    mft = (case_dir / "mock_outputs" / "mft.csv").read_text().splitlines()
    for row in mft[1:]:
        if row.split(",")[1] == name:
            cols = row.split(",")
            si, fn = cols[3], cols[4]
            assert si != fn, f"evil row {row!r} has matching $SI/$FN; timestomp must diverge"
            return
    raise AssertionError(f"target name {name!r} row not found in MFT")
