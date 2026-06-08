"""Tests for the Amcache Forge template — determinism + honesty invariants.

STATIC invariants on the generated case (manifest + answer key + mock outputs).
The live court loop needs DeepSeek and is non-deterministic, so it is NOT
exercised here.

The honest 2-tool corroboration is the cleanest possible: AmcacheParser's
FullPath column IS the contiguous binary path, and yara honestly reports the
path of the file whose content matched. So BOTH tools contain the full target
string verbatim — a direct "two distinct tools each name the target" assertion
(unlike multi_artifact, whose MFTECmd primary splits the path across columns).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from hexbreaker.forge import template_amcache
from hexbreaker.forge.case import load_case
from hexbreaker.tools import SUPPORTED_TOOLS


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


def _read_mock(case_dir: Path, name: str) -> str:
    return (case_dir / "mock_outputs" / name).read_text()


def _keyset(findings) -> set[tuple[str, str]]:
    return {(f.artifact_kind, f.target) for f in findings}


def test_generate_is_deterministic_from_seed(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    template_amcache.generate(seed=8821, out_dir=a)
    template_amcache.generate(seed=8821, out_dir=b)
    assert _dir_hash(a) == _dir_hash(b)


def test_generate_is_deterministic_provocateur(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    template_amcache.generate(seed=8821, out_dir=a, provocateur=True)
    template_amcache.generate(seed=8821, out_dir=b, provocateur=True)
    assert _dir_hash(a) == _dir_hash(b)


def test_different_seeds_produce_different_cases(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    template_amcache.generate(seed=1, out_dir=a)
    template_amcache.generate(seed=2, out_dir=b)
    assert _dir_hash(a) != _dir_hash(b)


def test_generated_case_loads_cleanly(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_amcache.generate(seed=8821, out_dir=case_dir)
    manifest, answer = load_case(case_dir)
    assert manifest.template == "amcache"
    assert len(manifest.pre_pass_steps) == 1
    assert len(manifest.defender_steps) == 1
    assert len(answer.expected_findings) == 1
    assert answer.expected_findings[0].artifact_kind == "amcache"
    assert answer.expected_findings[0].must_have_verdict == "CONFIRMED"
    assert len(answer.decoys) >= 3


def test_expected_decoy_planted_pairwise_disjoint(tmp_path: Path) -> None:
    """expected/decoy/planted (artifact_kind, target) sets must not overlap."""
    case_dir = tmp_path / "case"
    template_amcache.generate(seed=8821, out_dir=case_dir, provocateur=True)
    _, answer = load_case(case_dir)
    expected = _keyset(answer.expected_findings)
    decoys = _keyset(answer.decoys)
    planted = _keyset(answer.planted)
    assert expected & decoys == set(), "expected overlaps decoys"
    assert expected & planted == set(), "expected overlaps planted"
    assert decoys & planted == set(), "decoys overlaps planted"


def test_disjoint_across_many_seeds(tmp_path: Path) -> None:
    """Disjointness must hold for every seed, not just one lucky draw.

    All entries share artifact_kind='amcache', so disjointness rides entirely on
    distinct FullPath strings — the pools must be large enough that evil, decoys
    and plant never collide.
    """
    for seed in range(40):
        case_dir = tmp_path / f"case-{seed}"
        template_amcache.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _, answer = load_case(case_dir)
        expected = _keyset(answer.expected_findings)
        decoys = _keyset(answer.decoys)
        planted = _keyset(answer.planted)
        assert not (expected & decoys), f"seed {seed}: expected/decoy overlap"
        assert not (expected & planted), f"seed {seed}: expected/planted overlap"
        assert not (decoys & planted), f"seed {seed}: decoy/planted overlap"


def test_expected_target_corroborated_by_two_distinct_tools(tmp_path: Path) -> None:
    """JR-01 honesty: the true target is evidenced by >=2 distinct tool kinds.

    AmcacheParser's FullPath IS the contiguous target (primary names the full
    path). yara honestly reports the matched file by its BASENAME — so it
    evidences the SAME target via its distinguishing leaf component, NOT the full
    contiguous path. (Naming the basename keeps the full target string out of the
    sealed registry bundle; see the cheat-resistance invariant + template_timestomp
    precedent.) This is the data that lets the Defender honestly cite primary +
    corroborator for an honest CONFIRMED (JR-01 counts distinct cited tool KINDS).
    """
    case_dir = tmp_path / "case"
    manifest = template_amcache.generate(seed=8821, out_dir=case_dir)
    _, answer = load_case(case_dir)

    key_to_tool = {s.key: s.tool for s in manifest.pre_pass_steps + manifest.defender_steps}
    tool_stdouts = [
        (key_to_tool[key], (case_dir / rel).read_text())
        for key, rel in manifest.mock_outputs.items()
    ]

    ef = answer.expected_findings[0]
    leaf = ef.target.rsplit("\\", 1)[1]
    naming_full = {tool for tool, text in tool_stdouts if ef.target in text}
    naming_leaf = {
        tool for tool, text in tool_stdouts if leaf in text and ef.target not in text
    }
    assert "AmcacheParser" in naming_full, "AmcacheParser must name the target FullPath"
    assert "yara" in naming_leaf, "yara must name the target basename (not the full path)"
    assert len(naming_full | naming_leaf) >= 2, (
        f"expected target {ef.target!r} evidenced by tools {naming_full | naming_leaf} "
        f"(need >=2 distinct tool kinds for an honest CONFIRMED under JR-01)"
    )


def test_primary_records_sha1_for_target(tmp_path: Path) -> None:
    """AmcacheParser primary: the evil row carries the target's SHA1 fingerprint."""
    case_dir = tmp_path / "case"
    template_amcache.generate(seed=8821, out_dir=case_dir)
    _, answer = load_case(case_dir)
    target = answer.expected_findings[0].target
    expected_sha1 = hashlib.sha1(target.encode()).hexdigest()
    amcache = _read_mock(case_dir, "amcache.csv").splitlines()
    for row in amcache[1:]:
        cols = row.split(",")
        if cols[0] == target:
            assert cols[2] == expected_sha1, f"row {row!r} SHA1 mismatch"
            return
    raise AssertionError(f"target {target!r} row not found in AmcacheParser CSV")


def test_decoys_present_in_amcache_but_not_in_yara(tmp_path: Path) -> None:
    """Decoys are recorded as present (Amcache) but are NOT yara hits.

    The decoy/evil distinction is honest: both appear in the presence artifact;
    only the evil one matches a malware signature.
    """
    case_dir = tmp_path / "case"
    template_amcache.generate(seed=8821, out_dir=case_dir)
    _, answer = load_case(case_dir)
    amcache = _read_mock(case_dir, "amcache.csv")
    yara = _read_mock(case_dir, "yara.txt")
    for d in answer.decoys:
        assert d.target in amcache, f"decoy {d.target!r} missing from Amcache primary"
        assert d.target not in yara, f"decoy {d.target!r} must NOT be a yara hit"


def test_planted_has_primary_but_no_corroboration(tmp_path: Path) -> None:
    """The plant carries the suspicious-path primary signal but NO yara hit.

    Decoy vs plant differ ONLY in path-suspiciousness; evil vs plant differ ONLY
    in the corroborating yara hit. The plant is the bait the agent must REJECT.
    """
    case_dir = tmp_path / "case"
    template_amcache.generate(seed=8821, out_dir=case_dir, provocateur=True)
    _, answer = load_case(case_dir)
    assert len(answer.planted) == 1

    amcache = _read_mock(case_dir, "amcache.csv")
    yara = _read_mock(case_dir, "yara.txt")
    plant = answer.planted[0].target
    assert plant in amcache, "planted entry must appear in AmcacheParser primary"
    assert plant not in yara, "planted entry must NOT be in yara corroborator"


def test_no_planted_without_provocateur(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_amcache.generate(seed=8821, out_dir=case_dir, provocateur=False)
    _, answer = load_case(case_dir)
    assert answer.planted == []


def test_yara_hits_only_the_true_target(tmp_path: Path) -> None:
    """yara names exactly the true target (by basename) and nothing else."""
    case_dir = tmp_path / "case"
    template_amcache.generate(seed=8821, out_dir=case_dir, provocateur=True)
    _, answer = load_case(case_dir)
    yara = _read_mock(case_dir, "yara.txt")
    # yara names the matched file by basename (cheat-resistance: the full target
    # path must not appear contiguously in the issued bundle).
    target = answer.expected_findings[0].target
    assert target.rsplit("\\", 1)[1] in yara
    assert target not in yara, "full path must NOT leak into yara"
    for d in answer.decoys:
        assert d.target.rsplit("\\", 1)[1] not in yara
    for p in answer.planted:
        assert p.target.rsplit("\\", 1)[1] not in yara


def test_all_tools_supported_and_allowed(tmp_path: Path) -> None:
    """Every tool used is in SUPPORTED_TOOLS and listed in allowed_tools."""
    case_dir = tmp_path / "case"
    manifest = template_amcache.generate(seed=8821, out_dir=case_dir)
    used = {s.tool for s in manifest.pre_pass_steps + manifest.defender_steps}
    assert used == {"AmcacheParser", "yara"}
    assert used <= SUPPORTED_TOOLS, f"unsupported tools used: {used - SUPPORTED_TOOLS}"
    assert used <= set(manifest.allowed_tools), "used tools missing from allowed_tools"


def test_evil_row_not_always_at_position_zero(tmp_path: Path) -> None:
    """Regression: the evil row must be shuffled, not pinned to index 0.

    If position were a confound, an agent picking row #1 would score F1=1.0
    without forensic reasoning.
    """
    positions = []
    for seed in range(10):
        case_dir = tmp_path / f"case-{seed}"
        template_amcache.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _, answer = load_case(case_dir)
        target = answer.expected_findings[0].target
        rows = _read_mock(case_dir, "amcache.csv").splitlines()[1:]
        for i, row in enumerate(rows):
            if row.split(",")[0] == target:
                positions.append(i)
                break
    assert len(set(positions)) >= 2, f"evil positions {positions} — shuffle broken"
