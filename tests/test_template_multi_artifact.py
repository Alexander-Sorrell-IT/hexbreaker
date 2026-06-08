"""Tests for the multi-artifact Forge template — determinism + honesty invariants.

These are STATIC invariants on the generated case (manifest + answer key + mock
outputs). The live multi-round court loop needs DeepSeek and is non-deterministic,
so it is NOT exercised here; the C2 lift is realized by running this case with
max_rounds>=2 in the court runner, which is out of scope for the template.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from hexbreaker.forge import template_multi_artifact
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
    template_multi_artifact.generate(seed=4729, out_dir=a)
    template_multi_artifact.generate(seed=4729, out_dir=b)
    assert _dir_hash(a) == _dir_hash(b)


def test_generate_is_deterministic_provocateur(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    template_multi_artifact.generate(seed=4729, out_dir=a, provocateur=True)
    template_multi_artifact.generate(seed=4729, out_dir=b, provocateur=True)
    assert _dir_hash(a) == _dir_hash(b)


def test_different_seeds_produce_different_cases(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    template_multi_artifact.generate(seed=1, out_dir=a)
    template_multi_artifact.generate(seed=2, out_dir=b)
    assert _dir_hash(a) != _dir_hash(b)


def test_generated_case_loads_cleanly(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_multi_artifact.generate(seed=4729, out_dir=case_dir)
    manifest, answer = load_case(case_dir)
    assert manifest.template == "multi_artifact"
    # Two primaries pre-pass so round-2 Prosecutor has a second artifact.
    assert len(manifest.pre_pass_steps) == 2
    # Two corroborators in defender steps (satisfies R2 forced tool-call).
    assert len(manifest.defender_steps) == 2
    assert len(answer.expected_findings) == 2
    assert len(answer.decoys) >= 2


def test_expected_findings_are_two_distinct_kinds(tmp_path: Path) -> None:
    """The point of the case: two DIFFERENT (artifact_kind, target) findings."""
    case_dir = tmp_path / "case"
    template_multi_artifact.generate(seed=4729, out_dir=case_dir)
    _, answer = load_case(case_dir)
    kinds = {f.artifact_kind for f in answer.expected_findings}
    assert kinds == {"timestomp", "persistence"}
    keys = _keyset(answer.expected_findings)
    assert len(keys) == 2, "expected findings must be distinct (kind, target) tuples"


def test_expected_decoy_planted_pairwise_disjoint(tmp_path: Path) -> None:
    """expected/decoy/planted (artifact_kind, target) sets must not overlap."""
    case_dir = tmp_path / "case"
    template_multi_artifact.generate(seed=4729, out_dir=case_dir, provocateur=True)
    _, answer = load_case(case_dir)
    expected = _keyset(answer.expected_findings)
    decoys = _keyset(answer.decoys)
    planted = _keyset(answer.planted)
    assert expected & decoys == set(), "expected overlaps decoys"
    assert expected & planted == set(), "expected overlaps planted"
    assert decoys & planted == set(), "decoys overlaps planted"


def test_disjoint_across_many_seeds(tmp_path: Path) -> None:
    """Disjointness must hold for every seed, not just one lucky draw."""
    for seed in range(25):
        case_dir = tmp_path / f"case-{seed}"
        template_multi_artifact.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _, answer = load_case(case_dir)
        expected = _keyset(answer.expected_findings)
        decoys = _keyset(answer.decoys)
        planted = _keyset(answer.planted)
        assert not (expected & decoys), f"seed {seed}: expected/decoy overlap"
        assert not (expected & planted), f"seed {seed}: expected/planted overlap"
        assert not (decoys & planted), f"seed {seed}: decoy/planted overlap"


def test_each_expected_target_corroborated_by_two_distinct_tools(tmp_path: Path) -> None:
    """JR-01 honesty: each true target is evidenced by >=2 distinct tools.

    Real MFTECmd/RECmd split a path across columns (FileName+ParentPath;
    KeyPath+ValueName), so the *contiguous* target string only appears in the
    corroborator (yara file path; EvtxECmd RegistryEvent TargetObject). The
    primary genuinely evidences the SAME target via its distinguishing component
    (basename / Run value name). So two distinct tools each name the target:
      - corroborator: full contiguous target string present, AND
      - primary: the target's distinguishing leaf component present.
    JR-01 counts distinct cited tool KINDS — this is the data that lets the
    Defender honestly cite primary + corroborator for an honest CONFIRMED.
    """
    case_dir = tmp_path / "case"
    manifest = template_multi_artifact.generate(seed=4729, out_dir=case_dir)
    _, answer = load_case(case_dir)

    # Map each mock-output key back to its tool name and contents.
    key_to_tool = {s.key: s.tool for s in manifest.pre_pass_steps + manifest.defender_steps}
    tool_stdouts: list[tuple[str, str]] = []
    for key, rel in manifest.mock_outputs.items():
        tool_stdouts.append((key_to_tool[key], (case_dir / rel).read_text()))

    for ef in answer.expected_findings:
        leaf = ef.target.rsplit("\\", 1)[1]
        # Corroborator(s)/primary(ies): tools whose stdout contains the FULL
        # contiguous target vs. only its distinguishing leaf component.
        #
        # timestomp leg: BOTH tools name the target by leaf (MFT splits
        #   FileName/ParentPath; yara names the basename — cheat-resistance keeps
        #   the full driver path out of the bundle). No tool is contiguous.
        # persistence leg: EvtxECmd's RegistryEvent TargetObject IS the full
        #   contiguous Run key (corroborator); RECmd splits it (primary, leaf).
        contiguous = {tool for tool, text in tool_stdouts if ef.target in text}
        leaf_only = {
            tool for tool, text in tool_stdouts if leaf in text and ef.target not in text
        }
        distinct = contiguous | leaf_only
        assert len(distinct) >= 2, (
            f"expected target {ef.target!r} evidenced by tools {distinct} "
            f"(need >=2 distinct tool kinds for an honest CONFIRMED under JR-01)"
        )


def test_timestomp_corroborator_is_yara_persistence_is_evtx(tmp_path: Path) -> None:
    """Honesty: yara names a file path (timestomp), EvtxECmd names a registry key.

    yara cannot honestly emit a registry path; EvtxECmd's Sysmon RegistryEvent
    TargetObject genuinely is the full HKLM key. Pin the per-leg corroborator.
    """
    case_dir = tmp_path / "case"
    template_multi_artifact.generate(seed=4729, out_dir=case_dir)
    _, answer = load_case(case_dir)
    ts_target = next(f.target for f in answer.expected_findings if f.artifact_kind == "timestomp")
    pers_target = next(f.target for f in answer.expected_findings if f.artifact_kind == "persistence")

    yara = _read_mock(case_dir, "yara.txt")
    evtx = _read_mock(case_dir, "evtx_registry.csv")

    # yara names the timestomp file by basename (cheat-resistance: the full driver
    # path must not appear contiguously in the issued bundle).
    assert ts_target.rsplit("\\", 1)[1] in yara, "yara must name the timestomp file basename"
    assert ts_target not in yara, "full timestomp path must NOT leak contiguously into yara"
    assert pers_target in evtx, "EvtxECmd must name the persistence registry key"
    # Honesty: yara (file scanner) must NOT contain the registry key path.
    assert pers_target not in yara, "yara must not fabricate a registry key path"


def test_primaries_name_their_targets(tmp_path: Path) -> None:
    """Primary signals: MFT names the driver, RECmd names the Run value."""
    case_dir = tmp_path / "case"
    template_multi_artifact.generate(seed=4729, out_dir=case_dir)
    _, answer = load_case(case_dir)
    ts = next(f for f in answer.expected_findings if f.artifact_kind == "timestomp")
    pers = next(f for f in answer.expected_findings if f.artifact_kind == "persistence")

    mft = _read_mock(case_dir, "mft.csv")
    recmd = _read_mock(case_dir, "recmd_run.csv")
    # MFT splits the path across FileName + ParentPath columns.
    driver_name = ts.target.rsplit("\\", 1)[1]
    assert driver_name in mft and "\\Windows\\System32\\drivers" in mft
    # RECmd splits the target across KeyPath + ValueName columns.
    run_value = pers.target.rsplit("\\", 1)[1]
    assert run_value in recmd


def test_planted_has_primary_but_no_corroboration(tmp_path: Path) -> None:
    """Planted entries appear in their primary output but in NEITHER corroborator."""
    case_dir = tmp_path / "case"
    template_multi_artifact.generate(seed=4729, out_dir=case_dir, provocateur=True)
    _, answer = load_case(case_dir)
    assert len(answer.planted) == 2

    mft = _read_mock(case_dir, "mft.csv")
    recmd = _read_mock(case_dir, "recmd_run.csv")
    yara = _read_mock(case_dir, "yara.txt")
    evtx = _read_mock(case_dir, "evtx_registry.csv")

    for p in answer.planted:
        name = p.target.rsplit("\\", 1)[1]
        if p.artifact_kind == "timestomp":
            assert name in mft, "planted timestomp must appear in MFT primary"
            assert name not in yara, "planted timestomp must NOT be in yara corroborator"
        else:
            assert name in recmd, "planted persistence must appear in RECmd primary"
            assert p.target not in evtx, "planted persistence must NOT be in EvtxECmd corroborator"


def test_no_planted_without_provocateur(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_multi_artifact.generate(seed=4729, out_dir=case_dir, provocateur=False)
    _, answer = load_case(case_dir)
    assert answer.planted == []


def test_all_tools_supported_and_allowed(tmp_path: Path) -> None:
    """Every tool used is in SUPPORTED_TOOLS and listed in allowed_tools."""
    case_dir = tmp_path / "case"
    manifest = template_multi_artifact.generate(seed=4729, out_dir=case_dir)
    used = {s.tool for s in manifest.pre_pass_steps + manifest.defender_steps}
    assert used <= SUPPORTED_TOOLS, f"unsupported tools used: {used - SUPPORTED_TOOLS}"
    assert used <= set(manifest.allowed_tools), "used tools missing from allowed_tools"


def test_evil_driver_row_has_divergent_si_fn(tmp_path: Path) -> None:
    """Timestomp signature: the evil driver row must have $SI != $FN."""
    case_dir = tmp_path / "case"
    template_multi_artifact.generate(seed=4729, out_dir=case_dir)
    _, answer = load_case(case_dir)
    name = next(
        f.target for f in answer.expected_findings if f.artifact_kind == "timestomp"
    ).rsplit("\\", 1)[1]
    mft = _read_mock(case_dir, "mft.csv").splitlines()
    for row in mft[1:]:
        cols = row.split(",")
        if cols[1] == name:
            assert cols[3] != cols[4], f"evil driver row {row!r} has matching $SI/$FN"
            return
    raise AssertionError(f"driver {name!r} row not found in MFT")


def test_evil_rows_not_always_at_position_zero(tmp_path: Path) -> None:
    """Regression: evil rows must be shuffled, not pinned to index 0.

    If position were a confound, an agent picking row #1 would score F1=1.0
    without forensic reasoning and the C2 lift would be meaningless.
    """
    mft_positions = []
    recmd_positions = []
    for seed in range(10):
        case_dir = Path("/tmp") / f"hexbreaker-multi-{seed}"
        template_multi_artifact.generate(seed=seed, out_dir=case_dir)
        _, answer = load_case(case_dir)
        ts_name = next(
            f.target for f in answer.expected_findings if f.artifact_kind == "timestomp"
        ).rsplit("\\", 1)[1]
        pers_value = next(
            f.target for f in answer.expected_findings if f.artifact_kind == "persistence"
        ).rsplit("\\", 1)[1]
        mft = _read_mock(case_dir, "mft.csv").splitlines()[1:]
        recmd = _read_mock(case_dir, "recmd_run.csv").splitlines()[1:]
        for i, row in enumerate(mft):
            if row.split(",")[1] == ts_name:
                mft_positions.append(i)
                break
        for i, row in enumerate(recmd):
            if row.split(",")[1] == pers_value:
                recmd_positions.append(i)
                break
    assert len(set(mft_positions)) >= 2, f"MFT evil positions {mft_positions} — shuffle broken"
    assert len(set(recmd_positions)) >= 2, f"RECmd evil positions {recmd_positions} — shuffle broken"
