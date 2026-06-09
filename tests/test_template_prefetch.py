"""Tests for the Prefetch Forge template — determinism + honesty invariants.

STATIC invariants on the generated case (manifest + answer key + mock outputs).
The live court loop needs DeepSeek and is non-deterministic, so it is NOT
exercised here.

Honest 2-tool corroboration: PECmd's resolved FullPath IS the contiguous binary
path (execution primary), and yara honestly reports the path of the file whose
content matched (corroborator). BOTH stdouts contain the full target verbatim.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from hexbreaker.forge import template_prefetch
from hexbreaker.forge.case import load_case
from hexbreaker.tools import SUPPORTED_TOOLS


def _dir_hash(d: Path) -> str:
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
    a, b = tmp_path / "a", tmp_path / "b"
    template_prefetch.generate(seed=7731, out_dir=a)
    template_prefetch.generate(seed=7731, out_dir=b)
    assert _dir_hash(a) == _dir_hash(b)


def test_generate_is_deterministic_provocateur(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    template_prefetch.generate(seed=7731, out_dir=a, provocateur=True)
    template_prefetch.generate(seed=7731, out_dir=b, provocateur=True)
    assert _dir_hash(a) == _dir_hash(b)


def test_different_seeds_produce_different_cases(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    template_prefetch.generate(seed=1, out_dir=a)
    template_prefetch.generate(seed=2, out_dir=b)
    assert _dir_hash(a) != _dir_hash(b)


def test_generated_case_loads_cleanly(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_prefetch.generate(seed=7731, out_dir=case_dir)
    manifest, answer = load_case(case_dir)
    assert manifest.template == "prefetch"
    assert len(manifest.pre_pass_steps) == 1
    # Two defender steps: the malware yara scan + the catalog/signature scan (the
    # exculpatory third leg) — both are yara invocations with distinct rulesets.
    assert len(manifest.defender_steps) == 2
    assert len(answer.expected_findings) == 1
    assert answer.expected_findings[0].artifact_kind == "prefetch"
    assert answer.expected_findings[0].must_have_verdict == "CONFIRMED"
    assert len(answer.decoys) >= 3


def test_expected_decoy_planted_pairwise_disjoint(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_prefetch.generate(seed=7731, out_dir=case_dir, provocateur=True)
    _, answer = load_case(case_dir)
    expected, decoys, planted = (
        _keyset(answer.expected_findings), _keyset(answer.decoys), _keyset(answer.planted))
    assert expected & decoys == set()
    assert expected & planted == set()
    assert decoys & planted == set()


def test_disjoint_across_many_seeds(tmp_path: Path) -> None:
    for seed in range(40):
        case_dir = tmp_path / f"case-{seed}"
        template_prefetch.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _, answer = load_case(case_dir)
        expected, decoys, planted = (
            _keyset(answer.expected_findings), _keyset(answer.decoys), _keyset(answer.planted))
        assert not (expected & decoys), f"seed {seed}: expected/decoy overlap"
        assert not (expected & planted), f"seed {seed}: expected/planted overlap"
        assert not (decoys & planted), f"seed {seed}: decoy/planted overlap"


def test_expected_target_corroborated_by_two_distinct_tools(tmp_path: Path) -> None:
    """JR-01 honesty: the true target is evidenced by >=2 distinct tool kinds.

    PECmd's resolved FullPath IS the contiguous binary path (the execution
    primary names the full target). yara honestly reports the matched file by its
    BASENAME — so it evidences the SAME target via its distinguishing leaf
    component, NOT the full contiguous path. (Naming the basename keeps the full
    target string out of the sealed registry bundle; see the cheat-resistance
    invariant + template_timestomp precedent.) Two distinct tools each name the
    target: PECmd the full path, yara the basename.
    """
    case_dir = tmp_path / "case"
    manifest = template_prefetch.generate(seed=7731, out_dir=case_dir)
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
    assert "PECmd" in naming_full, "PECmd must name the target FullPath"
    assert "yara" in naming_leaf, "yara must name the target basename (not the full path)"
    assert len(naming_full | naming_leaf) >= 2


def test_decoys_present_in_prefetch_but_not_in_yara(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_prefetch.generate(seed=7731, out_dir=case_dir)
    _, answer = load_case(case_dir)
    prefetch = _read_mock(case_dir, "prefetch.csv")
    yara = _read_mock(case_dir, "yara.txt")
    for d in answer.decoys:
        assert d.target in prefetch, f"decoy {d.target!r} missing from PECmd primary"
        assert d.target not in yara, f"decoy {d.target!r} must NOT be a yara hit"


def test_planted_has_primary_but_no_corroboration(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_prefetch.generate(seed=7731, out_dir=case_dir, provocateur=True)
    _, answer = load_case(case_dir)
    assert len(answer.planted) == 1
    prefetch = _read_mock(case_dir, "prefetch.csv")
    yara = _read_mock(case_dir, "yara.txt")
    plant = answer.planted[0].target
    assert plant in prefetch, "planted entry must appear in PECmd primary"
    assert plant not in yara, "planted entry must NOT be in yara corroborator"


def test_no_planted_without_provocateur(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_prefetch.generate(seed=7731, out_dir=case_dir, provocateur=False)
    _, answer = load_case(case_dir)
    assert answer.planted == []


def test_yara_hits_the_target_and_one_benign_decoy(tmp_path: Path) -> None:
    """yara is NOT a 1:1 label for the answer (the self-labeling leak is killed).

    Reasoning-only posture: yara names the true target's basename AND exactly one
    benign decoy's basename (a correctly-located binary flagged by a PUA/packer/
    test rule). So "the file yara hit" no longer isolates the answer — the agent
    must reason about WHICH hit is a malware-family rule on a masquerading binary.
    The full target path still never leaks contiguously; the plant is never named.
    """
    case_dir = tmp_path / "case"
    template_prefetch.generate(seed=7731, out_dir=case_dir, provocateur=True)
    _, answer = load_case(case_dir)
    yara = _read_mock(case_dir, "yara.txt")
    evil_leaf = answer.expected_findings[0].target.rsplit("\\", 1)[1]
    named_leaves = {line.split(":", 1)[0] for line in yara.splitlines() if line}
    assert evil_leaf in named_leaves
    assert answer.expected_findings[0].target not in yara, "full path must NOT leak into yara"
    # >=2 distinct basenames named => yara is not a 1:1 giveaway.
    assert len(named_leaves) >= 2, f"yara names <2 files — self-labeling leak: {named_leaves}"
    # A benign decoy (PUA/packer-flagged, correctly-located) is ALSO named.
    benign_named = [
        d for d in answer.decoys
        if d.target.rsplit("\\", 1)[1] in named_leaves and "benign" in d.note.lower()
    ]
    assert benign_named, "no benign decoy is named by yara — self-labeling leak remains"
    # The plant (if any) is never corroborated by yara.
    for p in answer.planted:
        assert p.target.rsplit("\\", 1)[1] not in named_leaves


def test_all_tools_supported_and_allowed(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    manifest = template_prefetch.generate(seed=7731, out_dir=case_dir)
    used = {s.tool for s in manifest.pre_pass_steps + manifest.defender_steps}
    assert used == {"PECmd", "yara"}
    assert used <= SUPPORTED_TOOLS, f"unsupported tools used: {used - SUPPORTED_TOOLS}"
    assert used <= set(manifest.allowed_tools)


def test_evil_row_not_always_at_position_zero(tmp_path: Path) -> None:
    """The evil row's FullPath (column 1) must be shuffled, not pinned to index 0."""
    positions = []
    for seed in range(10):
        case_dir = tmp_path / f"case-{seed}"
        template_prefetch.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _, answer = load_case(case_dir)
        target = answer.expected_findings[0].target
        rows = _read_mock(case_dir, "prefetch.csv").splitlines()[1:]
        for i, row in enumerate(rows):
            if row.split(",")[1] == target:  # FullPath is column index 1
                positions.append(i)
                break
    assert len(set(positions)) >= 2, f"evil positions {positions} — shuffle broken"
