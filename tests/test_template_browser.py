"""Tests for the browser Forge template — determinism + honesty invariants.

These are STATIC invariants on the generated case (manifest + answer key + mock
outputs). The live court loop needs DeepSeek and is non-deterministic, so it is
NOT exercised here.

The one true evil artifact is a malicious URL. Honesty under JR-01: the URL is a
single contiguous string named by TWO distinct tools — bulk_extractor (url
scanner carves it from disk) and log2timeline.py (web-history timeline visit).
yara is deliberately not used: it hits files, not URLs.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from hexbreaker.forge import template_browser
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
    template_browser.generate(seed=8821, out_dir=a)
    template_browser.generate(seed=8821, out_dir=b)
    assert _dir_hash(a) == _dir_hash(b)


def test_generate_is_deterministic_provocateur(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    template_browser.generate(seed=8821, out_dir=a, provocateur=True)
    template_browser.generate(seed=8821, out_dir=b, provocateur=True)
    assert _dir_hash(a) == _dir_hash(b)


def test_different_seeds_produce_different_cases(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    template_browser.generate(seed=1, out_dir=a)
    template_browser.generate(seed=2, out_dir=b)
    assert _dir_hash(a) != _dir_hash(b)


def test_generated_case_loads_cleanly(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_browser.generate(seed=8821, out_dir=case_dir)
    manifest, answer = load_case(case_dir)
    assert manifest.template == "browser"
    assert len(manifest.pre_pass_steps) == 1
    assert len(manifest.defender_steps) == 1
    assert len(answer.expected_findings) == 1
    assert answer.expected_findings[0].artifact_kind == "browser"
    assert len(answer.decoys) >= 3


def test_expected_decoy_planted_pairwise_disjoint(tmp_path: Path) -> None:
    """expected/decoy/planted (artifact_kind, target) sets must not overlap."""
    case_dir = tmp_path / "case"
    template_browser.generate(seed=8821, out_dir=case_dir, provocateur=True)
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
        template_browser.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _, answer = load_case(case_dir)
        expected = _keyset(answer.expected_findings)
        decoys = _keyset(answer.decoys)
        planted = _keyset(answer.planted)
        assert not (expected & decoys), f"seed {seed}: expected/decoy overlap"
        assert not (expected & planted), f"seed {seed}: expected/planted overlap"
        assert not (decoys & planted), f"seed {seed}: decoy/planted overlap"


def test_expected_target_corroborated_by_two_distinct_tools(tmp_path: Path) -> None:
    """JR-01 honesty: the true URL is named verbatim by >=2 distinct tools.

    The target is a single contiguous URL, so unlike the split-column MFT/RECmd
    cases it appears whole in BOTH tool outputs: bulk_extractor's url feature
    file AND log2timeline's web-history timeline. JR-01 counts distinct cited
    tool KINDS — this is the data that lets the Defender honestly cite primary +
    corroborator for an honest CONFIRMED.
    """
    case_dir = tmp_path / "case"
    manifest = template_browser.generate(seed=8821, out_dir=case_dir)
    _, answer = load_case(case_dir)

    key_to_tool = {s.key: s.tool for s in manifest.pre_pass_steps + manifest.defender_steps}
    tool_stdouts: list[tuple[str, str]] = []
    for key, rel in manifest.mock_outputs.items():
        tool_stdouts.append((key_to_tool[key], (case_dir / rel).read_text()))

    ef = answer.expected_findings[0]
    naming = {tool for tool, text in tool_stdouts if ef.target in text}
    assert naming == {"bulk_extractor", "log2timeline.py"}, (
        f"expected URL {ef.target!r} must be named verbatim by BOTH "
        f"bulk_extractor and log2timeline.py; got {naming}"
    )


def test_corroborator_is_log2timeline_not_yara(tmp_path: Path) -> None:
    """Honesty: corroboration comes from a browser-history parser, not a file
    scanner. yara hits FILES not URLs, so it must not be used for this leg."""
    case_dir = tmp_path / "case"
    manifest = template_browser.generate(seed=8821, out_dir=case_dir)
    used = {s.tool for s in manifest.pre_pass_steps + manifest.defender_steps}
    assert used == {"bulk_extractor", "log2timeline.py"}
    assert "yara" not in used, "yara cannot honestly name a URL target"


def test_primary_carves_the_url(tmp_path: Path) -> None:
    """bulk_extractor (primary) names the true evil URL."""
    case_dir = tmp_path / "case"
    template_browser.generate(seed=8821, out_dir=case_dir)
    _, answer = load_case(case_dir)
    be = _read_mock(case_dir, "bulk_extractor_url.txt")
    assert answer.expected_findings[0].target in be


def test_planted_has_primary_but_no_corroboration(tmp_path: Path) -> None:
    """Planted URL is carved by bulk_extractor (primary) but ABSENT from the
    log2timeline corroborator (no confirmed history visit)."""
    case_dir = tmp_path / "case"
    template_browser.generate(seed=8821, out_dir=case_dir, provocateur=True)
    _, answer = load_case(case_dir)
    assert len(answer.planted) == 1
    plant_url = answer.planted[0].target

    be = _read_mock(case_dir, "bulk_extractor_url.txt")
    l2t = _read_mock(case_dir, "l2t_webhist.csv")
    assert plant_url in be, "planted URL must appear in bulk_extractor primary"
    assert plant_url not in l2t, "planted URL must NOT appear in log2timeline corroborator"


def test_planted_absent_from_corroborator_across_seeds(tmp_path: Path) -> None:
    """Plant invariant must hold for every seed, including any substring edge."""
    for seed in range(25):
        case_dir = tmp_path / f"case-{seed}"
        template_browser.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _, answer = load_case(case_dir)
        plant_url = answer.planted[0].target
        be = _read_mock(case_dir, "bulk_extractor_url.txt")
        l2t = _read_mock(case_dir, "l2t_webhist.csv")
        assert plant_url in be, f"seed {seed}: plant missing from primary"
        assert plant_url not in l2t, f"seed {seed}: plant leaked into corroborator"


def test_decoys_appear_in_both_tools(tmp_path: Path) -> None:
    """Benign decoys are real traffic — present in BOTH tools but not malicious.

    They are the false-positive surface the agent must reject by judgment, not
    by absence-from-a-tool."""
    case_dir = tmp_path / "case"
    template_browser.generate(seed=8821, out_dir=case_dir)
    _, answer = load_case(case_dir)
    be = _read_mock(case_dir, "bulk_extractor_url.txt")
    l2t = _read_mock(case_dir, "l2t_webhist.csv")
    for d in answer.decoys:
        assert d.target in be, f"decoy {d.target!r} missing from bulk_extractor"
        assert d.target in l2t, f"decoy {d.target!r} missing from log2timeline"


def test_be_context_column_is_class_independent(tmp_path: Path) -> None:
    """The bulk_extractor context column must NOT betray the class.

    If evil/decoy/plant rows carry distinguishable context strings, an agent
    could classify all three by string-matching that column alone — never
    consulting log2timeline — which defeats the 2-tool corroboration design and
    is the same kind of confound the row-shuffle rule exists to kill. The carver
    also cannot honestly know whether a URL was 'visited', so the context must be
    a uniform, class-independent carve marker derived only from the URL.
    """
    case_dir = tmp_path / "case"
    template_browser.generate(seed=8821, out_dir=case_dir, provocateur=True)
    be = _read_mock(case_dir, "bulk_extractor_url.txt")
    # Strip the offset (col 0) and URL (col 1); the remaining context (col 2+)
    # must follow ONE template for every row regardless of class.
    contexts = set()
    for row in be.splitlines():
        if row.startswith("#") or not row.strip():
            continue
        offset, url, context = row.split("\t", 2)
        # Normalize away the per-row URL so only the template shape remains.
        contexts.add(context.replace(url, "<URL>"))
    assert len(contexts) == 1, f"context column leaks class: {contexts}"


def test_no_planted_without_provocateur(tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    template_browser.generate(seed=8821, out_dir=case_dir, provocateur=False)
    _, answer = load_case(case_dir)
    assert answer.planted == []


def test_all_tools_supported_and_allowed(tmp_path: Path) -> None:
    """Every tool used is in SUPPORTED_TOOLS and listed in allowed_tools."""
    case_dir = tmp_path / "case"
    manifest = template_browser.generate(seed=8821, out_dir=case_dir)
    used = {s.tool for s in manifest.pre_pass_steps + manifest.defender_steps}
    assert used <= SUPPORTED_TOOLS, f"unsupported tools used: {used - SUPPORTED_TOOLS}"
    assert used <= set(manifest.allowed_tools), "used tools missing from allowed_tools"


def test_evil_url_not_always_at_position_zero(tmp_path: Path) -> None:
    """Regression: evil URL rows must be shuffled, not pinned to index 0.

    If position were a confound, an agent picking row #1 would score F1=1.0
    without forensic reasoning."""
    be_positions = []
    l2t_positions = []
    for seed in range(10):
        case_dir = tmp_path / f"case-{seed}"
        template_browser.generate(seed=seed, out_dir=case_dir)
        _, answer = load_case(case_dir)
        evil = answer.expected_findings[0].target
        be = _read_mock(case_dir, "bulk_extractor_url.txt").splitlines()
        # Skip the leading comment header line.
        be_data = [r for r in be if not r.startswith("#")]
        l2t = _read_mock(case_dir, "l2t_webhist.csv").splitlines()[1:]
        for i, row in enumerate(be_data):
            if evil in row:
                be_positions.append(i)
                break
        for i, row in enumerate(l2t):
            if evil in row:
                l2t_positions.append(i)
                break
    assert len(set(be_positions)) >= 2, f"bulk_extractor evil positions {be_positions} — shuffle broken"
    assert len(set(l2t_positions)) >= 2, f"log2timeline evil positions {l2t_positions} — shuffle broken"
