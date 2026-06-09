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


def test_decoys_present_in_amcache_and_four_are_benign_yara_hits(tmp_path: Path) -> None:
    """All decoys appear in the presence artifact (Amcache). FOUR decoys are
    themselves yara hits — benign packer false-positives in TRUSTED paths — so that
    reading yara.txt does NOT isolate the true answer (the yara signal has four
    benign carriers; precision of 'dump all yara hits' is 1/5). The other four
    decoys are not yara hits (suspicious-path benign carriers).

    The decoy/evil distinction is therefore NOT "only the evil one matches a
    signature": it is the CONJUNCTION (suspicious path AND yara hit). yara alone
    is no longer a 1:1 label for the answer.
    """
    from hexbreaker.forge.template_amcache import _is_suspicious_path

    case_dir = tmp_path / "case"
    template_amcache.generate(seed=8821, out_dir=case_dir)
    _, answer = load_case(case_dir)
    amcache = _read_mock(case_dir, "amcache.csv")
    yara = _read_mock(case_dir, "yara.txt")
    decoy_yara_hits = []
    for d in answer.decoys:
        assert d.target in amcache, f"decoy {d.target!r} missing from Amcache primary"
        if d.target.rsplit("\\", 1)[1] in yara:
            decoy_yara_hits.append(d.target)
    assert len(decoy_yara_hits) == 4, (
        f"four decoys must be benign yara hits (the yara signal's benign carriers); "
        f"got {decoy_yara_hits}"
    )
    # Every benign yara-hit decoy must sit in a TRUSTED (non-suspicious) path — it
    # is the near-miss that breaks the yara==evil shortcut without being evil.
    for hit in decoy_yara_hits:
        assert not _is_suspicious_path(hit), (
            f"the benign yara-hit decoy {hit!r} must be in a trusted path (else it "
            f"would satisfy the malicious conjunction)"
        )


def test_planted_has_primary_but_no_corroboration(tmp_path: Path) -> None:
    """The plant carries the suspicious-path primary signal but NO yara hit.

    The plant has the suspicious path (one leg of the conjunction) but lacks the
    yara corroborator (the other leg), so it must NOT be confirmed on path alone.
    It is the bait the agent must REJECT.
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


def test_yara_names_target_basename_and_four_benign_decoys_never_full_path(
    tmp_path: Path,
) -> None:
    """yara names the true target's BASENAME — but NOT only it.

    To kill the self-labeling leak, yara also names exactly FOUR benign decoys'
    basenames (the trusted-path packer false-positives). So:
      - the true target basename is present (corroborator leg), but
      - the FULL target path never leaks (cheat-resistance: not contiguous), and
      - exactly four decoy basenames are also yara hits, and
      - the plant is NEVER a yara hit.
    Reading yara.txt therefore yields FIVE basenames, four of which are benign — it
    is not a 1:1 label for the answer (precision 1/5).
    """
    case_dir = tmp_path / "case"
    template_amcache.generate(seed=8821, out_dir=case_dir, provocateur=True)
    _, answer = load_case(case_dir)
    yara = _read_mock(case_dir, "yara.txt")
    # yara names the matched file by basename (cheat-resistance: the full target
    # path must not appear contiguously in the issued bundle).
    target = answer.expected_findings[0].target
    assert target.rsplit("\\", 1)[1] in yara
    assert target not in yara, "full path must NOT leak into yara"
    decoy_yara_hits = [d for d in answer.decoys if d.target.rsplit("\\", 1)[1] in yara]
    assert len(decoy_yara_hits) == 4, (
        f"exactly four decoy basenames must be yara hits (the benign carriers); "
        f"got {[d.target for d in decoy_yara_hits]}"
    )
    for d in decoy_yara_hits:
        assert d.target not in yara, "decoy full path must NOT leak"
    for p in answer.planted:
        assert p.target.rsplit("\\", 1)[1] not in yara, "plant must NOT be a yara hit"


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


def _bn(path: str) -> str:
    return path.rsplit("\\", 1)[1]


def test_evil_basenames_disjoint_from_benign() -> None:
    """The three pools must be BASENAME-disjoint, not just FullPath-disjoint.

    yara names files by basename and the answer key matches on FullPath, so an
    evil basename equal to a benign decoy's basename would make the answer key
    ambiguous (and break the yara basename->target mapping). The pairwise-disjoint
    test guards FullPath; this guards the leaf names the evil pool now masquerades
    with (svchost.exe etc. share TOKENS with benign names but must not COLLIDE).
    """
    evil = {_bn(p) for p in template_amcache.EVIL_BINARIES}
    susp = {_bn(p) for p in template_amcache.SUSPICIOUS_PATH_BENIGN}
    trusted = {_bn(p) for p in template_amcache.TRUSTED_PATH_YARA}
    assert len(evil) == len(template_amcache.EVIL_BINARIES), "duplicate evil basenames"
    assert len(susp) == len(template_amcache.SUSPICIOUS_PATH_BENIGN), "dup susp basenames"
    assert len(trusted) == len(template_amcache.TRUSTED_PATH_YARA), "dup trusted basenames"
    assert evil & susp == set(), f"evil/susp basename collision: {evil & susp}"
    assert evil & trusted == set(), f"evil/trusted basename collision: {evil & trusted}"
    assert susp & trusted == set(), f"susp/trusted basename collision: {susp & trusted}"


def test_evil_yara_rule_shared_with_a_benign_decoy(tmp_path: Path) -> None:
    """Anti-leak: the evil binary's exact yara rule string must also land on >=1
    benign yara-hit decoy on EVERY seed.

    This kills two surface shortcuts at once: the rule string is no longer a
    1:1 malware label (rule-content scoring finds no argmax), and the evil row is
    never the one with a UNIQUE rule (rule-uniqueness scoring can't isolate it).
    All rules are drawn from a single generic-heuristic pool, so there is no
    malware-family lexicon to exploit either.
    """
    for seed in range(40):
        case_dir = tmp_path / f"case-{seed}"
        template_amcache.generate(seed=seed, out_dir=case_dir, provocateur=True)
        _, answer = load_case(case_dir)
        evil_leaf = _bn(answer.expected_findings[0].target)
        rule_by_leaf = {}
        for ln in _read_mock(case_dir, "yara.txt").splitlines():
            if ":" in ln:
                leaf, rule = ln.split(":", 1)
                rule_by_leaf[leaf.strip()] = rule.strip()
        evil_rule = rule_by_leaf[evil_leaf]
        # No rule string carries a malware-family term (generic heuristics only).
        for rule in rule_by_leaf.values():
            assert not any(
                kw in rule.lower()
                for kw in ("trojan", "backdoor", "malware", "cobalt", "beacon",
                           "shell", "inject", "apt", "loader")
            ), f"seed {seed}: rule {rule!r} leaks a malware-family lexicon term"
        # The evil rule is shared (not unique): >=2 basenames carry it.
        sharers = [leaf for leaf, rule in rule_by_leaf.items() if rule == evil_rule]
        assert len(sharers) >= 2, (
            f"seed {seed}: evil rule {evil_rule!r} carried only by {sharers} — "
            f"it must also hit a benign decoy so it is neither unique nor a label"
        )
