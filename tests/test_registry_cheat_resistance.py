"""Phase-1 cheat-resistance + provocation-parity for the Registry seed-strip.

The benchmark is worthless if a submitter can derive the answer key from the
issued bundle. Two leaks to seal (PLAN_REGISTRY.md):
  1. answer_key.json  — never copied into the bundle.
  2. manifest.seed    — the Forge is MIT, so a leaked seed lets a submitter run
                        `generate --seed N` locally and reconstruct the answer.

These tests pin the cheat-resistance invariant and prove the registry-mode run
(consuming the shipped provocation.json) is identical on the wire to the seeded
run — i.e. stripping the seed did not weaken the Provocateur (Layer 6).

NO live API: the Court is driven with the same deterministic FakeClient used by
test_court_runner_multi.py.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from hexbreaker import llm
from hexbreaker.court.provocateur import Provocation, emit_provocation
from hexbreaker.forge import template_timestomp as TS
from hexbreaker.forge.case import CaseManifest, load_case
from hexbreaker.registry.bundle import write_sealed_bundle
from hexbreaker.runner.court_runner import run_court_on_case
from hexbreaker.transcript import Kind, read

# Every template `registry issue` can emit (mirrors cli.TEMPLATES). The Phase-1
# cheat test MUST cover all of them — exercising only timestomp masked the leak
# the adversarial verifier found in the other five.
from hexbreaker.cli import TEMPLATES

_SEED = 4729

_TOOL_RE = re.compile(r"(S-\d+) \| TOOL \| tool_call \| meta=(\{[^}]*\})")


# --- FakeClient: same deterministic stand-in as test_court_runner_multi.py. ---


def _resp(content: str, *, model: str, reasoning: str | None = None) -> llm.LLMResponse:
    return llm.LLMResponse(
        model=model,
        content=content,
        reasoning_content=reasoning,
        usage=llm.Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
        latency_s=0.0,
        raw={},
    )


def _tool_steps(user: str):
    out = []
    for m in _TOOL_RE.finditer(user):
        meta = json.loads(m.group(2))
        out.append((m.group(1), meta["tool"], meta["stdout_hash"]))
    return out


class FakeClient:
    """Prosecutor accuses `target` citing the pre-pass tool; Defender CONFIRMs
    citing two distinct tool kinds (so JR-01 leaves CONFIRMED intact)."""

    def __init__(self, target: str):
        self.target = target

    def call(self, messages, *, model, temperature=0.2, json_mode=False) -> llm.LLMResponse:
        user = messages[-1]["content"]
        steps = _tool_steps(user)
        if model == llm.DEEPSEEK_CHAT:
            sid, _tool, h = steps[0]
            claim = {
                "text": f"accuse {self.target} of timestomp",
                "artifact_kind": "timestomp",
                "target": self.target,
                "cited_steps": [{"step_id": sid, "stdout_hash": h}],
            }
            return _resp(json.dumps(claim), model=model)
        by_tool: dict[str, tuple[str, str]] = {}
        for sid, tool, h in steps:
            by_tool.setdefault(tool, (sid, h))
        chosen = list(by_tool.values())[:2]
        verdict = {
            "verdict": "CONFIRMED",
            "cited_steps": [{"step_id": sid, "stdout_hash": h} for sid, h in chosen],
            "challenge_text": "fake verdict for test",
        }
        return _resp(json.dumps(verdict), model=model, reasoning="fake reasoning")


# --- helpers ---


def _seal(tmp_path: Path) -> tuple[Path, Path, Provocation]:
    """Generate a full case and seal it. Returns (full_case, sealed_bundle, prov)."""
    full = tmp_path / "full_case"
    TS.generate(seed=_SEED, out_dir=full)
    prov = emit_provocation(seed=_SEED)
    sealed = write_sealed_bundle(full, tmp_path / "bundle" / "case_0", prov)
    return full, sealed, prov


def _provocation_record(transcript_path: Path) -> dict:
    recs = [r for r in read(transcript_path) if r.kind == Kind.PROVOCATION]
    assert len(recs) == 1, f"expected exactly one PROVOCATION record, got {len(recs)}"
    return recs[0].content


# === Cheat-resistance invariant ===


def test_sealed_bundle_has_no_answer_key(tmp_path: Path) -> None:
    _full, sealed, _prov = _seal(tmp_path)
    assert not (sealed / "answer_key.json").exists()


def test_sealed_manifest_seed_is_null(tmp_path: Path) -> None:
    _full, sealed, _prov = _seal(tmp_path)
    raw = json.loads((sealed / "manifest.json").read_bytes())
    assert raw["seed"] is None
    # And it still loads as a valid manifest with seed=None.
    m = CaseManifest.model_validate_json((sealed / "manifest.json").read_bytes())
    assert m.seed is None


def test_sealed_bundle_ships_provocation(tmp_path: Path) -> None:
    _full, sealed, prov = _seal(tmp_path)
    assert (sealed / "provocation.json").exists()
    shipped = Provocation.model_validate_json((sealed / "provocation.json").read_bytes())
    assert shipped == prov


def test_sealed_bundle_carries_mock_outputs(tmp_path: Path) -> None:
    full, sealed, _prov = _seal(tmp_path)
    for p in (full / "mock_outputs").iterdir():
        assert (sealed / "mock_outputs" / p.name).read_bytes() == p.read_bytes()


def test_no_seed_anywhere_in_issued_files(tmp_path: Path) -> None:
    """The literal seed must not appear in any byte the submitter receives."""
    _full, sealed, _prov = _seal(tmp_path)
    needle = str(_SEED).encode()
    for p in sorted(sealed.rglob("*")):
        if p.is_file():
            assert needle not in p.read_bytes(), f"seed {_SEED} leaked into {p.name}"


def test_no_expected_target_substring_in_any_issued_file(tmp_path: Path) -> None:
    """The cheat-resistance invariant (b): no expected_findings target substring
    appears anywhere in the issued bundle.

    For timestomp the target is `ParentPath + "\\" + FileName`, and those live in
    SEPARATE MFT columns, so the joined path never appears contiguously — there
    is no copy-the-string shortcut to the answer. (This does NOT hold for the
    prefetch/amcache templates, whose answer target IS a literal CSV field; the
    cheat test is therefore pinned to timestomp, matching the FakeClient suite.)
    """
    full, sealed, _prov = _seal(tmp_path)
    _, answer = load_case(full)
    target = answer.expected_findings[0].target
    # Check BOTH the raw form (e.g. mft.csv, free text) AND the JSON-escaped form
    # (orjson doubles backslashes in string values, so the manifest's description/
    # case_id would carry `\\Windows\\...`). Checking only the raw form silently
    # fails to guard any JSON string field — the bug this strengthening fixes.
    needles = {target.encode(), target.encode().replace(b"\\", b"\\\\")}
    for p in sorted(sealed.rglob("*")):
        if p.is_file():
            body = p.read_bytes()
            for needle in needles:
                assert needle not in body, (
                    f"expected target {target!r} leaked into {p.name} (as {needle!r})"
                )


def test_generate_is_impossible_without_the_seed(tmp_path: Path) -> None:
    """Sanity: the sealed manifest carries no int seed to feed back to generate."""
    _full, sealed, _prov = _seal(tmp_path)
    m = CaseManifest.model_validate_json((sealed / "manifest.json").read_bytes())
    assert m.seed is None  # nothing to pass to template_*.generate(seed=...)


# === Cheat-resistance across EVERY issued template (static bundle inspection) ===
#
# The literal invariant "no expected_findings target substring appears anywhere
# in the issued files" is only satisfiable when the primary artifact splits the
# target across columns (timestomp: FileName + ParentPath). For a single-column
# primary (prefetch/amcache FullPath; browser URL) the target MUST appear
# contiguously in the evidence — the agent cannot investigate a path it never
# sees. So the achievable, verifier-aligned invariant is two-part:
#
#   (M) MANIFEST = zero target leakage. The full target string must not appear
#       anywhere in manifest.json — not in defender_steps[].args, not in the
#       mock_outputs keys, not in case_id/description. Metadata is not evidence;
#       a non-LLM script reading `manifest.json` must extract no answer.
#
#   (E) EVIDENCE = target never UNIQUELY extractable. In every evidence file
#       where the full target appears contiguously, at least one same-kind decoy
#       (or planted) target also appears. No single file is a 1:1 giveaway, so
#       selecting the true target still requires cross-referencing >=2 sources
#       plus the suspicious-path/maliciousness heuristic — i.e. forensic
#       reasoning, not copy-the-string.
#
# This is exactly the posture template_browser already had (target among 4 decoy
# URLs in both tools). The Phase-1 repair makes prefetch/amcache/registry_
# persistence/multi_artifact match it: yara names the matched file by BASENAME
# (not the full path), yara scans a target-independent dir (so manifest args /
# mock_outputs keys carry no answer), and single-row corroborators gain a benign
# decoy row. timestomp is the blessed precedent (column-split primary).

_SEEDS = [101, 4729, 8821, 31337]


def _seal_template(template: str, seed: int, tmp_path: Path) -> tuple[Path, Path]:
    """Generate a provocateur case for `template` at `seed` and seal it.

    Returns (full_case_dir_with_answer_key, sealed_bundle_dir). Uses
    provocateur=True so planted entries are present too (the strongest decoys).
    """
    full = tmp_path / f"full_{template}_{seed}"
    TEMPLATES[template](seed, full, provocateur=True)
    prov = emit_provocation(seed=seed)
    sealed = write_sealed_bundle(full, tmp_path / f"bundle_{template}_{seed}", prov)
    return full, sealed


def _escaped_forms(s: str) -> set[bytes]:
    """Raw bytes + the JSON-string-escaped bytes (orjson doubles backslashes)."""
    b = s.encode()
    return {b, b.replace(b"\\", b"\\\\")}


@pytest.mark.parametrize("template", sorted(TEMPLATES))
@pytest.mark.parametrize("seed", _SEEDS)
def test_manifest_leaks_no_target(template: str, seed: int, tmp_path: Path) -> None:
    """(M) No expected-findings target string appears anywhere in manifest.json.

    Catches the worst defect the verifier found: the yara invocation embedding
    evil_path in defender_steps[].args (and thus in the mock_outputs key), which
    let a script read the answer straight out of the sealed manifest.
    """
    full, sealed = _seal_template(template, seed, tmp_path)
    _, answer = load_case(full)
    manifest_bytes = (sealed / "manifest.json").read_bytes()
    for ef in answer.expected_findings:
        for needle in _escaped_forms(ef.target):
            assert needle not in manifest_bytes, (
                f"[{template} seed={seed}] target {ef.target!r} leaked into the "
                f"sealed manifest.json (as {needle!r}) — a non-LLM script reading "
                f"manifest.json would extract the answer"
            )


@pytest.mark.parametrize("template", sorted(TEMPLATES))
@pytest.mark.parametrize("seed", _SEEDS)
def test_evidence_target_never_uniquely_extractable(
    template: str, seed: int, tmp_path: Path
) -> None:
    """(E) In every evidence file carrying the target contiguously, a same-kind
    decoy/planted target also appears — so no single file is a 1:1 giveaway.

    A trivial 'echo the only path named in the corroborator' script must NOT
    score F1=1.0: the true target is never the lone occupant of any evidence file.
    """
    full, sealed = _seal_template(template, seed, tmp_path)
    _, answer = load_case(full)
    evidence_files = sorted((sealed / "mock_outputs").glob("*"))
    assert evidence_files, f"[{template}] sealed bundle has no mock_outputs"

    for ef in answer.expected_findings:
        same_kind_distractors = [
            d.target
            for d in (answer.decoys + answer.planted)
            if d.artifact_kind == ef.artifact_kind
        ]
        assert same_kind_distractors, (
            f"[{template} seed={seed}] no same-kind distractor for {ef.target!r}"
        )
        for f in evidence_files:
            body = f.read_text(errors="replace")
            if ef.target in body:
                # This file names the true target contiguously — it MUST also
                # carry at least one same-kind distractor, or it is a 1:1 leak.
                co_occurring = [d for d in same_kind_distractors if d in body]
                assert co_occurring, (
                    f"[{template} seed={seed}] evidence file {f.name} names the "
                    f"true target {ef.target!r} with NO same-kind decoy present — "
                    f"a 1:1 giveaway a non-LLM script could echo for F1=1.0"
                )


@pytest.mark.parametrize("template", sorted(TEMPLATES))
@pytest.mark.parametrize("seed", _SEEDS)
def test_sealed_bundle_seal_holds_for_every_template(
    template: str, seed: int, tmp_path: Path
) -> None:
    """The structural seal (no answer key, seed=None) holds for every template."""
    _full, sealed = _seal_template(template, seed, tmp_path)
    assert not (sealed / "answer_key.json").exists()
    assert (sealed / "provocation.json").exists()
    m = CaseManifest.model_validate_json((sealed / "manifest.json").read_bytes())
    assert m.seed is None


# === Provocation-injection parity (registry-mode == seeded run) ===


def test_registry_mode_provocation_matches_seeded_run(tmp_path: Path) -> None:
    """Drive the Court twice on the SAME case content:

      A. seeded run  — default path: emit_provocation(seed=manifest.seed).
      B. registry run — load the SHIPPED provocation.json off disk and pass it in
                        (exactly what registry-mode does).

    The PROVOCATION record written to each transcript must be byte-equal. This
    proves the runner consumed the shipped provocation and wrote it to the hash
    chain identically — stripping the seed did not weaken Layer 6.
    """
    target = r"\Windows\System32\drivers\evil.sys"

    # A. Seeded run on a full case (manifest carries the real seed).
    seeded_case = tmp_path / "seeded"
    TS.generate(seed=_SEED, out_dir=seeded_case)
    run_court_on_case(seeded_case, client=FakeClient(target), max_rounds=1)
    seeded_prov = _provocation_record(seeded_case / "transcript.jsonl")

    # B. Registry run: seal the same case, then run the Court loading the shipped
    # provocation.json from disk and passing it in via the new param.
    sealed = write_sealed_bundle(seeded_case, tmp_path / "bundle", emit_provocation(_SEED))
    shipped = Provocation.model_validate_json((sealed / "provocation.json").read_bytes())
    run_court_on_case(sealed, client=FakeClient(target), provocation=shipped, max_rounds=1)
    registry_prov = _provocation_record(sealed / "transcript.jsonl")

    assert registry_prov == seeded_prov


def test_provocation_json_fallback_used_when_no_param(tmp_path: Path) -> None:
    """A sealed bundle with seed=None and provocation.json (and no `provocation=`
    param) still fires the Provocateur — the runner picks up provocation.json."""
    target = r"\Windows\System32\drivers\evil.sys"
    seeded_case = tmp_path / "seeded"
    TS.generate(seed=_SEED, out_dir=seeded_case)
    sealed = write_sealed_bundle(seeded_case, tmp_path / "bundle", emit_provocation(_SEED))

    # No `provocation=` here — the runner must read provocation.json off disk.
    run_court_on_case(sealed, client=FakeClient(target), max_rounds=1)
    record = _provocation_record(sealed / "transcript.jsonl")
    assert record == emit_provocation(_SEED).model_dump()


def test_seedless_bundle_without_provocation_refuses(tmp_path: Path) -> None:
    """Falling through to emit_provocation(seed=None) would emit a bogus payload
    off the string 'None'. The runner must refuse instead."""
    seeded_case = tmp_path / "seeded"
    TS.generate(seed=_SEED, out_dir=seeded_case)
    sealed = write_sealed_bundle(seeded_case, tmp_path / "bundle", emit_provocation(_SEED))
    # Remove the shipped provocation to simulate a malformed bundle.
    (sealed / "provocation.json").unlink()

    with pytest.raises(RuntimeError, match="no provocation"):
        run_court_on_case(sealed, client=FakeClient("x"), max_rounds=1)
