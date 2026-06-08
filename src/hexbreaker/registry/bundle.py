"""Sealed-bundle writer — the core of registry cheat-resistance.

A Forge-generated case directory contains three things:

  case_<id>/
    manifest.json     — what the case is (carries the real seed)
    answer_key.json   — ground truth (expected findings + decoys + planted)
    mock_outputs/      — pre-baked tool stdout referenced by the manifest

Handing that directory to a submitter leaks the answer key two ways: the
answer_key.json file directly, AND the manifest.seed (the Forge is MIT, so a
submitter can `generate --seed N` locally and reconstruct expected_findings).

A SEALED bundle is what we actually issue. It strips both leaks while keeping
the case runnable:

  case_<idx>/
    manifest.json     — seed=None (everything else identical)
    provocation.json  — the precomputed attack payload (so the Provocateur fires
                        without the seed; the runner consumes this instead of
                        emit_provocation(seed))
    mock_outputs/      — copied verbatim (the evidence the agent investigates)
    (NO answer_key.json — withheld for scoring)

The Phase-1 cheat-resistance test proves: a sealed bundle contains no seed, no
answer key, and no expected_findings target substring in any issued file.
"""

from __future__ import annotations

import secrets
import shutil
import tempfile
from pathlib import Path

import orjson

from ..court.provocateur import Provocation, emit_provocation
from ..forge.case import CaseManifest
from .store import Store

_JSON_OPTS = orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS


def write_sealed_bundle(
    case_dir: str | Path,
    out_dir: str | Path,
    provocation: Provocation,
) -> Path:
    """Write a sealed bundle of `case_dir` into `out_dir`. Returns `out_dir`.

    Reads the source manifest, rewrites it with seed=None, copies mock_outputs/
    verbatim, writes the precomputed provocation.json, and deliberately does NOT
    copy answer_key.json. `provocation` is the payload to ship (typically
    `emit_provocation(seed)` computed server-side at issue time).
    """
    src = Path(case_dir)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Round-trip through the model so validators still run and we carry exactly the
    # manifest fields the runner needs (mock_outputs paths etc.).
    manifest = CaseManifest.model_validate_json((src / "manifest.json").read_bytes())

    # Seal three answer-bearing fields, all unused by the runner at execution time:
    #   - seed:        the literal leak — `generate --seed N` reconstructs the case.
    #   - case_id:     templates name it `case-<seed:06d>-<template>`, embedding the
    #                  seed in plaintext; re-key it to the seed-free output dir name.
    #   - description: timestomp's template writes "Expected finding: timestomp on
    #                  <target>" — i.e. the answer in prose. Withhold it entirely.
    # The runner builds prompts from the transcript + system prompts, never from
    # manifest.description/case_id/seed, so blanking them is functionally inert.
    sealed = manifest.model_copy(
        update={
            "seed": None,
            "case_id": out.name,
            "description": "issued registry case (description withheld)",
        }
    )
    (out / "manifest.json").write_bytes(orjson.dumps(sealed.model_dump(), option=_JSON_OPTS))

    # Ship the precomputed attack payload so the Provocateur fires without the seed.
    (out / "provocation.json").write_bytes(
        orjson.dumps(provocation.model_dump(), option=_JSON_OPTS)
    )

    # Copy the evidence verbatim. mock_outputs paths in the manifest are validated
    # relative subpaths, so a clean tree copy preserves every referenced file.
    src_mock = src / "mock_outputs"
    if src_mock.exists():
        shutil.copytree(src_mock, out / "mock_outputs")

    # NOTE: answer_key.json is intentionally NOT copied. That is the seal.
    return out


def issue(
    seeds_or_k: int | list[int],
    templates: list[str],
    provocateur_frac: float,
    out_dir: str | Path,
    store: Store,
) -> str:
    """Issue K sealed bundles, recording the withheld keys server-side.

    `seeds_or_k`: an int K → K freshly-drawn unpredictable seeds (the anti-gaming
    property: the submitter cannot pre-compute against a seed they can't predict);
    or an explicit list of seeds (used by tests for reproducibility).

    For each case i: generate the FULL case (seed + answer key) into a system temp
    dir OUTSIDE `out_dir`, precompute `emit_provocation(seed)`, write the SEALED
    bundle to `out_dir/case_<i>/`, and record `(seed, template, answer_key_json,
    provocation_json)` via `store`. The full case never touches `out_dir`, so the
    answer key and real seed can only leak through a seal bug in this function
    (the issue()-level analog of write_sealed_bundle's seal).

    Returns the new submission id.
    """
    # Lazy import: cli.py imports this module to register the subcommand, and
    # TEMPLATES is defined after that import block — a top-level import here would
    # cycle. By call time both modules are fully loaded.
    from ..cli import TEMPLATES

    if isinstance(seeds_or_k, int):
        seeds = [secrets.randbelow(2**31) for _ in range(seeds_or_k)]
    else:
        seeds = list(seeds_or_k)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Deterministic provocateur assignment: the first round(frac*K) cases plant
    # evidence. Round-robin the templates across cases.
    k = len(seeds)
    n_provoked = round(provocateur_frac * k)

    submission_id = store.new_submission()

    for idx, seed in enumerate(seeds):
        template = templates[idx % len(templates)]
        provocateur = idx < n_provoked
        provocation = emit_provocation(seed)

        with tempfile.TemporaryDirectory(prefix="hexbreaker_issue_") as tmp:
            full_case = Path(tmp) / f"case_{idx}"
            TEMPLATES[template](seed, full_case, provocateur=provocateur)
            answer_key_json = (full_case / "answer_key.json").read_bytes().decode()
            write_sealed_bundle(full_case, out / f"case_{idx}", provocation)

        store.add_case(
            submission_id=submission_id,
            idx=idx,
            seed=seed,
            template=template,
            answer_key_json=answer_key_json,
            provocation_json=provocation.model_dump_json(),
        )

    return submission_id
