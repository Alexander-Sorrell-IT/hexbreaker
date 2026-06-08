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

import shutil
from pathlib import Path

import orjson

from ..court.provocateur import Provocation
from ..forge.case import CaseManifest

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
