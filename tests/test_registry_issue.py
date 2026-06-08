"""Phase-2 tests for `bundle.issue()` + the registry store.

The whole architecture is one pairing: the SUBMITTER gets sealed bundles (no
seed, no answer key); the REGISTRY keeps the seeds + answer keys server-side in
the store. These tests pin that split:

  - issuing K cases creates exactly K sealed bundle dirs (no answer_key.json
    anywhere in the issued tree, manifest.seed null);
  - the store holds K rows, each carrying the WITHHELD real seed + answer key;
  - the stored answer key is the genuine one (regenerating the case from the
    stored seed reproduces it byte-for-byte).

NO live API: issue() is pure generate + seal + store.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import orjson

from hexbreaker.forge.case import CaseManifest
from hexbreaker.registry.bundle import issue
from hexbreaker.registry.store import Store

_SEEDS = [101, 4729, 8821, 31337, 55501, 60013, 71117, 90901]
_TEMPLATES = [
    "timestomp",
    "registry_persistence",
    "prefetch",
    "amcache",
    "browser",
    "multi_artifact",
]


def _issue(tmp_path: Path, seeds, provocateur_frac: float = 0.5):
    out = tmp_path / "bundle"
    store = Store(tmp_path / "registry.db")
    sub_id = issue(seeds, _TEMPLATES, provocateur_frac, out, store)
    return sub_id, out, store


# === the seal: K sealed bundles, no answer key, seed null ===


def test_issue_creates_k_sealed_bundle_dirs(tmp_path: Path) -> None:
    _sub, out, _store = _issue(tmp_path, _SEEDS)
    case_dirs = sorted(d for d in out.iterdir() if d.is_dir())
    assert [d.name for d in case_dirs] == [f"case_{i}" for i in range(len(_SEEDS))]


def test_no_answer_key_anywhere_in_issued_tree(tmp_path: Path) -> None:
    """The issue()-level seal: the full case (with its answer key) is generated
    in a temp dir OUTSIDE out_dir, so NO answer_key.json reaches the submitter."""
    _sub, out, _store = _issue(tmp_path, _SEEDS)
    leaked = [p for p in out.rglob("answer_key.json")]
    assert leaked == [], f"answer_key.json leaked into the issued tree: {leaked}"


def test_every_issued_manifest_has_null_seed(tmp_path: Path) -> None:
    _sub, out, _store = _issue(tmp_path, _SEEDS)
    for i in range(len(_SEEDS)):
        raw = json.loads((out / f"case_{i}" / "manifest.json").read_bytes())
        assert raw["seed"] is None
        m = CaseManifest.model_validate_json((out / f"case_{i}" / "manifest.json").read_bytes())
        assert m.seed is None


def test_no_case_seed_appears_in_its_own_bundle(tmp_path: Path) -> None:
    """A case's OWN seed must not appear as a literal anywhere in its bundle —
    that's the leak that lets a submitter `generate --seed N` to reconstruct it.

    We scope this to each case's own seed because these TEST seeds are tiny
    (101, 4729, ...) and collide with ordinary evidence integers (a prefetch
    run-count happened to be 101), which would false-positive a cross-product
    check. In production `issue()` draws seeds from secrets.randbelow(2**31), so
    a real 10-digit seed colliding with an evidence integer is negligible; the
    cross-case strong invariant is left to later-phase hardening.
    """
    _sub, out, _store = _issue(tmp_path, _SEEDS)
    for i, seed in enumerate(_SEEDS):
        needle = str(seed).encode()
        for p in sorted((out / f"case_{i}").rglob("*")):
            if p.is_file():
                assert needle not in p.read_bytes(), (
                    f"case_{i}'s own seed {seed} leaked into {p.relative_to(out)}"
                )


def test_every_bundle_ships_provocation(tmp_path: Path) -> None:
    _sub, out, _store = _issue(tmp_path, _SEEDS)
    for i in range(len(_SEEDS)):
        assert (out / f"case_{i}" / "provocation.json").exists()


# === the withheld half: K store rows carrying the real seeds + answer keys ===


def test_store_has_k_rows_with_withheld_seeds(tmp_path: Path) -> None:
    sub_id, _out, store = _issue(tmp_path, _SEEDS)
    rows = store.get_cases(sub_id)
    assert len(rows) == len(_SEEDS)
    assert [r.seed for r in rows] == _SEEDS  # the real seeds, withheld from the bundle
    for r in rows:
        # Each row carries a non-empty answer key + provocation (the withheld keys).
        assert r.answer_key_json
        assert r.provocation_json


def test_seed_lives_in_db_not_in_bundle(tmp_path: Path) -> None:
    """The defining pairing: the real seed is in the DB; it is NOT in the bundle.

    Reads the raw DB to prove the seed is persisted server-side, then confirms it
    does not appear anywhere in the issued tree for that same case.
    """
    sub_id, out, store = _issue(tmp_path, _SEEDS)
    rows = store.get_cases(sub_id)
    for r in rows:
        # In the DB.
        assert isinstance(r.seed, int) and r.seed == _SEEDS[r.idx]
        # Not in the bundle.
        needle = str(r.seed).encode()
        for p in (out / f"case_{r.idx}").rglob("*"):
            if p.is_file():
                assert needle not in p.read_bytes()


def test_stored_answer_key_is_the_real_withheld_key(tmp_path: Path) -> None:
    """Regenerating each case from its STORED seed reproduces the STORED answer
    key byte-for-byte — proving the row holds the genuine withheld key, not an
    empty string or a placeholder.

    provocateur_frac=0 fixes the planted-evidence flag to False for every case,
    so the regenerated answer key is unambiguous (planted entries would differ).
    """
    sub_id, _out, store = _issue(tmp_path, _SEEDS, provocateur_frac=0.0)
    rows = store.get_cases(sub_id)
    from hexbreaker.cli import TEMPLATES

    for r in rows:
        with tempfile.TemporaryDirectory() as tmp:
            regen = Path(tmp) / "regen"
            TEMPLATES[r.template](r.seed, regen, provocateur=False)
            regen_key = (regen / "answer_key.json").read_bytes()
        # The store decoded to str on write; compare canonically.
        stored = orjson.dumps(
            orjson.loads(r.answer_key_json), option=orjson.OPT_SORT_KEYS
        )
        assert stored == orjson.dumps(orjson.loads(regen_key), option=orjson.OPT_SORT_KEYS)


def test_returned_id_matches_store(tmp_path: Path) -> None:
    sub_id, _out, store = _issue(tmp_path, _SEEDS)
    assert store.get_cases(sub_id)  # the submission id resolves to its cases


# === provocateur_frac plumbs through to planted evidence ===


def test_provocateur_frac_controls_planted_cases(tmp_path: Path) -> None:
    """provocateur_frac=1.0 → every case plants evidence (non-empty `planted`);
    0.0 → none. Proves the flag reaches the generator deterministically."""
    sub_all, _out_a, store_all = _issue(tmp_path / "all", _SEEDS, provocateur_frac=1.0)
    sub_none, _out_n, store_none = _issue(tmp_path / "none", _SEEDS, provocateur_frac=0.0)

    for r in store_all.get_cases(sub_all):
        key = orjson.loads(r.answer_key_json)
        assert key["planted"], f"{r.template} seed={r.seed} should have planted entries"
    for r in store_none.get_cases(sub_none):
        key = orjson.loads(r.answer_key_json)
        assert key["planted"] == [], f"{r.template} seed={r.seed} should have no planted entries"
