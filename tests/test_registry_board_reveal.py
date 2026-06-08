"""Phase-4 tests: scorecard render (3 columns), board, reveal, and replay.

Two properties the plan's Gate pins (PLAN_REGISTRY.md P4):

  - the board renders the registry's THREE published columns (Capability,
    Integrity, Verifiability) for every scored submission;
  - a revealed seed re-run through the open-source Forge reproduces the
    originally-issued case BYTE-IDENTICALLY (sha256 match) — the "replay by math,
    not trust" property.

The sealed manifest is deliberately NOT reproducible (issue() blanks seed,
case_id, description), so the replay anchor is the two artifacts that ARE both
present in the issued case AND produced by `generate`:
  (a) mock_outputs/* — copied verbatim into the bundle;
  (b) answer_key.json — withheld in the store, regenerated from the revealed seed.
Replaying both ties the revealed seed to the issued evidence and the withheld key.

NO live API: issue/score/render are pure; the scorecards here are built from a
crafted CaseScore, not from a Court run.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import orjson

from hexbreaker.cli import TEMPLATES
from hexbreaker.registry.bundle import issue
from hexbreaker.registry.scorecard import CaseScore, Scorecard, board_html
from hexbreaker.registry.store import Store
from hexbreaker.scorer.exact_match import ScoreReport

_SEEDS = [101, 4729, 8821, 31337]
_TEMPLATES = ["timestomp", "registry_persistence", "prefetch", "amcache"]


def _file_sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _crafted_card(submission_id: str = "sub-demo") -> Scorecard:
    """A 2-case scorecard with non-trivial values in all three columns."""
    report_a = ScoreReport(
        case_id="case-a", template="timestomp",
        tp=1, fp=1, fn=0, fp_planted=1,
        precision=0.5, recall=1.0, f1=0.6667, results=[],
    )
    report_b = ScoreReport(
        case_id="case-b", template="amcache",
        tp=1, fp=0, fn=1, fp_planted=0,
        precision=1.0, recall=0.5, f1=0.6667, results=[],
    )
    cases = [
        CaseScore(
            idx=0, case_id="case-a", template="timestomp",
            findings_submitted=3, findings_dropped=1, findings_scored=2,
            planted_offered=2, chain_ok=True, hmac_checked=False, hmac_ok=False,
            report=report_a,
        ),
        CaseScore(
            idx=1, case_id="case-b", template="amcache",
            findings_submitted=1, findings_dropped=0, findings_scored=1,
            planted_offered=0, chain_ok=False, hmac_checked=False, hmac_ok=False,
            report=report_b,
        ),
    ]
    return Scorecard.aggregate(submission_id, cases)


# === scorecard render: the three columns are present ===


def test_aggregate_computes_bait_rate_denominator() -> None:
    card = _crafted_card()
    # 1 bait taken out of 2 offered across the cases.
    assert card.fp_planted == 1
    assert card.planted_offered == 2
    assert card.bait_rate == 0.5
    # 1 of 2 chains verified.
    assert card.chain_pass == 1
    assert card.chain_pass_rate == 0.5
    # 3 of 4 submitted findings survived validation.
    assert card.findings_scored == 3
    assert card.findings_submitted == 4
    assert card.verifiability_rate == 0.75


def test_markdown_renders_all_three_columns() -> None:
    md = _crafted_card().to_markdown()
    assert "Capability" in md
    assert "Integrity" in md
    assert "Verifiability" in md
    assert "sub-demo" in md


def test_board_html_renders_three_column_table() -> None:
    card = _crafted_card("sub-xyz")
    out = board_html([(card, False)])
    # Self-contained document with the three published axes as headers.
    assert out.startswith("<!doctype html>")
    assert "Capability" in out
    assert "Integrity" in out
    assert "Verifiability" in out
    # The submission's actual values surface in the row.
    assert "sub-xyz" in out
    assert "1/2" in out  # bait taken / offered
    assert "3/4" in out  # findings surviving / submitted


def test_to_html_renders_self_contained_document() -> None:
    out = _crafted_card("sub-one").to_html()
    assert out.startswith("<!doctype html>")
    assert "Capability" in out and "Integrity" in out and "Verifiability" in out
    assert "sub-one" in out


def test_board_html_marks_revealed_submissions() -> None:
    card = _crafted_card("sub-rev")
    assert "(revealed)" in board_html([(card, True)])
    assert "(revealed)" not in board_html([(card, False)])


def test_board_html_empty_when_no_submissions() -> None:
    out = board_html([])
    assert "no scored submissions yet" in out


# === store: results round-trip + reveal flag ===


def test_store_save_and_list_results(tmp_path: Path) -> None:
    store = Store(tmp_path / "registry.db")
    sub_id = store.new_submission()
    card = _crafted_card(sub_id)
    store.save_result(sub_id, card.model_dump_json())

    results = store.list_results()
    assert len(results) == 1
    assert results[0].submission_id == sub_id
    assert results[0].revealed == 0
    # Round-trips back to an equal Scorecard.
    restored = Scorecard.model_validate_json(results[0].scorecard_json)
    assert restored.bait_rate == card.bait_rate

    store.set_revealed(sub_id)
    assert store.get_result(sub_id).revealed == 1
    store.close()


def test_save_result_is_idempotent_and_preserves_reveal(tmp_path: Path) -> None:
    """Re-scoring (save_result again) must not silently un-reveal a submission."""
    store = Store(tmp_path / "registry.db")
    sub_id = store.new_submission()
    store.save_result(sub_id, _crafted_card(sub_id).model_dump_json())
    store.set_revealed(sub_id)
    # Score again — same id, new scorecard json.
    store.save_result(sub_id, _crafted_card(sub_id).model_dump_json())
    assert store.get_result(sub_id).revealed == 1  # reveal flag survives
    store.close()


# === replay: a revealed seed reproduces the issued case byte-identically ===


def test_revealed_seed_replays_byte_identical_case(tmp_path: Path) -> None:
    """Reveal -> regenerate -> sha256 match against BOTH the issued evidence and
    the withheld answer key. This is the registry's trust-free verifiability:
    anyone holding the revealed seed reconstructs the exact case by math.

    provocateur_frac=0.0 fixes every case to provocateur=False, so regenerating
    from (seed, template) alone is unambiguous (the provocateur flag is not a
    stored column, matching test_stored_answer_key_is_the_real_withheld_key)."""
    out = tmp_path / "bundle"
    store = Store(tmp_path / "registry.db")
    sub_id = issue(_SEEDS, _TEMPLATES, provocateur_frac=0.0, out_dir=out, store=store)

    # Reveal the seeds (the store already holds them; this is the published half).
    store.save_result(sub_id, "{}")  # a result row must exist before reveal in the CLI flow
    store.set_revealed(sub_id)
    rows = store.get_cases(sub_id)
    store.close()

    assert rows, "issue() must have recorded the withheld cases"
    for r in rows:
        regen = tmp_path / f"regen_{r.idx}"
        TEMPLATES[r.template](r.seed, regen, provocateur=False)

        # (a) Every issued mock_output byte-matches the regenerated one.
        issued_mock = out / f"case_{r.idx}" / "mock_outputs"
        regen_mock = regen / "mock_outputs"
        issued_files = sorted(p for p in issued_mock.rglob("*") if p.is_file())
        assert issued_files, f"case_{r.idx} shipped no mock_outputs"
        for ip in issued_files:
            rp = regen_mock / ip.relative_to(issued_mock)
            assert rp.exists(), f"replay missing {rp}"
            assert _file_sha256(ip) == _file_sha256(rp), (
                f"case_{r.idx} mock_output {ip.name} did not replay byte-identically"
            )

        # (b) The withheld answer key replays byte-identically from the revealed seed.
        regen_key = (regen / "answer_key.json").read_bytes()
        stored = orjson.dumps(orjson.loads(r.answer_key_json), option=orjson.OPT_SORT_KEYS)
        assert stored == orjson.dumps(orjson.loads(regen_key), option=orjson.OPT_SORT_KEYS), (
            f"case_{r.idx} answer key did not replay from the revealed seed"
        )


def _mock_dir_sha256(d: Path) -> str:
    """sha256 over a mock_outputs tree's file bytes, sorted by relative path."""
    h = hashlib.sha256()
    for p in sorted(p for p in d.rglob("*") if p.is_file()):
        h.update(p.relative_to(d).as_posix().encode())
        h.update(b"\x00")
        h.update(p.read_bytes())
        h.update(b"\x00")
    return h.hexdigest()


def test_provoked_case_replays_via_one_bit_search(tmp_path: Path) -> None:
    """The provocateur flag is not a stored column, but the verifier holds the
    issued bundle, so a provoked case still replays by math: regenerate with
    provocateur=False then True — exactly one matches the issued mock_outputs.
    This proves the "replay by math, not trust" property covers provoked cases
    (frac=1.0), not only the frac=0.0 path of the test above."""
    out = tmp_path / "bundle"
    store = Store(tmp_path / "registry.db")
    sub_id = issue(_SEEDS, _TEMPLATES, provocateur_frac=1.0, out_dir=out, store=store)
    rows = store.get_cases(sub_id)
    store.close()

    for r in rows:
        issued = _mock_dir_sha256(out / f"case_{r.idx}" / "mock_outputs")
        matches = []
        for flag in (False, True):
            regen = tmp_path / f"regen_{r.idx}_{flag}"
            TEMPLATES[r.template](r.seed, regen, provocateur=flag)
            if _mock_dir_sha256(regen / "mock_outputs") == issued:
                matches.append(flag)
        # Exactly one flag value reconstructs the issued evidence — and since this
        # is a frac=1.0 issuance, it must be the provoked one.
        assert matches == [True], (
            f"case_{r.idx} ({r.template}) provoked replay failed: matches={matches}"
        )
