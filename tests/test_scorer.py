"""Tests for the exact-match scorer."""

from __future__ import annotations

from hexbreaker.forge.case import AnswerKey, ExpectedFinding
from hexbreaker.scorer.exact_match import FindingClass, score


def _key(answer_kwargs: dict) -> AnswerKey:
    return AnswerKey(case_id="c", template="timestomp", **answer_kwargs)


def test_perfect_score() -> None:
    ans = _key(
        {
            "expected_findings": [ExpectedFinding(artifact_kind="timestomp", target="evil.sys")],
            "decoys": [ExpectedFinding(artifact_kind="timestomp", target="good.sys")],
        }
    )
    findings = [{"artifact_kind": "timestomp", "target": "evil.sys"}]
    r = score(findings, ans)
    assert r.tp == 1
    assert r.fp == 0
    assert r.fn == 0
    assert r.precision == 1.0
    assert r.recall == 1.0
    assert r.f1 == 1.0


def test_missed_finding_is_false_negative() -> None:
    ans = _key({"expected_findings": [ExpectedFinding(artifact_kind="timestomp", target="evil.sys")]})
    r = score([], ans)
    assert r.fn == 1
    assert r.precision == 0.0
    assert r.recall == 0.0


def test_decoy_finding_is_false_positive() -> None:
    ans = _key(
        {
            "expected_findings": [ExpectedFinding(artifact_kind="timestomp", target="evil.sys")],
            "decoys": [ExpectedFinding(artifact_kind="timestomp", target="good.sys")],
        }
    )
    findings = [
        {"artifact_kind": "timestomp", "target": "evil.sys"},  # TP
        {"artifact_kind": "timestomp", "target": "good.sys"},  # FP (decoy)
    ]
    r = score(findings, ans)
    assert r.tp == 1
    assert r.fp == 1
    assert r.fn == 0
    assert any(rr.classification == FindingClass.FP_DECOY for rr in r.results)


def test_extraneous_finding_is_false_positive() -> None:
    ans = _key({"expected_findings": [ExpectedFinding(artifact_kind="timestomp", target="evil.sys")]})
    findings = [
        {"artifact_kind": "timestomp", "target": "evil.sys"},
        {"artifact_kind": "timestomp", "target": "totally_random.exe"},
    ]
    r = score(findings, ans)
    assert r.tp == 1
    assert r.fp == 1
    assert any(rr.classification == FindingClass.FP_EXTRANEOUS for rr in r.results)


def test_case_sensitive_target_match() -> None:
    """Hashes are byte-identical; targets must be too. A case-mismatched filename is FP+FN."""
    ans = _key({"expected_findings": [ExpectedFinding(artifact_kind="timestomp", target="evil.sys")]})
    findings = [{"artifact_kind": "timestomp", "target": "Evil.sys"}]
    r = score(findings, ans)
    assert r.tp == 0
    assert r.fp == 1
    assert r.fn == 1


def test_f1_with_partial_recall() -> None:
    ans = _key(
        {
            "expected_findings": [
                ExpectedFinding(artifact_kind="timestomp", target="a.sys"),
                ExpectedFinding(artifact_kind="timestomp", target="b.sys"),
            ]
        }
    )
    findings = [{"artifact_kind": "timestomp", "target": "a.sys"}]
    r = score(findings, ans)
    assert r.tp == 1
    assert r.fn == 1
    assert r.precision == 1.0
    assert r.recall == 0.5
    assert abs(r.f1 - 2 / 3) < 1e-3
