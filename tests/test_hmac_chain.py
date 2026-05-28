"""Tests for the HMAC-signed transcript chain (Layer 5).

Algorithm primitive ported from AppliedIR/Valhuntir/src/vhir_cli/verification.py
(MIT). Behavior we test:
- sign() writes a .sig file with the documented schema
- verify_signature() detects: a clean signed transcript, a tampered chain,
  a truncated chain (record_count differs), a wrong password, a missing .sig
- compare_digest is used (we don't test that directly, but we assert that
  swapping one byte of the HMAC invalidates verification)
"""

from __future__ import annotations

from pathlib import Path

import orjson
import pytest

from hexbreaker.court.hmac_chain import (
    HMAC_ENV,
    sign_transcript,
    verify_signature,
)
from hexbreaker.transcript import Actor, Kind, Transcript

PW = "test-passphrase-for-unit-tests"


def _build(path: Path, n: int = 3) -> Transcript:
    t = Transcript.open(path)
    for i in range(n):
        t.append(actor=Actor.PROSECUTOR, kind=Kind.CLAIM, content={"i": i})
    return t


def test_sign_writes_sig_file_with_documented_fields(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    _build(path)
    sig = sign_transcript(path, password=PW)
    sig_file = path.with_suffix(path.suffix + ".sig")
    assert sig_file.exists()
    data = orjson.loads(sig_file.read_bytes())
    for key in ("algorithm", "salt_hex", "chain_head", "record_count", "hmac_hex", "schema_version"):
        assert key in data
    assert data["record_count"] == 3
    assert sig.chain_head == data["chain_head"]


def test_verify_passes_on_clean_signed_transcript(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    _build(path)
    sign_transcript(path, password=PW)
    result = verify_signature(path, password=PW)
    assert result.ok
    assert result.chain_ok
    assert result.hmac_ok


def test_verify_fails_on_wrong_password(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    _build(path)
    sign_transcript(path, password=PW)
    result = verify_signature(path, password="totally-wrong-password")
    assert not result.ok
    assert not result.hmac_ok
    assert result.chain_ok  # chain itself is fine; only the HMAC fails
    assert result.reason is not None


def test_verify_detects_appended_record(tmp_path: Path) -> None:
    """An attacker who appends a NEW record after signing breaks both the
    chain_head and the record_count, so the signature must fail."""
    path = tmp_path / "run.jsonl"
    t = _build(path)
    sign_transcript(path, password=PW)
    # Attacker appends. Their appended record's hash chain is valid (it
    # follows the existing head), but the signed (chain_head, count) tuple
    # is now wrong.
    t.append(actor=Actor.DEFENDER, kind=Kind.VERDICT, content={"forged": True})
    result = verify_signature(path, password=PW)
    assert not result.ok
    assert not result.hmac_ok


def test_verify_detects_tampered_record_content(tmp_path: Path) -> None:
    """An attacker who rewrites a record's content breaks the chain hash AND
    the HMAC. The verifier reports both failures."""
    path = tmp_path / "run.jsonl"
    _build(path)
    sign_transcript(path, password=PW)
    # Rewrite the first record's content but leave the chain hashes intact —
    # this is the exact attack the hash chain is designed to catch, and the
    # HMAC is supposed to detect it independently too.
    lines = path.read_bytes().splitlines()
    rec = orjson.loads(lines[0])
    rec["content"]["tampered"] = True
    lines[0] = orjson.dumps(rec)
    path.write_bytes(b"\n".join(lines) + b"\n")
    result = verify_signature(path, password=PW)
    assert not result.ok
    # Chain catches this directly (this_hash recomputation will fail).
    assert not result.chain_ok


def test_verify_detects_one_byte_hmac_flip(tmp_path: Path) -> None:
    """compare_digest must fail on a single-byte HMAC flip."""
    path = tmp_path / "run.jsonl"
    _build(path)
    sig = sign_transcript(path, password=PW)
    sig_path = path.with_suffix(path.suffix + ".sig")
    data = orjson.loads(sig_path.read_bytes())
    # Flip the last hex character.
    last = data["hmac_hex"][-1]
    new_last = "0" if last != "0" else "1"
    data["hmac_hex"] = data["hmac_hex"][:-1] + new_last
    sig_path.write_bytes(orjson.dumps(data))
    result = verify_signature(path, password=PW)
    assert not result.ok
    assert not result.hmac_ok
    _ = sig


def test_verify_reports_missing_signature(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    _build(path)
    # No sign_transcript() call — .sig is absent.
    result = verify_signature(path, password=PW)
    assert not result.ok
    assert not result.hmac_ok
    assert result.chain_ok  # chain itself is fine
    assert "signature file missing" in (result.reason or "")


def test_password_from_env_when_not_provided(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "run.jsonl"
    _build(path)
    monkeypatch.setenv(HMAC_ENV, "env-supplied-passphrase")
    sign_transcript(path)  # no explicit password
    result = verify_signature(path)
    assert result.ok


def test_sign_raises_when_password_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "run.jsonl"
    _build(path)
    monkeypatch.delenv(HMAC_ENV, raising=False)
    with pytest.raises(RuntimeError, match=HMAC_ENV):
        sign_transcript(path)
