"""HMAC-SHA256 transcript signing — ports Valhuntir's verification.py pattern.

Ports AppliedIR/Valhuntir's `src/vhir_cli/verification.py` (MIT-licensed,
Copyright (c) 2026 AppliedIncidentResponse.com). Their original code signs
per-finding content_snapshots and stores HMACs in a system-wide examiner
ledger. We adapted the same crypto primitive to sign Hexbreaker transcript
chain heads, since our threat model is "did anyone tamper with this transcript
after the Court closed it" rather than "is this examiner's approval valid."

Algorithm (identical to Valhuntir's):
  - PBKDF2-HMAC-SHA256, 600,000 iterations, on (password, salt) → 32-byte key
  - HMAC-SHA256 over the canonical message (here: the transcript chain head)
  - Validation via hmac.compare_digest (constant-time)

What we sign: the final `this_hash` of the transcript chain plus the count of
records. That tuple is canonical (orjson with sorted keys) and binds the
signature to BOTH the chain integrity AND the chain length, so an attacker
who truncates trailing records and chooses an earlier valid `this_hash` still
breaks the signature.

What lands today: sign(), verify_signature(), and the verify_chain_and_hmac
top-level entry the CLI uses. Salt is per-transcript and stored in the .sig
file (it doesn't need secrecy; PBKDF2 600K + a 16-byte salt is enough). The
password comes from $HEXBREAKER_HMAC_PASSWORD (set by the orchestrator out of
band, e.g., the analyst's password manager).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

import orjson
from pydantic import BaseModel, ConfigDict, Field

from ..transcript import StepRecord
from ..transcript import read as read_transcript
from ..transcript import verify as verify_chain

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
HMAC_ENV = "HEXBREAKER_HMAC_PASSWORD"


class TranscriptSignature(BaseModel):
    """Sidecar `.sig` file format. Sits next to transcript.jsonl."""

    model_config = ConfigDict(extra="forbid")

    algorithm: str = "PBKDF2-HMAC-SHA256/600000+HMAC-SHA256"
    salt_hex: str
    chain_head: str
    record_count: int
    hmac_hex: str
    schema_version: int = 1


class HMACVerifyResult(BaseModel):
    ok: bool
    reason: str | None = None
    chain_ok: bool
    chain_reason: str | None = None
    hmac_ok: bool


def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)


def _canonical_message(chain_head: str, record_count: int) -> bytes:
    """Bytes the HMAC is computed over. Canonical so signing is deterministic.

    Including record_count prevents truncation attacks: an attacker who chops
    trailing records off the JSONL still has a valid chain prefix (each record's
    this_hash is independently valid), but the count won't match the signed
    count.
    """
    return orjson.dumps(
        {"chain_head": chain_head, "record_count": record_count},
        option=orjson.OPT_SORT_KEYS,
    )


def _records_summary(records: list[StepRecord]) -> tuple[str, int]:
    head = records[-1].this_hash if records else ""
    return head, len(records)


def _password_from_env() -> str:
    pw = os.environ.get(HMAC_ENV)
    if not pw:
        raise RuntimeError(
            f"{HMAC_ENV} not set. Set it to a strong passphrase the analyst "
            f"controls before calling sign() or verify()."
        )
    return pw


def sign_transcript(transcript_path: str | Path, *, password: str | None = None) -> TranscriptSignature:
    """Compute and persist an HMAC signature for the transcript at `path`.

    Writes the signature to `<transcript>.sig` (a JSON file next to the
    transcript). Returns the TranscriptSignature object so callers can also
    embed it elsewhere if they want.

    The chain itself is NOT modified.
    """
    path = Path(transcript_path)
    pw = password or _password_from_env()
    records = list(read_transcript(path))
    chain_head, count = _records_summary(records)
    salt = secrets.token_bytes(SALT_BYTES)
    key = _derive_key(pw, salt)
    mac_hex = hmac.new(key, _canonical_message(chain_head, count), hashlib.sha256).hexdigest()
    sig = TranscriptSignature(
        salt_hex=salt.hex(),
        chain_head=chain_head,
        record_count=count,
        hmac_hex=mac_hex,
    )
    sig_path = path.with_suffix(path.suffix + ".sig")
    sig_path.write_bytes(orjson.dumps(sig.model_dump(), option=orjson.OPT_INDENT_2))
    os.chmod(sig_path, 0o600)
    return sig


def verify_signature(transcript_path: str | Path, *, password: str | None = None) -> HMACVerifyResult:
    """Verify the HMAC signature alongside the hash chain.

    Returns an HMACVerifyResult with both chain_ok and hmac_ok flags. ok is
    True iff BOTH pass.
    """
    path = Path(transcript_path)
    sig_path = path.with_suffix(path.suffix + ".sig")

    chain_ok, chain_reason = verify_chain(path)

    if not sig_path.exists():
        return HMACVerifyResult(
            ok=False,
            reason="signature file missing",
            chain_ok=chain_ok,
            chain_reason=chain_reason,
            hmac_ok=False,
        )

    sig = TranscriptSignature.model_validate_json(sig_path.read_bytes())
    pw = password or _password_from_env()

    # Re-derive key + recompute over the CURRENT chain state.
    records = list(read_transcript(path))
    chain_head, count = _records_summary(records)

    expected = hmac.new(
        _derive_key(pw, bytes.fromhex(sig.salt_hex)),
        _canonical_message(chain_head, count),
        hashlib.sha256,
    ).hexdigest()

    hmac_ok = hmac.compare_digest(expected, sig.hmac_hex)

    if not hmac_ok and chain_head != sig.chain_head:
        reason = "transcript chain head differs from signed value (truncation, append, or tampering)"
    elif not hmac_ok and count != sig.record_count:
        reason = f"record count differs (signed={sig.record_count}, actual={count})"
    elif not hmac_ok:
        reason = "HMAC mismatch (wrong password or tampering)"
    elif not chain_ok:
        reason = f"HMAC valid but chain broken: {chain_reason}"
    else:
        reason = None

    return HMACVerifyResult(
        ok=hmac_ok and chain_ok,
        reason=reason,
        chain_ok=chain_ok,
        chain_reason=chain_reason,
        hmac_ok=hmac_ok,
    )


# Attribution preserved for the upstream Valhuntir code we ported from.
# Algorithm: PBKDF2-HMAC-SHA256/600000 + HMAC-SHA256 + hmac.compare_digest.
# Original: AppliedIR/Valhuntir/src/vhir_cli/verification.py (MIT-licensed,
# Copyright (c) 2026 AppliedIncidentResponse.com).
__valhuntir_attribution__ = "Algorithm primitive ported from AppliedIR/Valhuntir verification.py (MIT, (c) 2026 AppliedIncidentResponse.com)"
