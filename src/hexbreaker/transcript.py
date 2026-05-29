"""Hash-chained transcript for Hexbreaker Court runs.

Implements Layer 4 of the hallucination safeguards: every step in a Court run is
recorded as a JSONL line. Each record's `this_hash` covers `prev_hash` plus the
canonical serialization of the record's payload, so any post-hoc edit breaks the
chain.

The Transcript also owns the `S-NNN` step_id namespace (Layer 1). Callers do not
assign step_ids; `append()` does, monotonically. This is what lets the Court
validator reject verdicts that cite step_ids the orchestrator never issued.

HMAC signing is deferred to 6/3 per plan; the `hmac_key` field is reserved.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

import orjson
from pydantic import BaseModel, ConfigDict, Field

GENESIS_HASH = "sha256:" + "0" * 64


class Actor(str, Enum):
    PROSECUTOR = "PROSECUTOR"
    DEFENDER = "DEFENDER"
    WITNESS = "WITNESS"
    JUDGE = "JUDGE"
    PROVOCATEUR = "PROVOCATEUR"
    TOOL = "TOOL"
    ORCHESTRATOR = "ORCHESTRATOR"
    SYSTEM = "SYSTEM"


class Kind(str, Enum):
    TOOL_CALL = "tool_call"
    LLM_CALL = "llm_call"
    CLAIM = "claim"
    VERDICT = "verdict"
    SYSTEM_EVENT = "system_event"
    PROVOCATION = "provocation"
    WITNESS_OPINION = "witness_opinion"


class StepRecord(BaseModel):
    """One immutable entry in a Court transcript.

    Chain fields (`prev_hash`, `this_hash`) are set by Transcript.append, not by
    the caller. `content` is an arbitrary JSON-serializable payload owned by the
    actor — tool stdout/stderr, an LLM message, a verdict struct, etc.
    """

    model_config = ConfigDict(extra="forbid")

    step_id: str
    turn: int
    actor: Actor
    kind: Kind
    content: dict[str, Any] = Field(default_factory=dict)
    ts: str
    prev_hash: str
    this_hash: str


def _canonical(obj: dict[str, Any]) -> bytes:
    return orjson.dumps(obj, option=orjson.OPT_SORT_KEYS)


def _hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _compute_this_hash(record: dict[str, Any]) -> str:
    """Hash everything except `this_hash` itself."""
    payload = {k: v for k, v in record.items() if k != "this_hash"}
    return _hash(_canonical(payload))


class Transcript:
    """Append-only hash-chained JSONL transcript.

    Usage:
        t = Transcript.open("/tmp/run.jsonl")
        rec = t.append(actor=Actor.PROSECUTOR, kind=Kind.CLAIM,
                       content={"text": "binary X is timestomped"})
        # rec.step_id == "S-001", rec.this_hash extends the chain.
    """

    def __init__(self, path: Path, last_hash: str, next_step: int, turn: int) -> None:
        self.path = path
        self._last_hash = last_hash
        self._next_step = next_step
        self._turn = turn

    @classmethod
    def open(cls, path: str | Path) -> "Transcript":
        """Create a new transcript or resume an existing one.

        Resuming reads through the file once to recover the chain head and the
        next step_id. Validation is NOT performed here — call verify() for that.
        """
        p = Path(path)
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            return cls(p, last_hash=GENESIS_HASH, next_step=1, turn=0)

        last_hash = GENESIS_HASH
        next_step = 1
        max_turn = 0
        with p.open("rb") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = orjson.loads(line)
                last_hash = rec["this_hash"]
                n = int(rec["step_id"].split("-", 1)[1])
                if n >= next_step:
                    next_step = n + 1
                if rec["turn"] > max_turn:
                    max_turn = rec["turn"]
        return cls(p, last_hash=last_hash, next_step=next_step, turn=max_turn)

    @property
    def head(self) -> str:
        return self._last_hash

    @property
    def next_step_id(self) -> str:
        return f"S-{self._next_step:03d}"

    def bump_turn(self) -> int:
        self._turn += 1
        return self._turn

    def append(
        self,
        *,
        actor: Actor,
        kind: Kind,
        content: dict[str, Any] | None = None,
        turn: int | None = None,
        ts: str | None = None,
    ) -> StepRecord:
        """Append a new record. Assigns step_id and chain hash."""
        step_id = self.next_step_id
        self._next_step += 1
        record_turn = turn if turn is not None else self._turn
        record_ts = ts if ts is not None else datetime.now(timezone.utc).isoformat()

        payload = {
            "step_id": step_id,
            "turn": record_turn,
            "actor": actor.value,
            "kind": kind.value,
            "content": content or {},
            "ts": record_ts,
            "prev_hash": self._last_hash,
        }
        this_hash = _compute_this_hash(payload)
        payload["this_hash"] = this_hash

        with self.path.open("ab") as f:
            f.write(_canonical(payload) + b"\n")

        self._last_hash = this_hash
        return StepRecord.model_validate(payload)


def read(path: str | Path) -> Iterator[StepRecord]:
    """Iterate records in a transcript file."""
    with Path(path).open("rb") as f:
        for line in f:
            if not line.strip():
                continue
            yield StepRecord.model_validate_json(line)


def _verify_sidecar(
    transcript_dir: Path, rel_path: str, expected_hash: str
) -> str | None:
    """Re-read a referenced sidecar file and check its bytes against the recorded
    hash. Returns an error reason on failure, or None if it matches.

    The bytes of real tool output live in unchained sidecar files; the chain only
    covers the hash STRING in the record. Without this check, editing only a
    sidecar (e.g. "clean" -> "EVIL") would leave verify() passing. The sidecar
    path is resolved against the transcript directory and a path that escapes it
    (poisoned `../../etc/passwd`) is treated as tampering, mirroring the defense
    in court_runner._render_transcript.
    """
    candidate = (transcript_dir / rel_path).resolve()
    if not candidate.is_relative_to(transcript_dir):
        return f"sidecar path escapes transcript dir: {rel_path}"
    try:
        data = candidate.read_bytes()
    except OSError:
        return f"sidecar missing or unreadable: {rel_path}"
    if _hash(data) != expected_hash:
        return f"sidecar hash mismatch: {rel_path}"
    return None


def verify(path: str | Path) -> tuple[bool, str | None]:
    """Walk the chain and verify every link, then verify referenced sidecars.

    Returns (ok, reason). On success reason is None; on failure reason names the
    first broken step_id (or sidecar).

    Two layers are checked:
      1. The hash chain over each record's payload (catches edits to the JSONL).
      2. For TOOL_CALL records, the bytes of each referenced sidecar file are
         re-read and re-hashed against the stored stdout_hash/stderr_hash. The
         real evidence lives in those unchained sidecars; without this, editing
         only a sidecar file would leave the chain (and verify) intact.
    """
    transcript_dir = Path(path).parent.resolve()
    prev = GENESIS_HASH
    expected_step = 1
    for record in read(path):
        if record.step_id != f"S-{expected_step:03d}":
            return False, f"step_id discontinuity at {record.step_id}"
        if record.prev_hash != prev:
            return False, f"prev_hash mismatch at {record.step_id}"
        recomputed = _compute_this_hash(record.model_dump(mode="json"))
        if recomputed != record.this_hash:
            return False, f"this_hash mismatch at {record.step_id}"
        content = record.content
        for path_key, hash_key in (
            ("stdout_path", "stdout_hash"),
            ("stderr_path", "stderr_hash"),
        ):
            if path_key in content and hash_key in content:
                reason = _verify_sidecar(
                    transcript_dir, content[path_key], content[hash_key]
                )
                if reason is not None:
                    return False, f"{reason} (at {record.step_id})"
        prev = record.this_hash
        expected_step += 1
    return True, None
