"""Tests for the hash-chained transcript — Layers 1 and 4 of the safeguards."""

from __future__ import annotations

from pathlib import Path

import orjson

from hexbreaker.transcript import (
    GENESIS_HASH,
    Actor,
    Kind,
    Transcript,
    read,
    verify,
)


def test_append_assigns_sequential_step_ids(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "run.jsonl")
    r1 = t.append(actor=Actor.PROSECUTOR, kind=Kind.CLAIM, content={"text": "a"})
    r2 = t.append(actor=Actor.DEFENDER, kind=Kind.VERDICT, content={"v": "CONTESTED"})
    r3 = t.append(actor=Actor.TOOL, kind=Kind.TOOL_CALL, content={"tool": "fls"})
    assert [r.step_id for r in (r1, r2, r3)] == ["S-001", "S-002", "S-003"]


def test_chain_links_via_prev_hash(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "run.jsonl")
    r1 = t.append(actor=Actor.PROSECUTOR, kind=Kind.CLAIM, content={"text": "a"})
    r2 = t.append(actor=Actor.DEFENDER, kind=Kind.VERDICT, content={"v": "CONTESTED"})
    assert r1.prev_hash == GENESIS_HASH
    assert r2.prev_hash == r1.this_hash
    assert r1.this_hash != r2.this_hash


def test_verify_passes_on_clean_chain(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    t = Transcript.open(path)
    for i in range(5):
        t.append(actor=Actor.PROSECUTOR, kind=Kind.CLAIM, content={"i": i})
    ok, reason = verify(path)
    assert ok, reason


def test_verify_detects_content_tampering(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    t = Transcript.open(path)
    t.append(actor=Actor.PROSECUTOR, kind=Kind.CLAIM, content={"text": "honest"})
    t.append(actor=Actor.DEFENDER, kind=Kind.VERDICT, content={"v": "CONFIRMED"})

    # Rewrite first record with tampered content but the original chain hashes.
    lines = path.read_bytes().splitlines()
    rec = orjson.loads(lines[0])
    rec["content"]["text"] = "tampered"
    lines[0] = orjson.dumps(rec)
    path.write_bytes(b"\n".join(lines) + b"\n")

    ok, reason = verify(path)
    assert not ok
    assert "S-001" in reason


def test_verify_detects_prev_hash_break(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    t = Transcript.open(path)
    t.append(actor=Actor.PROSECUTOR, kind=Kind.CLAIM, content={"a": 1})
    t.append(actor=Actor.DEFENDER, kind=Kind.VERDICT, content={"a": 2})

    # Corrupt the link between record 1 and 2.
    lines = path.read_bytes().splitlines()
    rec2 = orjson.loads(lines[1])
    rec2["prev_hash"] = GENESIS_HASH  # Pretend it follows nothing.
    lines[1] = orjson.dumps(rec2)
    path.write_bytes(b"\n".join(lines) + b"\n")

    ok, reason = verify(path)
    assert not ok
    assert "S-002" in reason


def test_open_resumes_step_counter_and_chain_head(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    t1 = Transcript.open(path)
    t1.append(actor=Actor.PROSECUTOR, kind=Kind.CLAIM, content={"a": 1})
    t1.append(actor=Actor.DEFENDER, kind=Kind.VERDICT, content={"a": 2})
    head_before = t1.head

    t2 = Transcript.open(path)
    assert t2.head == head_before
    assert t2.next_step_id == "S-003"
    r3 = t2.append(actor=Actor.WITNESS, kind=Kind.CLAIM, content={"a": 3})
    assert r3.prev_hash == head_before

    records = list(read(path))
    assert [r.step_id for r in records] == ["S-001", "S-002", "S-003"]
    ok, reason = verify(path)
    assert ok, reason


def test_bump_turn_increments(tmp_path: Path) -> None:
    t = Transcript.open(tmp_path / "run.jsonl")
    assert t.bump_turn() == 1
    assert t.bump_turn() == 2
    r = t.append(actor=Actor.PROSECUTOR, kind=Kind.CLAIM)
    assert r.turn == 2


def test_genesis_prev_hash_format() -> None:
    assert GENESIS_HASH.startswith("sha256:")
    assert len(GENESIS_HASH) == len("sha256:") + 64


def test_verify_detects_sidecar_byte_tampering(tmp_path: Path) -> None:
    """HOLE A regression: real tool output lives in UNCHAINED sidecar files;
    the chain only covers the hash STRING in the record. Editing ONLY a sidecar
    file (the evidence bytes) must make verify() FAIL — otherwise an attacker
    rewrites 'clean' -> 'EVIL' in the sidecar and the audit still passes."""
    from hexbreaker.tools import run_tool

    path = tmp_path / "run.jsonl"
    t = Transcript.open(path)

    def fake_runner(argv, cwd, timeout):
        return 0, b"clean: no malware found\n", b"", 0.01

    result = run_tool(t, "fls", ["-r"], runner=fake_runner)

    # Pre-condition: the freshly written transcript + sidecar verify clean.
    ok, reason = verify(path)
    assert ok, reason

    # Attack: edit ONLY the sidecar bytes. The JSONL chain is untouched.
    result.stdout_path.write_bytes(b"EVIL: malware confirmed\n")

    ok, reason = verify(path)
    assert not ok
    assert "sidecar hash mismatch" in reason
    assert result.step_id in reason


def test_verify_detects_missing_sidecar(tmp_path: Path) -> None:
    """A referenced sidecar that has been deleted must fail verify(), not be
    silently skipped."""
    from hexbreaker.tools import run_tool

    path = tmp_path / "run.jsonl"
    t = Transcript.open(path)

    def fake_runner(argv, cwd, timeout):
        return 0, b"some output\n", b"err\n", 0.01

    result = run_tool(t, "fls", [], runner=fake_runner)
    result.stdout_path.unlink()

    ok, reason = verify(path)
    assert not ok
    assert "sidecar missing" in reason
