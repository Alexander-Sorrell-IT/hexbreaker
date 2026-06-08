"""Server-side registry store — the withheld half of the benchmark.

The whole cheat-resistance design hinges on a clean split: the submitter gets a
SEALED bundle (no seed, no answer key); the registry keeps the secrets here. For
each issued case this records `(seed, template, answer_key_json, provocation_json)`
so scoring (P3) can grade the returned run against a key the submitter never saw,
and `reveal` (P4) can publish the seeds for byte-identical replay.

Plain stdlib `sqlite3` — datetime/uuid from stdlib are fine in Python (only the
JS orchestration script forbids Date.now). Schema is verbatim from
PLAN_REGISTRY.md:

  submissions(id TEXT PK, created_ts, status)
  cases(submission_id, idx, seed, template, answer_key_json, provocation_json)
  results(submission_id, scorecard_json, revealed INT)

The `results` table is created now (P2) but written by P3/P4; keeping the schema
whole here means later phases add no migration.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS submissions (
    id          TEXT PRIMARY KEY,
    created_ts  TEXT NOT NULL,
    status      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cases (
    submission_id     TEXT NOT NULL,
    idx               INTEGER NOT NULL,
    seed              INTEGER NOT NULL,
    template          TEXT NOT NULL,
    answer_key_json   TEXT NOT NULL,
    provocation_json  TEXT NOT NULL,
    PRIMARY KEY (submission_id, idx)
);
CREATE TABLE IF NOT EXISTS results (
    submission_id  TEXT NOT NULL,
    scorecard_json TEXT NOT NULL,
    revealed       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (submission_id)
);
"""


@dataclass(frozen=True)
class CaseRow:
    """One withheld case as stored server-side."""

    submission_id: str
    idx: int
    seed: int
    template: str
    answer_key_json: str
    provocation_json: str


@dataclass(frozen=True)
class ResultRow:
    """A scored submission's persisted scorecard + reveal flag."""

    submission_id: str
    scorecard_json: str
    revealed: int


class Store:
    """SQLite-backed registry store. One connection per instance."""

    def __init__(self, db_path: str | Path = "./registry.db") -> None:
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def new_submission(self, status: str = "issued") -> str:
        """Create a submission row and return its id."""
        sub_id = uuid.uuid4().hex
        created_ts = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT INTO submissions (id, created_ts, status) VALUES (?, ?, ?)",
            (sub_id, created_ts, status),
        )
        self._conn.commit()
        return sub_id

    def add_case(
        self,
        submission_id: str,
        idx: int,
        seed: int,
        template: str,
        answer_key_json: str,
        provocation_json: str,
    ) -> None:
        """Record one withheld case (the real seed + answer key + provocation)."""
        self._conn.execute(
            "INSERT INTO cases "
            "(submission_id, idx, seed, template, answer_key_json, provocation_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (submission_id, idx, seed, template, answer_key_json, provocation_json),
        )
        self._conn.commit()

    def get_cases(self, submission_id: str) -> list[CaseRow]:
        """Return all withheld cases for a submission, ordered by idx."""
        rows = self._conn.execute(
            "SELECT submission_id, idx, seed, template, answer_key_json, provocation_json "
            "FROM cases WHERE submission_id = ? ORDER BY idx",
            (submission_id,),
        ).fetchall()
        return [
            CaseRow(
                submission_id=r["submission_id"],
                idx=r["idx"],
                seed=r["seed"],
                template=r["template"],
                answer_key_json=r["answer_key_json"],
                provocation_json=r["provocation_json"],
            )
            for r in rows
        ]

    # --- results: written by `score`, read by `board`, flagged by `reveal` (P4) ---

    def save_result(self, submission_id: str, scorecard_json: str) -> None:
        """Persist (or replace) a submission's scorecard. Preserves `revealed`."""
        self._conn.execute(
            "INSERT INTO results (submission_id, scorecard_json, revealed) "
            "VALUES (?, ?, 0) "
            "ON CONFLICT(submission_id) DO UPDATE SET scorecard_json = excluded.scorecard_json",
            (submission_id, scorecard_json),
        )
        self._conn.commit()

    def get_result(self, submission_id: str) -> ResultRow | None:
        """Return the stored scorecard row for a submission, or None if unscored."""
        r = self._conn.execute(
            "SELECT submission_id, scorecard_json, revealed FROM results "
            "WHERE submission_id = ?",
            (submission_id,),
        ).fetchone()
        if r is None:
            return None
        return ResultRow(
            submission_id=r["submission_id"],
            scorecard_json=r["scorecard_json"],
            revealed=r["revealed"],
        )

    def list_results(self) -> list[ResultRow]:
        """Return every scored submission's result row (for `board`)."""
        rows = self._conn.execute(
            "SELECT r.submission_id, r.scorecard_json, r.revealed "
            "FROM results r JOIN submissions s ON s.id = r.submission_id "
            "ORDER BY s.created_ts"
        ).fetchall()
        return [
            ResultRow(
                submission_id=r["submission_id"],
                scorecard_json=r["scorecard_json"],
                revealed=r["revealed"],
            )
            for r in rows
        ]

    def set_revealed(self, submission_id: str) -> None:
        """Flag a scored submission's seeds as revealed (enables replay)."""
        self._conn.execute(
            "UPDATE results SET revealed = 1 WHERE submission_id = ?",
            (submission_id,),
        )
        self._conn.commit()
