"""The durable review queue: one row per request, and a checkpoint per reviewer slot.

Everything lives in one SQLite database owned by the daemon user, so a restart resumes from what was
committed. A request is keyed by repository, pull request, head and the plan run that made it. Only one
request runs at a time, oldest first.

A slot is checkpointed as started before the reviewer is launched and as captured after its output is
copied. A slot that started but was never captured was interrupted: the first time it is run again, the
second time it is recorded as interrupted so the reviewer chain moves on.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

QUEUED = "queued"
CLAIMED = "claimed"
POSTING = "posting"
RECORDING = "recording"
DONE = "done"
SUPERSEDED = "superseded"
DUPLICATE = "duplicate"
VERSION_SKEW = "version-skew"
FAILED = "failed"

RUNNING = (CLAIMED, POSTING, RECORDING)
ACTIVE = (QUEUED, VERSION_SKEW, *RUNNING)
TRANSITIONS = {
    QUEUED: {CLAIMED, SUPERSEDED, FAILED},
    VERSION_SKEW: {QUEUED, SUPERSEDED, FAILED},
    CLAIMED: {POSTING, SUPERSEDED, FAILED},
    POSTING: {RECORDING, DONE, SUPERSEDED, FAILED},
    RECORDING: {DONE, FAILED},
}

RERUN = "rerun"
INTERRUPTED = "interrupted"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY,
    repo TEXT NOT NULL,
    pr INTEGER NOT NULL,
    head_sha TEXT NOT NULL,
    plan_run_id TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    state TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    enqueued_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (repo, pr, head_sha, plan_run_id)
);
CREATE TABLE IF NOT EXISTS slots (
    item_id INTEGER NOT NULL REFERENCES items (id),
    slot INTEGER NOT NULL,
    reviewer TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    runs INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    captured_at TEXT,
    captured_sha256 TEXT,
    scan TEXT,
    PRIMARY KEY (item_id, slot)
);
"""


class QueueError(RuntimeError):
    pass


def connect(path: Path) -> sqlite3.Connection:
    """Open the state database with write-ahead logging and full syncs, creating it private to its owner."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


@dataclass(frozen=True)
class Item:
    id: int
    repo: str
    pr: int
    head_sha: str
    plan_run_id: str
    engine_version: str
    state: str
    reason: str
    enqueued_at: str


@dataclass(frozen=True)
class Enqueued:
    item: Item
    outcome: str  # queued, held, duplicate or known
    superseded: tuple[Item, ...] = ()


@dataclass(frozen=True)
class Slot:
    slot: int
    reviewer: str
    attempt_id: str
    runs: int
    captured: bool
    captured_sha256: str | None
    scan: str | None


@dataclass(frozen=True)
class Recovery:
    slot: int
    attempt_id: str
    action: str  # RERUN or INTERRUPTED


def _item(row: sqlite3.Row) -> Item:
    return Item(**{field: row[field] for field in Item.__dataclass_fields__})


class Queue:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db
        with db:
            db.executescript(_SCHEMA)

    def get(self, item_id: int) -> Item:
        row = self.db.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if row is None:
            raise QueueError(f"no queue item {item_id}")
        return _item(row)

    def _items(self, where: str, args: tuple = ()) -> list[Item]:
        rows = self.db.execute(f"SELECT * FROM items WHERE {where} ORDER BY enqueued_at, id", args)  # noqa: S608
        return [_item(row) for row in rows]

    def active(self, repo: str, pr: int) -> list[Item]:
        marks = ",".join("?" * len(ACTIVE))
        return self._items(f"repo = ? AND pr = ? AND state IN ({marks})", (repo, pr, *ACTIVE))

    def in_state(self, state: str) -> list[Item]:
        return self._items("state = ?", (state,))

    def enqueue(
        self, repo: str, pr: int, head_sha: str, plan_run_id: str, engine_version: str, now: datetime, *, held: bool
    ) -> Enqueued:
        """Record a request. A request for a newer head supersedes older ones; one for the same head is a duplicate."""
        stamp = now.isoformat()
        with self.db:
            known = self.db.execute(
                "SELECT * FROM items WHERE repo = ? AND pr = ? AND head_sha = ? AND plan_run_id = ?",
                (repo, pr, head_sha, plan_run_id),
            ).fetchone()
            if known is not None:
                return Enqueued(_item(known), "known")
            active = self.active(repo, pr)
            same_head = [item for item in active if item.head_sha == head_sha]
            state, outcome = (
                (DUPLICATE, "duplicate") if same_head else ((VERSION_SKEW, "held") if held else (QUEUED, "queued"))
            )
            older = [] if same_head else [item for item in active if item.head_sha != head_sha]
            for item in older:
                self._move(item, SUPERSEDED, f"a request for head {head_sha} replaced it", stamp)
            cursor = self.db.execute(
                "INSERT INTO items (repo, pr, head_sha, plan_run_id, engine_version, state, reason, enqueued_at,"
                " updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (repo, pr, head_sha, plan_run_id, engine_version, state, "", stamp, stamp),
            )
        item_id = cursor.lastrowid
        assert item_id is not None
        return Enqueued(self.get(item_id), outcome, tuple(self.get(item.id) for item in older))

    def _move(self, item: Item, state: str, reason: str, stamp: str) -> None:
        if state not in TRANSITIONS.get(item.state, set()):
            raise QueueError(f"item {item.id} cannot move from {item.state} to {state}")
        changed = self.db.execute(
            "UPDATE items SET state = ?, reason = ?, updated_at = ? WHERE id = ? AND state = ?",
            (state, reason, stamp, item.id, item.state),
        ).rowcount
        if changed != 1:
            raise QueueError(f"item {item.id} changed while it was being moved to {state}")

    def move(self, item_id: int, state: str, now: datetime, reason: str = "") -> Item:
        with self.db:
            self._move(self.get(item_id), state, reason, now.isoformat())
        return self.get(item_id)

    def claim_next(self, now: datetime) -> Item | None:
        """Claim the oldest queued request, unless one is already running."""
        with self.db:
            marks = ",".join("?" * len(RUNNING))
            if self.db.execute(f"SELECT 1 FROM items WHERE state IN ({marks})", RUNNING).fetchone():  # noqa: S608
                return None
            waiting = self.in_state(QUEUED)
            if not waiting:
                return None
            self._move(waiting[0], CLAIMED, "", now.isoformat())
        return self.get(waiting[0].id)

    def position(self, item_id: int) -> int:
        """The item's place among queued requests, counting from one."""
        ids = [item.id for item in self.in_state(QUEUED)]
        if item_id not in ids:
            raise QueueError(f"item {item_id} is not queued")
        return ids.index(item_id) + 1

    def release_held(self, installed: set[str], now: datetime) -> list[Item]:
        """Queue held requests whose engine version is now installed."""
        released = [item for item in self.in_state(VERSION_SKEW) if item.engine_version in installed]
        with self.db:
            for item in released:
                self._move(item, QUEUED, "its engine is installed", now.isoformat())
        return [self.get(item.id) for item in released]

    def counts(self) -> dict[str, int]:
        return {row[0]: row[1] for row in self.db.execute("SELECT state, COUNT(*) FROM items GROUP BY state")}

    def slot_started(self, item_id: int, slot: int, reviewer: str, attempt_id: str, now: datetime) -> None:
        """Checkpoint a slot before its reviewer starts. Starting an uncaptured slot again counts a second run."""
        with self.db:
            row = self.db.execute("SELECT * FROM slots WHERE item_id = ? AND slot = ?", (item_id, slot)).fetchone()
            if row is None:
                self.db.execute(
                    "INSERT INTO slots (item_id, slot, reviewer, attempt_id, runs, started_at) VALUES (?, ?, ?, ?, 1, ?)",
                    (item_id, slot, reviewer, attempt_id, now.isoformat()),
                )
            elif row["captured_at"] is None and row["attempt_id"] != attempt_id:
                self.db.execute(
                    "UPDATE slots SET reviewer = ?, attempt_id = ?, runs = runs + 1, started_at = ?"
                    " WHERE item_id = ? AND slot = ?",
                    (reviewer, attempt_id, now.isoformat(), item_id, slot),
                )
            else:
                raise QueueError(f"slot {slot} of item {item_id} is already captured or started as {attempt_id}")

    def slot_captured(self, item_id: int, slot: int, attempt_id: str, sha256: str, scan: str, now: datetime) -> None:
        """Checkpoint a slot after its output was captured and scanned."""
        with self.db:
            changed = self.db.execute(
                "UPDATE slots SET captured_at = ?, captured_sha256 = ?, scan = ?"
                " WHERE item_id = ? AND slot = ? AND attempt_id = ? AND captured_at IS NULL",
                (now.isoformat(), sha256, scan, item_id, slot, attempt_id),
            ).rowcount
        if changed != 1:
            raise QueueError(f"slot {slot} of item {item_id} has no uncaptured attempt {attempt_id}")

    def slots(self, item_id: int) -> list[Slot]:
        rows = self.db.execute("SELECT * FROM slots WHERE item_id = ? ORDER BY slot", (item_id,))
        return [
            Slot(
                r["slot"],
                r["reviewer"],
                r["attempt_id"],
                r["runs"],
                r["captured_at"] is not None,
                r["captured_sha256"],
                r["scan"],
            )
            for r in rows
        ]

    def recover(self, item_id: int) -> list[Recovery]:
        """What to do with each slot that started but was never captured: cancel it, then rerun or give up."""
        return [
            Recovery(slot.slot, slot.attempt_id, RERUN if slot.runs < 2 else INTERRUPTED)
            for slot in self.slots(item_id)
            if not slot.captured
        ]

    def slot_interrupted(self, item_id: int, slot: int, attempt_id: str, now: datetime) -> None:
        """Close a twice-interrupted slot; the caller writes its attempt file with the interrupted reason."""
        self.slot_captured(item_id, slot, attempt_id, "", INTERRUPTED, now)
