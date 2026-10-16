"""The durable review queue: one row per request, and a checkpoint per reviewer slot.

Everything lives in one SQLite database owned by the daemon user, so a restart resumes from what was
committed. A request is keyed by repository, pull request, head and the plan run that made it. Only one
request runs at a time, oldest first.

Requests for one pull request are ordered by the state generation their plan read and then by when the
plan run was created. A request older than one already waiting for another head, or older than the
newest finished review of another head, is recorded as stale and never replaces it; a newer one supersedes waiting and claimed requests for older heads. A request
that is already posting or recording finishes: posting re-checks the head before each write.

A slot is checkpointed as started before the reviewer is launched and as captured after its output is
copied. A slot that started but was never captured was interrupted: the first time it is run again, the
second time it is recorded as interrupted so the reviewer chain moves on.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from collections.abc import Generator, Mapping
from contextlib import contextmanager
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
# Posting and recording items are past the point where a newer request may take their place.
REPLACEABLE = (QUEUED, VERSION_SKEW, CLAIMED)
TRANSITIONS = {
    QUEUED: {CLAIMED, SUPERSEDED, FAILED},
    VERSION_SKEW: {QUEUED, SUPERSEDED, FAILED},
    CLAIMED: {POSTING, SUPERSEDED, FAILED},
    POSTING: {RECORDING, DONE, SUPERSEDED, FAILED},
    RECORDING: {DONE, FAILED},
}

RERUN = "rerun"
INTERRUPTED = "interrupted"
CLEAN = "clean"
SCAN_FAILURES = ("hit", "unreadable")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY,
    repo TEXT NOT NULL,
    pr INTEGER NOT NULL,
    head_sha TEXT NOT NULL,
    plan_run_id TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    engine_sha256 TEXT NOT NULL,
    generation INTEGER NOT NULL,
    planned_at TEXT NOT NULL,
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
    """Open the state database with write-ahead logging and full syncs, private to its owner.

    The database and its -wal and -shm files are set to 0600 and must belong to this user. The
    connection is in autocommit mode; multi-statement writes go through ``transaction``.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.close(os.open(path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600))
    db = sqlite3.connect(path, timeout=30, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA foreign_keys=ON")
    for name in (path.name, f"{path.name}-wal", f"{path.name}-shm"):
        member = path.with_name(name)
        try:
            info = member.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            db.close()
            raise QueueError(f"{member} is not a regular file owned by the service user")
        if stat.S_IMODE(info.st_mode) != 0o600:
            member.chmod(0o600)
    return db


@contextmanager
def transaction(db: sqlite3.Connection) -> Generator[sqlite3.Connection]:
    """A write transaction that takes the write lock before its first read."""
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
    except BaseException:
        db.execute("ROLLBACK")
        raise
    db.execute("COMMIT")


@dataclass(frozen=True)
class Request:
    repo: str
    pr: int
    head_sha: str
    plan_run_id: str
    engine_version: str
    engine_sha256: str
    generation: int  # the retry state generation the plan read
    planned_at: datetime  # when GitHub created the plan run

    def order(self) -> tuple[int, str]:
        return self.generation, self.planned_at.isoformat()


@dataclass(frozen=True)
class Item:
    id: int
    repo: str
    pr: int
    head_sha: str
    plan_run_id: str
    engine_version: str
    engine_sha256: str
    generation: int
    planned_at: str
    state: str
    reason: str
    enqueued_at: str

    def order(self) -> tuple[int, str]:
        return self.generation, self.planned_at


@dataclass(frozen=True)
class Enqueued:
    item: Item
    outcome: str  # queued, held, duplicate, stale or known
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

    def _insert(self, request: Request, state: str, reason: str, stamp: str) -> int:
        cursor = self.db.execute(
            "INSERT INTO items (repo, pr, head_sha, plan_run_id, engine_version, engine_sha256, generation,"
            " planned_at, state, reason, enqueued_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                request.repo,
                request.pr,
                request.head_sha,
                request.plan_run_id,
                request.engine_version,
                request.engine_sha256,
                request.generation,
                request.planned_at.isoformat(),
                state,
                reason,
                stamp,
                stamp,
            ),
        )
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    def enqueue(self, request: Request, now: datetime, *, held: bool) -> Enqueued:
        """Record a request: queued, held, a duplicate of a waiting head, stale, or superseding older heads."""
        stamp = now.isoformat()
        superseded: list[Item] = []
        with transaction(self.db):
            known = self.db.execute(
                "SELECT * FROM items WHERE repo = ? AND pr = ? AND head_sha = ? AND plan_run_id = ?",
                (request.repo, request.pr, request.head_sha, request.plan_run_id),
            ).fetchone()
            if known is not None:
                return Enqueued(_item(known), "known")
            active = self.active(request.repo, request.pr)
            others = [item for item in active if item.head_sha != request.head_sha]
            finished = self._items("repo = ? AND pr = ? AND state = ?", (request.repo, request.pr, DONE))
            latest = max(finished, key=Item.order, default=None)
            if latest is not None and latest.head_sha != request.head_sha:
                others_and_finished = [*others, latest]
            else:
                others_and_finished = others
            newer = [item for item in others_and_finished if item.order() >= request.order()]
            if any(item.head_sha == request.head_sha for item in active):
                outcome, state, reason = "duplicate", DUPLICATE, "a request for this head is already waiting"
            elif newer:
                outcome, state = "stale", SUPERSEDED
                reason = f"older than the request for head {newer[0].head_sha}"
            else:
                outcome, state, reason = ("held", VERSION_SKEW, "") if held else ("queued", QUEUED, "")
                for item in others:
                    if item.state in REPLACEABLE:
                        self._move(item, SUPERSEDED, f"a request for head {request.head_sha} replaced it", stamp)
                        superseded.append(item)
            item_id = self._insert(request, state, reason, stamp)
        return Enqueued(self.get(item_id), outcome, tuple(self.get(item.id) for item in superseded))

    def _move(self, item: Item, state: str, reason: str, stamp: str) -> None:
        if state not in TRANSITIONS.get(item.state, set()):
            raise QueueError(f"item {item.id} cannot move from {item.state} to {state}")
        if state == POSTING:
            self._check_slots(item.id)
        if state == DONE:
            self._check_outbox(item.id)
        changed = self.db.execute(
            "UPDATE items SET state = ?, reason = ?, updated_at = ? WHERE id = ? AND state = ?",
            (state, reason, stamp, item.id, item.state),
        ).rowcount
        if changed != 1:
            raise QueueError(f"item {item.id} changed while it was being moved to {state}")

    def _check_slots(self, item_id: int) -> None:
        """Posting needs a closed history: no open slot, no failed scan, and at least one clean capture.

        A twice-interrupted slot is closed as interrupted so that the reviewer chain can move on; it is
        allowed, but it never counts as the clean capture.
        """
        slots = self.slots(item_id)
        if any(not slot.captured for slot in slots):
            raise QueueError(f"item {item_id} has a slot that was started but not captured")
        if any(slot.scan in SCAN_FAILURES for slot in slots):
            raise QueueError(f"item {item_id} has output that failed the credential scan")
        if not any(slot.scan == CLEAN for slot in slots):
            raise QueueError(f"item {item_id} has no cleanly captured slot")

    def _check_outbox(self, item_id: int) -> None:
        table = self.db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'outbox'").fetchone()
        if table is None:
            return
        unfinished = self.db.execute(
            "SELECT COUNT(*) FROM outbox WHERE item_id = ? AND state NOT IN ('done', 'abandoned')", (item_id,)
        ).fetchone()[0]
        if unfinished:
            raise QueueError(f"item {item_id} still has {unfinished} unfinished outbox writes")
        abandoned = self.db.execute(
            "SELECT COUNT(*) FROM outbox WHERE item_id = ? AND state = 'abandoned' AND kind IN ('review', 'comment')",
            (item_id,),
        ).fetchone()[0]
        if abandoned:
            raise QueueError(f"item {item_id} never posted its result; move it to failed or superseded, not done")

    def move(self, item_id: int, state: str, now: datetime, reason: str = "") -> Item:
        with transaction(self.db):
            self._move(self.get(item_id), state, reason, now.isoformat())
        return self.get(item_id)

    def claim_next(self, now: datetime) -> Item | None:
        """Claim the oldest queued request, unless one is already running."""
        with transaction(self.db):
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

    def release_held(self, installed: Mapping[str, str], now: datetime) -> list[Item]:
        """Queue held requests whose engine version is installed with the same build digest."""
        with transaction(self.db):
            released = [
                item for item in self.in_state(VERSION_SKEW) if installed.get(item.engine_version) == item.engine_sha256
            ]
            for item in released:
                self._move(item, QUEUED, "its engine is installed", now.isoformat())
        return [self.get(item.id) for item in released]

    def counts(self) -> dict[str, int]:
        return {row[0]: row[1] for row in self.db.execute("SELECT state, COUNT(*) FROM items GROUP BY state")}

    def slot_started(self, item_id: int, slot: int, reviewer: str, attempt_id: str, now: datetime) -> None:
        """Checkpoint a slot before its reviewer starts. Starting an uncaptured slot again counts a second run."""
        with transaction(self.db):
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
