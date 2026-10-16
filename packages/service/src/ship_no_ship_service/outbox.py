"""The outbox: every public write is committed to SQLite before it is sent.

A row holds the full payload of one status, review, comment or record dispatch. Before a send, the
attempt is counted and committed; so after a crash, a row with a counted attempt but no recorded
response is ambiguous, and GitHub is read first to see whether the write landed. It is sent again only
if GitHub shows nothing.

A record dispatch stays open after it is sent, until the record workflow's state artifact for that
generation is confirmed. Until then it is sent again on a backoff of 1, 5, 15 and 60 minutes, then
hourly; the row asks for an alert once the backoff reaches hourly. Failed sends of other kinds back off
the same way.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

STATUS = "status"
REVIEW = "review"
COMMENT = "comment"
DISPATCH = "dispatch"
KINDS = (STATUS, REVIEW, COMMENT, DISPATCH)

PENDING = "pending"
SENT = "sent"
DONE = "done"

BACKOFF = (timedelta(minutes=1), timedelta(minutes=5), timedelta(minutes=15), timedelta(minutes=60))
HOURLY = timedelta(hours=1)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY,
    item_id INTEGER,
    key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    state TEXT NOT NULL,
    tries INTEGER NOT NULL DEFAULT 0,
    response_id TEXT,
    error TEXT NOT NULL DEFAULT '',
    next_at TEXT NOT NULL,
    alert INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


class OutboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class Row:
    id: int
    item_id: int | None
    key: str
    kind: str
    payload: Mapping[str, Any]
    state: str
    tries: int
    response_id: str | None
    error: str
    next_at: str
    alert: bool


class Effects(Protocol):
    """How the outbox reaches GitHub. Implementations re-check the pull request before each write."""

    def find(self, row: Row) -> str | None:
        """The ID of the write if GitHub already shows it, else None."""
        ...

    def send(self, row: Row) -> str:
        """Perform the write and return its ID."""
        ...

    def confirmed(self, row: Row) -> bool:
        """For a dispatch: whether the record workflow's state artifact for this generation exists."""
        ...


def backoff(tries: int) -> timedelta:
    return BACKOFF[tries - 1] if 0 < tries <= len(BACKOFF) else HOURLY


def _row(row: sqlite3.Row) -> Row:
    return Row(
        id=row["id"],
        item_id=row["item_id"],
        key=row["key"],
        kind=row["kind"],
        payload=json.loads(row["payload"]),
        state=row["state"],
        tries=row["tries"],
        response_id=row["response_id"],
        error=row["error"],
        next_at=row["next_at"],
        alert=bool(row["alert"]),
    )


class Outbox:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db
        with db:
            db.executescript(_SCHEMA)

    def add(self, key: str, kind: str, payload: Mapping[str, Any], now: datetime, item_id: int | None = None) -> Row:
        """Commit a write before it is sent. Adding the same key again returns the existing row unchanged."""
        if kind not in KINDS:
            raise OutboxError(f"unknown outbox kind {kind!r}")
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        stamp = now.isoformat()
        with self.db:
            self.db.execute(
                "INSERT INTO outbox (item_id, key, kind, payload, state, next_at, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (key) DO NOTHING",
                (item_id, key, kind, body, PENDING, stamp, stamp, stamp),
            )
        row = self.get_key(key)
        if row.kind != kind or json.dumps(row.payload, sort_keys=True, separators=(",", ":")) != body:
            raise OutboxError(f"outbox key {key} already holds a different write")
        return row

    def get(self, row_id: int) -> Row:
        found = self.db.execute("SELECT * FROM outbox WHERE id = ?", (row_id,)).fetchone()
        if found is None:
            raise OutboxError(f"no outbox row {row_id}")
        return _row(found)

    def get_key(self, key: str) -> Row:
        found = self.db.execute("SELECT * FROM outbox WHERE key = ?", (key,)).fetchone()
        if found is None:
            raise OutboxError(f"no outbox row {key}")
        return _row(found)

    def open_rows(self, item_id: int | None = None) -> list[Row]:
        query = "SELECT * FROM outbox WHERE state != ?" + ("" if item_id is None else " AND item_id = ?")
        args = (DONE,) if item_id is None else (DONE, item_id)
        return [_row(row) for row in self.db.execute(query + " ORDER BY id", args)]

    def alerts(self) -> list[Row]:
        return [_row(row) for row in self.db.execute("SELECT * FROM outbox WHERE state != ? AND alert = 1", (DONE,))]

    def _update(self, row: Row, now: datetime, **values: Any) -> Row:
        values["updated_at"] = now.isoformat()
        columns = ", ".join(f"{name} = ?" for name in values)
        with self.db:
            self.db.execute(f"UPDATE outbox SET {columns} WHERE id = ?", (*values.values(), row.id))  # noqa: S608
        return self.get(row.id)

    def _sent(self, row: Row, response_id: str, now: datetime) -> Row:
        if row.kind == DISPATCH:
            # Wait for the record workflow; send again on the backoff if its state never appears.
            wait = (now + backoff(row.tries)).isoformat()
            alert = int(row.tries > len(BACKOFF))
            return self._update(row, now, state=SENT, response_id=response_id, error="", next_at=wait, alert=alert)
        return self._update(row, now, state=DONE, response_id=response_id, error="", alert=0)

    def deliver(self, row_id: int, effects: Effects, now: datetime) -> Row:
        """Move one row as far as it can go now. A send that raises is recorded and retried later."""
        row = self.get(row_id)
        if row.state == DONE:
            return row
        if row.state == SENT:
            if effects.confirmed(row):
                return self._update(row, now, state=DONE, alert=0)
            if now < datetime.fromisoformat(row.next_at):
                return row
            return self._send(row, effects, now)
        if row.tries:
            found = effects.find(row)
            if found is not None:
                return self._sent(row, found, now)
        if now < datetime.fromisoformat(row.next_at):
            return row
        return self._send(row, effects, now)

    def _send(self, row: Row, effects: Effects, now: datetime) -> Row:
        tries = row.tries + 1
        wait = now + backoff(tries)
        alert = int(tries > len(BACKOFF))
        # Count the attempt before the side effect, so a crash during it is known to be ambiguous.
        row = self._update(row, now, tries=tries, next_at=(now if row.state == PENDING else wait).isoformat())
        try:
            response_id = effects.send(row)
        except Exception as exc:  # noqa: BLE001 - any failure is recorded and retried
            return self._update(
                row, now, error=f"{type(exc).__name__}: {exc}"[:500], next_at=wait.isoformat(), alert=alert
            )
        return self._sent(row, response_id, now)

    def deliver_all(self, effects: Effects, now: datetime, item_id: int | None = None) -> list[Row]:
        return [self.deliver(row.id, effects, now) for row in self.open_rows(item_id)]
