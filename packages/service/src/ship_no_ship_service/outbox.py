"""The outbox: every public write is committed to SQLite before it is sent.

A row holds the full payload of one status, review, comment or record dispatch. Before a send, the
attempt is counted and committed; so after a crash, a row with a counted attempt but no recorded
response is ambiguous, and GitHub is read first to see whether the write landed. It is sent again only
if GitHub still shows nothing after a short settling time, which allows for read-after-write lag.

How a write is found again:

- Reviews and comments carry a hidden ``<!-- ship-no-ship-write ... -->`` line at the top of the body,
  unique to the row. The oracle's protocol marker stays the last line, where the required check reads it.
- Statuses cannot carry a hidden marker. They are found by commit, context, state and description, and
  posting an identical status twice is harmless.
- Record dispatches cannot carry one either: the record workflow's inputs are fixed. ``Effects.find``
  reports a record run for this plan run that is queued, running or succeeded (never a failed one), and
  ``Effects.confirmed`` reports the state artifact for this generation. Sending a dispatch again is
  safe because record-state accepts an identical state as a no-op.

A record dispatch stays open after it is sent, until its state artifact is confirmed. Until then it is
sent again on a backoff of 1, 5, 15 and 60 minutes, then hourly; the row asks for an alert once the
backoff reaches hourly. Failed sends of other kinds back off the same way. A row whose write no longer
applies (the pull request closed or moved on) is abandoned.

A status describes one moment, so an older one must never land after a newer one for the same commit
and context. Before a status row is sent or looked for, it is abandoned if a later status row exists
for that commit and context, or if its queue item has left the states the status describes
(``applies_in``). Without this, a queued status waiting out a backoff could be posted after the
final result and leave the pull request showing pending.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from .queue import transaction

STATUS = "status"
REVIEW = "review"
COMMENT = "comment"
DISPATCH = "dispatch"
KINDS = (STATUS, REVIEW, COMMENT, DISPATCH)
MARKED = (REVIEW, COMMENT)

PENDING = "pending"
SENT = "sent"
DONE = "done"
ABANDONED = "abandoned"
CLOSED = (DONE, ABANDONED)

BACKOFF = (timedelta(minutes=1), timedelta(minutes=5), timedelta(minutes=15), timedelta(minutes=60))
HOURLY = timedelta(hours=1)
SETTLE = timedelta(seconds=30)
ERROR_LIMIT = 500

_SECRETS = re.compile(
    r"(?i)(?:\b(?:bearer|token)\s+\S+"
    r"|\bgh[pousr]_[A-Za-z0-9_]{8,}"
    r"|\bgithub_pat_[A-Za-z0-9_]{8,}"
    r"|\beyJ[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*){0,2}"
    r"|[A-Za-z0-9+/_-]{32,}={0,2})"
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY,
    item_id INTEGER,
    key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    state TEXT NOT NULL,
    tries INTEGER NOT NULL DEFAULT 0,
    tried_at TEXT,
    response_id TEXT,
    error TEXT NOT NULL DEFAULT '',
    next_at TEXT NOT NULL,
    alert INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    applies_in TEXT
);
"""


class OutboxError(RuntimeError):
    pass


def scrub(text: str) -> str:
    """Error text safe to store: anything shaped like a token or other long secret is replaced."""
    return _SECRETS.sub("[redacted]", text)[:ERROR_LIMIT]


def marker(key: str) -> str:
    return f"<!-- ship-no-ship-write {hashlib.sha256(key.encode()).hexdigest()[:24]} -->"


@dataclass(frozen=True)
class Row:
    id: int
    item_id: int | None
    key: str
    kind: str
    payload: Mapping[str, Any]
    state: str
    tries: int
    tried_at: str | None
    response_id: str | None
    error: str
    next_at: str
    alert: bool
    applies_in: tuple[str, ...] | None = None

    @property
    def marker(self) -> str | None:
        """The hidden line that identifies this write on GitHub, for reviews and comments."""
        return marker(self.key) if self.kind in MARKED else None


class Effects(Protocol):
    """How the outbox reaches GitHub. Implementations re-check the pull request before each write."""

    def find(self, row: Row) -> str | None:
        """The ID of the write if GitHub already shows it, else None (see the module notes per kind)."""
        ...

    def send(self, row: Row) -> str:
        """Perform the write and return its ID."""
        ...

    def confirmed(self, row: Row) -> bool:
        """For a dispatch: whether the record workflow's state artifact for this generation exists."""
        ...


def backoff(tries: int) -> timedelta:
    return BACKOFF[tries - 1] if 0 < tries <= len(BACKOFF) else HOURLY


def _encode(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _row(row: sqlite3.Row) -> Row:
    return Row(
        id=row["id"],
        item_id=row["item_id"],
        key=row["key"],
        kind=row["kind"],
        payload=json.loads(row["payload"]),
        state=row["state"],
        tries=row["tries"],
        tried_at=row["tried_at"],
        response_id=row["response_id"],
        error=row["error"],
        next_at=row["next_at"],
        alert=bool(row["alert"]),
        applies_in=None if row["applies_in"] is None else tuple(json.loads(row["applies_in"])),
    )


class Outbox:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db
        db.executescript(_SCHEMA)
        columns = {row[1] for row in db.execute("PRAGMA table_info(outbox)")}
        if "applies_in" not in columns:
            db.execute("ALTER TABLE outbox ADD COLUMN applies_in TEXT")

    def add(
        self,
        key: str,
        kind: str,
        payload: Mapping[str, Any],
        now: datetime,
        item_id: int | None = None,
        applies_in: Iterable[str] | None = None,
    ) -> Row:
        """Commit a write before it is sent. Adding the same key again returns the existing row unchanged.

        Review and comment bodies get the row's hidden marker as their first line. ``applies_in`` names
        the queue states of ``item_id`` in which the write still applies; outside them it is abandoned.
        """
        if kind not in KINDS:
            raise OutboxError(f"unknown outbox kind {kind!r}")
        if kind in MARKED:
            payload = {**payload, "body": f"{marker(key)}\n{payload.get('body', '')}"}
        body = _encode(payload)
        stamp = now.isoformat()
        states = None if applies_in is None else json.dumps(sorted(set(applies_in)))
        if states is not None and item_id is None:
            raise OutboxError(f"outbox key {key} names the states it applies in but no queue item")
        with transaction(self.db):
            self.db.execute(
                "INSERT INTO outbox (item_id, key, kind, payload, state, next_at, created_at, updated_at, applies_in)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (key) DO NOTHING",
                (item_id, key, kind, body, PENDING, stamp, stamp, stamp, states),
            )
        row = self.get_key(key)
        if row.kind != kind or _encode(row.payload) != body:
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
        query = "SELECT * FROM outbox WHERE state NOT IN (?, ?)" + ("" if item_id is None else " AND item_id = ?")
        args = CLOSED if item_id is None else (*CLOSED, item_id)
        return [_row(row) for row in self.db.execute(query + " ORDER BY id", args)]

    def alerts(self) -> list[Row]:
        query = "SELECT * FROM outbox WHERE state NOT IN (?, ?) AND alert = 1 ORDER BY id"
        return [_row(row) for row in self.db.execute(query, CLOSED)]

    def _update(self, row: Row, now: datetime, **values: Any) -> Row:
        values["updated_at"] = now.isoformat()
        columns = ", ".join(f"{name} = ?" for name in values)
        self.db.execute(f"UPDATE outbox SET {columns} WHERE id = ?", (*values.values(), row.id))  # noqa: S608
        return self.get(row.id)

    def abandon(self, row_id: int, reason: str, now: datetime) -> Row:
        """Close a row whose write no longer applies, for example because the head moved on."""
        row = self.get(row_id)
        if row.state in CLOSED:
            return row
        return self._update(row, now, state=ABANDONED, error=scrub(reason), alert=0)

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
        if row.state in CLOSED:
            return row
        outdated = self._outdated(row)
        if outdated is not None:
            return self._update(row, now, state=ABANDONED, error=scrub(outdated), alert=0)
        if row.state == SENT:
            if effects.confirmed(row):
                return self._update(row, now, state=DONE, alert=0)
            if now < datetime.fromisoformat(row.next_at):
                return row
            if effects.find(row) is not None:
                # The record run is still going; wait one more step before dispatching again.
                return self._sent(self._update(row, now, tries=row.tries + 1), row.response_id or "", now)
            return self._send(row, effects, now)
        if row.tries:
            found = effects.find(row)
            if found is not None:
                return self._sent(row, found, now)
            if row.tried_at is not None and now - datetime.fromisoformat(row.tried_at) < SETTLE:
                return row
        if now < datetime.fromisoformat(row.next_at):
            return row
        return self._send(row, effects, now)

    def _outdated(self, row: Row) -> str | None:
        """Why a status row no longer describes its commit, or None while it still does."""
        if row.kind != STATUS:
            return None
        newer = self.db.execute(
            "SELECT key FROM outbox WHERE kind = ? AND id > ? AND json_extract(payload, '$.sha') = ?"
            " AND json_extract(payload, '$.context') IS ? ORDER BY id DESC LIMIT 1",
            (STATUS, row.id, row.payload.get("sha"), row.payload.get("context")),
        ).fetchone()
        if newer is not None:
            return f"a later status for this commit and context ({newer[0]}) replaces it"
        if row.applies_in is None or row.item_id is None:
            return None
        table = self.db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'items'").fetchone()
        if table is None:
            return None
        item = self.db.execute("SELECT state FROM items WHERE id = ?", (row.item_id,)).fetchone()
        if item is not None and item[0] not in row.applies_in:
            return f"item {row.item_id} is now {item[0]}, which this status does not describe"
        return None

    def _send(self, row: Row, effects: Effects, now: datetime) -> Row:
        tries = row.tries + 1
        wait = now + backoff(tries)
        alert = int(tries > len(BACKOFF))
        # Count the attempt before the side effect, so a crash during it is known to be ambiguous.
        next_at = (now if row.state == PENDING else wait).isoformat()
        row = self._update(row, now, tries=tries, tried_at=now.isoformat(), next_at=next_at)
        try:
            response_id = effects.send(row)
        except Exception as exc:  # noqa: BLE001 - any failure is recorded and retried
            error = scrub(f"{type(exc).__name__}: {exc}")
            return self._update(row, now, error=error, next_at=wait.isoformat(), alert=alert)
        return self._sent(row, response_id, now)

    def deliver_all(self, effects: Effects, now: datetime, item_id: int | None = None) -> list[Row]:
        return [self.deliver(row.id, effects, now) for row in self.open_rows(item_id)]
