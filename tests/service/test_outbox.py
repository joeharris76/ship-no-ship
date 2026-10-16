from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ship_no_ship_service import outbox, queue
from ship_no_ship_service.outbox import Outbox, OutboxError, Row

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
HEAD = "a" * 40


class Crash(BaseException):
    """Stands for the service being killed mid-call."""


class FakeGitHub:
    """Records each write once, the way GitHub would, and can die just before or just after one."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, dict]] = []
        self.artifacts: set[tuple[str, int]] = set()
        self.crash: str | None = None
        self.fail: Exception | None = None

    def _match(self, row: Row) -> int | None:
        for index, (kind, payload) in enumerate(self.writes):
            if kind == row.kind and payload == dict(row.payload):
                return index
        return None

    def find(self, row: Row) -> str | None:
        index = self._match(row)
        return None if index is None else f"id-{index}"

    def send(self, row: Row) -> str:
        if self.crash == "before":
            raise Crash
        if self.fail is not None:
            raise self.fail
        self.writes.append((row.kind, dict(row.payload)))
        if self.crash == "after":
            raise Crash
        return f"id-{len(self.writes) - 1}"

    def confirmed(self, row: Row) -> bool:
        return (row.payload["plan_run"], row.payload["generation"]) in self.artifacts


PAYLOADS = {
    outbox.STATUS: {"sha": HEAD, "state": "pending", "description": "queued locally (position 1)"},
    outbox.REVIEW: {"commit_id": HEAD, "body": "marker", "event": "COMMENT"},
    outbox.COMMENT: {"body": "Local oracle proof run (not a gate)"},
    outbox.DISPATCH: {"plan_run": "101", "generation": 3, "state": "e30="},
}


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "state" / "state.db"


def open_box(db_path: Path) -> Outbox:
    return Outbox(queue.connect(db_path))


def test_a_row_is_committed_before_anything_is_sent(db_path):
    box = open_box(db_path)
    box.add("status-1", outbox.STATUS, PAYLOADS[outbox.STATUS], NOW, item_id=1)
    other = sqlite3.connect(db_path)
    assert other.execute("SELECT kind, state, tries FROM outbox").fetchall() == [("status", "pending", 0)]


def test_adding_a_key_twice_is_idempotent_but_a_different_payload_is_refused(db_path):
    box = open_box(db_path)
    first = box.add("k", outbox.STATUS, {"a": 1}, NOW)
    assert box.add("k", outbox.STATUS, {"a": 1}, NOW).id == first.id
    with pytest.raises(OutboxError, match="different"):
        box.add("k", outbox.STATUS, {"a": 2}, NOW)
    with pytest.raises(OutboxError, match="unknown"):
        box.add("j", "label", {}, NOW)


@pytest.mark.parametrize("kind", [outbox.STATUS, outbox.REVIEW, outbox.COMMENT, outbox.DISPATCH])
@pytest.mark.parametrize("moment", ["before", "after"])
def test_a_crash_at_a_side_effect_ends_with_exactly_one_write(db_path, kind, moment):
    github = FakeGitHub()
    row = open_box(db_path).add("k", kind, PAYLOADS[kind], NOW)
    github.crash = moment
    with pytest.raises(Crash):
        open_box(db_path).deliver(row.id, github, NOW)
    github.crash = None
    after = open_box(db_path).deliver(row.id, github, NOW + timedelta(seconds=5))
    assert len(github.writes) == 1
    assert after.state == (outbox.SENT if kind == outbox.DISPATCH else outbox.DONE)
    assert after.response_id == "id-0"
    # Delivering a finished row again never writes again.
    open_box(db_path).deliver(row.id, github, NOW + timedelta(minutes=1))
    assert len(github.writes) == 1


def test_a_failed_send_is_retried_after_backoff_and_reconciled_first(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    row = box.add("k", outbox.REVIEW, PAYLOADS[outbox.REVIEW], NOW)
    github.fail = TimeoutError("slow")
    failed = box.deliver(row.id, github, NOW)
    assert (failed.state, failed.tries, "slow" in failed.error) == (outbox.PENDING, 1, True)
    github.fail = None
    assert box.deliver(row.id, github, NOW + timedelta(seconds=30)).state == outbox.PENDING
    assert github.writes == []
    # The timed-out POST actually landed: the retry finds it and does not post twice.
    github.writes.append((outbox.REVIEW, dict(PAYLOADS[outbox.REVIEW])))
    done = box.deliver(row.id, github, NOW + timedelta(minutes=2))
    assert (done.state, len(github.writes)) == (outbox.DONE, 1)


def test_a_dispatch_stays_open_until_its_state_artifact_is_confirmed(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    row = box.add("dispatch-101-3", outbox.DISPATCH, PAYLOADS[outbox.DISPATCH], NOW)
    moments = [NOW]
    box.deliver(row.id, github, NOW)
    clock = NOW
    for minutes in (1, 5, 15, 60, 60):
        before = len(github.writes)
        assert (
            box.deliver(row.id, github, clock + timedelta(minutes=minutes) - timedelta(seconds=1)).state == outbox.SENT
        )
        assert len(github.writes) == before
        clock += timedelta(minutes=minutes)
        sent = box.deliver(row.id, github, clock)
        moments.append(clock)
        assert len(github.writes) == before + 1
    assert [m - NOW for m in moments] == [timedelta(minutes=m) for m in (0, 1, 6, 21, 81, 141)]
    assert sent.alert and box.alerts() == [box.get(row.id)]
    github.artifacts.add(("101", 3))
    done = box.deliver(row.id, github, clock + timedelta(seconds=1))
    assert (done.state, done.alert, box.alerts()) == (outbox.DONE, False, [])


def test_a_crash_after_dispatch_before_confirmation_waits_for_the_artifact(db_path):
    github = FakeGitHub()
    row = open_box(db_path).add("d", outbox.DISPATCH, PAYLOADS[outbox.DISPATCH], NOW)
    open_box(db_path).deliver(row.id, github, NOW)
    github.artifacts.add(("101", 3))
    # The restart confirms the artifact instead of dispatching again.
    assert open_box(db_path).deliver(row.id, github, NOW + timedelta(minutes=30)).state == outbox.DONE
    assert len(github.writes) == 1


def test_deliver_all_moves_every_open_row_for_an_item(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    for index, kind in enumerate((outbox.STATUS, outbox.REVIEW)):
        box.add(f"k{index}", kind, PAYLOADS[kind], NOW, item_id=7)
    box.add("other", outbox.STATUS, {"x": 1}, NOW, item_id=8)
    rows = box.deliver_all(github, NOW, item_id=7)
    assert [row.state for row in rows] == [outbox.DONE, outbox.DONE]
    assert [row.key for row in box.open_rows()] == ["other"]


def test_backoff_schedule():
    assert [outbox.backoff(n) for n in range(1, 7)] == [timedelta(minutes=m) for m in (1, 5, 15, 60, 60, 60)]
