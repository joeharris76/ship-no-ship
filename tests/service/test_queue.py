from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ship_no_ship_service import queue
from ship_no_ship_service.queue import Queue, QueueError

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
REPO = "example-owner/example-repo"
A, B, C = "a" * 40, "b" * 40, "c" * 40


class Crash(BaseException):
    """Stands for the service being killed: nothing after it in the same process runs."""


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "state" / "state.db"


@pytest.fixture
def q(db_path: Path) -> Queue:
    return Queue(queue.connect(db_path))


def reopen(db_path: Path) -> Queue:
    return Queue(queue.connect(db_path))


def add(q: Queue, pr: int, head: str, run: str, minutes: int = 0, held: bool = False, version: str = "0.1.0"):
    return q.enqueue(REPO, pr, head, run, version, NOW + timedelta(minutes=minutes), held=held)


def test_the_database_is_private_to_its_owner(q, db_path):
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(db_path.parent.stat().st_mode) == 0o700


def test_requests_run_one_at_a_time_oldest_first(q):
    first = add(q, 1, A, "11").item
    second = add(q, 2, B, "12", minutes=1).item
    assert (q.position(first.id), q.position(second.id)) == (1, 2)
    claimed = q.claim_next(NOW)
    assert claimed is not None and claimed.id == first.id and claimed.state == queue.CLAIMED
    assert q.claim_next(NOW) is None
    assert q.position(second.id) == 1
    q.move(first.id, queue.POSTING, NOW)
    q.move(first.id, queue.RECORDING, NOW)
    assert q.claim_next(NOW) is None
    q.move(first.id, queue.DONE, NOW)
    nxt = q.claim_next(NOW)
    assert nxt is not None and nxt.id == second.id


def test_the_same_request_seen_twice_is_known_and_not_added(q):
    first = add(q, 1, A, "11")
    again = add(q, 1, A, "11", minutes=5)
    assert again.outcome == "known" and again.item.id == first.item.id
    assert q.counts() == {queue.QUEUED: 1}


def test_another_run_for_a_queued_or_claimed_head_is_a_duplicate(q):
    first = add(q, 1, A, "11").item
    assert add(q, 1, A, "12").outcome == "duplicate"
    q.claim_next(NOW)
    dup = add(q, 1, A, "13")
    assert dup.outcome == "duplicate" and dup.item.state == queue.DUPLICATE
    assert q.get(first.id).state == queue.CLAIMED


def test_a_request_after_a_finished_review_of_the_same_head_is_queued_again(q):
    first = add(q, 1, A, "11").item
    q.claim_next(NOW)
    q.move(first.id, queue.POSTING, NOW)
    q.move(first.id, queue.DONE, NOW)
    assert add(q, 1, A, "12").outcome == "queued"


def test_a_newer_head_supersedes_queued_claimed_and_held_requests(q):
    claimed = add(q, 1, A, "11").item
    q.claim_next(NOW)
    held = add(q, 2, B, "12", held=True).item
    result = add(q, 1, C, "13")
    assert result.outcome == "queued"
    assert [item.id for item in result.superseded] == [claimed.id]
    assert result.superseded[0].state == queue.SUPERSEDED
    newer_for_two = add(q, 2, C, "14")
    assert [item.id for item in newer_for_two.superseded] == [held.id]
    assert q.get(held.id).state == queue.SUPERSEDED


def test_held_requests_wait_until_their_engine_is_installed(q):
    held = add(q, 1, A, "11", held=True, version="0.2.0")
    assert held.outcome == "held" and held.item.state == queue.VERSION_SKEW
    assert q.claim_next(NOW) is None
    assert q.release_held({"0.1.0"}, NOW) == []
    released = q.release_held({"0.1.0", "0.2.0"}, NOW)
    assert [item.state for item in released] == [queue.QUEUED]
    assert q.claim_next(NOW) is not None


def test_illegal_moves_are_refused(q):
    item = add(q, 1, A, "11").item
    with pytest.raises(QueueError, match="cannot move"):
        q.move(item.id, queue.DONE, NOW)
    with pytest.raises(QueueError, match="not queued"):
        q.claim_next(NOW)
        q.position(item.id)


def test_a_crash_before_the_start_checkpoint_leaves_nothing_to_recover(q, db_path):
    item = add(q, 1, A, "11").item
    q.claim_next(NOW)
    assert reopen(db_path).recover(item.id) == []


def test_a_slot_interrupted_once_is_rerun_and_twice_is_recorded_interrupted(q, db_path):
    item = add(q, 1, A, "11").item
    q.claim_next(NOW)
    q.slot_started(item.id, 1, "codex", "attempt-0001", NOW)
    # The service dies while the reviewer runs; the restart finds the started slot uncaptured.
    restarted = reopen(db_path)
    assert restarted.recover(item.id) == [queue.Recovery(1, "attempt-0001", queue.RERUN)]
    restarted.slot_started(item.id, 1, "codex", "attempt-0002", NOW)
    again = reopen(db_path)
    assert again.recover(item.id) == [queue.Recovery(1, "attempt-0002", queue.INTERRUPTED)]
    again.slot_interrupted(item.id, 1, "attempt-0002", NOW)
    assert again.recover(item.id) == []
    assert again.slots(item.id)[0].scan == queue.INTERRUPTED


def test_a_crash_after_capture_needs_no_recovery(q, db_path):
    item = add(q, 1, A, "11").item
    q.claim_next(NOW)
    q.slot_started(item.id, 1, "claude", "attempt-0001", NOW)
    q.slot_captured(item.id, 1, "attempt-0001", "f" * 64, "clean", NOW)
    restarted = reopen(db_path)
    assert restarted.recover(item.id) == []
    slot = restarted.slots(item.id)[0]
    assert (slot.captured, slot.captured_sha256, slot.scan, slot.runs) == (True, "f" * 64, "clean", 1)


def test_capture_must_name_the_running_attempt_and_slots_cannot_restart_after_capture(q):
    item = add(q, 1, A, "11").item
    q.slot_started(item.id, 1, "claude", "attempt-0001", NOW)
    with pytest.raises(QueueError, match="no uncaptured attempt"):
        q.slot_captured(item.id, 1, "attempt-other", "f" * 64, "clean", NOW)
    with pytest.raises(QueueError, match="already"):
        q.slot_started(item.id, 1, "claude", "attempt-0001", NOW)
    q.slot_captured(item.id, 1, "attempt-0001", "f" * 64, "clean", NOW)
    with pytest.raises(QueueError, match="already"):
        q.slot_started(item.id, 1, "claude", "attempt-0003", NOW)


def test_a_crash_inside_a_transaction_commits_nothing(q, db_path, monkeypatch):
    add(q, 1, A, "11")
    original = q._move

    def die(*args, **kwargs):
        original(*args, **kwargs)
        raise Crash

    monkeypatch.setattr(q, "_move", die)
    with pytest.raises(Crash):
        add(q, 1, B, "12")
    q.db.close()
    assert [item.state for item in reopen(db_path).in_state(queue.QUEUED)] == [queue.QUEUED]
    assert reopen(db_path).counts() == {queue.QUEUED: 1}
