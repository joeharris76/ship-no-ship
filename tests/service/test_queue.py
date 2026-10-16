from __future__ import annotations

import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ship_no_ship_service import outbox, queue
from ship_no_ship_service.queue import Queue, QueueError, Request

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
REPO = "example-owner/example-repo"
A, B, C = "a" * 40, "b" * 40, "c" * 40
ENGINE = ("0.1.0", "e" * 64)


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


def request(pr: int, head: str, run: str, minutes: int = 0, generation: int = 0, engine=ENGINE) -> Request:
    return Request(REPO, pr, head, run, engine[0], engine[1], generation, NOW + timedelta(minutes=minutes))


def add(q: Queue, pr: int, head: str, run: str, minutes: int = 0, held: bool = False, **kwargs):
    return q.enqueue(request(pr, head, run, minutes, **kwargs), NOW + timedelta(minutes=minutes), held=held)


def finish_slots(q: Queue, item_id: int, scan: str = "clean") -> None:
    q.slot_started(item_id, 1, "claude", f"attempt-{item_id:04d}", NOW)
    q.slot_captured(item_id, 1, f"attempt-{item_id:04d}", "f" * 64, scan, NOW)


def test_the_database_and_its_journal_files_are_private_to_their_owner(q, db_path):
    q.db.close()
    for name in ("state.db-wal", "state.db-shm"):
        db_path.with_name(name).touch()
        db_path.with_name(name).chmod(0o644)
    reopened = reopen(db_path)
    for name in ("state.db", "state.db-wal", "state.db-shm"):
        assert stat.S_IMODE(db_path.with_name(name).stat().st_mode) == 0o600
    assert stat.S_IMODE(db_path.parent.stat().st_mode) == 0o700
    reopened.db.close()


def test_a_database_owned_by_someone_else_is_refused(db_path, monkeypatch):
    reopen(db_path).db.close()
    monkeypatch.setattr(queue.os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(QueueError, match="owned by the service user"):
        queue.connect(db_path)


def test_requests_run_one_at_a_time_oldest_first(q):
    first = add(q, 1, A, "11").item
    second = add(q, 2, B, "12", minutes=1).item
    assert (q.position(first.id), q.position(second.id)) == (1, 2)
    claimed = q.claim_next(NOW)
    assert claimed is not None and claimed.id == first.id and claimed.state == queue.CLAIMED
    assert q.claim_next(NOW) is None
    assert q.position(second.id) == 1
    finish_slots(q, first.id)
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
    assert add(q, 1, A, "12", minutes=1).outcome == "duplicate"
    q.claim_next(NOW)
    dup = add(q, 1, A, "13", minutes=2)
    assert dup.outcome == "duplicate" and dup.item.state == queue.DUPLICATE
    assert q.get(first.id).state == queue.CLAIMED


def test_a_request_after_a_finished_review_of_the_same_head_is_queued_again(q):
    first = add(q, 1, A, "11").item
    q.claim_next(NOW)
    finish_slots(q, first.id)
    q.move(first.id, queue.POSTING, NOW)
    q.move(first.id, queue.DONE, NOW)
    assert add(q, 1, A, "12", minutes=1).outcome == "queued"


def test_a_newer_head_supersedes_queued_claimed_and_held_requests(q):
    claimed = add(q, 1, A, "11").item
    q.claim_next(NOW)
    held = add(q, 2, B, "12", held=True).item
    result = add(q, 1, C, "13", minutes=1)
    assert result.outcome == "queued"
    assert [item.id for item in result.superseded] == [claimed.id]
    assert result.superseded[0].state == queue.SUPERSEDED
    newer_for_two = add(q, 2, C, "14", minutes=1)
    assert [item.id for item in newer_for_two.superseded] == [held.id]


def test_a_recording_item_finishes_and_the_new_head_is_still_queued(q):
    old = add(q, 1, A, "11").item
    q.claim_next(NOW)
    finish_slots(q, old.id)
    q.move(old.id, queue.POSTING, NOW)
    q.move(old.id, queue.RECORDING, NOW)
    result = add(q, 1, B, "12", minutes=1)
    assert (result.outcome, result.superseded) == ("queued", ())
    assert q.get(old.id).state == queue.RECORDING
    q.move(old.id, queue.DONE, NOW)
    claimed = q.claim_next(NOW)
    assert claimed is not None and claimed.head_sha == B


@pytest.mark.parametrize("newer_first", [True, False])
def test_an_older_head_never_replaces_a_newer_one_in_either_arrival_order(q, newer_first):
    older = request(1, A, "11", minutes=0)
    newer = request(1, B, "12", minutes=5)
    arrivals = [newer, older] if newer_first else [older, newer]
    results = [q.enqueue(item, NOW, held=False) for item in arrivals]
    assert [item.head_sha for item in q.in_state(queue.QUEUED)] == [B]
    if newer_first:
        assert results[1].outcome == "stale"
        assert results[1].item.reason == f"older than the request for head {B}"
    else:
        assert [item.head_sha for item in results[1].superseded] == [A]


def test_a_later_plan_run_with_a_lower_generation_is_stale(q):
    q.enqueue(request(1, B, "12", minutes=0, generation=3), NOW, held=False)
    assert q.enqueue(request(1, A, "13", minutes=5, generation=2), NOW, held=False).outcome == "stale"


def test_held_requests_wait_until_their_exact_engine_build_is_installed(q):
    held = add(q, 1, A, "11", held=True, engine=("0.2.0", "d" * 64))
    assert held.outcome == "held" and held.item.state == queue.VERSION_SKEW
    assert held.item.engine_sha256 == "d" * 64
    assert q.claim_next(NOW) is None
    assert q.release_held({"0.1.0": "e" * 64}, NOW) == []
    assert q.release_held({"0.2.0": "0" * 64}, NOW) == []
    released = q.release_held({"0.2.0": "d" * 64}, NOW)
    assert [item.state for item in released] == [queue.QUEUED]
    assert q.claim_next(NOW) is not None


def test_illegal_moves_are_refused(q):
    item = add(q, 1, A, "11").item
    with pytest.raises(QueueError, match="cannot move"):
        q.move(item.id, queue.DONE, NOW)
    q.claim_next(NOW)
    with pytest.raises(QueueError, match="not queued"):
        q.position(item.id)


@pytest.mark.parametrize(
    ("slots", "message"),
    [
        ([], "no cleanly captured slot"),
        ([("open", None)], "started but not captured"),
        ([("captured", "clean"), ("captured", "hit")], "failed the credential scan"),
        ([("captured", "unreadable")], "failed the credential scan"),
        ([("interrupted", None)], "no cleanly captured slot"),
    ],
)
def test_posting_needs_a_closed_history_with_a_clean_capture(q, slots, message):
    item = add(q, 1, A, "11").item
    q.claim_next(NOW)
    for number, (how, scan) in enumerate(slots, start=1):
        q.slot_started(item.id, number, "claude", f"attempt-{number:04d}", NOW)
        if how == "captured":
            q.slot_captured(item.id, number, f"attempt-{number:04d}", "f" * 64, scan, NOW)
        elif how == "interrupted":
            q.slot_interrupted(item.id, number, f"attempt-{number:04d}", NOW)
    with pytest.raises(QueueError, match=message):
        q.move(item.id, queue.POSTING, NOW)


def test_an_interrupted_slot_is_allowed_beside_a_clean_one(q):
    item = add(q, 1, A, "11").item
    q.claim_next(NOW)
    q.slot_started(item.id, 1, "codex", "attempt-0001", NOW)
    q.slot_interrupted(item.id, 1, "attempt-0001", NOW)
    q.slot_started(item.id, 2, "claude", "attempt-0002", NOW)
    q.slot_captured(item.id, 2, "attempt-0002", "f" * 64, "clean", NOW)
    assert q.move(item.id, queue.POSTING, NOW).state == queue.POSTING


def test_done_needs_every_outbox_write_finished(q):
    box = outbox.Outbox(q.db)
    item = add(q, 1, A, "11").item
    q.claim_next(NOW)
    finish_slots(q, item.id)
    q.move(item.id, queue.POSTING, NOW)
    row = box.add("status-1", outbox.STATUS, {"sha": A}, NOW, item_id=item.id)
    with pytest.raises(QueueError, match="1 unfinished outbox writes"):
        q.move(item.id, queue.DONE, NOW)
    box.abandon(row.id, "the pull request closed", NOW)
    assert q.move(item.id, queue.DONE, NOW).state == queue.DONE


def test_a_slot_interrupted_once_is_rerun_and_twice_is_recorded_interrupted(q, db_path):
    item = add(q, 1, A, "11").item
    q.claim_next(NOW)
    q.slot_started(item.id, 1, "codex", "attempt-0001", NOW)
    restarted = reopen(db_path)
    assert restarted.recover(item.id) == [queue.Recovery(1, "attempt-0001", queue.RERUN)]
    restarted.slot_started(item.id, 1, "codex", "attempt-0002", NOW)
    again = reopen(db_path)
    assert again.recover(item.id) == [queue.Recovery(1, "attempt-0002", queue.INTERRUPTED)]
    again.slot_interrupted(item.id, 1, "attempt-0002", NOW)
    assert again.recover(item.id) == []
    assert again.slots(item.id)[0].scan == queue.INTERRUPTED


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
        add(q, 1, B, "12", minutes=1)
    q.db.close()
    assert reopen(db_path).counts() == {queue.QUEUED: 1}
