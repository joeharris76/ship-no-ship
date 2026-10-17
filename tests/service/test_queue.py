from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import replace
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


def test_an_older_head_rerun_after_the_newer_head_finished_is_stale(q):
    newer = add(q, 1, B, "12", minutes=5).item
    q.claim_next(NOW)
    finish_slots(q, newer.id)
    q.move(newer.id, queue.POSTING, NOW)
    q.move(newer.id, queue.DONE, NOW)
    late = q.enqueue(request(1, A, "11", minutes=0), NOW + timedelta(minutes=10), held=False)
    assert (late.outcome, late.item.reason) == ("stale", f"older than the request for head {B}")
    assert q.in_state(queue.QUEUED) == []
    assert add(q, 1, C, "13", minutes=9).outcome == "queued"


@pytest.mark.parametrize("kind", [outbox.REVIEW, outbox.COMMENT])
def test_an_item_whose_result_was_abandoned_cannot_be_done(q, kind):
    box = outbox.Outbox(q.db)
    item = add(q, 1, A, "11").item
    q.claim_next(NOW)
    finish_slots(q, item.id)
    q.move(item.id, queue.POSTING, NOW)
    row = box.add("result-1", kind, {"body": "x"}, NOW, item_id=item.id)
    box.abandon(row.id, "the head moved", NOW)
    with pytest.raises(QueueError, match="never posted its result"):
        q.move(item.id, queue.DONE, NOW)
    assert q.move(item.id, queue.SUPERSEDED, NOW).state == queue.SUPERSEDED


def finish(q: Queue, item_id: int) -> None:
    claimed = q.claim_next(NOW)
    assert claimed is not None and claimed.id == item_id
    finish_slots(q, item_id)
    q.move(item_id, queue.POSTING, NOW)
    q.move(item_id, queue.DONE, NOW)


def test_a_late_plan_is_stale_when_any_finished_review_is_newer(q):
    finish(q, add(q, 1, B, "15", minutes=5).item.id)
    finish(q, add(q, 1, A, "19", minutes=9).item.id)
    late = q.enqueue(request(1, A, "10", minutes=0), NOW + timedelta(minutes=20), held=False)
    assert late.outcome == "stale"
    assert q.in_state(queue.QUEUED) == []


def test_a_newer_plan_after_another_head_finished_is_queued(q):
    finish(q, add(q, 1, B, "15", minutes=5).item.id)
    assert add(q, 1, A, "17", minutes=7).outcome == "queued"


def finished_with(q: Queue, head: str, run: str, generation: int, minutes: int) -> None:
    item = q.enqueue(request(1, head, run, minutes=minutes, generation=generation), NOW, held=False).item
    finish(q, item.id)


@pytest.mark.parametrize("head", [A, C], ids=["same head", "new head"])
def test_a_plan_after_the_state_expired_is_a_reset_not_stale(q, head):
    finished_with(q, A, "10", generation=3, minutes=0)
    eight_days = 8 * 24 * 60
    result = q.enqueue(request(1, head, "20", minutes=eight_days, generation=0), NOW, held=False)
    assert result.outcome == "queued"


def test_a_generation_zero_plan_newer_than_a_finished_review_is_queued_within_retention(q):
    finished_with(q, B, "10", generation=2, minutes=0)
    assert q.enqueue(request(1, A, "20", minutes=30, generation=0), NOW, held=False).outcome == "queued"


def test_a_generation_zero_plan_older_than_a_finished_review_is_stale(q):
    finished_with(q, B, "10", generation=2, minutes=30)
    assert q.enqueue(request(1, A, "20", minutes=0, generation=0), NOW, held=False).outcome == "stale"


class Records:
    """Record dispatches whose state artifact appears as soon as they are sent."""

    def find(self, row):
        return None

    def send(self, row):
        return "run"

    def confirmed(self, row):
        return True

    def rejected(self, row):
        return None


def finished_and_recorded(
    q: Queue, head: str, run: str, generation: int, minutes: int, recorded: bool, proof: bool = False
) -> None:
    box = outbox.Outbox(q.db)
    planned = replace(request(1, head, run, minutes=minutes, generation=generation), proof=proof)
    item = q.enqueue(planned, NOW, held=False).item
    payload = {"plan_run": run, "generation": generation + 1, "state": "e30="}
    row = box.add(f"dispatch-{run}", outbox.DISPATCH, payload, NOW, item_id=item.id)
    box.deliver(row.id, Records(), NOW)
    if recorded:
        assert box.deliver(row.id, Records(), NOW).state == outbox.DONE
    else:
        box.abandon(row.id, "the record run refused it", NOW)
    finish(q, item.id)


@pytest.mark.parametrize("generation", [0, 2])
def test_a_generation_zero_plan_after_a_recorded_review_is_stale_while_the_state_exists(q, generation):
    finished_and_recorded(q, B, "10", generation, minutes=0, recorded=True)
    assert q.recorded_review(REPO, 1) and not q.recorded_review(REPO, 2)
    late = q.enqueue(request(1, A, "20", minutes=30, generation=0), NOW, held=False, state_exists=True)
    assert (late.outcome, late.item.state) == ("stale", queue.SUPERSEDED)
    assert late.item.reason == f"older than the request for head {B}"


def test_a_generation_zero_plan_after_its_recorded_state_expired_is_queued_within_retention(q):
    """A repository may keep artifacts for a day; once the state is gone record-state accepts generation 0."""
    finished_and_recorded(q, B, "10", 2, minutes=0, recorded=True)
    two_days = 2 * 24 * 60
    late = q.enqueue(request(1, A, "20", minutes=two_days, generation=0), NOW, held=False, state_exists=False)
    assert late.outcome == "queued"


def test_a_generation_zero_plan_after_a_review_whose_record_was_refused_is_queued(q):
    finished_and_recorded(q, B, "10", 2, minutes=0, recorded=False)
    assert not q.recorded_review(REPO, 1)
    late = q.enqueue(request(1, A, "20", minutes=30, generation=0), NOW, held=False, state_exists=True)
    assert late.outcome == "queued"


def test_a_recorded_review_does_not_make_a_plan_that_read_state_stale(q):
    finished_and_recorded(q, B, "10", 2, minutes=0, recorded=True)
    assert q.enqueue(request(1, A, "20", minutes=30, generation=3), NOW, held=False, state_exists=True).outcome == (
        "queued"
    )


def test_a_recorded_review_older_than_the_state_retention_no_longer_orders_anything(q):
    finished_and_recorded(q, B, "10", 2, minutes=0, recorded=True)
    eight_days = 8 * 24 * 60
    late = q.enqueue(request(1, A, "20", minutes=eight_days, generation=0), NOW, held=False, state_exists=True)
    assert late.outcome == "queued"


def test_releasing_held_requests_runs_the_callback_inside_the_move(q):
    held = add(q, 1, A, "10", held=True, engine=("0.2.0", "f" * 64)).item
    seen = []

    def crash(item):
        seen.append(item.state)
        raise Crash

    with pytest.raises(Crash):
        q.release_held({"0.2.0": "f" * 64}, NOW, on_released=crash)
    assert seen == [queue.QUEUED] and q.get(held.id).state == queue.VERSION_SKEW


def test_proof_runs_take_no_part_in_the_recorded_state_rule(q):
    finished_and_recorded(q, B, "10", 2, minutes=0, recorded=True)
    proof = replace(request(1, A, "20", minutes=30, generation=0), proof=True)
    result = q.enqueue(proof, NOW, held=False, state_exists=True)
    assert (result.outcome, result.item.proof) == ("queued", True)


def test_a_recorded_proof_review_does_not_stale_a_gating_request(q):
    finished_and_recorded(q, B, "10", 2, minutes=0, recorded=True, proof=True)
    assert not q.recorded_review(REPO, 1)
    late = q.enqueue(request(1, A, "20", minutes=30, generation=0), NOW, held=False, state_exists=True)
    assert (late.outcome, late.item.proof) == ("queued", False)


def test_a_queue_made_before_proof_was_recorded_gains_the_column(db_path):
    db_path.parent.mkdir(parents=True)
    old = sqlite3.connect(db_path)
    old.executescript(queue._SCHEMA)
    old.execute(
        "INSERT INTO items (repo, pr, head_sha, plan_run_id, engine_version, engine_sha256, generation, planned_at,"
        " state, enqueued_at, updated_at) VALUES (?, 1, ?, '10', '0.1.0', ?, 0, ?, 'queued', ?, ?)",
        (REPO, A, "e" * 64, NOW.isoformat(), NOW.isoformat(), NOW.isoformat()),
    )
    old.commit()
    old.close()
    [item] = reopen(db_path).in_state(queue.QUEUED)
    assert item.proof is False
