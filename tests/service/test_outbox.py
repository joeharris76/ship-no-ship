from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ship_no_ship_service import outbox, queue
from ship_no_ship_service.outbox import Outbox, OutboxError, Row

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
HEAD = "a" * 40
LATER = NOW + timedelta(seconds=31)


class Crash(BaseException):
    """Stands for the service being killed mid-call."""


class FakeGitHub:
    """Records each write the way GitHub would, finds it by its marker, and can die around a write."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, dict]] = []
        self.artifacts: set[tuple[str, int]] = set()
        self.running: set[str] = set()
        self.crash: str | None = None
        self.fail: Exception | None = None
        self.lagging = 0

    def find(self, row: Row) -> str | None:
        if self.lagging:
            self.lagging -= 1
            return None
        if row.kind == outbox.DISPATCH:
            return "run" if row.payload["plan_run"] in self.running else None
        for index, (kind, payload) in enumerate(self.writes):
            if kind != row.kind:
                continue
            if row.marker is not None and payload["body"].startswith(row.marker):
                return f"id-{index}"
            if row.marker is None and payload == dict(row.payload):
                return f"id-{index}"
        return None

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
    outbox.REVIEW: {"commit_id": HEAD, "body": "Review\n\n<!-- oracle-protocol: v1 abc -->", "event": "COMMENT"},
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
    first = box.add("k", outbox.REVIEW, {"body": "x"}, NOW)
    assert box.add("k", outbox.REVIEW, {"body": "x"}, NOW).id == first.id
    with pytest.raises(OutboxError, match="different"):
        box.add("k", outbox.REVIEW, {"body": "y"}, NOW)
    with pytest.raises(OutboxError, match="unknown"):
        box.add("j", "label", {}, NOW)


def test_reviews_and_comments_carry_a_unique_hidden_marker_above_the_protocol_marker(db_path):
    box = open_box(db_path)
    review = box.add("review-1", outbox.REVIEW, PAYLOADS[outbox.REVIEW], NOW)
    comment = box.add("comment-1", outbox.COMMENT, PAYLOADS[outbox.COMMENT], NOW)
    status = box.add("status-1", outbox.STATUS, PAYLOADS[outbox.STATUS], NOW)
    assert review.marker is not None and comment.marker is not None and review.marker != comment.marker
    assert review.payload["body"].splitlines()[0] == review.marker
    assert review.payload["body"].endswith("<!-- oracle-protocol: v1 abc -->")
    assert status.marker is None and status.payload == PAYLOADS[outbox.STATUS]


@pytest.mark.parametrize("kind", [outbox.STATUS, outbox.REVIEW, outbox.COMMENT, outbox.DISPATCH])
@pytest.mark.parametrize("moment", ["before", "after"])
def test_a_crash_at_a_side_effect_ends_with_exactly_one_write(db_path, kind, moment):
    github = FakeGitHub()
    row = open_box(db_path).add("k", kind, PAYLOADS[kind], NOW)
    github.crash = moment
    with pytest.raises(Crash):
        open_box(db_path).deliver(row.id, github, NOW)
    github.crash = None
    if moment == "after" and kind == outbox.DISPATCH:
        github.running.add("101")
    after = open_box(db_path).deliver(row.id, github, LATER)
    assert len(github.writes) == 1
    assert after.state == (outbox.SENT if kind == outbox.DISPATCH else outbox.DONE)
    open_box(db_path).deliver(row.id, github, NOW + timedelta(minutes=1))
    assert len(github.writes) == 1


def test_a_marked_write_is_found_even_when_github_changed_its_body(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    row = box.add("k", outbox.COMMENT, PAYLOADS[outbox.COMMENT], NOW)
    github.crash = "after"
    with pytest.raises(Crash):
        box.deliver(row.id, github, NOW)
    github.crash = None
    kind, payload = github.writes[0]
    github.writes[0] = (kind, {"body": payload["body"].replace("\n", "\r\n")})
    assert box.deliver(row.id, github, LATER).state == outbox.DONE
    assert len(github.writes) == 1


def test_an_ambiguous_write_is_not_repeated_while_github_may_still_be_catching_up(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    row = box.add("k", outbox.REVIEW, PAYLOADS[outbox.REVIEW], NOW)
    github.crash = "after"
    with pytest.raises(Crash):
        box.deliver(row.id, github, NOW)
    github.crash = None
    github.lagging = 1
    assert box.deliver(row.id, github, NOW + timedelta(seconds=5)).state == outbox.PENDING
    assert box.deliver(row.id, github, LATER).state == outbox.DONE
    assert len(github.writes) == 1


def test_a_failed_send_is_retried_after_backoff_and_reconciled_first(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    row = box.add("k", outbox.REVIEW, PAYLOADS[outbox.REVIEW], NOW)
    github.fail = TimeoutError("slow")
    failed = box.deliver(row.id, github, NOW)
    assert (failed.state, failed.tries, "slow" in failed.error) == (outbox.PENDING, 1, True)
    github.fail = None
    assert box.deliver(row.id, github, LATER).state == outbox.PENDING
    assert github.writes == []
    # The timed-out POST actually landed: the retry finds it and does not post twice.
    github.writes.append((outbox.REVIEW, dict(box.get(row.id).payload)))
    done = box.deliver(row.id, github, NOW + timedelta(minutes=2))
    assert (done.state, len(github.writes)) == (outbox.DONE, 1)


def test_errors_are_stored_without_anything_token_shaped(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    row = box.add("k", outbox.STATUS, PAYLOADS[outbox.STATUS], NOW)
    secret = "ghs" + "_" + "Ab1" * 12
    github.fail = RuntimeError(
        f"HTTP 401 for Authorization: Bearer {secret} and token {secret} jwt eyJhbGciOi.eyJpc3Mi.c2ln"
    )
    stored = box.deliver(row.id, github, NOW).error
    assert "Ab1Ab1" not in stored and "eyJ" not in stored and "[redacted]" in stored
    assert stored.startswith("RuntimeError: HTTP 401")


def test_a_dispatch_stays_open_until_its_state_artifact_is_confirmed(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    row = box.add("dispatch-101-3", outbox.DISPATCH, PAYLOADS[outbox.DISPATCH], NOW)
    moments = [NOW]
    box.deliver(row.id, github, NOW)
    clock = NOW
    for minutes in (1, 5, 15, 60, 60):
        before = len(github.writes)
        early = clock + timedelta(minutes=minutes) - timedelta(seconds=1)
        assert box.deliver(row.id, github, early).state == outbox.SENT
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


def test_a_sent_dispatch_whose_record_run_is_still_going_is_not_sent_again(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    row = box.add("d", outbox.DISPATCH, PAYLOADS[outbox.DISPATCH], NOW)
    box.deliver(row.id, github, NOW)
    github.running.add("101")
    waited = box.deliver(row.id, github, NOW + timedelta(minutes=2))
    assert (waited.state, len(github.writes)) == (outbox.SENT, 1)
    assert datetime.fromisoformat(waited.next_at) > NOW + timedelta(minutes=2)


def test_a_crash_after_dispatch_before_confirmation_waits_for_the_artifact(db_path):
    github = FakeGitHub()
    row = open_box(db_path).add("d", outbox.DISPATCH, PAYLOADS[outbox.DISPATCH], NOW)
    open_box(db_path).deliver(row.id, github, NOW)
    github.artifacts.add(("101", 3))
    assert open_box(db_path).deliver(row.id, github, NOW + timedelta(minutes=30)).state == outbox.DONE
    assert len(github.writes) == 1


def test_an_abandoned_row_is_closed_and_never_sent(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    row = box.add("k", outbox.REVIEW, PAYLOADS[outbox.REVIEW], NOW, item_id=3)
    abandoned = box.abandon(row.id, "head moved on", NOW)
    assert (abandoned.state, abandoned.error) == (outbox.ABANDONED, "head moved on")
    assert box.deliver(row.id, github, LATER).state == outbox.ABANDONED
    assert github.writes == [] and box.open_rows() == []


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


def status(state: str, description: str, context: str = "oracle-verdict", sha: str = HEAD) -> dict:
    return {"sha": sha, "state": state, "context": context, "description": description}


QUEUED_STATUS = status("pending", "queued locally (position 1)")
SUCCESS = status("success", "ship")


def test_a_delayed_queued_status_never_lands_after_a_newer_result(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    pending = box.add("status-1-queued", outbox.STATUS, QUEUED_STATUS, NOW, item_id=1)
    github.fail = TimeoutError("slow")
    assert box.deliver(pending.id, github, NOW).state == outbox.PENDING
    github.fail = None
    result = box.add("status-1-success", outbox.STATUS, SUCCESS, LATER, item_id=1)
    assert box.deliver(result.id, github, LATER).state == outbox.DONE
    # The queued status is due for its retry now, after the result was posted.
    rows = box.deliver_all(github, NOW + timedelta(minutes=2))
    assert [(row.key, row.state) for row in rows] == [("status-1-queued", outbox.ABANDONED)]
    assert "status-1-success" in box.get(pending.id).error
    assert github.writes == [(outbox.STATUS, SUCCESS)]


def test_a_newer_status_row_still_waiting_also_replaces_an_older_one(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    older = box.add("status-1-queued", outbox.STATUS, QUEUED_STATUS, NOW, item_id=1)
    box.add("status-1-success", outbox.STATUS, SUCCESS, NOW, item_id=1)
    rows = box.deliver_all(github, NOW)
    assert [row.state for row in rows] == [outbox.ABANDONED, outbox.DONE]
    assert box.get(older.id).state == outbox.ABANDONED
    assert github.writes == [(outbox.STATUS, SUCCESS)]


def test_a_status_for_another_commit_or_context_does_not_replace_one(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    box.add("queued", outbox.STATUS, QUEUED_STATUS, NOW, item_id=1)
    box.add("other-context", outbox.STATUS, status("success", "ship", context="oracle-verdict-local"), NOW, item_id=1)
    box.add("other-commit", outbox.STATUS, status("success", "ship", sha="b" * 40), NOW, item_id=2)
    assert [row.state for row in box.deliver_all(github, NOW)] == [outbox.DONE] * 3
    assert len(github.writes) == 3


def enqueue(db) -> int:
    planned = queue.Request("example-owner/example-repo", 1, HEAD, "101", "0.1.0", "c" * 64, 0, NOW)
    return queue.Queue(db).enqueue(planned, NOW, held=False).item.id


def test_a_status_is_abandoned_once_its_item_leaves_the_states_it_describes(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    items = queue.Queue(box.db)
    item_id = enqueue(box.db)
    row = box.add("status-q", outbox.STATUS, QUEUED_STATUS, NOW, item_id=item_id, applies_in=(queue.QUEUED,))
    github.fail = TimeoutError("slow")
    box.deliver(row.id, github, NOW)
    github.fail = None
    # The final result was posted elsewhere and the item moved on while the retry waited.
    items.move(item_id, queue.SUPERSEDED, NOW)
    later = box.deliver(row.id, github, NOW + timedelta(minutes=2))
    assert (later.state, later.error) == (
        outbox.ABANDONED,
        f"item {item_id} is now superseded, which this status does not describe",
    )
    assert github.writes == []


def test_a_status_is_sent_while_its_item_is_in_a_state_it_describes(db_path):
    github = FakeGitHub()
    box = open_box(db_path)
    item_id = enqueue(box.db)
    applies = (queue.QUEUED, queue.CLAIMED)
    row = box.add("status-q", outbox.STATUS, QUEUED_STATUS, NOW, item_id=item_id, applies_in=applies)
    assert box.get(row.id).applies_in == tuple(sorted(applies))
    assert queue.Queue(box.db).claim_next(NOW) is not None
    assert box.deliver(row.id, github, NOW).state == outbox.DONE
    with pytest.raises(OutboxError, match="no queue item"):
        box.add("loose", outbox.STATUS, QUEUED_STATUS, NOW, applies_in=(queue.QUEUED,))


def test_an_outbox_made_before_applies_in_existed_gains_the_column(db_path):
    db_path.parent.mkdir(parents=True)
    old = sqlite3.connect(db_path)
    old.execute(
        "CREATE TABLE outbox (id INTEGER PRIMARY KEY, item_id INTEGER, key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,"
        " payload TEXT NOT NULL, state TEXT NOT NULL, tries INTEGER NOT NULL DEFAULT 0, tried_at TEXT,"
        " response_id TEXT, error TEXT NOT NULL DEFAULT '', next_at TEXT NOT NULL, alert INTEGER NOT NULL DEFAULT 0,"
        " created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
    )
    old.execute(
        "INSERT INTO outbox (key, kind, payload, state, next_at, created_at, updated_at)"
        " VALUES ('k', 'status', '{}', 'pending', ?, ?, ?)",
        (NOW.isoformat(),) * 3,
    )
    old.commit()
    old.close()
    box = open_box(db_path)
    assert box.get_key("k").applies_in is None
    assert box.add("j", outbox.STATUS, QUEUED_STATUS, NOW, item_id=1, applies_in=["queued"]).applies_in == ("queued",)
