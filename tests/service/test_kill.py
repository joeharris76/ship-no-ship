"""The service process is killed for real (os._exit) at each checkpoint, then a new process resumes."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ship_no_ship_service import outbox, queue

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)

CHILD = textwrap.dedent(
    """
    import json, os, sys
    from datetime import datetime
    from ship_no_ship_service import outbox, queue

    db_path, log_path, mode, point = sys.argv[1:5]
    now = datetime.fromisoformat(sys.argv[5])
    db = queue.connect(__import__("pathlib").Path(db_path))

    class FileGitHub:
        def _writes(self):
            try:
                with open(log_path, encoding="utf-8") as handle:
                    return [json.loads(line) for line in handle]
            except FileNotFoundError:
                return []

        def find(self, row):
            for index, write in enumerate(self._writes()):
                if write["key_marker"] == (row.marker or row.key):
                    return f"id-{index}"
            return None

        def send(self, row):
            if point == "before-send":
                os._exit(9)
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({"key_marker": row.marker or row.key}) + "\\n")
                handle.flush()
                os.fsync(handle.fileno())
            if point == "after-send":
                os._exit(9)
            return f"id-{len(self._writes()) - 1}"

        def confirmed(self, row):
            return False

        def rejected(self, row):
            return None

    if mode == "outbox":
        box = outbox.Outbox(db)
        row = box.get_key("k")
        box.deliver(row.id, FileGitHub(), now)
    elif mode == "slot":
        q = queue.Queue(db)
        item = q.in_state(queue.CLAIMED)[0]
        q.slot_started(item.id, 1, "codex", "attempt-0001", now)
        if point == "after-start":
            os._exit(9)
        q.slot_captured(item.id, 1, "attempt-0001", "f" * 64, "clean", now)
        if point == "after-capture":
            os._exit(9)
    elif mode == "enqueue":
        q = queue.Queue(db)
        original = q._insert
        def insert(*args):
            original(*args)
            os._exit(9)
        q._insert = insert
        q.enqueue(queue.Request("o/r", 1, "b" * 40, "12", "0.1.0", "e" * 64, 0, now), now, held=False)
    os._exit(0)
    """
)


def run_child(db_path: Path, log_path: Path, mode: str, point: str, now: datetime) -> int:
    args = [sys.executable, "-c", CHILD, str(db_path), str(log_path), mode, point, now.isoformat()]
    return subprocess.run(args, check=False, timeout=60).returncode


@pytest.fixture
def paths(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "state" / "state.db", tmp_path / "github.log"


def writes(log_path: Path) -> int:
    return len(log_path.read_text(encoding="utf-8").splitlines()) if log_path.exists() else 0


@pytest.mark.parametrize("kind", [outbox.STATUS, outbox.REVIEW, outbox.COMMENT, outbox.DISPATCH])
@pytest.mark.parametrize("point", ["before-send", "after-send"])
def test_a_killed_write_ends_with_exactly_one_effect(paths, kind, point):
    db_path, log_path = paths
    box = outbox.Outbox(queue.connect(db_path))
    box.add("k", kind, {"body": "x", "plan_run": "101", "generation": 1}, NOW)
    box.db.close()
    assert run_child(db_path, log_path, "outbox", point, NOW) == 9
    assert writes(log_path) == (1 if point == "after-send" else 0)
    resumed_at = NOW + timedelta(minutes=2)
    assert run_child(db_path, log_path, "outbox", "none", resumed_at) == 0
    assert writes(log_path) == 1
    row = outbox.Outbox(queue.connect(db_path)).get_key("k")
    assert row.state == (outbox.SENT if kind == outbox.DISPATCH else outbox.DONE)


@pytest.mark.parametrize(("point", "expected"), [("after-start", [queue.RERUN]), ("after-capture", [])])
def test_a_kill_at_a_slot_checkpoint_resumes_from_what_was_committed(paths, point, expected):
    db_path, log_path = paths
    q = queue.Queue(queue.connect(db_path))
    item = q.enqueue(queue.Request("o/r", 1, "a" * 40, "11", "0.1.0", "e" * 64, 0, NOW), NOW, held=False).item
    q.claim_next(NOW)
    q.db.close()
    assert run_child(db_path, log_path, "slot", point, NOW) == 9
    recovered = queue.Queue(queue.connect(db_path)).recover(item.id)
    assert [recovery.action for recovery in recovered] == expected


def test_a_kill_inside_a_transaction_leaves_nothing_half_written(paths):
    db_path, log_path = paths
    q = queue.Queue(queue.connect(db_path))
    first = q.enqueue(queue.Request("o/r", 1, "a" * 40, "11", "0.1.0", "e" * 64, 0, NOW), NOW, held=False).item
    q.db.close()
    later = NOW + timedelta(minutes=1)
    assert run_child(db_path, log_path, "enqueue", "insert", later) == 9
    resumed = queue.Queue(queue.connect(db_path))
    assert resumed.counts() == {queue.QUEUED: 1}
    assert resumed.get(first.id).state == queue.QUEUED
