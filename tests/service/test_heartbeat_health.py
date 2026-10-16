from __future__ import annotations

import json
import stat
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from ship_no_ship_service import health, heartbeat
from ship_no_ship_service.config import Repository

from .fake_github import BASE_SHA, SLUG, FakeGitHub

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
REPO = Repository(SLUG, 7, 9, Path("/var/empty/key.pem"), "example-bot", "main")


def test_heartbeat_is_due_on_change_or_after_thirty_minutes():
    beat = heartbeat.Heartbeat(REPO)
    assert beat.due(NOW, BASE_SHA, ["0.1.0"], 2)
    beat.posted(NOW, BASE_SHA, ["0.1.0"], 2)
    assert not beat.due(NOW + timedelta(minutes=29), BASE_SHA, ["0.1.0"], 2)
    assert beat.due(NOW + timedelta(minutes=30), BASE_SHA, ["0.1.0"], 2)
    assert beat.due(NOW + timedelta(minutes=1), BASE_SHA, ["0.1.0"], 3)
    assert beat.due(NOW + timedelta(minutes=1), BASE_SHA, ["0.1.0", "0.2.0"], 2)
    assert beat.due(NOW + timedelta(minutes=1), "1" * 40, ["0.1.0"], 2)
    assert beat.due(NOW - timedelta(minutes=1), BASE_SHA, ["0.1.0"], 2)


def test_heartbeat_payload_names_engines_and_queue_on_the_base_head():
    payload = heartbeat.Heartbeat(REPO).payload(NOW, heartbeat.base_head(FakeGitHub(), REPO), ["0.2.0", "0.1.0"], 4)
    assert payload == {
        "sha": BASE_SHA,
        "state": "success",
        "context": "ship-no-ship/heartbeat",
        "description": "alive 2026-10-16T12:00Z; engines 0.1.0,0.2.0; queue 4",
    }
    assert len(heartbeat.description(NOW, [f"9.9.{n}" for n in range(40)], 1)) == 140


def test_health_is_written_atomically_world_readable_and_without_secrets(tmp_path: Path):
    path = tmp_path / "health.json"
    path.write_text("old", encoding="utf-8")
    path.chmod(0o600)
    report = health.Health(
        updated_at=NOW,
        service_version="0.1.0",
        last_poll=NOW,
        queue={"queued": 2, "claimed": 1},
        engines=["0.1.0"],
        auth={"claude": "ok", "codex": "not_run"},
        pool_blocked_until={"codex": NOW + timedelta(hours=1)},
        version_skew=[health.Held(SLUG, 3, "a" * 40, "0.2.0")],
    )
    health.write(path, report)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    data = health.read(path)
    assert data["queue"] == {"claimed": 1, "queued": 2}
    assert data["version_skew"] == [{"repo": SLUG, "pr": 3, "head_sha": "a" * 40, "engine_version": "0.2.0"}]
    assert data["last_claim"] is None
    assert set(data) == {
        "schema", "updated_at", "service_version", "last_poll", "last_claim", "queue", "engines", "auth",
        "pool_blocked_until", "version_skew", "outbox_alerts",
    }  # fmt: skip
    assert "token" not in json.dumps(data) and "key" not in json.dumps(data)
    assert not list(tmp_path.glob(".*.tmp"))


def test_auth_results_are_limited_to_known_values(tmp_path: Path):
    report = health.Health(updated_at=NOW, service_version="0.1.0", auth={"claude": "token abc"})
    with pytest.raises(health.HealthError, match="ok, failed, not_run"):
        health.write(tmp_path / "health.json", report)
    assert list(tmp_path.iterdir()) == []


def test_the_heartbeat_time_is_always_utc():
    eastern = NOW.astimezone(timezone(timedelta(hours=-4)))
    assert heartbeat.description(eastern, ["0.1.0"], 0).startswith("alive 2026-10-16T12:00Z;")
