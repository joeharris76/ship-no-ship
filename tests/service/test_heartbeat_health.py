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
    github = FakeGitHub()
    payload = heartbeat.Heartbeat(REPO).payload(github, NOW, heartbeat.base_head(github, REPO), ["0.2.0", "0.1.0"], 4)
    assert payload == {
        "sha": BASE_SHA,
        "state": "success",
        "context": "ship-no-ship/heartbeat",
        "description": "alive 2026-10-16T12:00Z; beat 1; engines 0.1.0,0.2.0; queue 4",
    }
    long = heartbeat.description(NOW, [f"9.9.{n}" for n in range(40)], 1, beat=899)
    assert len(long) == 140 and long.startswith("alive 2026-10-16T12:00Z; beat 899; engines ")


def beat_for(beat: heartbeat.Heartbeat, github: FakeGitHub, now: datetime, sha: str = BASE_SHA) -> dict:
    payload = beat.payload(github, now, sha, ["0.1.0"], 0)
    github.post_status(payload)
    beat.posted(now, sha, ["0.1.0"], 0)
    return payload


def contexts(github: FakeGitHub, sha: str = BASE_SHA) -> dict[str, int]:
    counts: dict[str, int] = {}
    for status in github.statuses.get(sha, []):
        counts[status["context"]] = counts.get(status["context"], 0) + 1
    return counts


def test_an_idle_base_commit_never_reaches_githubs_status_limit():
    """Two months of half-hourly heartbeats on one commit stay under 1,000 per context."""
    github, beat = FakeGitHub(), heartbeat.Heartbeat(REPO)
    for n in range(60 * 48):
        beat_for(beat, github, NOW + n * heartbeat.INTERVAL)
    assert contexts(github) == {
        "ship-no-ship/heartbeat": 900,
        "ship-no-ship/heartbeat/2": 900,
        "ship-no-ship/heartbeat/3": 900,
        "ship-no-ship/heartbeat/4": 180,
    }
    assert github.statuses[BASE_SHA][-1]["description"].startswith("alive 2026-12-15T11:30Z; beat 180; ")


def test_a_restart_resumes_the_count_from_the_latest_description():
    github = FakeGitHub()
    first = heartbeat.Heartbeat(REPO)
    for n in range(850):
        beat_for(first, github, NOW + n * heartbeat.INTERVAL)
    restarted = heartbeat.Heartbeat(REPO)
    for n in range(100):
        beat_for(restarted, github, NOW + (850 + n) * heartbeat.INTERVAL)
    assert contexts(github) == {"ship-no-ship/heartbeat": 900, "ship-no-ship/heartbeat/2": 50}


@pytest.mark.parametrize(
    ("description", "creator"),
    [
        ("alive 2026-10-16T12:00Z; engines 0.1.0; queue 0", "example-bot"),  # no count: an older service
        ("alive 2026-10-16T12:00Z; beat 3; engines 0.1.0; queue 0", "someone-else"),
    ],
)
def test_a_context_whose_count_cannot_be_trusted_is_treated_as_full(description, creator):
    github = FakeGitHub()
    github.post_status(
        {"sha": BASE_SHA, "state": "success", "context": "ship-no-ship/heartbeat", "description": description},
        creator,
    )
    payload = beat_for(heartbeat.Heartbeat(REPO), github, NOW)
    assert payload["context"] == "ship-no-ship/heartbeat/2"
    assert payload["description"].startswith("alive 2026-10-16T12:00Z; beat 1; ")


def test_a_new_base_head_starts_again_at_the_configured_context():
    github, beat = FakeGitHub(), heartbeat.Heartbeat(REPO)
    for n in range(901):
        beat_for(beat, github, NOW + n * heartbeat.INTERVAL)
    payload = beat_for(beat, github, NOW + 1000 * heartbeat.INTERVAL, sha="1" * 40)
    assert (payload["context"], payload["description"][:31]) == (
        "ship-no-ship/heartbeat",
        "alive 2026-11-06T08:00Z; beat 1",
    )


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


def test_a_restart_finds_the_count_behind_other_statuses_and_stops_reading_there():
    github = FakeGitHub()
    first = heartbeat.Heartbeat(REPO)
    for n in range(10):
        beat_for(first, github, NOW + n * heartbeat.INTERVAL)
    for n in range(150):
        github.post_status({"sha": BASE_SHA, "state": "success", "context": f"ci/{n}", "description": "ok"}, "ci")
    github.calls.clear()
    payload = heartbeat.Heartbeat(REPO).payload(github, NOW, BASE_SHA, ["0.1.0"], 0)
    assert payload["context"] == "ship-no-ship/heartbeat"
    assert payload["description"].startswith("alive 2026-10-16T12:00Z; beat 11; ")
    reads = [call.split("?")[1] for call in github.calls if "/statuses?" in call]
    assert reads == ["per_page=100&page=1", "per_page=100&page=2"]
