from __future__ import annotations

from pathlib import Path

import pytest

from ship_no_ship_service import config
from ship_no_ship_service.config import ConfigError

EXAMPLE = """
[service]
poll_seconds = 90

[[repositories]]
slug = "example-owner/example-repo"
app_id = 7
installation_id = 9
key_path = "/var/empty/keys/example.pem"
bot_login = "example-bot"
base_branch = "develop"
"""


def repo_table(**changes):
    table = {
        "slug": "example-owner/example-repo",
        "app_id": 7,
        "installation_id": 9,
        "key_path": "/var/empty/keys/example.pem",
        "bot_login": "example-bot",
        "base_branch": "develop",
    }
    return {**table, **changes}


def test_load_reads_the_file_and_applies_engine_defaults(tmp_path: Path):
    path = tmp_path / "service.toml"
    path.write_text(EXAMPLE, encoding="utf-8")
    loaded = config.load(path)
    assert loaded.poll_seconds == 90
    assert loaded.overlap_minutes == 30
    assert loaded.state_db == config.DEFAULT_DATA_DIR / "state" / "state.db"
    assert loaded.health_path == config.DEFAULT_DATA_DIR / "run" / "health.json"
    repo = loaded.repository("Example-Owner/Example-Repo")
    assert repo.name == "example-repo"
    assert repo.bot == "example-bot[bot]"
    assert repo.request_artifact == "oracle-verdict-request"
    assert repo.verdict_workflow == ".github/workflows/oracle-verdict.yml"
    assert repo.heartbeat_context == "ship-no-ship/heartbeat"


def test_optional_names_can_be_overridden():
    parsed = config.parse({"repositories": [repo_table(request_artifact="review-request", review_command="/review")]})
    assert parsed.repositories[0].request_artifact == "review-request"
    assert parsed.repositories[0].review_command == "/review"


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"repositories": [repo_table()], "extra": 1}, "unknown keys extra"),
        ({"repositories": [repo_table(token="x")]}, "unknown keys token"),
        ({"repositories": []}, "at least one"),
        ({}, "at least one"),
        ({"repositories": [repo_table(slug="no-slash")]}, "slug"),
        ({"repositories": [repo_table(app_id=True)]}, "app_id"),
        ({"repositories": [repo_table(installation_id=0)]}, "installation_id"),
        ({"repositories": [repo_table(key_path="keys/app.pem")]}, "key_path"),
        ({"repositories": [repo_table(key_path="/var/empty/../app.pem")]}, "key_path"),
        ({"repositories": [repo_table(bot_login="bot[bot]")]}, "bot_login"),
        ({"repositories": [repo_table(base_branch="refs/heads/main")]}, "base_branch"),
        ({"repositories": [repo_table(base_branch="HEAD")]}, "base_branch"),
        ({"repositories": [repo_table(verdict_workflow="../x.yml")]}, "verdict_workflow"),
        ({"repositories": [{k: v for k, v in repo_table().items() if k != "bot_login"}]}, "missing keys bot_login"),
        ({"repositories": [repo_table(), repo_table(slug="EXAMPLE-OWNER/example-repo")]}, "twice"),
        ({"service": {"api_url": "http://api.example.test"}, "repositories": [repo_table()]}, "api_url"),
        ({"service": {"data_dir": "relative"}, "repositories": [repo_table()]}, "data_dir"),
        ({"service": {"poll_seconds": -1}, "repositories": [repo_table()]}, "poll_seconds"),
    ],
)
def test_invalid_configuration_is_refused(data, message):
    with pytest.raises(ConfigError, match=message):
        config.parse(data)


def test_an_unknown_repository_is_an_error():
    with pytest.raises(ConfigError, match="not configured"):
        config.parse({"repositories": [repo_table()]}).repository("example-owner/other")


def test_an_unreadable_file_is_a_config_error(tmp_path: Path):
    with pytest.raises(ConfigError, match="cannot be read"):
        config.load(tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("[service", encoding="utf-8")
    with pytest.raises(ConfigError, match="cannot be read"):
        config.load(bad)
