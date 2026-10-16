from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import ship_no_ship
from ship_no_ship.engine import cli, executor, github
from ship_no_ship.engine.policy import ExecutorConfig, Policy, load_policy
from ship_no_ship.engine.retry import State

from .conftest import BENCHBOX_ROOT, POLICY_PATH
from .test_cli_plan import HEAD, REPO, SOUNDNESS, FakeGitHub, _env, _plan, _pull

pytestmark = [pytest.mark.unit, pytest.mark.fast]

BOT = "benchbox-oracle[bot]"
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


def _use_mode(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    def load(path: Path) -> Policy:
        return dataclasses.replace(load_policy(path), executor=ExecutorConfig(mode, "oracle-local-proof"))

    monkeypatch.setattr(cli, "load_policy", load)


def _status(description: str, at: datetime, state: str = "pending", creator: str = BOT) -> dict[str, Any]:
    return {
        "context": "oracle-verdict",
        "state": state,
        "description": description,
        "updated_at": at.isoformat(),
        "creator": {"login": creator},
    }


def _local_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
    fake: FakeGitHub | None = None,
    status: dict[str, Any] | None = None,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    _use_mode(monkeypatch, mode)
    statuses: list[str] = []
    monkeypatch.setattr(github, "newest_status", lambda repo, sha, context, creator: statuses.append(sha) or status)
    return _plan(monkeypatch, tmp_path, fake or FakeGitHub(_pull(), SOUNDNESS))


# Executor selection


def test_the_hosted_executor_adds_no_outputs_and_writes_no_request(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, values, _ = _plan(monkeypatch, tmp_path, FakeGitHub(_pull(), SOUNDNESS))
    assert code == 0 and set(values) == {"decision", "post", "pr", "head_sha", "tier"}
    assert not (tmp_path / "plan" / executor.REQUEST_FILE).exists()


def test_a_local_review_hands_off_instead_of_posting(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    hosted_dir, local_dir = tmp_path / "hosted", tmp_path / "local"
    hosted_dir.mkdir()
    local_dir.mkdir()
    monkeypatch.setattr(cli, "_now", lambda: NOW)
    _, _, hosted = _plan(monkeypatch, hosted_dir, FakeGitHub(_pull(), SOUNDNESS))
    code, values, plan = _local_plan(monkeypatch, local_dir, "local")
    assert code == 0
    assert values["decision"] == "review" and values["post"] == "false"
    assert values["executor"] == "local" and values["handoff"] == "true" and values["queued_status"] == "true"
    assert plan == hosted
    request = json.loads((local_dir / "plan" / executor.REQUEST_FILE).read_text(encoding="utf-8"))
    assert request == {
        "schema": 1,
        "executor": "local",
        "repo": REPO,
        "pr": 7,
        "head_sha": HEAD,
        "run_id": "99",
        "engine_version": ship_no_ship.__version__,
        "engine_sha256": executor.engine_sha256(),
        "policy_sha256": hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest(),
        "state_generation": 0,
    }
    queued = json.loads((local_dir / "plan" / executor.QUEUED_STATUS_FILE).read_text(encoding="utf-8"))
    assert queued["state"] == "pending" and queued["context"] == "oracle-verdict"
    assert queued["description"] == executor.WAITING and queued["target_url"].endswith(f"{REPO}/actions/runs/99")


def test_the_request_carries_the_generation_of_the_state_the_plan_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    previous = State(7, "c" * 40, "success", NOW - timedelta(days=1), generation=3, predecessor=2)
    _local_plan(monkeypatch, tmp_path, "local", FakeGitHub(_pull(), SOUNDNESS, previous))
    request = json.loads((tmp_path / "plan" / executor.REQUEST_FILE).read_text(encoding="utf-8"))
    assert request["state_generation"] == 3


@pytest.mark.parametrize(
    "description", ["queued locally (position 2)", "local review running (attempt 1/5: sonnet)", "held: engine 0.2"]
)
def test_a_re_offer_does_not_replace_the_service_status_for_the_same_head(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, description: str
) -> None:
    _, values, _ = _local_plan(monkeypatch, tmp_path, "local", status=_status(description, NOW))
    assert values["handoff"] == "true" and values["queued_status"] == "false"
    assert (tmp_path / "plan" / executor.REQUEST_FILE).is_file()
    assert not (tmp_path / "plan" / executor.QUEUED_STATUS_FILE).exists()


def test_an_unreadable_head_status_still_hands_off_without_a_waiting_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_mode(monkeypatch, "local")

    def unreadable(repo: str, sha: str, context: str, creator: str) -> None:
        raise github.GitHubError("HTTP 502")

    monkeypatch.setattr(github, "newest_status", unreadable)
    _, values, _ = _plan(monkeypatch, tmp_path, FakeGitHub(_pull(), SOUNDNESS))
    assert values["handoff"] == "true" and values["queued_status"] == "false" and values["post"] == "false"


def test_a_local_non_review_decision_posts_as_before(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    readme = [{"filename": "README.md", "additions": 1, "deletions": 0}]
    _, values, _ = _local_plan(monkeypatch, tmp_path, "local", FakeGitHub(_pull(), readme))
    assert values["decision"] == "success" and values["post"] == "true" and values["handoff"] == "false"
    assert not (tmp_path / "plan" / executor.REQUEST_FILE).exists()


@pytest.mark.parametrize(("labelled", "handoff"), [(True, "true"), (False, "false")])
def test_proof_runs_the_hosted_path_and_hands_off_only_labelled_prs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, labelled: bool, handoff: str
) -> None:
    labels = [{"name": "author-family:codex"}, *([{"name": "oracle-local-proof"}] if labelled else [])]
    _, values, _ = _local_plan(monkeypatch, tmp_path, "proof", FakeGitHub(_pull(labels=labels), SOUNDNESS))
    assert values["post"] == "true" and values["handoff"] == handoff and values["queued_status"] == "false"
    assert (tmp_path / "plan" / executor.REQUEST_FILE).is_file() is labelled
    assert not (tmp_path / "plan" / executor.QUEUED_STATUS_FILE).exists()


def test_the_override_forces_hosted_whatever_the_policy_says(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_mode(monkeypatch, "local")
    fake = FakeGitHub(_pull(), SOUNDNESS)
    fake.install(monkeypatch)
    output = _env(monkeypatch, tmp_path, "pull_request_target", {"action": "synchronize"}, "refs/heads/develop")
    monkeypatch.setenv("ORACLE_EXECUTOR", "hosted")
    out = tmp_path / "plan"
    assert (
        cli.main(["plan", "--policy", str(POLICY_PATH), "--pr", "7", "--out", str(out), "--root", str(BENCHBOX_ROOT)])
        == 0
    )
    values = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    assert values["post"] == "true" and "handoff" not in values
    assert not (out / executor.REQUEST_FILE).exists()


@pytest.mark.parametrize("value", ["local", "proof", "Hosted", "off"])
def test_the_override_refuses_anything_but_hosted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str) -> None:
    fake = FakeGitHub(_pull(), SOUNDNESS)
    fake.install(monkeypatch)
    _env(monkeypatch, tmp_path, "pull_request_target", {"action": "synchronize"}, "refs/heads/develop")
    monkeypatch.setenv("ORACLE_EXECUTOR", value)
    out = tmp_path / "plan"
    assert (
        cli.main(["plan", "--policy", str(POLICY_PATH), "--pr", "7", "--out", str(out), "--root", str(BENCHBOX_ROOT)])
        == 2
    )
    assert cli.main(["sweep", "--policy", str(POLICY_PATH)]) == 2
    assert not out.exists() and fake.dispatched == []


# Sweep re-offer


@pytest.mark.parametrize(
    ("status", "fresh", "expected"),
    [
        (None, True, True),
        (None, False, True),
        (_status("queued locally (position 1)", NOW - timedelta(hours=3)), True, False),
        (_status("local review running (attempt 2/5: sol)", NOW - timedelta(hours=3)), True, False),
        (_status("queued locally (position 1)", NOW - timedelta(days=2)), False, False),
        (_status("queued locally (position 1)", NOW - timedelta(days=6)), False, True),
        (_status("held: engine 0.2.0 not installed on the reviewer host", NOW - timedelta(days=6)), False, False),
        (_status(executor.WAITING, NOW - timedelta(minutes=30)), True, False),
        (_status(executor.WAITING, NOW - timedelta(hours=2)), True, True),
        (_status(executor.WAITING, NOW - timedelta(hours=2)), False, False),
        (_status(executor.WAITING, NOW - timedelta(days=6)), False, True),
        (_status("2 of 5 reviewers absent", NOW - timedelta(days=1)), True, False),
        (_status("SHIP", NOW - timedelta(days=1), state="success"), True, False),
    ],
    ids=[
        "never-offered-fresh",
        "never-offered-stale",
        "queued-fresh",
        "running-fresh",
        "queued-stale-young",
        "queued-stale-near-expiry",
        "held",
        "waiting-outstanding",
        "waiting-missed",
        "waiting-stale-young",
        "waiting-stale-near-expiry",
        "pending-result",
        "decided",
    ],
)
def test_should_reoffer(status: dict[str, Any] | None, fresh: bool, expected: bool) -> None:
    assert executor.should_reoffer(status, fresh, NOW) is expected


class Sweep:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, count: int, beat_age: timedelta | None) -> None:
        self.pulls = [
            {"number": number, "draft": False, "head": {"sha": f"{number:040x}", "repo": {"full_name": REPO}}}
            for number in range(1, count + 1)
        ]
        self.statuses: dict[str, dict[str, Any]] = {}
        self.dispatched: list[int] = []
        self.status_reads: list[str] = []
        self.due: State | None = None
        monkeypatch.setattr(github, "get_paginated", lambda path: self.pulls)
        monkeypatch.setattr(github, "latest_state", lambda repo, pr, repository, **_: self.due if pr == 1 else None)
        monkeypatch.setattr(github, "dispatch", lambda repo, workflow, pr, ref: self.dispatched.append(pr))
        monkeypatch.setattr(
            github,
            "heartbeat",
            lambda repo, base, context, creator: None if beat_age is None else cli._now() - beat_age,
        )
        monkeypatch.setattr(github, "newest_status", self._status)
        _env(monkeypatch, tmp_path, "schedule", {}, "refs/heads/develop")

    def _status(self, repo: str, sha: str, context: str, creator: str) -> dict[str, Any] | None:
        self.status_reads.append(sha)
        return self.statuses.get(sha)

    def run(self, monkeypatch: pytest.MonkeyPatch, now: datetime) -> list[int]:
        monkeypatch.setattr(cli, "_now", lambda: now)
        self.dispatched = []
        assert cli.main(["sweep", "--policy", str(POLICY_PATH)]) == 0
        for number in self.dispatched:
            self.statuses[f"{number:040x}"] = _status(executor.WAITING, now)
        return self.dispatched


def test_waiting_prs_are_offered_round_robin_under_their_own_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_mode(monkeypatch, "local")
    sweep = Sweep(monkeypatch, tmp_path, 8, timedelta(minutes=10))
    sweep.due = State(1, f"{1:040x}", "pending", NOW - timedelta(days=1), pending_cause="all-absent")
    assert sweep.run(monkeypatch, NOW) == [1, 2, 3, 4, 5, 6]
    sweep.due = None
    assert sweep.run(monkeypatch, NOW + timedelta(hours=1)) == [7, 8, 1, 2, 3]
    assert sweep.run(monkeypatch, NOW + timedelta(hours=2)) == [4, 5, 6, 1, 2]


def test_queued_work_is_left_alone_while_the_service_is_alive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_mode(monkeypatch, "local")
    sweep = Sweep(monkeypatch, tmp_path, 2, timedelta(minutes=10))
    sweep.statuses[f"{1:040x}"] = _status("queued locally (position 1)", NOW - timedelta(days=6))
    sweep.statuses[f"{2:040x}"] = _status("held: engine 0.2.0 not installed", NOW - timedelta(days=6))
    assert sweep.run(monkeypatch, NOW) == []


def test_a_stale_heartbeat_renews_only_requests_near_expiry(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_mode(monkeypatch, "local")
    sweep = Sweep(monkeypatch, tmp_path, 2, timedelta(hours=3))
    sweep.statuses[f"{1:040x}"] = _status("queued locally (position 1)", NOW - timedelta(days=6))
    sweep.statuses[f"{2:040x}"] = _status(executor.WAITING, NOW - timedelta(days=1))
    assert sweep.run(monkeypatch, NOW) == [1]


def test_the_hosted_sweep_reads_no_status(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sweep = Sweep(monkeypatch, tmp_path, 3, None)
    assert sweep.run(monkeypatch, NOW) == []
    assert sweep.status_reads == []


def test_newest_status_takes_the_first_match_from_the_bot(monkeypatch: pytest.MonkeyPatch) -> None:
    listing = [
        _status("spoofed", NOW, creator="someone"),
        {**_status("x", NOW), "context": "other"},
        _status("queued locally (position 1)", NOW - timedelta(minutes=5)),
        _status(executor.WAITING, NOW - timedelta(minutes=9)),
    ]
    monkeypatch.setattr(github, "get_json", lambda path: listing)
    status = github.newest_status(REPO, HEAD, "oracle-verdict", BOT)
    assert status is not None and status["description"] == "queued locally (position 1)"


def test_heartbeat_is_the_newest_success_across_recent_base_commits(monkeypatch: pytest.MonkeyPatch) -> None:
    def beat(at: datetime, state: str = "success", creator: str = BOT) -> dict[str, Any]:
        return {
            "context": "ship-no-ship/heartbeat",
            "state": state,
            "updated_at": at.isoformat(),
            "creator": {"login": creator},
        }

    statuses = {
        "c1": [beat(NOW, creator="someone"), beat(NOW - timedelta(hours=2))],
        "c2": [beat(NOW - timedelta(minutes=20))],
        "c3": [beat(NOW, state="failure")],
    }
    paths: list[str] = []

    def get_json(path: str) -> Any:
        paths.append(path)
        if path.startswith(f"repos/{REPO}/commits?"):
            return [{"sha": sha} for sha in statuses]
        return statuses[path.split("/commits/", 1)[1].split("/", 1)[0]]

    monkeypatch.setattr(github, "get_json", get_json)
    assert github.heartbeat(REPO, "develop", "ship-no-ship/heartbeat", BOT) == NOW - timedelta(minutes=20)
    assert paths[0] == f"repos/{REPO}/commits?sha=develop&per_page=20"


def test_engine_digest_is_stable() -> None:
    assert executor.engine_sha256() == executor.engine_sha256()
    assert len(executor.engine_sha256()) == 64
