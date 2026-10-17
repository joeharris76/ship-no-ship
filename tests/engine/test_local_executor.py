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


@pytest.fixture(autouse=True)
def _pinned_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_now", lambda: NOW)


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
    assert plan == {**hosted, "executor": "local"}
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


def test_a_comment_run_names_the_comment_for_the_service_to_check(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_mode(monkeypatch, "local")
    monkeypatch.setattr(github, "newest_status", lambda repo, sha, context, creator: None)
    comment = {
        "id": 4242,
        "body": "/oracle-review",
        "user": {"login": "maintainer"},
        "created_at": "2026-10-16T11:58:00Z",
    }
    event = {"action": "created", "issue": {"number": 7, "pull_request": {}}, "comment": comment}
    _, values, _ = _plan(monkeypatch, tmp_path, FakeGitHub(_pull(), SOUNDNESS), event_name="issue_comment", event=event)
    request = json.loads((tmp_path / "plan" / executor.REQUEST_FILE).read_text(encoding="utf-8"))
    assert values["handoff"] == "true"
    assert (request["comment_id"], request["comment_author"], request["comment_created_at"]) == (
        4242,
        "maintainer",
        "2026-10-16T11:58:00Z",
    )


def test_comment_fields_keep_only_what_the_event_has() -> None:
    assert executor.comment_fields("issue_comment", {"comment": {"id": 9}}) == {"comment_id": 9}
    assert executor.comment_fields("workflow_dispatch", {"comment": {"id": 9}}) == {}


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


def test_a_stalled_service_status_is_replaced_by_a_waiting_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stalled = _status("queued locally (position 3)", NOW - timedelta(hours=25))
    _, values, _ = _local_plan(monkeypatch, tmp_path, "local", status=stalled)
    assert values["handoff"] == "true" and values["queued_status"] == "true"
    assert (tmp_path / "plan" / executor.QUEUED_STATUS_FILE).is_file()


def test_a_stalled_held_status_is_kept(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    held = _status("held: engine 0.2.0 not installed", NOW - timedelta(days=3))
    _, values, _ = _local_plan(monkeypatch, tmp_path, "local", status=held)
    assert values["queued_status"] == "false"


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


# Hosted jobs refuse a local review


@pytest.mark.parametrize("command", ["select", "finalize", "review"])
def test_hosted_jobs_refuse_a_review_handed_to_the_local_reviewer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command: str
) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps({"executor": "local", "decision": "review", "run_id": "99"}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "99")
    argv = {
        "select": ["select", "--plan", str(plan_path), "--attempts-dir", str(tmp_path), "--slot", "1"],
        "finalize": ["finalize", "--plan", str(plan_path), "--attempts-dir", str(tmp_path), "--out-dir", str(tmp_path)],
        "review": [
            *("review", "--plan", str(plan_path), "--slot", "1", "--reviewer", "sonnet", "--harness", "claude"),
            *("--workspace", str(tmp_path), "--scratch", str(tmp_path), "--out-dir", str(tmp_path)),
        ],
    }[command]
    with pytest.raises(SystemExit, match="handed to the local reviewer"):
        cli.main(argv)


# Sweep re-offer

DAY = timedelta(hours=24)


@pytest.mark.parametrize(
    ("status", "fresh", "expected"),
    [
        (None, True, True),
        (None, False, True),
        (_status("queued locally (position 1)", NOW - timedelta(hours=3)), True, False),
        (_status("local review running (attempt 2/5: sol)", NOW - timedelta(hours=3)), True, False),
        (_status("queued locally (position 1)", NOW - timedelta(hours=25)), True, True),
        (_status("local review running (attempt 2/5: sol)", NOW - timedelta(hours=25)), True, True),
        (_status("queued locally (position 1)", NOW - timedelta(hours=2)), False, False),
        (_status("queued locally (position 1)", NOW - timedelta(days=6)), False, True),
        (_status("held: engine 0.2.0 not installed on the reviewer host", NOW - timedelta(days=6)), False, False),
        (_status(executor.WAITING, NOW - timedelta(minutes=30)), True, False),
        (_status(executor.WAITING, NOW - timedelta(hours=2)), True, True),
        (_status(executor.WAITING, NOW - timedelta(hours=2)), False, False),
        (_status(executor.WAITING, NOW - timedelta(days=6)), False, True),
        ({**_status(executor.WAITING, NOW), "updated_at": "yesterday"}, True, True),
        ({**_status(executor.WAITING, NOW), "updated_at": "2026-10-16T11:00:00"}, True, True),
        (_status("2 of 5 reviewers absent", NOW - timedelta(days=1)), True, False),
        (_status("SHIP", NOW - timedelta(days=1), state="success"), True, False),
    ],
    ids=[
        "never-offered-fresh",
        "never-offered-stale",
        "queued-fresh",
        "running-fresh",
        "queued-stalled",
        "running-stalled",
        "queued-stale-young",
        "queued-stale-near-expiry",
        "held",
        "waiting-outstanding",
        "waiting-missed",
        "waiting-stale-young",
        "waiting-stale-near-expiry",
        "unparseable-time-counts-as-long-ago",
        "time-without-zone-counts-as-long-ago",
        "pending-result",
        "decided",
    ],
)
def test_should_reoffer(status: dict[str, Any] | None, fresh: bool, expected: bool) -> None:
    assert executor.should_reoffer(status, fresh, NOW, DAY) is expected


@pytest.mark.parametrize(
    ("offset", "fresh"),
    [
        (timedelta(minutes=10), True),
        (timedelta(minutes=89), True),
        (timedelta(minutes=90), False),
        (timedelta(minutes=-4), True),
        (timedelta(minutes=-6), False),
        (timedelta(days=-1), False),
    ],
)
def test_a_heartbeat_is_fresh_only_when_recent_and_not_from_the_future(offset: timedelta, fresh: bool) -> None:
    assert executor.heartbeat_fresh(NOW - offset, NOW) is fresh
    assert executor.heartbeat_fresh(None, NOW) is False


class Sweep:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, count: int, beat_age: timedelta | None) -> None:
        self.pulls = [
            {"number": number, "draft": False, "head": {"sha": f"{number:040x}", "repo": {"full_name": REPO}}}
            for number in range(1, count + 1)
        ]
        self.statuses: dict[str, dict[str, Any]] = {}
        self.silent: set[int] = set()
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
        monkeypatch.setattr(github, "own_issues", lambda repo, label, title, author: [])
        monkeypatch.setattr(github, "send", lambda method, path, payload: {"number": 1})
        _env(monkeypatch, tmp_path, "schedule", {}, "refs/heads/develop")

    def _status(self, repo: str, sha: str, context: str, creator: str) -> dict[str, Any] | None:
        self.status_reads.append(sha)
        return self.statuses.get(sha)

    def run(self, monkeypatch: pytest.MonkeyPatch, now: datetime) -> list[int]:
        monkeypatch.setattr(cli, "_now", lambda: now)
        self.dispatched = []
        assert cli.main(["sweep", "--policy", str(POLICY_PATH)]) == 0
        for number in self.dispatched:
            if number not in self.silent:
                self.statuses[f"{number:040x}"] = _status(executor.WAITING, now)
        return self.dispatched


def test_waiting_prs_are_offered_round_robin_under_their_own_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_mode(monkeypatch, "local")
    sweep = Sweep(monkeypatch, tmp_path, 8, timedelta(minutes=10))
    sweep.due = State(1, f"{1:040x}", "pending", NOW - timedelta(days=1), pending_cause="all-absent")
    first = sweep.run(monkeypatch, NOW)
    assert first[0] == 1 and len(first) == 6 and len(set(first)) == 6
    sweep.due = None
    offered = set(first)
    for hour in (1, 2):
        batch = sweep.run(monkeypatch, NOW + timedelta(hours=hour))
        assert len(batch) == 5 and len(set(batch)) == 5
        offered |= set(batch)
    assert offered == set(range(1, 9))


def test_heads_that_never_get_a_status_cannot_starve_waiting_heads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_mode(monkeypatch, "local")
    sweep = Sweep(monkeypatch, tmp_path, 7, timedelta(minutes=10))
    sweep.silent = set(range(1, 7))
    sweep.statuses[f"{7:040x}"] = _status(executor.WAITING, NOW - timedelta(hours=2))
    seen: set[int] = set()
    for hour in range(6):
        batch = sweep.run(monkeypatch, NOW + timedelta(hours=2 * hour))
        assert batch[0] == 7 and len(batch) == 5
        seen |= set(batch)
    assert seen == set(range(1, 8))


def _waiting(number: int, hours: int) -> tuple[dict[str, Any], int]:
    return _status(executor.WAITING, NOW - timedelta(hours=hours)), number


@pytest.mark.parametrize(
    ("cap", "with_waiting", "expected"),
    [
        (0, True, []),
        (0, False, []),
        (-1, True, []),
        (1, True, [1]),
        (1, False, [9]),
        (2, True, [1, 9]),
        (2, False, [9]),
        (3, True, [1, 2, 9]),
    ],
)
def test_choose_honours_small_caps(cap: int, with_waiting: bool, expected: list[int]) -> None:
    candidates = [*([_waiting(1, 5), _waiting(2, 4), _waiting(3, 3)] if with_waiting else []), (None, 9)]
    assert executor.choose(candidates, cap, NOW) == expected


def test_without_waiting_heads_unseen_heads_use_every_slot() -> None:
    assert len(executor.choose([(None, number) for number in range(1, 9)], 5, NOW)) == 5
    assert sorted(executor.choose([(None, 3), (None, 4)], 5, NOW)) == [3, 4]


def test_a_backlog_of_stalled_heads_does_not_block_a_waiting_head(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_mode(monkeypatch, "local")
    sweep = Sweep(monkeypatch, tmp_path, 9, timedelta(minutes=10))
    for number in range(1, 9):
        sweep.statuses[f"{number:040x}"] = _status("queued locally (position 1)", NOW - timedelta(hours=30))
    sweep.statuses[f"{9:040x}"] = _status(executor.WAITING, NOW - timedelta(hours=2))
    first = sweep.run(monkeypatch, NOW)
    second = sweep.run(monkeypatch, NOW + timedelta(hours=1))
    assert 9 not in first and 9 in second


def test_queued_work_is_left_alone_while_the_service_is_alive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_mode(monkeypatch, "local")
    sweep = Sweep(monkeypatch, tmp_path, 2, timedelta(minutes=10))
    sweep.statuses[f"{1:040x}"] = _status("queued locally (position 1)", NOW - timedelta(hours=20))
    sweep.statuses[f"{2:040x}"] = _status("held: engine 0.2.0 not installed", NOW - timedelta(days=6))
    assert sweep.run(monkeypatch, NOW) == []
    assert sweep.run(monkeypatch, NOW + timedelta(hours=5)) == [1]


def test_a_stale_heartbeat_renews_only_requests_near_expiry(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_mode(monkeypatch, "local")
    sweep = Sweep(monkeypatch, tmp_path, 2, timedelta(hours=3))
    sweep.statuses[f"{1:040x}"] = _status("queued locally (position 1)", NOW - timedelta(days=6))
    sweep.statuses[f"{2:040x}"] = _status(executor.WAITING, NOW - timedelta(hours=10))
    assert sweep.run(monkeypatch, NOW) == [1]


def test_a_heartbeat_from_the_future_counts_as_stale(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_mode(monkeypatch, "local")
    sweep = Sweep(monkeypatch, tmp_path, 1, timedelta(hours=-2))
    sweep.statuses[f"{1:040x}"] = _status(executor.WAITING, NOW - timedelta(hours=2))
    assert sweep.run(monkeypatch, NOW) == []


def test_the_hosted_sweep_reads_no_status(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sweep = Sweep(monkeypatch, tmp_path, 3, None)
    assert sweep.run(monkeypatch, NOW) == []
    assert sweep.status_reads == []


def test_the_sweep_exits_2_on_a_bad_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_mode(monkeypatch, "local")
    sweep = Sweep(monkeypatch, tmp_path, 3, timedelta(minutes=10))
    monkeypatch.setenv("ORACLE_EXECUTOR", "local")
    assert cli.main(["sweep", "--policy", str(POLICY_PATH)]) == 2
    assert sweep.dispatched == [] and sweep.status_reads == []


def test_newest_status_reads_past_the_first_page(monkeypatch: pytest.MonkeyPatch) -> None:
    listing = [
        _status("spoofed", NOW, creator="someone"),
        *[{**_status("x", NOW), "context": "other"} for _ in range(120)],
        _status("queued locally (position 1)", NOW - timedelta(minutes=5)),
        _status(executor.WAITING, NOW - timedelta(minutes=9)),
    ]
    paths: list[str] = []
    monkeypatch.setattr(github, "get_paginated", lambda path: paths.append(path) or listing)
    monkeypatch.setattr(github, "get_json", lambda path: pytest.fail(f"unpaginated read of {path}"))
    status = github.newest_status(REPO, HEAD, "oracle-verdict", BOT)
    assert status is not None and status["description"] == "queued locally (position 1)"
    assert paths == [f"repos/{REPO}/commits/{HEAD}/statuses?per_page=100"]


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
    monkeypatch.setattr(github, "get_json", lambda path: [{"sha": sha} for sha in statuses])
    monkeypatch.setattr(github, "get_paginated", lambda path: statuses[path.split("/commits/", 1)[1].split("/", 1)[0]])
    assert github.heartbeat(REPO, "develop", "ship-no-ship/heartbeat", BOT) == NOW - timedelta(minutes=20)


def test_heartbeat_reads_the_newest_of_its_numbered_contexts(monkeypatch: pytest.MonkeyPatch) -> None:
    def beat(context: str, at: datetime, state: str = "success", creator: str = BOT) -> dict[str, Any]:
        return {"context": context, "state": state, "updated_at": at.isoformat(), "creator": {"login": creator}}

    base = "ship-no-ship/heartbeat"
    # Newest first, as GitHub lists statuses.
    statuses = {
        "c1": [
            beat(f"{base}/3", NOW, creator="someone"),
            beat(f"{base}/02", NOW),
            beat(f"{base}/1", NOW),
            beat(f"{base}-other", NOW),
            beat(f"{base}/2", NOW - timedelta(minutes=10)),
            beat(base, NOW - timedelta(days=20)),
        ],
        "c2": [beat(base, NOW - timedelta(minutes=30))],
    }
    monkeypatch.setattr(github, "get_json", lambda path: [{"sha": sha} for sha in statuses])
    monkeypatch.setattr(github, "get_paginated", lambda path: statuses[path.split("/commits/", 1)[1].split("/", 1)[0]])
    assert github.heartbeat(REPO, "develop", base, BOT) == NOW - timedelta(minutes=10)
    statuses["c1"].insert(0, beat(f"{base}/4", NOW - timedelta(minutes=1), state="failure"))
    assert github.heartbeat(REPO, "develop", base, BOT) == NOW - timedelta(minutes=30)


@pytest.mark.parametrize(
    ("name", "number"),
    [
        ("ship-no-ship/heartbeat", 1),
        ("ship-no-ship/heartbeat/2", 2),
        ("ship-no-ship/heartbeat/117", 117),
        ("ship-no-ship/heartbeat/1", None),
        ("ship-no-ship/heartbeat/0", None),
        ("ship-no-ship/heartbeat/02", None),
        ("ship-no-ship/heartbeat/x", None),
        ("ship-no-ship/heartbeat/\u0663", None),
        ("ship-no-ship/heartbeat2", None),
        ("ship-no-ship/heartbeat/", None),
        ("oracle-verdict", None),
    ],
)
def test_heartbeat_context_numbers_round_trip(name: str, number: int | None) -> None:
    base = "ship-no-ship/heartbeat"
    assert executor.heartbeat_number(name, base) == number
    if number is not None:
        assert executor.heartbeat_context(base, number) == name


def test_heartbeat_context_numbers_start_at_one() -> None:
    with pytest.raises(ValueError, match="below 1"):
        executor.heartbeat_context("ship-no-ship/heartbeat", 0)


def test_engine_digest_is_stable() -> None:
    assert executor.engine_sha256() == executor.engine_sha256()
    assert len(executor.engine_sha256()) == 64


# Offline issue


class Issues:
    """Open issues labelled offline, and the writes the sweep sends."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *bodies: str) -> None:
        self.open: list[dict[str, Any]] = [{"number": 50 + i, "body": body} for i, body in enumerate(bodies)]
        self.writes: list[tuple[str, str, dict[str, Any]]] = []
        monkeypatch.setattr(github, "own_issues", self.own)
        monkeypatch.setattr(github, "send", self.send)

    def own(self, repo: str, label: str, title: str, author: str) -> list[dict[str, Any]]:
        assert (label, title, author) == (executor.OFFLINE_LABEL, executor.OFFLINE_TITLE, BOT)
        return list(self.open)

    def send(self, method: str, path: str, payload: dict[str, Any]) -> Any:
        self.writes.append((method, path, payload))
        if method == "POST":
            self.open.append({"number": 90, "body": payload["body"]})
            return {"number": 90}
        number = int(path.rsplit("/", 1)[1])
        if payload.get("state") == "closed":
            self.open = [issue for issue in self.open if issue["number"] != number]
        for issue in self.open:
            if issue["number"] == number and "body" in payload:
                issue["body"] = payload["body"]
        return {"number": number}


def _offline_sweep(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, beat_age: timedelta) -> Sweep:
    _use_mode(monkeypatch, "local")
    sweep = Sweep(monkeypatch, tmp_path, 3, beat_age)
    sweep.statuses[f"{1:040x}"] = _status(executor.WAITING, NOW - timedelta(hours=10))
    sweep.statuses[f"{2:040x}"] = _status("local review running (attempt 1/5: sonnet)", NOW - timedelta(hours=4))
    sweep.statuses[f"{3:040x}"] = _status("SHIP", NOW, state="success")
    return sweep


def test_a_stale_heartbeat_opens_one_offline_issue_listing_waiting_prs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sweep = _offline_sweep(monkeypatch, tmp_path, timedelta(hours=3))
    issues = Issues(monkeypatch)
    sweep.run(monkeypatch, NOW)
    ((method, path, payload),) = issues.writes
    assert (method, path) == ("POST", f"repos/{REPO}/issues") and payload["labels"] == [executor.OFFLINE_LABEL]
    assert "- #1: 10 h (waiting for the local reviewer)" in payload["body"]
    assert "- #2: 4 h (local review running" in payload["body"] and "#3" not in payload["body"]
    assert payload["body"].index("#1:") < payload["body"].index("#2:")
    sweep.run(monkeypatch, NOW)
    assert len(issues.writes) == 1 and len(issues.open) == 1
    sweep.run(monkeypatch, NOW + timedelta(hours=1))
    assert [write[0] for write in issues.writes] == ["POST", "PATCH"] and len(issues.open) == 1


def test_a_stale_heartbeat_keeps_only_the_oldest_offline_issue(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sweep = _offline_sweep(monkeypatch, tmp_path, timedelta(hours=3))
    issues = Issues(monkeypatch, "old text", "a duplicate")
    sweep.run(monkeypatch, NOW)
    assert ("PATCH", f"repos/{REPO}/issues/51", {"state": "closed"}) in issues.writes
    assert [issue["number"] for issue in issues.open] == [50] and "#1:" in issues.open[0]["body"]


def test_a_fresh_heartbeat_closes_the_offline_issue(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sweep = _offline_sweep(monkeypatch, tmp_path, timedelta(minutes=10))
    issues = Issues(monkeypatch, "offline")
    sweep.run(monkeypatch, NOW)
    assert issues.writes == [("PATCH", f"repos/{REPO}/issues/50", {"state": "closed"})] and issues.open == []
    sweep.run(monkeypatch, NOW)
    assert len(issues.writes) == 1


def test_a_stale_heartbeat_with_nothing_waiting_opens_no_issue(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_mode(monkeypatch, "local")
    sweep = Sweep(monkeypatch, tmp_path, 1, None)
    sweep.statuses[f"{1:040x}"] = _status("SHIP", NOW, state="success")
    issues = Issues(monkeypatch)
    sweep.run(monkeypatch, NOW)
    assert issues.writes == []


def test_a_failed_issue_update_does_not_fail_the_sweep(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sweep = _offline_sweep(monkeypatch, tmp_path, timedelta(hours=3))

    def broken(repo: str, label: str, title: str, author: str) -> list[dict[str, Any]]:
        raise github.GitHubError("HTTP 403")

    monkeypatch.setattr(github, "own_issues", broken)
    sweep.run(monkeypatch, NOW)


def test_a_stale_heartbeat_with_nothing_left_waiting_keeps_the_issue_and_says_so(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sweep = _offline_sweep(monkeypatch, tmp_path, timedelta(hours=3))
    issues = Issues(monkeypatch)
    sweep.run(monkeypatch, NOW)
    for number in (1, 2):
        sweep.statuses[f"{number:040x}"] = _status("SHIP", NOW, state="success")
    sweep.run(monkeypatch, NOW + timedelta(hours=1))
    assert [write[0] for write in issues.writes] == ["POST", "PATCH"] and len(issues.open) == 1
    assert "No pull request is waiting" in issues.open[0]["body"] and "#1:" not in issues.open[0]["body"]


def test_only_the_bots_own_offline_issues_are_touched(monkeypatch: pytest.MonkeyPatch) -> None:
    def issue(number: int, title: str, login: str, **extra: Any) -> dict[str, Any]:
        return {"number": number, "title": title, "user": {"login": login}, **extra}

    found = [
        issue(1, executor.OFFLINE_TITLE, "a-person"),
        issue(2, "Something else", BOT),
        issue(3, executor.OFFLINE_TITLE, BOT, pull_request={}),
        issue(4, executor.OFFLINE_TITLE, BOT),
    ]
    paths: list[str] = []
    monkeypatch.setattr(github, "get_paginated", lambda path: paths.append(path) or found)
    owned = github.own_issues(REPO, executor.OFFLINE_LABEL, executor.OFFLINE_TITLE, BOT)
    assert [item["number"] for item in owned] == [4]
    assert f"labels={executor.OFFLINE_LABEL}&" in paths[0]


# Waiting status post


def _post_queued(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, seen: dict[str, Any] | None, now: Any
) -> tuple[int, dict[str, str], list[tuple[str, str, dict[str, Any]]]]:
    _local_plan(monkeypatch, tmp_path, "local", status=seen)
    posts: list[tuple[str, str, dict[str, Any]]] = []
    monkeypatch.setattr(github, "send", lambda method, path, payload: posts.append((method, path, payload)))

    def newest(repo: str, sha: str, context: str, creator: str) -> dict[str, Any] | None:
        assert (repo, sha, context, creator) == (REPO, HEAD, "oracle-verdict", BOT)
        if isinstance(now, Exception):
            raise now
        return now

    monkeypatch.setattr(github, "newest_status", newest)
    output = tmp_path / "post-output.txt"
    output.write_text("", encoding="utf-8")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    code = cli.main(["post-queued-status", "--plan", str(tmp_path / "plan" / cli.PLAN_FILE)])
    values = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    return code, values, posts


@pytest.mark.parametrize(
    "seen", [None, {**_status("queued locally (position 1)", NOW - timedelta(hours=30)), "id": 11}]
)
def test_the_waiting_status_is_posted_when_the_head_status_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, seen: dict[str, Any] | None
) -> None:
    code, values, posts = _post_queued(monkeypatch, tmp_path, seen, seen)
    assert code == 0 and values == {"posted": "true"}
    ((method, path, payload),) = posts
    assert (method, path) == ("POST", f"repos/{REPO}/statuses/{HEAD}") and payload["description"] == executor.WAITING


@pytest.mark.parametrize(
    "now",
    [
        {**_status("SHIP", NOW, state="success"), "id": 12},
        {**_status("queued locally (position 1)", NOW), "id": 12},
        github.GitHubError("HTTP 502"),
    ],
    ids=["verdict-posted-meanwhile", "service-queued-meanwhile", "unreadable"],
)
def test_the_waiting_status_is_not_posted_over_a_newer_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, now: Any
) -> None:
    code, values, posts = _post_queued(monkeypatch, tmp_path, None, now)
    assert code == 0 and values == {"posted": "false"} and posts == []


def test_nothing_is_posted_when_the_plan_wrote_no_waiting_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    owned = _status("queued locally (position 1)", NOW)
    code, values, posts = _post_queued(monkeypatch, tmp_path, owned, owned)
    assert code == 0 and values == {"posted": "false"} and posts == []
