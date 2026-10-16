from __future__ import annotations

import base64
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ship_no_ship.engine import cli, github
from ship_no_ship.engine.policy import V1_REPOSITORY
from ship_no_ship.engine.retry import State, next_state

from .conftest import POLICY_PATH
from .test_cli_plan import HEAD, REPO, _env

pytestmark = [pytest.mark.unit, pytest.mark.fast]

BOT = "benchbox-oracle[bot]"
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
RECORD = V1_REPOSITORY.workflows.record
RUN_SHA = "d" * 40

# State generations


def test_each_written_state_is_the_successor_of_the_one_it_read() -> None:
    first = next_state(
        previous=None, pr=7, head_sha=HEAD, outcome="pending", manual=False, now=NOW, pool_blocked_until={}
    )
    assert (first.generation, first.predecessor) == (1, 0)
    second = next_state(
        previous=first, pr=7, head_sha=HEAD, outcome="success", manual=True, now=NOW, pool_blocked_until={}
    )
    assert (second.generation, second.predecessor) == (2, 1)
    assert State.from_json(second.to_json()) == second


def test_state_written_before_generations_reads_as_generation_zero() -> None:
    legacy = {
        key: value
        for key, value in State(7, HEAD, "pending", NOW).to_json().items()
        if key not in ("generation", "predecessor")
    }
    state = State.from_json(legacy)
    assert (state.generation, state.predecessor) == (0, None)


@pytest.mark.parametrize("value", [-1, True, "3", 1.5])
def test_a_malformed_generation_is_refused(value: Any) -> None:
    with pytest.raises(ValueError, match="generation"):
        State.from_json({**State(7, HEAD, "pending", NOW).to_json(), "generation": value})


STATE_ARTIFACT = "oracle-verdict-state-7"
REQUEST_ARTIFACT = V1_REPOSITORY.artifacts.request
PLAN_RUN = "500"


def _record_run(actor: str = BOT, **over: Any) -> dict[str, Any]:
    run = {
        "path": RECORD,
        "repository": {"full_name": REPO},
        "event": "workflow_dispatch",
        "head_branch": "develop",
        "head_sha": RUN_SHA,
        "created_at": "2026-10-16T11:00:00Z",
        "triggering_actor": {"login": actor},
    }
    run.update(over)
    return run


def _verdict_run(**over: Any) -> dict[str, Any]:
    run = {
        "path": V1_REPOSITORY.workflows.verdict,
        "repository": {"full_name": REPO},
        "event": "issue_comment",
        "head_sha": RUN_SHA,
        "created_at": "2026-10-16T10:00:00Z",
    }
    run.update(over)
    return run


def _gen(generation: int, outcome: str = "pending") -> State:
    return State(7, HEAD, outcome, NOW, generation=generation, predecessor=generation - 1 if generation else None)


def _legacy(outcome: str = "pending") -> dict[str, Any]:
    data = State(7, HEAD, outcome, NOW).to_json()
    return {key: value for key, value in data.items() if key not in ("generation", "predecessor")}


def _recorded(state: State, run_id: str) -> dict[str, Any]:
    return {**state.to_json(), github.RECORDED_RUN: run_id}


class World:
    """A fake GitHub that serves state artifacts, runs and plan requests through the real engine code."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.artifacts: list[dict[str, Any]] = []
        self.runs: dict[str, dict[str, Any]] = {PLAN_RUN: _verdict_run()}
        self.payloads: dict[tuple[str, str], Any] = {
            (PLAN_RUN, REQUEST_ARTIFACT): {
                "repo": REPO,
                "pr": 7,
                "head_sha": HEAD,
                "run_id": PLAN_RUN,
                "decision": "review",
            }
        }
        self.pull_head = HEAD
        self.downloads: list[tuple[str, str]] = []
        self.run_reads: list[str] = []
        monkeypatch.setattr(github, "get_json", self.get_json)
        monkeypatch.setattr(github, "get_paginated", lambda path: [])
        monkeypatch.setattr(github.subprocess, "run", self.run)

    def add(self, created_at: str, run: dict[str, Any], payload: Any, run_id: str | None = None) -> str:
        run_id = run_id or str(100 + len(self.artifacts))
        self.runs[run_id] = run
        self.payloads[(run_id, STATE_ARTIFACT)] = payload
        self.artifacts.append({"created_at": created_at, "workflow_run": {"id": int(run_id)}, "expired": False})
        return run_id

    def get_json(self, path: str) -> Any:
        if path.startswith(f"repos/{REPO}/actions/artifacts?name={STATE_ARTIFACT}&"):
            return {"total_count": len(self.artifacts), "artifacts": self.artifacts}
        if path.startswith(f"repos/{REPO}/actions/runs/"):
            run_id = path.rsplit("/", 1)[1]
            self.run_reads.append(run_id)
            return self.runs[run_id]
        if path.endswith("/git/ref/heads/develop"):
            return {"object": {"sha": "f" * 40}}
        if "/compare/" in path:
            return {"status": "ahead"}
        if path == f"repos/{REPO}/pulls/7":
            return {"head": {"sha": self.pull_head}}
        raise AssertionError(f"unexpected request {path}")

    def run(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        run_id, name = argv[3], argv[argv.index("-n") + 1]
        self.downloads.append((run_id, name))
        payload = self.payloads.get((run_id, name), "missing")
        if payload == "missing":
            return subprocess.CompletedProcess(argv, 1, "", "no artifact")
        file = github.STATE_FILE if name == STATE_ARTIFACT else cli.PLAN_FILE
        text = payload if isinstance(payload, str) else json.dumps(payload)
        (Path(argv[argv.index("-D") + 1]) / file).write_text(text, encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def latest(self) -> State | None:
        return github.latest_state(REPO, 7, V1_REPOSITORY, record_actor=BOT)


def test_latest_state_picks_the_highest_generation_not_the_newest_artifact(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    late = world.add("2026-10-16T11:30:00Z", _record_run(), None)
    world.payloads[(late, STATE_ARTIFACT)] = _recorded(_gen(2), late)
    early = world.add("2026-10-16T11:00:00Z", _record_run(), None)
    world.payloads[(early, STATE_ARTIFACT)] = _recorded(_gen(3, "success"), early)
    state = world.latest()
    assert state is not None and (state.generation, state.outcome) == (3, "success")


def test_an_untrusted_higher_generation_never_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    world.add("2026-10-16T11:30:00Z", _record_run(actor="someone"), _gen(9).to_json())
    world.add("2026-10-16T11:20:00Z", _verdict_run(event="pull_request"), _gen(8).to_json())
    world.add("2026-10-16T11:00:00Z", _verdict_run(), _gen(2).to_json())
    state = world.latest()
    assert state is not None and state.generation == 2
    assert [name for _, name in world.downloads] == [STATE_ARTIFACT]


def test_a_legacy_newest_state_is_read_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    world.add("2026-10-16T11:30:00Z", _verdict_run(), _legacy("success"))
    world.add("2026-10-16T11:00:00Z", _verdict_run(), _gen(5).to_json())
    world.add("2026-10-16T10:00:00Z", _verdict_run(), _gen(4).to_json())
    state = world.latest()
    assert state is not None and state.outcome == "success" and state.predecessor is None
    assert len(world.downloads) == 1 and len(world.run_reads) == 1


def test_reading_stops_at_a_legacy_state_behind_newer_generations(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    world.add("2026-10-16T11:30:00Z", _verdict_run(), _gen(1, "success").to_json())
    world.add("2026-10-16T11:00:00Z", _verdict_run(), _legacy())
    world.add("2026-10-16T10:00:00Z", _verdict_run(), _gen(5).to_json())
    state = world.latest()
    assert state is not None and state.generation == 1
    assert len(world.downloads) == 2


def test_a_corrupt_or_missing_artifact_is_skipped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = World(monkeypatch)
    world.add("2026-10-16T11:30:00Z", _verdict_run(), "{not json")
    world.add("2026-10-16T11:20:00Z", _verdict_run(), "missing")
    world.add("2026-10-16T11:00:00Z", _verdict_run(), _gen(2).to_json())
    state = world.latest()
    assert state is not None and state.generation == 2
    assert capsys.readouterr().err.count("::warning::") == 2


def test_it_is_an_error_only_when_no_trusted_state_can_be_read(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    world.add("2026-10-16T11:30:00Z", _verdict_run(), "{not json")
    with pytest.raises(github.GitHubError, match="no trusted retry state"):
        world.latest()


def test_the_sweep_skips_a_pull_request_whose_state_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    world = World(monkeypatch)
    world.add("2026-10-16T11:30:00Z", _verdict_run(), "{not json")
    monkeypatch.setattr(
        github, "get_paginated", lambda path: [{"number": 7, "head": {"sha": HEAD, "repo": {"full_name": REPO}}}]
    )
    _env(monkeypatch, tmp_path, "schedule", {}, "refs/heads/develop")
    assert cli.main(["sweep", "--policy", str(POLICY_PATH)]) == 0


def test_a_recorded_state_beats_a_plan_run_state_of_the_same_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    world.add("2026-10-16T11:30:00Z", _verdict_run(), _gen(4, "failure").to_json())
    record = world.add("2026-10-16T11:00:00Z", _record_run(), None)
    world.payloads[(record, STATE_ARTIFACT)] = _recorded(_gen(4, "success"), record)
    state = world.latest()
    assert state is not None and state.outcome == "success"


def test_equal_plan_run_generations_keep_the_newest_artifact(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    world.add("2026-10-16T10:00:00Z", _verdict_run(), _gen(3, "failure").to_json())
    world.add("2026-10-16T11:00:00Z", _verdict_run(), _gen(3, "success").to_json())
    state = world.latest()
    assert state is not None and state.outcome == "success"


@pytest.mark.parametrize(
    ("run", "actor", "tagged"),
    [
        (_record_run(actor="someone"), BOT, True),
        (_record_run(), "", True),
        (_record_run(event="schedule"), BOT, True),
        (_record_run(path=".github/workflows/other.yml"), BOT, True),
        (_record_run(head_branch="feature"), BOT, True),
        (_record_run(), BOT, False),
    ],
    ids=[
        "dispatched-by-a-person",
        "no-bot-configured",
        "not-a-dispatch",
        "another-workflow",
        "another-branch",
        "not-accepted-by-record-state",
    ],
)
def test_latest_state_trusts_record_runs_only_from_the_bot_on_the_base_branch(
    monkeypatch: pytest.MonkeyPatch, run: dict[str, Any], actor: str, tagged: bool
) -> None:
    world = World(monkeypatch)
    run_id = world.add("2026-10-16T11:00:00Z", run, None)
    world.payloads[(run_id, STATE_ARTIFACT)] = _recorded(_gen(9), run_id) if tagged else _gen(9).to_json()
    world.add("2026-10-16T10:00:00Z", _verdict_run(), _gen(2).to_json())
    for strict in (False, True):
        state = github.latest_state(REPO, 7, V1_REPOSITORY, record_actor=actor, strict=strict)
        assert state is not None and state.generation == 2


def test_at_most_three_trusted_states_are_read(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    for hour in range(10, 0, -1):
        world.add(f"2026-10-16T{hour:02d}:00:00Z", _verdict_run(), _gen(hour).to_json())
    state = world.latest()
    assert state is not None and state.generation == 10
    assert len(world.downloads) == 3 and len(world.run_reads) == 3


def test_an_unreadable_state_is_replaced_by_the_next_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    world.add("2026-10-16T11:00:00Z", _verdict_run(), "missing")
    for hour in (10, 9, 8, 7):
        world.add(f"2026-10-16T{hour:02d}:00:00Z", _verdict_run(), _gen(hour - 4).to_json())
    state = world.latest()
    assert state is not None and state.generation == 6
    assert len(world.downloads) == 4


# record-state


def _encode(state: State) -> str:
    return base64.b64encode(json.dumps(state.to_json()).encode()).decode()


def _record(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    world: World,
    state: State,
    *,
    actor: str = BOT,
    ref: str = "refs/heads/develop",
    encoded: str | None = None,
    head_sha: str = HEAD,
) -> tuple[int, dict[str, str]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    output = _env(monkeypatch, tmp_path, "workflow_dispatch", {}, ref)
    monkeypatch.setenv("GITHUB_TRIGGERING_ACTOR", actor)
    monkeypatch.setenv("GITHUB_RUN_ID", "900")
    argv = ["record-state", "--policy", str(POLICY_PATH), "--pr", "7", "--head-sha", head_sha]
    argv += ["--plan-run", PLAN_RUN, "--state", encoded or _encode(state), "--out", str(tmp_path / "out")]
    code = cli.main(argv)
    values = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    return code, values


def _stored(tmp_path: Path) -> dict[str, Any] | None:
    path = tmp_path / "out" / github.STATE_FILE
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def _world_at(monkeypatch: pytest.MonkeyPatch, current: State | None) -> World:
    world = World(monkeypatch)
    if current is not None:
        run_id = world.add("2026-10-16T09:00:00Z", _record_run(), None)
        world.payloads[(run_id, STATE_ARTIFACT)] = _recorded(current, run_id)
    return world


def test_record_state_stores_the_successor_tagged_with_its_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    world = _world_at(monkeypatch, _gen(3))
    code, values = _record(monkeypatch, tmp_path, world, _gen(4))
    assert code == 0 and values == {"upload": "true"}
    assert _stored(tmp_path) == {**_gen(4).to_json(), github.RECORDED_RUN: "900"}
    assert (PLAN_RUN, REQUEST_ARTIFACT) in world.downloads


def test_record_state_stores_the_first_generation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    world = _world_at(monkeypatch, None)
    assert _record(monkeypatch, tmp_path, world, _gen(1)) == (0, {"upload": "true"})


def test_a_duplicate_dispatch_is_a_no_op(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    world = _world_at(monkeypatch, _gen(4))
    code, values = _record(monkeypatch, tmp_path, world, _gen(4))
    assert code == 0 and values == {"upload": "false"}
    assert _stored(tmp_path) is None


@pytest.mark.parametrize(
    ("state", "current"),
    [(_gen(3), _gen(4)), (_gen(4, "success"), _gen(4, "failure")), (_gen(6), _gen(4))],
    ids=["delayed-older-dispatch", "same-generation-different-content", "skipped-generation"],
)
def test_record_state_rejects_anything_but_the_successor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state: State, current: State
) -> None:
    world = _world_at(monkeypatch, current)
    code, values = _record(monkeypatch, tmp_path, world, state)
    assert code == 1 and values == {}
    assert _stored(tmp_path) is None


def test_reversed_completion_order_keeps_the_newer_generation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    first, second = _gen(1), _gen(2)
    assert _record(monkeypatch, tmp_path / "a", _world_at(monkeypatch, None), second)[0] == 1
    assert _record(monkeypatch, tmp_path / "b", _world_at(monkeypatch, None), first)[0] == 0
    assert _record(monkeypatch, tmp_path / "c", _world_at(monkeypatch, first), second)[0] == 0
    assert _record(monkeypatch, tmp_path / "d", _world_at(monkeypatch, second), first)[0] == 1


def _plan_for(**over: Any) -> dict[str, Any]:
    return {"repo": REPO, "pr": 7, "head_sha": HEAD, "run_id": PLAN_RUN, "decision": "review", **over}


@pytest.mark.parametrize(
    ("change", "options", "code"),
    [
        ({}, {"actor": "someone"}, 1),
        ({}, {"ref": "refs/heads/feature"}, 2),
        ({"run": _verdict_run(event="pull_request")}, {}, 1),
        ({"run": _verdict_run(path=RECORD)}, {}, 1),
        ({"plan": _plan_for(pr=8)}, {}, 1),
        ({"plan": _plan_for(head_sha="c" * 40)}, {}, 1),
        ({"plan": _plan_for(run_id="501")}, {}, 1),
        ({"plan": _plan_for(decision="carry")}, {}, 1),
        ({"plan": "missing"}, {}, 1),
        ({"pull_head": "c" * 40}, {}, 1),
        ({}, {"encoded": "not base64!"}, 1),
        ({}, {"head_sha": "c" * 40}, 1),
        ({}, {"encoded": base64.b64encode(json.dumps({**_gen(4).to_json(), "predecessor": 2}).encode()).decode()}, 1),
    ],
    ids=[
        "wrong-actor",
        "wrong-ref",
        "untrusted-plan-run",
        "plan-run-of-another-workflow",
        "plan-for-another-pull-request",
        "plan-for-another-head",
        "plan-from-another-run",
        "plan-without-a-review",
        "plan-run-without-a-request",
        "head-moved-since",
        "malformed",
        "other-head",
        "broken-chain",
    ],
)
def test_record_state_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, change: dict[str, Any], options: dict[str, Any], code: int
) -> None:
    world = _world_at(monkeypatch, _gen(3))
    if "run" in change:
        world.runs[PLAN_RUN] = change["run"]
    if "plan" in change:
        world.payloads[(PLAN_RUN, REQUEST_ARTIFACT)] = change["plan"]
    world.pull_head = change.get("pull_head", HEAD)
    assert _record(monkeypatch, tmp_path, world, _gen(4), **options)[0] == code
    assert _stored(tmp_path) is None


def test_record_state_fails_rather_than_fork_the_chain_when_the_current_state_is_unreadable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    world = World(monkeypatch)
    world.add("2026-10-16T09:30:00Z", _verdict_run(), "missing")
    record = world.add("2026-10-16T09:00:00Z", _record_run(), None)
    world.payloads[(record, STATE_ARTIFACT)] = _recorded(_gen(4), record)
    lenient = world.latest()
    assert lenient is not None and lenient.generation == 4
    code, values = _record(monkeypatch, tmp_path, world, _gen(5))
    assert code == 1 and values == {}
    assert _stored(tmp_path) is None
