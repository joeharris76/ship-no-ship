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


def _record_run(actor: str = BOT, **over: Any) -> dict[str, Any]:
    run = {
        "path": RECORD,
        "repository": {"full_name": REPO},
        "event": "workflow_dispatch",
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


def _sources(monkeypatch: pytest.MonkeyPatch, entries: list[tuple[str, dict[str, Any], State]]) -> list[str]:
    """Install artifacts as (created_at, run, state) and record which runs are downloaded."""
    runs = {str(index): run for index, (_, run, _) in enumerate(entries, start=1)}
    states = {str(index): state for index, (_, _, state) in enumerate(entries, start=1)}
    listing = {
        "artifacts": [
            {"created_at": created, "workflow_run": {"id": index}, "expired": False}
            for index, (created, _, _) in enumerate(entries, start=1)
        ]
    }
    downloaded: list[str] = []

    def get_json(path: str) -> Any:
        if path.startswith(f"repos/{REPO}/actions/artifacts?name=oracle-verdict-state-7&"):
            return listing
        if path.startswith(f"repos/{REPO}/actions/runs/"):
            return runs[path.rsplit("/", 1)[1]]
        if "/git/ref/heads/develop" in path:
            return {"object": {"sha": "f" * 40}}
        if "/compare/" in path:
            return {"status": "ahead"}
        raise AssertionError(f"unexpected request {path}")

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        run_id = argv[3]
        downloaded.append(run_id)
        target = Path(argv[argv.index("-D") + 1]) / github.STATE_FILE
        target.write_text(json.dumps(states[run_id].to_json()), encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(github, "get_json", get_json)
    monkeypatch.setattr(github, "get_paginated", lambda path: [])
    monkeypatch.setattr(github.subprocess, "run", fake_run)
    return downloaded


def _gen(generation: int, outcome: str = "pending") -> State:
    return State(7, HEAD, outcome, NOW, generation=generation, predecessor=generation - 1 if generation else None)


def test_latest_state_picks_the_highest_generation_not_the_newest_artifact(monkeypatch: pytest.MonkeyPatch) -> None:
    _sources(
        monkeypatch,
        [
            ("2026-10-16T11:30:00Z", _record_run(), _gen(2, "pending")),
            ("2026-10-16T11:00:00Z", _record_run(), _gen(3, "success")),
        ],
    )
    state = github.latest_state(REPO, 7, V1_REPOSITORY, record_actor=BOT)
    assert state is not None and state.generation == 3 and state.outcome == "success"


def test_equal_generations_keep_the_newest_artifact(monkeypatch: pytest.MonkeyPatch) -> None:
    _sources(
        monkeypatch,
        [
            ("2026-10-16T10:00:00Z", _verdict_run(), _gen(0, "failure")),
            ("2026-10-16T11:00:00Z", _verdict_run(), _gen(0, "success")),
        ],
    )
    state = github.latest_state(REPO, 7, V1_REPOSITORY)
    assert state is not None and state.outcome == "success"


@pytest.mark.parametrize(
    ("run", "actor"),
    [
        (_record_run(actor="someone"), BOT),
        (_record_run(), ""),
        (_record_run(event="schedule"), BOT),
        (_record_run(path=".github/workflows/other.yml"), BOT),
    ],
    ids=["dispatched-by-a-person", "no-bot-configured", "not-a-dispatch", "another-workflow"],
)
def test_latest_state_trusts_record_runs_only_from_the_bot(
    monkeypatch: pytest.MonkeyPatch, run: dict[str, Any], actor: str
) -> None:
    downloaded = _sources(monkeypatch, [("2026-10-16T11:00:00Z", run, _gen(9))])
    assert github.latest_state(REPO, 7, V1_REPOSITORY, record_actor=actor) is None
    assert downloaded == []


# record-state


def _encode(state: State) -> str:
    return base64.b64encode(json.dumps(state.to_json()).encode()).decode()


def _record(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state: State,
    current: State | None,
    *,
    actor: str = BOT,
    ref: str = "refs/heads/develop",
    trusted: bool = True,
    encoded: str | None = None,
    head_sha: str = HEAD,
) -> tuple[int, dict[str, str]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    output = _env(monkeypatch, tmp_path, "workflow_dispatch", {}, ref)
    monkeypatch.setenv("GITHUB_TRIGGERING_ACTOR", actor)
    monkeypatch.setattr(github, "get_json", lambda path: _verdict_run())
    monkeypatch.setattr(github, "plan_run_trusted", lambda run, repo, pr, repository: trusted)
    monkeypatch.setattr(github, "latest_state", lambda repo, pr, repository, **_: current)
    argv = ["record-state", "--policy", str(POLICY_PATH), "--pr", "7", "--head-sha", head_sha]
    argv += ["--plan-run", "123", "--state", encoded or _encode(state), "--out", str(tmp_path / "out")]
    code = cli.main(argv)
    values = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    return code, values


def _stored(tmp_path: Path) -> dict[str, Any] | None:
    path = tmp_path / "out" / github.STATE_FILE
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def test_record_state_stores_the_successor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    code, values = _record(monkeypatch, tmp_path, _gen(4), _gen(3))
    assert code == 0 and values == {"upload": "true"}
    assert _stored(tmp_path) == _gen(4).to_json()


def test_record_state_stores_the_first_generation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert _record(monkeypatch, tmp_path, _gen(1), None) == (0, {"upload": "true"})


def test_a_duplicate_dispatch_is_a_no_op(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    code, values = _record(monkeypatch, tmp_path, _gen(4), _gen(4))
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
    code, values = _record(monkeypatch, tmp_path, state, current)
    assert code == 1 and values == {}
    assert _stored(tmp_path) is None


def test_reversed_completion_order_keeps_the_newer_generation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    first, second = _gen(1), _gen(2)
    assert _record(monkeypatch, tmp_path / "a", second, None)[0] == 1
    assert _record(monkeypatch, tmp_path / "b", first, None)[0] == 0
    assert _record(monkeypatch, tmp_path / "c", second, first)[0] == 0
    assert _record(monkeypatch, tmp_path / "d", first, second)[0] == 1


@pytest.mark.parametrize(
    ("options", "code"),
    [
        ({"actor": "someone"}, 1),
        ({"ref": "refs/heads/feature"}, 2),
        ({"trusted": False}, 1),
        ({"encoded": "not base64!"}, 1),
        ({"head_sha": "c" * 40}, 1),
        ({"encoded": base64.b64encode(json.dumps({**_gen(4).to_json(), "predecessor": 2}).encode()).decode()}, 1),
    ],
    ids=["wrong-actor", "wrong-ref", "untrusted-plan-run", "malformed", "other-head", "broken-chain"],
)
def test_record_state_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, options: dict[str, Any], code: int
) -> None:
    assert _record(monkeypatch, tmp_path, _gen(4), _gen(3), **options)[0] == code
    assert _stored(tmp_path) is None
