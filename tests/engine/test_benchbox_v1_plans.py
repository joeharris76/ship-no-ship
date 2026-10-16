from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from ship_no_ship.engine import cli, github
from ship_no_ship.engine.retry import State

from .conftest import MANIFEST_PATH, POLICY_PATH
from .test_cli_plan import (
    BASE,
    HEAD,
    REPO,
    SOUNDNESS,
    TWO_FILE_DIFF,
    FakeGitHub,
    _env,
    _fake,
    _plan,
    _pull,
    _record,
    _review,
    _strike,
)

pytestmark = [pytest.mark.unit, pytest.mark.fast]

GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "benchbox" / "v1_plan_outcomes.json"
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
README = [{"filename": "README.md", "additions": 1, "deletions": 0}]
GATE = [{"filename": ".github/oracle-reviewers.yml", "additions": 1, "deletions": 0}]
EVIDENCE = [
    *SOUNDNESS,
    {"filename": "benchbox/core/equivalence/gone.py", "additions": 0, "deletions": 3, "status": "removed"},
    {"filename": "docs/notes.md", "additions": 1, "deletions": 0},
]
COMMENT = {"action": "created", "issue": {"number": 7, "pull_request": {}}, "comment": {"body": "/oracle-review"}}

PLANS: dict[str, Callable[[], tuple[FakeGitHub, dict[str, Any]]]] = {
    "review": lambda: (FakeGitHub(_pull(), SOUNDNESS), {}),
    "evidence-files": lambda: (FakeGitHub(_pull(), EVIDENCE), {}),
    "not-soundness": lambda: (FakeGitHub(_pull(), README), {}),
    "gate-file": lambda: (FakeGitHub(_pull(), GATE), {}),
    "tier-label": lambda: (FakeGitHub(_pull(labels=[{"name": "oracle-tier:very-high"}]), SOUNDNESS), {}),
    "fork": lambda: (FakeGitHub(_pull(head={"sha": HEAD, "repo": {"full_name": "someone/BenchBox"}}), SOUNDNESS), {}),
    "closed": lambda: (FakeGitHub(_pull(state="closed"), SOUNDNESS), {}),
    "draft": lambda: (FakeGitHub(_pull(draft=True), SOUNDNESS), {}),
    "other-base": lambda: (FakeGitHub(_pull(base={"ref": "release", "sha": BASE}), SOUNDNESS), {}),
    "stale-event-head": lambda: (
        FakeGitHub(_pull(), SOUNDNESS),
        {"event": {"action": "synchronize", "pull_request": {"head": {"sha": "c" * 40}}}},
    ),
    "comment": lambda: (FakeGitHub(_pull(), SOUNDNESS), {"event_name": "issue_comment", "event": COMMENT}),
    "dispatch-on-base": lambda: (
        FakeGitHub(_pull(), SOUNDNESS),
        {"event_name": "workflow_dispatch", "event": {"inputs": {"pr": "7"}}},
    ),
    "dispatch-off-base": lambda: (
        FakeGitHub(_pull(), SOUNDNESS),
        {"event_name": "workflow_dispatch", "event": {"inputs": {"pr": "7"}}, "ref": "refs/heads/feature"},
    ),
    "decided-head": lambda: (_fake(_review(_record(TWO_FILE_DIFF, "SHIP_WITH_FIXES", head_sha=HEAD))), {}),
    "follow-up": lambda: (_fake(_review(_record(TWO_FILE_DIFF.replace("a\n+", "b\n+"), "SHIP_WITH_FIXES"))), {}),
    "refused": lambda: (_fake(_strike(1), _strike(2), _strike(3)), {}),
}


REAL_LATEST_STATE = github.latest_state
REAL_DISPATCH = github.dispatch
REAL_RUN = subprocess.run
BASE_COMMIT = "9" * 40
BRANCH_SHA = "f" * 40
RUN_HEAD = "d" * 40
STATE_RUN = 41
STATE_ARTIFACT = "oracle-verdict-state-7"
MANIFEST_BLOB = hashlib.sha1(
    b"blob %d\0" % len(MANIFEST_PATH.read_bytes()) + MANIFEST_PATH.read_bytes(), usedforsecurity=False
).hexdigest()
OWNER = "BenchBox-dev"


@dataclass(frozen=True)
class StateRun:
    event: str
    path: str = ".github/workflows/oracle-verdict.yml"
    repository: str = "BenchBox-dev/BenchBox"
    status: str = "ahead"
    bases: tuple[str, ...] = ("develop",)
    head_pull_base: str = "develop"
    expired: bool = False

    def run(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "repository": {"full_name": self.repository},
            "event": self.event,
            "head_sha": RUN_HEAD,
            "created_at": "2026-10-07T23:05:42Z",
            "pull_requests": [{"number": 7, "base": {"ref": base}} for base in self.bases],
            "head_repository": {"owner": {"login": OWNER}},
            "head_branch": "fix/example",
        }


STATE_RUNS = {
    "state-issue-comment": StateRun("issue_comment"),
    "state-schedule": StateRun("schedule"),
    "state-workflow-dispatch": StateRun("workflow_dispatch"),
    "state-pull-request-target": StateRun("pull_request_target"),
    "state-not-on-base": StateRun("issue_comment", status="behind"),
    "state-diverged": StateRun("schedule", status="diverged"),
    "state-target-other-base": StateRun("pull_request_target", bases=("release",)),
    "state-target-sibling-base": StateRun("pull_request_target", head_pull_base="release"),
    "state-pull-request": StateRun("pull_request"),
    "state-push": StateRun("push"),
    "state-shadow-workflow": StateRun("schedule", path=".github/workflows/oracle-review-shadow.yml"),
    "state-other-repository": StateRun("schedule", repository="someone/BenchBox"),
    "state-expired": StateRun("schedule", expired=True),
}


def _instrument(
    monkeypatch: pytest.MonkeyPatch, fake: FakeGitHub, state_run: StateRun | None, state: State | None
) -> list[list[str]]:
    calls: list[list[str]] = []
    original = fake.install

    def run(argv: list[str], **kwargs: Any) -> Any:
        if argv[:3] == ["gh", "workflow", "run"]:
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:3] == ["gh", "run", "download"] and state is not None:
            calls.append(list(argv[:6]))
            target = Path(argv[argv.index("-D") + 1]) / github.STATE_FILE
            target.write_text(json.dumps(state.to_json()), encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, "", "")
        return REAL_RUN(argv, **kwargs)

    def install(patch: pytest.MonkeyPatch) -> None:
        original(patch)
        patch.setattr(github, "dispatch", REAL_DISPATCH)
        patch.setattr(github.subprocess, "run", run)
        fake_json, fake_pages = github.get_json, github.get_paginated

        def get_json(path: str) -> Any:
            if "/contents/" in path:
                return {"sha": MANIFEST_BLOB}
            if state_run is not None:
                if "/actions/artifacts?" in path:
                    found = f"name={STATE_ARTIFACT}&" in path
                    artifact = {
                        "created_at": "2026-10-07T23:10:00Z",
                        "workflow_run": {"id": STATE_RUN},
                        "expired": state_run.expired,
                    }
                    return {"total_count": int(found), "artifacts": [artifact] if found else []}
                if path.endswith(f"/actions/runs/{STATE_RUN}"):
                    return state_run.run()
                if path.endswith("/git/ref/heads/develop"):
                    return {"object": {"sha": BRANCH_SHA}}
                if re.search(rf"/compare/{RUN_HEAD}\.\.\.(?:develop|{BRANCH_SHA})$", path):
                    return {"status": state_run.status}
            return fake_json(path)

        def get_paginated(path: str) -> list[Any]:
            if state_run is not None:
                if "pulls?state=all&head=" in path:
                    pull = {
                        "number": 7,
                        "created_at": "2026-10-07T23:00:00Z",
                        "base": {"ref": state_run.head_pull_base},
                    }
                    return [pull]
                if path.endswith("/timeline?per_page=100"):
                    return []
            return fake_pages(path)

        patch.setattr(github, "get_json", get_json)
        patch.setattr(github, "get_paginated", get_paginated)
        if state_run is not None:
            patch.setattr(github, "latest_state", REAL_LATEST_STATE)

    monkeypatch.setattr(fake, "install", install)
    return calls


def _digest(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def _plan_outcome(
    monkeypatch: pytest.MonkeyPatch, workdir: Path, fake: FakeGitHub, options: dict[str, Any], calls: list[list[str]]
) -> dict[str, Any]:
    workdir.mkdir()
    code, values, plan = _plan(monkeypatch, workdir, fake, **options)
    return {
        "code": code,
        "outputs": values,
        "plan": plan,
        "brief_sha256": _digest(workdir / "plan" / "brief.md"),
        "diff_sha256": _digest(workdir / "plan" / "diff.patch"),
        "gh_calls": calls,
    }


def _sweep_outcome(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fake: FakeGitHub, calls: list[list[str]]) -> Any:
    fake.install(monkeypatch)
    _env(monkeypatch, tmp_path, "schedule", {}, "refs/heads/develop")
    return {"code": cli.main(["sweep", "--policy", str(POLICY_PATH)]), "gh_calls": calls}


def collect_outcomes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    monkeypatch.setattr(cli, "_now", lambda: NOW)
    monkeypatch.setenv("GITHUB_SHA", BASE_COMMIT)
    outcomes: dict[str, Any] = {}
    for name, build in PLANS.items():
        fake, options = build()
        calls = _instrument(monkeypatch, fake, None, None)
        outcomes[name] = _plan_outcome(monkeypatch, tmp_path / name, fake, options, calls)
    due = State(7, HEAD, "pending", NOW - timedelta(hours=2), pending_cause="all-absent")
    for name, state_run in STATE_RUNS.items():
        fake = FakeGitHub(_pull(), SOUNDNESS)
        calls = _instrument(monkeypatch, fake, state_run, due)
        outcomes[f"plan-{name}"] = _plan_outcome(monkeypatch, tmp_path / name, fake, {}, calls)
        fake = FakeGitHub(_pull(), SOUNDNESS)
        calls = _instrument(monkeypatch, fake, state_run, due)
        outcomes[f"sweep-{name}"] = _sweep_outcome(monkeypatch, tmp_path, fake, calls)
    for name, pull in {"sweep-due": _pull(), "sweep-draft": _pull(draft=True)}.items():
        fake = FakeGitHub(pull, SOUNDNESS, due)
        calls = _instrument(monkeypatch, fake, None, None)
        outcomes[name] = _sweep_outcome(monkeypatch, tmp_path, fake, calls)
    return json.loads(json.dumps(outcomes, sort_keys=True))


def test_benchbox_v1_policy_plans_exactly_as_the_imported_engine(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    actual = collect_outcomes(monkeypatch, tmp_path)
    assert sorted(actual) == sorted(expected)
    for name in expected:
        assert actual[name] == expected[name], name


def test_the_golden_covers_trusted_and_untrusted_state_and_dispatches() -> None:
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    read = {name for name in STATE_RUNS if expected[f"plan-{name}"]["plan"]["previous_state"] is not None}
    assert read == {"state-issue-comment", "state-schedule", "state-workflow-dispatch", "state-pull-request-target"}
    dispatches = [call for call in expected["sweep-due"]["gh_calls"] if call[:3] == ["gh", "workflow", "run"]]
    assert dispatches == [["gh", "workflow", "run", "oracle-verdict.yml", "--ref", "develop", "-f", "pr=7", "-R", REPO]]
