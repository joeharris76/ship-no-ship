from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ship_no_ship.engine import github
from ship_no_ship.engine.policy import V1_REPOSITORY, Artifacts, RepositoryConfig, Workflows
from ship_no_ship.engine.retry import State

from .test_github import PR, REPO, SHA, _head_pull, _pull, _run

pytestmark = [pytest.mark.unit, pytest.mark.fast]

MAIN = RepositoryConfig(
    base_branch="main",
    paths_manifest="config/review-paths.txt",
    workflows=Workflows(verdict=".github/workflows/review-verdict.yml", record=".github/workflows/review-record.yml"),
    artifacts=Artifacts(plan="p", request="r", state_prefix="review-state-"),
    heartbeat_context="reviews/heartbeat",
)
VERDICT = MAIN.workflows.verdict


def _trusted(
    run: dict[str, Any],
    is_on_base: Callable[[str, str], bool] | None = None,
    pulls: Sequence[github.HeadPull] | None = None,
) -> bool:
    return github.trusted_run(run, REPO, PR, is_on_base, pulls, workflow_path=VERDICT, base_branch="main")


def _target_run(*bases: str) -> dict[str, Any]:
    return _run(path=VERDICT, event="pull_request_target", pull_requests=[_pull(base) for base in bases])


def test_a_pull_request_target_run_is_trusted_only_into_the_configured_base() -> None:
    assert _trusted(_target_run("main"), pulls=[_head_pull(base_ref="main")])
    assert not _trusted(_target_run("develop"), pulls=[_head_pull(base_ref="develop")])
    assert not _trusted(_target_run("main"), pulls=[_head_pull(base_ref="main"), _head_pull(9, base_ref="develop")])


def test_other_runs_must_be_on_the_configured_base(monkeypatch: pytest.MonkeyPatch) -> None:
    paths: list[str] = []

    def get_json(path: str) -> Any:
        paths.append(path)
        return {"object": {"sha": "f" * 40}} if "/git/ref/" in path else {"status": "ahead"}

    monkeypatch.setattr(github, "get_json", get_json)
    assert _trusted(_run(path=VERDICT))
    assert paths == [f"repos/{REPO}/git/ref/heads/main", f"repos/{REPO}/compare/{SHA}...{'f' * 40}"]


def test_runs_of_another_workflow_are_untrusted() -> None:
    assert not _trusted(_run(), is_on_base=lambda repo, sha: True)
    assert _trusted(_run(path=VERDICT), is_on_base=lambda repo, sha: True)


def _listing(count: int, start: int = 0, total: int | None = None) -> dict[str, Any]:
    artifacts = [
        {"created_at": f"2026-10-05T12:{(start + n) % 60:02d}:00Z", "workflow_run": {"id": start + n}, "expired": False}
        for n in range(count)
    ]
    return {"total_count": total if total is not None else count, "artifacts": artifacts}


def test_artifact_listing_reads_every_page(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = {1: _listing(100, 0, 130), 2: _listing(30, 100, 130)}
    paths: list[str] = []

    def get_json(path: str) -> Any:
        paths.append(path)
        return pages[int(path.rsplit("page=", 1)[1])]

    monkeypatch.setattr(github, "get_json", get_json)
    found = github.list_artifacts(REPO, "review-state-7")
    assert len(found) == 130
    assert paths == [f"repos/{REPO}/actions/artifacts?name=review-state-7&per_page=100&page={n}" for n in (1, 2)]


def test_artifact_listing_stops_at_the_total_count(monkeypatch: pytest.MonkeyPatch) -> None:
    paths: list[str] = []
    monkeypatch.setattr(github, "get_json", lambda path: paths.append(path) or _listing(100, 0, 100))
    assert len(github.list_artifacts(REPO, "x")) == 100
    assert len(paths) == 1


def test_latest_state_reads_the_configured_artifact_name_and_workflow(monkeypatch: pytest.MonkeyPatch) -> None:
    state = State(7, "a" * 40, "pending", datetime(2026, 10, 5, tzinfo=UTC))
    names: list[str] = []

    def get_json(path: str) -> Any:
        if path.startswith(f"repos/{REPO}/actions/artifacts?name="):
            names.append(path.split("name=", 1)[1].split("&", 1)[0])
            return _listing(1, 40)
        if path.startswith(f"repos/{REPO}/actions/runs/"):
            return _run(path=VERDICT)
        if path == f"repos/{REPO}/git/ref/heads/main":
            return {"object": {"sha": "f" * 40}}
        if path == f"repos/{REPO}/compare/{SHA}...{'f' * 40}":
            return {"status": "identical"}
        raise AssertionError(f"unexpected request {path}")

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        (Path(argv[argv.index("-D") + 1]) / github.STATE_FILE).write_text(json.dumps(state.to_json()), "utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(github, "get_json", get_json)
    monkeypatch.setattr(github.subprocess, "run", fake_run)
    assert github.latest_state(REPO, 7, MAIN) == state
    assert names == ["review-state-7"]
    assert github.latest_state(REPO, 7, V1_REPOSITORY) is None
    assert names[-1] == "oracle-verdict-state-7"


def test_dispatch_runs_the_workflow_on_the_given_ref(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        github.subprocess, "run", lambda argv, **kwargs: calls.append(argv) or subprocess.CompletedProcess(argv, 0)
    )
    github.dispatch(REPO, "review-verdict.yml", 7, "main")
    assert calls == [["gh", "workflow", "run", "review-verdict.yml", "--ref", "main", "-f", "pr=7", "-R", REPO]]


def test_artifact_listing_without_a_total_pages_until_a_short_page(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = {1: _listing(100), 2: _listing(100, 100), 3: _listing(5, 200)}
    for page in pages.values():
        del page["total_count"]
    monkeypatch.setattr(github, "get_json", lambda path: pages[int(path.rsplit("page=", 1)[1])])
    assert len(github.list_artifacts(REPO, "x")) == 205


def test_artifact_listing_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    paths: list[str] = []
    monkeypatch.setattr(github, "get_json", lambda path: paths.append(path) or _listing(100, 0, 5000))
    with pytest.raises(github.GitHubError, match="more than 1000 artifacts are named x"):
        github.list_artifacts(REPO, "x")
    assert len(paths) == github.MAX_ARTIFACT_PAGES


def test_an_artifact_without_the_expected_file_is_a_github_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(args: Sequence[str], **_: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(github.subprocess, "run", run)
    with pytest.raises(github.GitHubError, match="state.json is missing from state-7 in run 41"):
        github.download_json("owner/repo", "41", "state-7", "state.json")
