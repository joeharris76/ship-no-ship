from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from ship_no_ship.engine import cli, github
from ship_no_ship.engine.retry import State

from .conftest import BENCHBOX_ROOT, POLICY_PATH
from .test_cli_plan import BASE, BASE_COMMIT, HEAD, REPO, FakeGitHub, _env, _pull

pytestmark = [pytest.mark.unit, pytest.mark.fast]

FILES = [{"filename": "lib/checks/compare.py", "additions": 4, "deletions": 1}]


def _root(tmp_path: Path, **repository: Any) -> tuple[Path, Path]:
    root = tmp_path / "repo"
    (root / "config").mkdir(parents=True)
    (root / "config" / "review-paths.txt").write_text("prefix\tlib/checks/\n", encoding="utf-8")
    raw = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    del raw["bot_login"]
    raw["version"] = 2
    raw["repository"] = {
        "base_branch": "main",
        "paths_manifest": "config/review-paths.txt",
        "bot_login": "review-bot",
        "workflows": {"verdict": ".github/workflows/review-verdict.yml"},
        "artifacts": {"state_prefix": "review-state-"},
        **repository,
    }
    policy = root / "policy.yml"
    policy.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return root, policy


def _main_pull(**over: Any) -> dict[str, Any]:
    return _pull(base={"ref": "main", "sha": BASE}, **over)


def _run_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fake: FakeGitHub,
    root: Path,
    policy: Path,
    event_name: str = "pull_request_target",
    ref: str = "refs/heads/main",
) -> tuple[int, dict[str, str], dict[str, Any]]:
    fake.root = root
    fake.install(monkeypatch)
    seen: list[Any] = []
    monkeypatch.setattr(github, "latest_state", lambda repo, pr, repository: seen.append(repository))
    output = _env(monkeypatch, tmp_path, event_name, {"action": "synchronize"}, ref)
    out_dir = tmp_path / "plan"
    code = cli.main(["plan", "--policy", str(policy), "--pr", "7", "--out", str(out_dir), "--root", str(root)])
    values = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    plan_file = out_dir / "plan.json"
    plan = json.loads(plan_file.read_text(encoding="utf-8")) if plan_file.is_file() else {}
    if plan.get("decision") == "review":
        assert [item.base_branch for item in seen] == ["main"]
    return code, values, plan


def test_a_pull_request_into_the_configured_base_is_reviewed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path)
    code, values, plan = _run_plan(monkeypatch, tmp_path, FakeGitHub(_main_pull(), FILES), root, policy)
    assert code == 0 and values["decision"] == "review"
    assert plan["bot_login"] == "review-bot" and plan["base_ref"] == "main"
    assert plan["evidence_files"] == ["lib/checks/compare.py"]


def test_the_configured_manifest_decides_what_needs_review(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path)
    files = [{"filename": "benchbox/core/equivalence/checker.py", "additions": 4, "deletions": 1}]
    _, values, plan = _run_plan(monkeypatch, tmp_path, FakeGitHub(_main_pull(), files), root, policy)
    assert values["decision"] == "success" and plan["decision_reason"] == "no soundness path changed"


def test_a_pull_request_into_another_branch_is_skipped(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path)
    _, values, plan = _run_plan(monkeypatch, tmp_path, FakeGitHub(_pull(), FILES), root, policy)
    assert values["decision"] == "skip"
    assert plan["decision_reason"] == "the pull request does not target main"


@pytest.mark.parametrize(("ref", "code"), [("refs/heads/main", 0), ("refs/heads/develop", 2)])
def test_dispatch_runs_only_from_the_configured_base(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], ref: str, code: int
) -> None:
    root, policy = _root(tmp_path)
    fake = FakeGitHub(_main_pull(), FILES)
    result, _, _ = _run_plan(monkeypatch, tmp_path, fake, root, policy, event_name="workflow_dispatch", ref=ref)
    assert result == code
    if code:
        assert "dispatch runs only from main" in capsys.readouterr().err


def test_a_missing_manifest_fails_closed_before_any_plan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path, paths_manifest="config/absent.txt")
    with pytest.raises(SystemExit, match="the path manifest cannot be read"):
        _run_plan(monkeypatch, tmp_path, FakeGitHub(_main_pull(), FILES), root, policy)
    assert not (tmp_path / "plan" / "plan.json").exists()


def test_a_malformed_manifest_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path)
    (root / "config" / "review-paths.txt").write_text("dir\tlib/\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="unknown rule kind"):
        _run_plan(monkeypatch, tmp_path, FakeGitHub(_main_pull(), FILES), root, policy)


def test_a_policy_for_another_repository_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path, slug="octo-org/widgets")
    with pytest.raises(SystemExit, match=f"the policy is for octo-org/widgets, not {REPO}"):
        _run_plan(monkeypatch, tmp_path, FakeGitHub(_main_pull(), FILES), root, policy)


def test_a_policy_naming_this_repository_plans(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path, slug=REPO)
    _, values, _ = _run_plan(monkeypatch, tmp_path, FakeGitHub(_main_pull(), FILES), root, policy)
    assert values["decision"] == "review"


def test_the_sweep_uses_the_configured_base_and_workflow(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path)
    due = State(7, HEAD, "pending", datetime.now(UTC) - timedelta(hours=2), pending_cause="all-absent")
    fake = FakeGitHub(_main_pull(), FILES, due)
    fake.install(monkeypatch)
    listed: list[str] = []
    paginated = github.get_paginated
    monkeypatch.setattr(github, "get_paginated", lambda path: listed.append(path) or paginated(path))
    seen: list[Any] = []
    monkeypatch.setattr(github, "latest_state", lambda repo, pr, repository: seen.append(repository) or due)
    _env(monkeypatch, tmp_path, "schedule", {}, "refs/heads/main")
    assert cli.main(["sweep", "--policy", str(policy)]) == 0
    assert listed == [f"repos/{REPO}/pulls?state=open&base=main&per_page=100"]
    assert fake.dispatches == [("review-verdict.yml", 7, "main")]
    assert seen[0].artifacts.state_prefix == "review-state-"


def test_the_benchbox_sweep_dispatches_its_verdict_workflow_on_develop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    due = State(7, HEAD, "pending", datetime.now(UTC) - timedelta(hours=2), pending_cause="all-absent")
    fake = FakeGitHub(_pull(), FILES, due)
    fake.install(monkeypatch)
    _env(monkeypatch, tmp_path, "schedule", {}, "refs/heads/develop")
    assert cli.main(["sweep", "--policy", str(POLICY_PATH)]) == 0
    assert fake.dispatches == [("oracle-verdict.yml", 7, "develop")]


def test_validate_config_accepts_the_benchbox_policy(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["validate-config", "--policy", str(POLICY_PATH), "--root", str(BENCHBOX_ROOT)]) == 0
    out = capsys.readouterr().out
    assert "valid policy version 1" in out
    assert "base branch develop" in out
    assert "paths manifest: .github/soundness-paths.txt (" in out
    assert "executor: hosted" in out


def test_validate_config_accepts_a_version_2_policy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root, policy = _root(tmp_path, slug="octo-org/widgets")
    assert cli.main(["validate-config", "--policy", str(policy), "--root", str(root)]) == 0
    out = capsys.readouterr().out
    assert "valid policy version 2" in out and "octo-org/widgets, base branch main" in out
    assert "config/review-paths.txt (1 rules)" in out


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"paths_manifest": "config/absent.txt"}, "cannot be read"),
        ({"base_branch": "a..b"}, "base_branch must be a branch name"),
    ],
)
def test_validate_config_reports_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], change: dict[str, Any], message: str
) -> None:
    root, policy = _root(tmp_path, **change)
    assert cli.main(["validate-config", "--policy", str(policy), "--root", str(root)]) == 1
    assert message in capsys.readouterr().err


def test_validate_config_reports_an_unreadable_policy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["validate-config", "--policy", str(tmp_path / "absent.yml")]) == 1
    assert "ship-no-ship: error:" in capsys.readouterr().err


def test_validate_config_reports_invalid_yaml(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy = tmp_path / "policy.yml"
    policy.write_text("version: [1\n", encoding="utf-8")
    assert cli.main(["validate-config", "--policy", str(policy)]) == 1
    assert "ship-no-ship: error:" in capsys.readouterr().err


def test_an_off_base_pull_request_is_skipped_with_a_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, policy = _root(tmp_path)
    _, values, _ = _run_plan(monkeypatch, tmp_path, FakeGitHub(_pull(), FILES), root, policy)
    assert values["decision"] == "skip"
    assert "::warning::ship-no-ship: #7 targets develop, not main; it is not reviewed" in capsys.readouterr().out


def test_a_pull_request_target_run_from_another_branch_is_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, policy = _root(tmp_path)
    fake = FakeGitHub(_main_pull(), FILES)
    _, values, plan = _run_plan(monkeypatch, tmp_path, fake, root, policy, ref="refs/heads/release")
    assert values["decision"] == "skip" and plan["decision_reason"] == "the pull request does not target main"
    assert "::warning::" in capsys.readouterr().out
    assert fake.contents_paths == []


@pytest.mark.parametrize("event_name", ["issue_comment", "schedule", "workflow_dispatch"])
def test_other_events_run_only_from_the_base_branch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], event_name: str
) -> None:
    root, policy = _root(tmp_path)
    fake = FakeGitHub(_main_pull(), FILES)
    code, values, _ = _run_plan(monkeypatch, tmp_path, fake, root, policy, event_name, ref="refs/heads/develop")
    assert code == 2 and values == {}
    assert f"{event_name} runs only from main" in capsys.readouterr().err


def test_the_sweep_runs_only_from_the_base_branch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, policy = _root(tmp_path)
    fake = FakeGitHub(_main_pull(), FILES)
    fake.install(monkeypatch)
    _env(monkeypatch, tmp_path, "schedule", {}, "refs/heads/develop")
    assert cli.main(["sweep", "--policy", str(policy)]) == 2
    assert fake.dispatched == [] and "sweep runs only from main" in capsys.readouterr().err


def test_the_manifest_is_checked_against_the_trusted_base_commit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, policy = _root(tmp_path)
    fake = FakeGitHub(_main_pull(), FILES)
    _run_plan(monkeypatch, tmp_path, fake, root, policy)
    assert fake.contents_paths == [
        f"repos/{REPO}/contents/policy.yml?ref={BASE_COMMIT}",
        f"repos/{REPO}/contents/config/review-paths.txt?ref={BASE_COMMIT}",
    ]


@pytest.mark.parametrize("path", ["policy.yml", "config/review-paths.txt"])
def test_a_policy_or_manifest_that_differs_from_the_base_commit_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, path: str
) -> None:
    root, policy = _root(tmp_path)
    fake = FakeGitHub(_main_pull(), FILES)
    fake.contents[path] = {"type": "file", "sha": "0" * 40}
    with pytest.raises(SystemExit, match=f"{path} differs from the copy at"):
        _run_plan(monkeypatch, tmp_path, fake, root, policy)
    assert not (tmp_path / "plan" / "plan.json").exists()


def test_a_policy_outside_the_root_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path)
    outside = tmp_path / "elsewhere.yml"
    outside.write_bytes(policy.read_bytes())
    fake = FakeGitHub(_main_pull(), FILES)
    with pytest.raises(SystemExit, match="--policy must be inside --root"):
        _run_plan(monkeypatch, tmp_path, fake, root, outside)
    assert fake.contents_paths == []


@pytest.mark.parametrize("link", ["policy.yml", "config"])
def test_a_policy_or_manifest_behind_a_symlink_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, link: str
) -> None:
    root, policy = _root(tmp_path)
    target = root / f"{link}.real"
    (root / link).rename(target)
    (root / link).symlink_to(target.name)
    fake = FakeGitHub(_main_pull(), FILES)
    with pytest.raises(SystemExit, match="must not pass through a symlink"):
        _run_plan(monkeypatch, tmp_path, fake, root, policy)


def test_a_relative_policy_path_is_checked_at_its_own_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path)
    monkeypatch.chdir(root)
    fake = FakeGitHub(_main_pull(), FILES)
    _, values, _ = _run_plan(monkeypatch, tmp_path, fake, Path("."), Path("policy.yml"))
    assert values["decision"] == "review"
    assert fake.contents_paths[0] == f"repos/{REPO}/contents/policy.yml?ref={BASE_COMMIT}"


def test_a_root_reached_through_a_symlink_is_accepted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(root)
    fake = FakeGitHub(_main_pull(), FILES)
    _, values, _ = _run_plan(monkeypatch, tmp_path, fake, alias, alias / policy.name)
    assert values["decision"] == "review"


def test_a_policy_path_with_parent_segments_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path)
    fake = FakeGitHub(_main_pull(), FILES)
    with pytest.raises(SystemExit, match="must not contain '..'"):
        _run_plan(monkeypatch, tmp_path, fake, root, root / "config" / ".." / policy.name)
    assert fake.contents_paths == []


def test_a_base_entry_that_is_not_a_file_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path)
    fake = FakeGitHub(_main_pull(), FILES)
    fake.contents["config/review-paths.txt"] = [{"type": "file", "name": "review-paths.txt"}]
    with pytest.raises(SystemExit, match="config/review-paths.txt at .* is not a file"):
        _run_plan(monkeypatch, tmp_path, fake, root, policy)


def test_a_missing_base_commit_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path)
    FakeGitHub(_main_pull(), FILES).install(monkeypatch)
    _env(monkeypatch, tmp_path, "pull_request_target", {"action": "synchronize"}, "refs/heads/main")
    monkeypatch.delenv("GITHUB_SHA")
    with pytest.raises(SystemExit, match="GITHUB_SHA must name the base commit"):
        cli.main(["plan", "--policy", str(policy), "--pr", "7", "--out", str(tmp_path / "plan"), "--root", str(root)])


def test_an_unreadable_base_manifest_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path)
    fake = FakeGitHub(_main_pull(), FILES)
    original = fake._json

    def broken(path: str) -> Any:
        if "/contents/" in path:
            raise github.GitHubError("HTTP 404")
        return original(path)

    monkeypatch.setattr(fake, "_json", broken)
    with pytest.raises(SystemExit, match="cannot be read: HTTP 404"):
        _run_plan(monkeypatch, tmp_path, fake, root, policy)


def test_the_slug_matches_regardless_of_case(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root, policy = _root(tmp_path, slug=REPO.upper())
    _, values, _ = _run_plan(monkeypatch, tmp_path, FakeGitHub(_main_pull(), FILES), root, policy)
    assert values["decision"] == "review"


def _git_tree(root: Path, *paths: str) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    for path in paths:
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)


def _check_tree(root: Path, policy: Path, *extra: str) -> int:
    return cli.main(["validate-config", "--policy", str(policy), "--root", str(root), "--check-tree", *extra])


def test_check_tree_counts_the_files_the_manifest_matches(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root, policy = _root(tmp_path)
    _git_tree(root, "lib/checks/a.py", "lib/checks/b.py", "docs/x.md", ".github/workflows/review-verdict.yml")
    assert _check_tree(root, policy) == 0
    assert "matches 2 of 6 tracked files" in capsys.readouterr().out


def test_check_tree_fails_when_the_manifest_matches_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root, policy = _root(tmp_path)
    _git_tree(root, "docs/x.md", ".github/workflows/review-verdict.yml")
    assert _check_tree(root, policy) == 1
    assert "the paths manifest matches no tracked file" in capsys.readouterr().err


def test_check_tree_needs_the_verdict_workflow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root, policy = _root(tmp_path)
    _git_tree(root, "lib/checks/a.py")
    assert _check_tree(root, policy) == 1
    assert "workflow .github/workflows/review-verdict.yml does not exist" in capsys.readouterr().err


def test_check_tree_needs_the_record_workflow_off_the_hosted_executor(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, policy = _root(tmp_path)
    raw = yaml.safe_load(policy.read_text(encoding="utf-8"))
    raw["executor"] = {"mode": "proof"}
    policy.write_text(yaml.safe_dump(raw), encoding="utf-8")
    _git_tree(root, "lib/checks/a.py", ".github/workflows/review-verdict.yml")
    assert _check_tree(root, policy) == 1
    assert "workflow .github/workflows/oracle-verdict-record.yml does not exist" in capsys.readouterr().err


def test_check_tree_compares_the_slug(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root, policy = _root(tmp_path, slug="octo-org/widgets")
    _git_tree(root, "lib/checks/a.py", ".github/workflows/review-verdict.yml")
    assert _check_tree(root, policy, "--repository", "Octo-Org/Widgets") == 0
    assert _check_tree(root, policy, "--repository", "someone/else") == 1
    assert "the policy is for octo-org/widgets, not someone/else" in capsys.readouterr().err


def test_check_tree_needs_a_git_checkout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root, policy = _root(tmp_path)
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "review-verdict.yml").write_text("x\n", encoding="utf-8")
    monkey_env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, "-m", "ship_no_ship.engine.cli", "validate-config", "--policy", str(policy)]
        + ["--root", str(root), "--check-tree"],
        capture_output=True,
        text=True,
        env=monkey_env,
    )
    assert result.returncode == 1 and "is not a git checkout" in result.stderr
