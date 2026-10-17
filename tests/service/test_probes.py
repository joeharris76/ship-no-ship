from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ship_no_ship_service import doctor, probes
from ship_no_ship_service.config import Repository
from ship_no_ship_service.doctor import FAIL, NOT_RUN, PASS, WARN
from ship_no_ship_service.probes import Probes, RecordActorProbe, SudoRunner

PRIVATE_OUTPUT = "signed in as private-account-name"
SLUG = "example-owner/example-repo"
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


class Runner:
    def __init__(self, answers: dict[tuple[str, str], tuple[int, str] | Exception] | None = None) -> None:
        self.answers = answers or {}
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def __call__(self, cli, argv, timeout):
        self.calls.append((cli, tuple(argv)))
        answer = self.answers.get((cli, argv[1]), (0, PRIVATE_OUTPUT))
        if isinstance(answer, Exception):
            raise answer
        return answer


def statuses(results) -> dict[str, str]:
    return {result.name: result.status for result in results}


def test_without_sudo_the_role_user_checks_fail_once_installed_and_are_not_run_before():
    assert {r.status for r in Probes().auth_status(["claude", "codex"])} == {FAIL}
    assert {r.status for r in Probes(strict=False).auth_status(["claude", "codex"])} == {NOT_RUN}
    assert Probes().triggering_actor()[0].status == NOT_RUN


def test_auth_status_reports_exit_codes_never_output_and_unknown_clis_stay_disabled():
    runner = Runner({("codex", "login"): (1, PRIVATE_OUTPUT)})
    results = Probes(runner=runner).auth_status(doctor.CLIS)
    assert statuses(results) == {"auth claude": PASS, "auth codex": FAIL, "auth muse": WARN, "auth agy": WARN}
    assert all("private-account-name" not in result.detail for result in results)
    assert "stays disabled" in results[3].detail


def test_a_runner_failure_is_a_failed_check():
    [result] = Probes(runner=Runner({("claude", "auth"): TimeoutError()})).auth_status(["claude"])
    assert (result.status, result.detail) == (FAIL, "could not run as the claude role user: TimeoutError")


@pytest.mark.parametrize(
    ("output", "status"),
    [("SSNS-UNREADABLE\n", PASS), ("SSNS-READABLE\n", WARN), ("the word SSNS-READABLE in a sentence", FAIL)],
)
def test_codex_token_readability_runs_in_codexs_own_sandbox(output, status):
    runner = Runner({("codex", "sandbox"): (0, output)})
    assert Probes(runner=runner).codex_token().status == status
    exists, sandboxed = runner.calls[0][1], runner.calls[1][1]
    assert exists[0] == "/bin/sh" and "test -f" in exists[2]
    assert sandboxed[:4] == ("codex", "sandbox", "macos", "--") and "$CODEX_HOME/auth.json" in sandboxed[6]


def test_a_missing_codex_token_fails_before_the_sandbox_runs():
    runner = Runner({("codex", "-c"): (1, "")})
    result = Probes(runner=runner).codex_token()
    assert result.status == FAIL and "missing or not a regular file" in result.detail
    assert len(runner.calls) == 1


def test_post_reboot_checks_keychain_clis_with_unlock_steps_and_agy_warns():
    runner = Runner({("claude", "auth"): (1, ""), ("claude", "-p"): (0, "OK\n")})
    results = Probes(runner=runner).post_reboot()
    assert statuses(results) == {"auth claude": FAIL, "auth agy": WARN, "headless claude": PASS, "headless agy": WARN}
    assert "security unlock-keychain" in results[0].detail and "_ssnsclaude" in results[0].detail


@pytest.mark.parametrize(
    ("output", "status"), [("OK", PASS), ("  OK  \n", PASS), ("TOKEN", FAIL), ("OK then more", FAIL)]
)
def test_headless_needs_ok_on_a_line_of_its_own(output, status):
    [result] = Probes(runner=Runner({("claude", "-p"): (0, output)})).headless(["claude"])
    assert result.status == status


def test_sudo_runner_switches_user_with_a_clean_environment(monkeypatch, tmp_path):
    seen = {}

    class Done:
        returncode, stdout, stderr = 0, "OK\n", ""

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        return Done()

    monkeypatch.setattr(probes.subprocess, "run", fake_run)
    assert SudoRunner(tmp_path / "data", tmp_path / "libexec")("codex", ["codex", "login", "status"], 5) == (0, "OK\n")
    assert seen["argv"][:8] == [
        "/usr/bin/sudo",
        "-n",
        "-u",
        "_ssnscodex",
        "-H",
        "/usr/bin/env",
        "-i",
        f"HOME={tmp_path / 'data' / 'home' / 'codex'}",
    ]
    assert seen["argv"][8] == f"PATH={tmp_path / 'libexec' / 'bin'}:/usr/bin:/bin"
    assert seen["argv"][9] == f"CODEX_HOME={tmp_path / 'data' / 'home' / 'codex' / '.codex'}"


class FakeGitHub:
    """Runs, artifacts and issues for the actor probe; runs finish on the second read."""

    def __init__(self) -> None:
        self.runs: dict[int, dict] = {}
        self.artifacts: dict[int, list[dict]] = {}
        self.issues: list[dict] = []
        self.comments: dict[int, list[dict]] = {}
        self.reads: dict[int, int] = {}
        # The record workflow's blob at each ref, and the commits on the base branch.
        self.workflow_at: dict[str, str] = {"main": "w" * 40, BASE_SHA: "w" * 40}
        self.on_base = {BASE_SHA}

    def get(self, path: str):
        if path.startswith(f"repos/{SLUG}/contents/"):
            workflow, ref = path.removeprefix(f"repos/{SLUG}/contents/").split("?ref=")
            assert workflow == ".github/workflows/oracle-verdict-record.yml"
            return {"sha": self.workflow_at[ref]}
        if path == f"repos/{SLUG}/git/ref/heads/main":
            return {"object": {"sha": "f" * 40}}
        if path.startswith(f"repos/{SLUG}/compare/"):
            sha = path.removeprefix(f"repos/{SLUG}/compare/").split("...")[0]
            return {"status": "ahead" if sha in self.on_base else "diverged"}
        if path.startswith(f"repos/{SLUG}/actions/runs/77/artifacts"):
            return {"artifacts": [{"id": 5, "name": "oracle-verdict-request"}]}
        if "/actions/workflows/" in path:
            return {"workflow_runs": sorted(self.runs.values(), key=lambda run: -run["id"])}
        tail = path.split("/actions/runs/")[1]
        run_id = int(tail.split("/")[0])
        if tail.endswith("/artifacts"):
            return {"artifacts": self.artifacts.get(run_id, [])}
        self.reads[run_id] = self.reads.get(run_id, 0) + 1
        run = dict(self.runs[run_id])
        if self.reads[run_id] == 1:
            run.update(status="in_progress", conclusion=None)
        return run

    def paginate(self, path: str):
        if "/comments" in path:
            return self.comments.get(int(path.split("/issues/")[1].split("/")[0]), [])
        assert "labels=oracle-record-rejected" in path and "state=open" in path
        return self.issues

    def artifact_files(self, artifact_id: int):
        plan = {"pr": 4, "head_sha": "a" * 40, "previous_state": {"generation": 2}}
        return {"plan.json": json.dumps(plan).encode()}


def repo() -> Repository:
    return Repository(SLUG, 7, 9, Path("/var/empty/key.pem"), "example-bot", "main")


BASE_SHA = "b" * 40


def record_run(
    run_id: int, actor: str, conclusion: str, path: str = ".github/workflows/oracle-verdict-record.yml"
) -> dict:
    return {
        "id": run_id,
        "path": path,  # GitHub's REST API shape: no "@ref" suffix
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": BASE_SHA,
        "repository": {"full_name": SLUG},
        "created_at": NOW.isoformat(),
        "status": "completed",
        "conclusion": conclusion,
        "triggering_actor": {"login": actor},
    }


def make_probe(github: FakeGitHub, answer: str, returned_id: int | None = 123456, recorded: list | None = None):
    clock = {"now": NOW}

    def dispatch(inputs):
        state = json.loads(base64.b64decode(inputs["state"]))
        assert (inputs["proof"], state["generation"], state["predecessor"]) == ("true", 3, 2)
        return returned_id

    def sleep(seconds):
        clock["now"] += timedelta(seconds=seconds)

    return RecordActorProbe(
        repo(),
        github,
        github,
        dispatch,
        lambda question: answer,
        "77",
        on_success=(lambda app, human, workflow: recorded.append((app, human, workflow)))
        if recorded is not None
        else None,
        clock=lambda: clock["now"],
        sleep=sleep,
    )


BOT = {"login": "example-bot[bot]", "type": "Bot"}


def world(
    issue_text: str = "Rejected record run 654321",
    author_type: str = "Bot",
    human_conclusion: str = "failure",
    author_login: str = "example-bot[bot]",
):
    github = FakeGitHub()
    github.runs[123456] = record_run(123456, "example-bot[bot]", "success")
    github.runs[654321] = record_run(654321, "example-owner", human_conclusion)
    github.artifacts[123456] = [{"name": "oracle-verdict-proof-state-4"}]
    github.issues = [{"number": 8, "user": {"login": author_login, "type": author_type}, "body": issue_text}]
    return github


def test_the_actor_probe_follows_its_own_runs_and_records_activation():
    recorded: list = []
    results = make_probe(world(), "https://github.com/x/y/actions/runs/654321", recorded=recorded)()
    assert [r.status for r in results] == [PASS, PASS]
    assert "run 123456 by example-bot[bot]: success" in results[0].detail
    assert recorded == [(123456, 654321, "w" * 40)]


def test_without_a_returned_run_id_the_probe_fails_closed():
    recorded: list = []
    result = make_probe(world(), "654321", returned_id=None, recorded=recorded)()[0]
    assert result.status == FAIL and "did not return" in result.detail
    assert recorded == []


def test_the_rejection_issue_may_name_the_run_in_a_comment_by_the_app():
    github = world(issue_text="Rejected")
    github.comments[8] = [{"user": BOT, "body": "Also run 654321"}]
    assert make_probe(github, "654321")()[1].status == PASS


@pytest.mark.parametrize(
    "author",
    [
        {"login": "outsider", "type": "User"},
        {"login": "other-app[bot]", "type": "Bot"},
        {"login": "example-bot[bot]", "type": "User"},
        None,
    ],
)
def test_a_comment_by_anyone_else_naming_the_run_does_not_count(author):
    github = world(issue_text="Rejected")
    github.comments[8] = [{"user": author, "body": "Rejected record run 654321"}]
    result = make_probe(github, "654321")()[1]
    assert result.status == FAIL and "no open oracle-record-rejected issue" in result.detail


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda gh: gh.runs[123456].update(conclusion="failure"), "failure"),
        (lambda gh: gh.artifacts.clear(), "missing"),
        (lambda gh: gh.runs[123456].update(triggering_actor={"login": "example-owner"}), "by example-owner"),
        (
            lambda gh: gh.runs[123456].update(path=".github/workflows/other.yml"),
            "is not the record workflow",
        ),
    ],
)
def test_the_app_run_must_be_the_apps_successful_record_run(change, message):
    github = world()
    change(github)
    result = make_probe(github, "654321")()[0]
    assert result.status == FAIL and message in result.detail


@pytest.mark.parametrize(
    ("github", "answer", "status", "message"),
    [
        (world(human_conclusion="success"), "654321", FAIL, "not failure"),
        (world(issue_text="Rejected record run 6543210"), "654321", FAIL, "no open oracle-record-rejected issue"),
        (world(author_type="User"), "654321", FAIL, "no open oracle-record-rejected issue"),
        (world(author_login="other-app[bot]"), "654321", FAIL, "no open oracle-record-rejected issue"),
        (world(author_login="github-actions[bot]"), "654321", FAIL, "no open oracle-record-rejected issue"),
        (world(issue_text="Rejected record run 1654321"), "654321", FAIL, "no open oracle-record-rejected issue"),
        (world(issue_text="Rejected record run 65432"), "654321", FAIL, "no open oracle-record-rejected issue"),
        (world(), "123456", FAIL, "was dispatched by example-bot[bot], not a person"),
        (world(), "", NOT_RUN, "no run ID"),
    ],
)
def test_the_human_run_must_fail_closed_with_a_bot_issue_naming_it(github, answer, status, message):
    recorded: list = []
    result = make_probe(github, answer, recorded=recorded)()[1]
    assert result.status == status and message in result.detail
    assert recorded == []


def test_activation_record_round_trip(tmp_path):
    path = tmp_path / "activation" / "actor-probe.json"
    workflow = "w" * 40
    assert probes.read_activation(path, "d" * 64, True, workflow).status == NOT_RUN
    probes.write_activation(path, 123456, 654321, "0.1.0", "d" * 64, workflow, NOW)
    assert (path.stat().st_mode & 0o777) == 0o644
    assert probes.read_activation(path, "d" * 64, True, workflow).status == PASS
    assert "another engine build" in probes.read_activation(path, "e" * 64, True, workflow).detail
    changed = probes.read_activation(path, "d" * 64, True, "x" * 40)
    assert changed.status == WARN and "record workflow has changed" in changed.detail
    assert "could not be compared" in probes.read_activation(path, "d" * 64, True, None).detail
    path.write_text("{", encoding="utf-8")
    assert probes.read_activation(path, "d" * 64, True, workflow).status == FAIL


def test_routine_runs_use_the_activation_record():
    checks = Probes(activation=lambda: doctor.Result("record workflow triggering_actor", PASS, "checked"))
    assert checks.triggering_actor()[0].status == PASS


def test_a_probe_that_raises_is_a_failure_not_a_crash():
    def broken():
        raise RuntimeError("down")

    assert Probes(actor_probe=broken).triggering_actor()[0].status == FAIL


ATTACKER_SHA = "c" * 40


def branch_copy(run: dict) -> None:
    """The reproduced case: the record workflow copied to a branch and run there by a push."""
    run.update(
        path=".github/workflows/oracle-verdict-record.yml@refs/heads/attacker",
        head_branch="attacker",
        event="push",
        head_sha=ATTACKER_SHA,
    )


@pytest.mark.parametrize(
    "change",
    [
        branch_copy,
        lambda run: run.update(event="push"),
        lambda run: run.update(head_branch="attacker"),
        lambda run: run.update(path=".github/workflows/oracle-verdict-record.yml@refs/heads/attacker"),
        lambda run: run.update(head_sha=ATTACKER_SHA),
        lambda run: run.update(repository={"full_name": "example-owner/fork"}),
    ],
    ids=["branch-copy", "event", "head-branch", "path-ref", "head-sha-off-base", "repository"],
)
@pytest.mark.parametrize("which", ["person", "app"])
def test_a_run_off_the_base_branch_fails(change, which):
    github = world()
    github.workflow_at[ATTACKER_SHA] = "w" * 40
    change(github.runs[654321 if which == "person" else 123456])
    recorded: list = []
    results = make_probe(github, "654321", recorded=recorded)()
    result = results[1] if which == "person" else results[0]
    assert result.status == FAIL and "is not the record workflow dispatched on main" in result.detail
    assert recorded == []


@pytest.mark.parametrize("which", ["person", "app"])
def test_a_run_of_a_changed_record_workflow_fails(which):
    github = world()
    github.on_base.add(ATTACKER_SHA)
    github.workflow_at[ATTACKER_SHA] = "x" * 40
    github.runs[654321 if which == "person" else 123456]["head_sha"] = ATTACKER_SHA
    results = make_probe(github, "654321")()
    result = results[1] if which == "person" else results[0]
    assert result.status == FAIL and "differs from the one on main" in result.detail


def test_a_path_with_the_base_ref_suffix_is_also_accepted():
    github = world()
    for run_id in (123456, 654321):
        github.runs[run_id]["path"] = ".github/workflows/oracle-verdict-record.yml@refs/heads/main"
    assert [r.status for r in make_probe(github, "654321")()] == [PASS, PASS]
