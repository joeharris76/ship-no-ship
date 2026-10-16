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
    argv = runner.calls[0][1]
    assert argv[:4] == ("codex", "sandbox", "macos", "--") and argv[4] == "/bin/sh"


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


class FakeGitHub:
    def __init__(self) -> None:
        self.runs: list[dict] = []
        self.artifacts: dict[int, list[dict]] = {}

    def get(self, path: str):
        if path.startswith(f"repos/{SLUG}/actions/runs/77/artifacts"):
            return {"artifacts": [{"id": 5, "name": "oracle-verdict-request"}]}
        if "/actions/workflows/" in path:
            return {"workflow_runs": list(self.runs)}
        run_id = int(path.split("/actions/runs/")[1].split("/")[0])
        return {"artifacts": self.artifacts.get(run_id, [])}

    def paginate(self, path: str):
        raise AssertionError(path)

    def artifact_files(self, artifact_id: int):
        plan = {"pr": 4, "head_sha": "a" * 40, "previous_state": {"generation": 2}}
        return {"plan.json": json.dumps(plan).encode()}


def repo() -> Repository:
    return Repository(SLUG, 7, 9, Path("/var/empty/key.pem"), "example-bot", "main")


def actor_probe(github: FakeGitHub, answers: list[bool], on_dispatch=None, on_confirm=None) -> RecordActorProbe:
    clock = {"now": NOW}

    def dispatch(inputs):
        state = json.loads(base64.b64decode(inputs["state"]))
        assert (inputs["proof"], state["generation"], state["predecessor"]) == ("true", 3, 2)
        if on_dispatch:
            on_dispatch(github)

    def confirm(question):
        if on_confirm:
            on_confirm(github)
        return answers.pop(0)

    def sleep(seconds):
        clock["now"] += timedelta(seconds=seconds)

    return RecordActorProbe(repo(), github, dispatch, confirm, "77", clock=lambda: clock["now"], sleep=sleep)


def run(run_id: int, actor: str, conclusion: str) -> dict:
    return {
        "id": run_id,
        "created_at": NOW.isoformat(),
        "status": "completed",
        "conclusion": conclusion,
        "triggering_actor": {"login": actor},
    }


def test_the_actor_probe_passes_when_only_the_bot_can_record():
    github = FakeGitHub()
    github.artifacts[90] = [{"name": "oracle-verdict-proof-state-4"}]
    probe = actor_probe(
        github,
        [True, True],
        on_dispatch=lambda gh: gh.runs.append(run(90, "example-bot[bot]", "success")),
        on_confirm=lambda gh: gh.runs.append(run(91, "example-owner", "failure")) if len(gh.runs) == 1 else None,
    )
    results = probe()
    assert [r.status for r in results] == [PASS, PASS]
    assert "run 90 by example-bot[bot]: success" in results[0].detail


@pytest.mark.parametrize(
    ("bot_run", "human_run", "answers", "expected"),
    [
        (run(90, "example-bot[bot]", "failure"), run(91, "example-owner", "failure"), [True, True], [FAIL, PASS]),
        (run(90, "example-bot[bot]", "success"), run(91, "example-owner", "success"), [True], [PASS, FAIL]),
        (run(90, "example-bot[bot]", "success"), run(91, "example-owner", "failure"), [True, False], [PASS, FAIL]),
        (run(90, "example-bot[bot]", "success"), None, [False], [PASS, NOT_RUN]),
    ],
)
def test_the_actor_probe_fails_closed(bot_run, human_run, answers, expected):
    github = FakeGitHub()
    github.artifacts[90] = [{"name": "oracle-verdict-proof-state-4"}]
    github.runs = [bot_run] + ([human_run] if human_run else [])
    assert [r.status for r in actor_probe(github, answers)()] == expected


def test_no_record_run_appearing_fails():
    results = actor_probe(FakeGitHub(), [True])()
    assert results[0].status == FAIL and "no completed record run" in results[0].detail


def test_a_probe_that_raises_is_a_failure_not_a_crash():
    def broken():
        raise RuntimeError("down")

    assert Probes(actor_probe=broken).triggering_actor()[0].status == FAIL
