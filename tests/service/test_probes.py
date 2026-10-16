from __future__ import annotations

import pytest

from ship_no_ship_service import probes
from ship_no_ship_service.probes import FAIL, NOT_RUN, PASS, WARN, Probes

SECRET_OUTPUT = "signed in as private-account-name"


class Runner:
    def __init__(self, answers: dict[tuple[str, str], tuple[int, str] | Exception]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def __call__(self, cli, argv, timeout):
        self.calls.append((cli, tuple(argv)))
        answer = self.answers.get((cli, argv[1]), (0, SECRET_OUTPUT))
        if isinstance(answer, Exception):
            raise answer
        return answer


def statuses(results) -> dict[str, str]:
    return {result.name: result.status for result in results}


def test_without_a_runner_or_app_every_probe_is_not_run():
    results = Probes().all()
    assert {result.status for result in results} == {NOT_RUN}
    assert any("wrapper is not installed" in result.detail for result in results)


def test_auth_status_per_role_user_reports_exit_codes_but_never_output():
    runner = Runner({("codex", "login"): (1, SECRET_OUTPUT)})
    results = Probes(runner=runner).auth_status(probes.CLIS)
    assert statuses(results) == {"auth claude": PASS, "auth codex": FAIL, "auth muse": NOT_RUN, "auth agy": NOT_RUN}
    assert all("private-account-name" not in result.detail for result in results)
    assert [cli for cli, _ in runner.calls] == ["claude", "codex"]


def test_a_runner_failure_is_a_failed_check():
    runner = Runner({("claude", "auth"): TimeoutError()})
    [result] = Probes(runner=runner).auth_status(["claude"])
    assert (result.status, result.detail) == (FAIL, "could not run as the claude role user: TimeoutError")


@pytest.mark.parametrize(
    ("output", "status"),
    [
        ("SSNS-UNREADABLE\n", PASS),
        ("SSNS-READABLE\n", WARN),
        ("I will not run that.", FAIL),
    ],
)
def test_codex_token_readability(output, status):
    runner = Runner({("codex", "exec"): (0, output)})
    result = Probes(runner=runner).codex_token()
    assert result.status == status
    assert runner.calls[0][1][:4] == ("codex", "exec", "--sandbox", "read-only")


def test_the_codex_prompt_cannot_echo_either_marker():
    prompt = probes.CODEX_TOKEN_PROBE[-1]
    assert probes.READABLE not in prompt and probes.UNREADABLE not in prompt


def test_codex_not_enabled_is_not_run():
    assert Probes(runner=Runner({}), clis=("claude",)).codex_token().status == NOT_RUN


@pytest.mark.parametrize(
    ("actor", "status"),
    [("example-bot[bot]", PASS), ("example-owner", FAIL), (None, FAIL), (RuntimeError("down"), FAIL)],
)
def test_triggering_actor_probe(actor, status):
    def probe():
        if isinstance(actor, Exception):
            raise actor
        return actor

    assert Probes(actor_probe=probe, bot="example-bot[bot]").triggering_actor().status == status
    assert Probes(actor_probe=probe).triggering_actor().status == NOT_RUN


def test_post_reboot_checks_keychain_clis_and_prints_unlock_steps():
    runner = Runner({("claude", "auth"): (1, ""), ("claude", "-p"): (0, "OK")})
    results = Probes(runner=runner).post_reboot()
    assert statuses(results) == {
        "auth claude": FAIL,
        "auth agy": NOT_RUN,
        "headless claude": PASS,
        "headless agy": NOT_RUN,
    }
    assert "security unlock-keychain" in results[0].detail and "_ssnsclaude" in results[0].detail
    assert {cli for cli, _ in runner.calls} == {"claude"}


def test_post_reboot_headless_must_answer_ok_and_agy_failure_only_warns(monkeypatch):
    monkeypatch.setitem(probes.AUTH_STATUS, "agy", ("agy", "status"))
    runner = Runner({("claude", "-p"): (0, "Sorry"), ("agy", "status"): (2, "")})
    results = statuses(Probes(runner=runner).post_reboot())
    assert results == {"auth claude": PASS, "auth agy": WARN, "headless claude": FAIL, "headless agy": NOT_RUN}
