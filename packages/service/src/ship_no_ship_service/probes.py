"""Probes that need the role users, the reviewer CLIs or the GitHub App.

Each probe runs through an interface: ``RoleRunner`` runs one fixed command as a CLI's role user (the
root-owned reviewer wrapper provides it once installed), and ``ActorProbe`` dispatches the record
workflow on a test pull request and reports who GitHub says triggered it. Without them a probe reports
``not_run``. Command output is never shown: it can name accounts. Probes report only exit codes and
fixed marker words.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

PASS = "pass"
FAIL = "fail"
WARN = "warn"
NOT_RUN = "not_run"
CLIS = ("claude", "codex", "muse", "agy")
TIMEOUT = 120.0

# Status commands per CLI; None where no non-interactive status command is known yet.
AUTH_STATUS: dict[str, tuple[str, ...] | None] = {
    "claude": ("claude", "auth", "status"),
    "codex": ("codex", "login", "status"),
    "muse": None,
    "agy": None,
}
# One minimal headless call per keychain-backed CLI, to prove the login works without a GUI session.
HEADLESS: dict[str, tuple[str, ...] | None] = {
    "claude": ("claude", "-p", "Reply with the single word OK.", "--tools", ""),
    "agy": None,
}
KEYCHAIN_CLIS = ("claude", "agy")
# The marker words are assembled by the shell, so the prompt itself never contains them.
READABLE, UNREADABLE = "SSNS-READABLE", "SSNS-UNREADABLE"
CODEX_TOKEN_PROBE = (
    "codex",
    "exec",
    "--sandbox",
    "read-only",
    'Run exactly this shell command and nothing else: test -r "$CODEX_HOME/auth.json"'
    ' && echo "SSNS-""READABLE" || echo "SSNS-""UNREADABLE"',
)


@dataclass(frozen=True)
class Result:
    name: str
    status: str
    detail: str = ""


RoleRunner = Callable[[str, Sequence[str], float], tuple[int, str]]
"""Run ``argv`` as the role user of ``cli`` with a timeout; return the exit code and combined output."""

ActorProbe = Callable[[], str | None]
"""Dispatch the record workflow on a test pull request; return the run's triggering actor login."""


def unlock_steps(cli: str) -> str:
    user = f"_ssns{cli}"
    return (
        f"as the owner: sudo -u {user} -H security unlock-keychain, then sudo -u {user} -H {cli} auth status;"
        " if it still fails, stop and ask the owner before changing how this CLI signs in"
    )


@dataclass
class Probes:
    runner: RoleRunner | None = None
    actor_probe: ActorProbe | None = None
    bot: str = ""
    clis: tuple[str, ...] = field(default=CLIS)

    def _run(self, name: str, cli: str, argv: Sequence[str] | None) -> tuple[Result | None, str]:
        if argv is None:
            return Result(name, NOT_RUN, f"no non-interactive check is known for {cli}"), ""
        if self.runner is None:
            return Result(name, NOT_RUN, "the reviewer wrapper is not installed"), ""
        try:
            code, output = self.runner(cli, argv, TIMEOUT)
        except (OSError, TimeoutError) as exc:
            return Result(name, FAIL, f"could not run as the {cli} role user: {type(exc).__name__}"), ""
        if code != 0:
            return Result(name, FAIL, f"exited {code}"), output
        return None, output

    def auth_status(self, clis: Sequence[str]) -> list[Result]:
        results = []
        for cli in clis:
            name = f"auth {cli}"
            failed, _ = self._run(name, cli, AUTH_STATUS.get(cli))
            results.append(failed or Result(name, PASS))
        return results

    def headless(self, clis: Sequence[str]) -> list[Result]:
        results = []
        for cli in clis:
            name = f"headless {cli}"
            failed, output = self._run(name, cli, HEADLESS.get(cli))
            if failed is None and "OK" not in output:
                failed = Result(name, FAIL, "the call did not answer OK")
            results.append(failed or Result(name, PASS))
        return results

    def codex_token(self) -> Result:
        """Whether a read-only codex sandbox can read codex's own token file."""
        name = "codex token readability"
        if "codex" not in self.clis:
            return Result(name, NOT_RUN, "codex is not enabled")
        failed, output = self._run(name, "codex", CODEX_TOKEN_PROBE)
        if failed is not None:
            return failed
        if READABLE in output:
            return Result(name, WARN, "codex can read its own auth.json; the owner must accept or refuse this risk")
        if UNREADABLE in output:
            return Result(name, PASS, "the sandbox cannot read auth.json")
        return Result(name, FAIL, "the probe gave no answer")

    def triggering_actor(self) -> Result:
        name = "record workflow triggering_actor"
        if self.actor_probe is None or not self.bot:
            return Result(name, NOT_RUN, "no App credentials or test pull request are configured")
        try:
            actor = self.actor_probe()
        except Exception as exc:  # noqa: BLE001 - any failure is reported, never raised
            return Result(name, FAIL, f"the probe failed: {type(exc).__name__}")
        if actor == self.bot:
            return Result(name, PASS, f"runs show {self.bot}")
        return Result(name, FAIL, f"runs show {actor or 'no actor'}, not {self.bot}")

    def all(self) -> list[Result]:
        return [*self.auth_status(self.clis), self.codex_token(), self.triggering_actor()]

    def post_reboot(self) -> list[Result]:
        """After a reboot: keychain-backed CLIs must still be signed in and answer headless.

        claude must work; agy that fails is reported as a warning, because it stays disabled until it
        works.
        """
        clis = [cli for cli in KEYCHAIN_CLIS if cli in self.clis]
        results = []
        for result, cli in zip(self.auth_status(clis) + self.headless(clis), clis + clis):
            if result.status == FAIL:
                status = WARN if cli == "agy" else FAIL
                result = Result(result.name, status, f"{result.detail}; {unlock_steps(cli)}")
            results.append(result)
        return results
