"""Probes that need the role users, the reviewer CLIs or the GitHub App.

Commands run as a CLI's role user through ``sudo -u`` (doctor runs as root once installed), with a
minimal environment and the toolchain PATH. Output is never shown, because it can name accounts; probes
report exit codes and fixed marker words only.

The record-actor probe dispatches the record workflow as the App for a proof plan run and checks that
GitHub shows the App's bot as the triggering actor, that the run succeeded and that it uploaded proof
state. Its second step asks the operator to dispatch the same workflow as themselves and confirms that
run fails closed and opens an ``oracle-record-rejected`` issue.
"""

from __future__ import annotations

import base64
import json
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ship_no_ship.engine import retry
from ship_no_ship.engine.policy import DEFAULT_ARTIFACTS

from .config import Repository
from .doctor import CLIS, FAIL, NOT_RUN, PASS, WARN, Result, role_user
from .ghclient import GitHub

TIMEOUT = 120.0
# Status commands per CLI; None where no non-interactive status command is known yet.
AUTH_STATUS: dict[str, tuple[str, ...] | None] = {
    "claude": ("claude", "auth", "status"),
    "codex": ("codex", "login", "status"),
    "muse": None,
    "agy": None,
}
# One minimal headless call per keychain-backed CLI, proving the login works without a GUI session.
HEADLESS: dict[str, tuple[str, ...] | None] = {
    "claude": ("claude", "-p", "Reply with the single word OK.", "--tools", ""),
    "agy": None,
}
KEYCHAIN_CLIS = ("claude", "agy")
READABLE, UNREADABLE = "SSNS-READABLE", "SSNS-UNREADABLE"
# codex's own sandbox runs the read directly: no model decides what is run or reported.
CODEX_TOKEN_PROBE = (
    "codex",
    "sandbox",
    "macos",
    "--",
    "/bin/sh",
    "-c",
    'test -r "${CODEX_HOME:-$HOME/.codex}/auth.json" && echo SSNS-READABLE || echo SSNS-UNREADABLE',
)
REJECTED_LABEL = "oracle-record-rejected"

RoleRunner = Callable[[str, Sequence[str], float], tuple[int, str]]
"""Run ``argv`` as the role user of ``cli`` with a timeout; return the exit code and combined output."""


class SudoRunner:
    """Runs a command as a CLI's role user. doctor must run as root for sudo to switch users."""

    def __init__(self, data_dir: Path, libexec: Path) -> None:
        self.data_dir = data_dir
        self.libexec = libexec

    def __call__(self, cli: str, argv: Sequence[str], timeout: float) -> tuple[int, str]:
        home = self.data_dir / "home" / cli
        path = f"{self.libexec / 'bin'}:/usr/bin:/bin"
        command = [
            "/usr/bin/sudo",
            "-n",
            "-u",
            role_user(cli),
            "-H",
            "/usr/bin/env",
            "-i",
            f"HOME={home}",
            f"PATH={path}",
        ]
        done = subprocess.run([*command, *argv], capture_output=True, text=True, timeout=timeout, check=False)
        return done.returncode, done.stdout + done.stderr


def _ok_line(output: str) -> bool:
    return any(line.strip() == "OK" for line in output.splitlines())


@dataclass
class Probes:
    runner: RoleRunner | None = None
    actor_probe: Callable[[], list[Result]] | None = None
    clis: tuple[str, ...] = field(default=CLIS)
    strict: bool = True
    why_no_runner: str = "doctor must run with sudo to check the role users"

    def _missing(self, name: str, why: str) -> Result:
        return Result(name, FAIL if self.strict else NOT_RUN, why)

    def _run(self, name: str, cli: str, argv: Sequence[str]) -> tuple[Result | None, str]:
        if self.runner is None:
            return self._missing(name, self.why_no_runner), ""
        try:
            code, output = self.runner(cli, argv, TIMEOUT)
        except (OSError, subprocess.TimeoutExpired, TimeoutError) as exc:
            return Result(name, FAIL, f"could not run as the {cli} role user: {type(exc).__name__}"), ""
        if code != 0:
            return Result(name, FAIL, f"exited {code}"), output
        return None, output

    def auth_status(self, clis: Sequence[str]) -> list[Result]:
        results = []
        for cli in clis:
            name, argv = f"auth {cli}", AUTH_STATUS.get(cli)
            if argv is None:
                results.append(Result(name, WARN, f"no status command is known; {cli} stays disabled until one is"))
                continue
            failed, _ = self._run(name, cli, argv)
            results.append(failed or Result(name, PASS))
        return results

    def headless(self, clis: Sequence[str]) -> list[Result]:
        results = []
        for cli in clis:
            name, argv = f"headless {cli}", HEADLESS.get(cli)
            if argv is None:
                results.append(Result(name, WARN, f"no headless check is known; {cli} stays disabled until one is"))
                continue
            failed, output = self._run(name, cli, argv)
            if failed is None and not _ok_line(output):
                failed = Result(name, FAIL, "the call did not answer OK on a line of its own")
            results.append(failed or Result(name, PASS))
        return results

    def codex_token(self) -> Result:
        """Whether codex's read-only sandbox can read codex's own token file."""
        name = "codex token readability"
        if "codex" not in self.clis:
            return Result(name, PASS, "codex is not enabled")
        failed, output = self._run(name, "codex", CODEX_TOKEN_PROBE)
        if failed is not None:
            return failed
        lines = {line.strip() for line in output.splitlines()}
        if READABLE in lines:
            return Result(name, WARN, "codex can read its own auth.json; the owner must accept or refuse this risk")
        if UNREADABLE in lines:
            return Result(name, PASS, "the sandbox cannot read auth.json")
        return Result(name, FAIL, "the probe gave no answer")

    def triggering_actor(self) -> list[Result]:
        if self.actor_probe is None:
            name = "record workflow triggering_actor"
            return [Result(name, NOT_RUN, "run doctor --actor-probe --probe-plan-run <run> once before activation")]
        try:
            return self.actor_probe()
        except Exception as exc:  # noqa: BLE001 - any failure is reported, never raised
            return [Result("record workflow triggering_actor", FAIL, f"the probe failed: {type(exc).__name__}: {exc}")]

    def all(self) -> list[Result]:
        return [*self.auth_status(self.clis), self.codex_token(), *self.triggering_actor()]

    def post_reboot(self) -> list[Result]:
        """After a reboot, claude must still be signed in and answer headless; agy only warns."""
        clis = [cli for cli in KEYCHAIN_CLIS if cli in self.clis]
        results = []
        for result, cli in zip(self.auth_status(clis) + self.headless(clis), clis + clis):
            if result.status == FAIL:
                user = role_user(cli)
                steps = (
                    f"as the owner: sudo -u {user} -H security unlock-keychain, then check {cli} again; if it"
                    " still fails, stop and ask the owner before changing how this CLI signs in"
                )
                result = Result(result.name, WARN if cli == "agy" else FAIL, f"{result.detail}; {steps}")
            results.append(result)
        return results


@dataclass
class RecordActorProbe:
    """Activation check that only the App's bot can record state, driven step by step with the operator."""

    repository: Repository
    github: GitHub
    dispatch: Callable[[Mapping[str, str]], None]
    confirm: Callable[[str], bool]
    plan_run: str
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    sleep: Callable[[float], None] = time.sleep
    wait: timedelta = timedelta(minutes=15)
    poll_seconds: float = 15.0

    def inputs(self) -> dict[str, str]:
        """Record inputs for a proof state that follows the generation the proof plan read."""
        slug, name = self.repository.slug, quote(self.repository.request_artifact)
        listing = self.github.get(f"repos/{slug}/actions/runs/{self.plan_run}/artifacts?name={name}")
        artifact = (listing.get("artifacts") or [None])[0]
        if artifact is None:
            raise ValueError(f"run {self.plan_run} uploaded no request")
        plan = json.loads(self.github.artifact_files(int(artifact["id"]))["plan.json"])
        read = int((plan.get("previous_state") or {}).get("generation") or 0)
        state = retry.State(
            int(plan["pr"]),
            str(plan["head_sha"]),
            retry.PENDING,
            self.clock(),
            (),
            {},
            retry.UNREPORTED,
            0,
            read + 1,
            read,
        )
        encoded = base64.b64encode(json.dumps(state.to_json()).encode()).decode()
        return {
            "pr": str(plan["pr"]),
            "head_sha": str(plan["head_sha"]),
            "plan_run": self.plan_run,
            "state": encoded,
            "proof": "true",
        }

    def _run_after(self, started: datetime, by_bot: bool) -> dict[str, Any] | None:
        workflow = Path(self.repository.record_workflow).name
        deadline = self.clock() + self.wait
        while self.clock() < deadline:
            listing = self.github.get(
                f"repos/{self.repository.slug}/actions/workflows/{workflow}/runs?event=workflow_dispatch&per_page=20"
            )
            for run in listing.get("workflow_runs") or []:
                created = datetime.fromisoformat(str(run["created_at"]).replace("Z", "+00:00"))
                actor = (run.get("triggering_actor") or {}).get("login")
                if created >= started - timedelta(minutes=1) and (actor == self.repository.bot) == by_bot:
                    if run.get("status") == "completed":
                        return run
            self.sleep(self.poll_seconds)
        return None

    def __call__(self) -> list[Result]:
        inputs = self.inputs()
        started = self.clock()
        self.dispatch(inputs)
        run = self._run_after(started, by_bot=True)
        name = "record workflow dispatched by the App"
        if run is None:
            positive = Result(name, FAIL, "no completed record run by the App's bot appeared")
        else:
            artifacts = self.github.get(f"repos/{self.repository.slug}/actions/runs/{run['id']}/artifacts")
            proof = f"{DEFAULT_ARTIFACTS.proof_state_prefix}{inputs['pr']}"
            uploaded = any(item.get("name") == proof for item in artifacts.get("artifacts") or [])
            ok = run.get("conclusion") == "success" and uploaded
            detail = f"run {run['id']} by {self.repository.bot}: {run.get('conclusion')}; {proof} {'uploaded' if uploaded else 'missing'}"
            positive = Result(name, PASS if ok else FAIL, detail)
        fields = " ".join(f"-f {key}={value}" for key, value in inputs.items())
        command = f"gh workflow run {Path(self.repository.record_workflow).name} --ref {self.repository.base_branch} {fields} -R {self.repository.slug}"
        name = "record workflow dispatched by a person"
        prompted = self.clock()
        if not self.confirm(f"As yourself, not the App, run:\n  {command}\nDispatched?"):
            return [positive, Result(name, NOT_RUN, "the operator did not dispatch the human run")]
        human = self._run_after(prompted, by_bot=False)
        if human is None:
            return [positive, Result(name, FAIL, "no completed record run by a person appeared")]
        if human.get("conclusion") != "failure":
            return [positive, Result(name, FAIL, f"run {human['id']} concluded {human.get('conclusion')}, not failure")]
        if not self.confirm(f"Did run {human['id']} open or update an issue labelled {REJECTED_LABEL}?"):
            return [positive, Result(name, FAIL, f"no {REJECTED_LABEL} issue was confirmed")]
        return [positive, Result(name, PASS, f"run {human['id']} failed closed and opened {REJECTED_LABEL}")]


def app_dispatch(
    repository: Repository, tokens: Any, transport: Any, api_url: str
) -> Callable[[Mapping[str, str]], None]:
    """Dispatch the record workflow as the App, with a token that holds only actions: write."""
    from .appauth import API_VERSION, DISPATCH

    def dispatch(inputs: Mapping[str, str]) -> None:
        workflow = Path(repository.record_workflow).name
        url = f"{api_url}/repos/{repository.slug}/actions/workflows/{workflow}/dispatches"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {tokens.token(DISPATCH)}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": API_VERSION,
        }
        body = json.dumps({"ref": repository.base_branch, "inputs": dict(inputs)}).encode()
        response = transport("POST", url, headers=headers, body=body)
        if response.status != 204:
            raise RuntimeError(f"the record dispatch returned HTTP {response.status}")

    return dispatch


def ask(question: str) -> bool:
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")
