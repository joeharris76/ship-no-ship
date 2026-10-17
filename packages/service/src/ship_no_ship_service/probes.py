"""Probes that need the role users, the reviewer CLIs or the GitHub App.

Commands run as a CLI's role user through ``sudo -u`` (doctor runs as root once installed), with a
minimal environment and the toolchain PATH. Output is never shown, because it can name accounts; probes
report exit codes and fixed marker words only.

The record-actor probe is the one-time activation check that only the App's bot can record state. It
dispatches the record workflow as the App for a proof plan run and follows that exact run: it must be
the App's, succeed and upload proof state. Then the operator dispatches the same workflow as
themselves and gives doctor that run's ID; it must fail, and GitHub must show an open
``oracle-record-rejected`` issue opened by the App's bot that names the run, in its body or in a
comment by the same bot. When both pass, doctor writes an
activation record that later routine runs accept until the engine build changes.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ship_no_ship.engine import github as engine_github, retry
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
# The token must exist as a regular file before the sandboxed read means anything.
CODEX_TOKEN_EXISTS = ("/bin/sh", "-c", 'test -f "$CODEX_HOME/auth.json" && ! test -h "$CODEX_HOME/auth.json"')
# codex's own sandbox runs the read directly: no model decides what is run or reported.
CODEX_TOKEN_PROBE = (
    "codex",
    "sandbox",
    "macos",
    "--",
    "/bin/sh",
    "-c",
    'test -r "$CODEX_HOME/auth.json" && echo SSNS-READABLE || echo SSNS-UNREADABLE',
)
REJECTED_LABEL = "oracle-record-rejected"
ACTIVATION_RECORD = "actor-probe.json"

RoleRunner = Callable[[str, Sequence[str], float], tuple[int, str]]
"""Run ``argv`` as the role user of ``cli`` with a timeout; return the exit code and combined output."""


def codex_home(data_dir: Path) -> Path:
    """Where the codex role user keeps its login: CODEX_HOME is set to this for every codex command."""
    return data_dir / "home" / "codex" / ".codex"


class SudoRunner:
    """Runs a command as a CLI's role user. doctor must run as root for sudo to switch users."""

    def __init__(self, data_dir: Path, libexec: Path) -> None:
        self.data_dir = data_dir
        self.libexec = libexec

    def __call__(self, cli: str, argv: Sequence[str], timeout: float) -> tuple[int, str]:
        home = self.data_dir / "home" / cli
        environment = [f"HOME={home}", f"PATH={self.libexec / 'bin'}:/usr/bin:/bin"]
        if cli == "codex":
            environment.append(f"CODEX_HOME={codex_home(self.data_dir)}")
        command = ["/usr/bin/sudo", "-n", "-u", role_user(cli), "-H", "/usr/bin/env", "-i", *environment]
        done = subprocess.run([*command, *argv], capture_output=True, text=True, timeout=timeout, check=False)
        return done.returncode, done.stdout + done.stderr


def _ok_line(output: str) -> bool:
    return any(line.strip() == "OK" for line in output.splitlines())


def read_activation(path: Path, installed_sha256: str, strict: bool, workflow_sha: str | None) -> Result:
    """The recorded activation check, accepted while the same engine build and record workflow are in place.

    ``workflow_sha`` is the record workflow's current blob SHA on the base branch, or None when it could
    not be read; then the result warns rather than passing unchecked.
    """
    name = "record workflow triggering_actor"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        recorded, recorded_workflow = str(data["engine_sha256"]), str(data["record_workflow_sha"])
        runs = f"runs {data['positive_run']} and {data['negative_run']} on {data['recorded_at']}"
    except FileNotFoundError:
        return Result(name, NOT_RUN, "not activated: run doctor --actor-probe --probe-plan-run <run>")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return Result(name, FAIL if strict else NOT_RUN, f"{path} cannot be read: {type(exc).__name__}")
    if recorded != installed_sha256:
        return Result(name, WARN, f"checked by {runs} for another engine build; run --actor-probe again")
    if workflow_sha is None:
        return Result(name, WARN, f"checked by {runs}; the record workflow could not be compared")
    if workflow_sha != recorded_workflow:
        return Result(name, WARN, f"checked by {runs}; the record workflow has changed since; run --actor-probe again")
    return Result(name, PASS, f"checked by {runs}")


def write_activation(
    path: Path, positive_run: int, negative_run: int, version: str, sha256: str, workflow_sha: str, now: datetime
) -> None:
    """Write the activation record atomically, mode 0644, owned by whoever runs doctor (root once installed)."""
    record = {
        "schema": 1,
        "positive_run": positive_run,
        "negative_run": negative_run,
        "recorded_at": now.isoformat(),
        "engine_version": version,
        "engine_sha256": sha256,
        "record_workflow_sha": workflow_sha,
    }
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def record_workflow_sha(github: GitHub, repository: Repository, ref: str | None = None) -> str:
    """The record workflow file's blob SHA on the base branch, or at ``ref``."""
    path = quote(repository.record_workflow)
    entry = github.get(f"repos/{repository.slug}/contents/{path}?ref={quote(ref or repository.base_branch)}")
    return str(entry["sha"])


@dataclass
class Probes:
    runner: RoleRunner | None = None
    actor_probe: Callable[[], list[Result]] | None = None
    activation: Callable[[], Result] | None = None
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
        """Whether codex's read-only sandbox can read codex's own token, which must exist first."""
        name = "codex token readability"
        if "codex" not in self.clis:
            return Result(name, PASS, "codex is not enabled")
        failed, _ = self._run(name, "codex", CODEX_TOKEN_EXISTS)
        if failed is not None:
            if failed.detail.startswith("exited"):
                return Result(name, FAIL, "codex's auth.json is missing or not a regular file; sign codex in first")
            return failed
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
            if self.activation is not None:
                return [self.activation()]
            name = "record workflow triggering_actor"
            return [Result(name, NOT_RUN, "not activated: run doctor --actor-probe --probe-plan-run <run>")]
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
    """Activation check that only the App's bot can record state, driven step by step with the operator.

    ``dispatch`` returns the ID of the run it started, or None when GitHub did not report one, which
    fails the check. ``issues`` reads with an issues-scoped token.
    """

    repository: Repository
    github: GitHub
    issues: GitHub
    dispatch: Callable[[Mapping[str, str]], int | None]
    ask: Callable[[str], str]
    plan_run: str
    on_success: Callable[[int, int, str], None] | None = None
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

    def _on_base(self, repo: str, sha: str) -> bool:
        """Whether ``sha`` is on the base branch: the branch is the commit or ahead of it."""
        base = quote(self.repository.base_branch)
        branch = self.github.get(f"repos/{repo}/git/ref/heads/{base}")["object"]["sha"]
        comparison = self.github.get(f"repos/{repo}/compare/{sha}...{branch}")
        return comparison.get("status") in ("ahead", "identical")

    def _run_problem(self, run: Mapping[str, Any], by_app: bool) -> str | None:
        """Why ``run`` is not the base branch's record workflow dispatched by the App (or, with ``by_app``
        False, by anyone else), or None.

        Both runs pass the checks the engine applies to a record run, except that the actor is inverted
        for the person's run. So a copy of the workflow on another branch, or one run by another event,
        cannot stand in for the real one.
        """
        repository = self.repository
        base = repository.base_branch
        actor = (run.get("triggering_actor") or {}).get("login")
        trusted = (
            run.get("event") == "workflow_dispatch"
            and run.get("head_branch") == base
            and run.get("path") == f"{repository.record_workflow}@refs/heads/{base}"
            and engine_github.trusted_run(
                dict(run),
                repository.slug,
                0,
                self._on_base,
                workflow_path=repository.record_workflow,
                base_branch=base,
            )
        )
        if not trusted:
            return f"is not the record workflow dispatched on {base}"
        if (actor == repository.bot) != by_app:
            return f"was dispatched by {actor}, not {'the App' if by_app else 'a person'}"
        ran = record_workflow_sha(self.github, repository, str(run["head_sha"]))
        if ran != record_workflow_sha(self.github, repository):
            return f"ran a record workflow that differs from the one on {base}"
        return None

    def _finished(self, run_id: int) -> dict[str, Any] | None:
        deadline = self.clock() + self.wait
        while self.clock() < deadline:
            run = self.github.get(f"repos/{self.repository.slug}/actions/runs/{run_id}")
            if run.get("status") == "completed":
                return run
            self.sleep(self.poll_seconds)
        return None

    def _positive(self, inputs: Mapping[str, str]) -> tuple[Result, int | None]:
        name = "record workflow dispatched by the App"
        run_id = self.dispatch(inputs)
        if run_id is None:
            # Without the ID GitHub assigned, another App run could be mistaken for this one.
            return Result(name, FAIL, "GitHub did not return the dispatched run's ID"), None
        run = self._finished(run_id)
        if run is None:
            return Result(name, FAIL, "the App's record run did not finish"), None
        actor = (run.get("triggering_actor") or {}).get("login")
        artifacts = self.github.get(f"repos/{self.repository.slug}/actions/runs/{run_id}/artifacts")
        proof = f"{DEFAULT_ARTIFACTS.proof_state_prefix}{inputs['pr']}"
        uploaded = any(item.get("name") == proof for item in artifacts.get("artifacts") or [])
        problem = self._run_problem(run, by_app=True)
        if problem:
            return Result(name, FAIL, f"run {run_id} {problem}"), run_id
        ok = run.get("conclusion") == "success" and uploaded
        detail = f"run {run_id} by {actor}: {run.get('conclusion')}; {proof} {'uploaded' if uploaded else 'missing'}"
        return Result(name, PASS if ok else FAIL, detail), run_id

    def _by_app(self, item: Mapping[str, Any]) -> bool:
        user = item.get("user") or {}
        return user.get("type") == "Bot" and user.get("login") == self.repository.bot

    def _rejection_issue(self, run_id: int) -> bool:
        """An open rejection issue that the App's bot opened names the run, in its body or its own comment.

        Anyone can comment on an issue in a public repository, so other people's comments do not count.
        """
        slug = self.repository.slug
        named = re.compile(rf"(?<!\d){run_id}(?!\d)")
        for issue in self.issues.paginate(f"repos/{slug}/issues?state=open&labels={REJECTED_LABEL}"):
            if not self._by_app(issue):
                continue
            texts = [issue.get("body") or ""]
            texts += [
                item.get("body") or ""
                for item in self.issues.paginate(f"repos/{slug}/issues/{issue['number']}/comments")
                if self._by_app(item)
            ]
            if any(named.search(text) for text in texts):
                return True
        return False

    def _negative(self, inputs: Mapping[str, str], prompted: datetime) -> Result:
        name = "record workflow dispatched by a person"
        fields = " ".join(f"-f {key}={value}" for key, value in inputs.items())
        workflow = Path(self.repository.record_workflow).name
        command = f"gh workflow run {workflow} --ref {self.repository.base_branch} {fields} -R {self.repository.slug}"
        answer = self.ask(f"As yourself, not the App, run:\n  {command}\nThen paste the new run's ID or URL:")
        found = re.search(r"(\d{6,})\s*$", answer.strip())
        if found is None:
            return Result(name, NOT_RUN, "no run ID was given")
        run_id = int(found.group(1))
        run = self._finished(run_id)
        if run is None:
            return Result(name, FAIL, f"run {run_id} did not finish")
        created = datetime.fromisoformat(str(run["created_at"]).replace("Z", "+00:00"))
        problem = self._run_problem(run, by_app=False)
        if problem:
            return Result(name, FAIL, f"run {run_id} {problem}")
        if created < prompted - timedelta(minutes=1):
            return Result(name, FAIL, f"run {run_id} is not a new record run dispatched by a person")
        if run.get("conclusion") != "failure":
            return Result(name, FAIL, f"run {run_id} concluded {run.get('conclusion')}, not failure")
        if not self._rejection_issue(run_id):
            return Result(name, FAIL, f"no open {REJECTED_LABEL} issue from a bot names run {run_id}")
        return Result(name, PASS, f"run {run_id} failed closed and {REJECTED_LABEL} names it")

    def __call__(self) -> list[Result]:
        inputs = self.inputs()
        positive, app_run = self._positive(inputs)
        negative = self._negative(inputs, self.clock())
        if positive.status == PASS and negative.status == PASS and app_run is not None and self.on_success:
            human = int(re.findall(r"\d+", negative.detail)[0])
            self.on_success(app_run, human, record_workflow_sha(self.github, self.repository))
        return [positive, negative]


class ScopedTokens:
    """A token source fixed to one permission set, so a read client can use issues-only tokens."""

    def __init__(self, tokens: Any, permissions: Mapping[str, str]) -> None:
        self.tokens = tokens
        self.repository = tokens.repository
        self.permissions = permissions

    def token(self, permissions: Mapping[str, str]) -> str:
        return self.tokens.token(self.permissions)

    def forget(self) -> None:
        self.tokens.forget()


def app_dispatch(
    repository: Repository, tokens: Any, transport: Any, api_url: str
) -> Callable[[Mapping[str, str]], int | None]:
    """Dispatch the record workflow as the App, with an actions: write token, and return the new run's ID."""
    from .appauth import API_VERSION, DISPATCH

    def dispatch(inputs: Mapping[str, str]) -> int | None:
        workflow = Path(repository.record_workflow).name
        url = f"{api_url}/repos/{repository.slug}/actions/workflows/{workflow}/dispatches"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {tokens.token(DISPATCH)}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": API_VERSION,
        }
        body = json.dumps({"ref": repository.base_branch, "inputs": dict(inputs), "return_run_details": True}).encode()
        response = transport("POST", url, headers=headers, body=body)
        if response.status == 204:
            return None
        if response.status != 200:
            raise RuntimeError(f"the record dispatch returned HTTP {response.status}")
        return int(response.json()["workflow_run_id"])

    return dispatch


def ask(question: str) -> str:
    return input(f"{question} ").strip()
