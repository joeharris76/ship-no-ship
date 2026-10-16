"""Find review requests the plan workflow uploaded, check where they came from, and queue them.

Polling follows every page of the request-artifact listing back to a durable cursor, less an overlap
window, so a quiet week or an artifact listed late is not missed. The cursor compares GitHub's own
timestamps only, so this machine's clock does not matter.

The plan run is checked before anything is downloaded: it must be a trusted run of this repository's
plan workflow (the engine's ``trusted_run``). Only then is the artifact read, and it must hold a
request and plan of the expected shape for that run, a ``review`` decision for the base branch, and a
pull request that is still open, not a draft, from this repository and at the planned head. For a
comment run, the comment is read again and must come from an owner, member or collaborator.

The request's ``policy_sha256`` is not checked here. The plan ran on the base branch with the policy
file the engine verified against that commit (``plan`` refuses a policy that differs from the copy at
GITHUB_SHA), and the plan carries the resolved reviewer chain, so the service never reads the policy.

Reconciliation does not depend on the listing window. It lists open pull requests on the base branch,
and for each one whose head has no decision and no request in the queue, it looks up that pull
request's newest plan runs directly. Comment and dispatch runs run on the base branch and do not name
their pull request, so while any pull request is waiting, the newest such runs are read as well; each
request in them is checked like any other and names its own pull request.

A request for an engine version or build that is not installed is held until it is. An artifact that
fails for a passing reason is tried again until it has failed three times over at least an hour, then dropped. Any
other failure drops that one artifact with its reason; it never stops the poll.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import ship_no_ship
from ship_no_ship.engine import executor, github as engine_github, protocol

from . import outbox as outbox_module
from .config import Repository
from .ghclient import MAX_PAGES, PER_PAGE, ArtifactError, GitHub, GitHubError
from .outbox import Outbox
from .queue import ACTIVE, DONE, Enqueued, Queue, Request, transaction
from .transport import TransportError

TRUSTED_COMMENTERS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
COMMENT_SKEW = timedelta(minutes=2)
STATUS_LIMIT = 140
MAX_TRIES = 3
RETRY_WINDOW = timedelta(hours=1)
RECONCILE_RUNS = 5
BASE_RUNS = 20
BASE_EVENTS = ("workflow_dispatch", "issue_comment")
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cursors (repo TEXT PRIMARY KEY, artifact_id INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS seen (
    repo TEXT NOT NULL, artifact_id INTEGER NOT NULL, outcome TEXT NOT NULL, reason TEXT NOT NULL,
    PRIMARY KEY (repo, artifact_id)
);
CREATE TABLE IF NOT EXISTS retries (
    repo TEXT NOT NULL, artifact_id INTEGER NOT NULL, tries INTEGER NOT NULL, first_at TEXT NOT NULL,
    PRIMARY KEY (repo, artifact_id)
);
"""


class DiscoveryError(RuntimeError):
    pass


class RequestRefusedError(Exception):
    """The request is not acted on; the reason is recorded."""

    def __init__(self, kind: str, reason: str) -> None:
        super().__init__(reason)
        self.kind = kind


@dataclass(frozen=True)
class Outcome:
    artifact_id: int
    kind: str  # queued, held, duplicate, stale, known, dropped, untrusted or error
    reason: str = ""
    enqueued: Enqueued | None = None


def installed_engines() -> dict[str, str]:
    """The engine build this service runs with, as version to build digest."""
    return {ship_no_ship.__version__: executor.engine_sha256()}


def _time(value: Any) -> datetime:
    moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError(f"{value!r} has no time zone")
    return moment


class Discovery:
    def __init__(
        self,
        repository: Repository,
        github: GitHub,
        queue: Queue,
        outbox: Outbox,
        *,
        requests_dir: Path,
        installed: Mapping[str, str],
        clock: Callable[[], datetime],
        overlap: timedelta = timedelta(minutes=30),
    ) -> None:
        self.repo = repository
        self.github = github
        self.queue = queue
        self.db = queue.db
        self.outbox = outbox
        self.requests_dir = requests_dir
        self.installed = installed
        self.clock = clock
        self.overlap = overlap
        self.db.executescript(_SCHEMA)

    # Polling ---------------------------------------------------------------------------------------

    def _cursor(self) -> tuple[datetime, int] | None:
        row = self.db.execute(
            "SELECT created_at, artifact_id FROM cursors WHERE repo = ?", (self.repo.slug,)
        ).fetchone()
        return None if row is None else (_time(row[0]), row[1])

    def _seen(self, artifact_id: int) -> bool:
        found = self.db.execute("SELECT 1 FROM seen WHERE repo = ? AND artifact_id = ?", (self.repo.slug, artifact_id))
        return found.fetchone() is not None

    def _listing(self, floor: datetime | None) -> list[dict[str, Any]]:
        """Every listed request artifact back to the floor. A listing too long to read fully is an error."""
        path = f"repos/{self.repo.slug}/actions/artifacts?name={quote(self.repo.request_artifact)}&per_page={PER_PAGE}"
        found: list[dict[str, Any]] = []
        for page in range(1, MAX_PAGES + 1):
            items = self.github.get(f"{path}&page={page}").get("artifacts") or []
            found.extend(items)
            if len(items) < PER_PAGE or (
                floor is not None and any(_time(item["created_at"]) < floor for item in items)
            ):
                return found
        raise DiscoveryError(f"more than {MAX_PAGES * PER_PAGE} request artifacts are newer than the cursor")

    def poll(self) -> list[Outcome]:
        """Consider every artifact newer than the cursor less the overlap, oldest first, then move the cursor."""
        cursor = self._cursor()
        floor = None if cursor is None else cursor[0] - self.overlap
        listed = self._listing(floor)
        fresh = sorted(
            (
                item
                for item in listed
                if not item.get("expired")
                and (floor is None or _time(item["created_at"]) >= floor)
                and not self._seen(item["id"])
            ),
            key=lambda item: (_time(item["created_at"]), item["id"]),
        )
        outcomes = [self.consider(item) for item in fresh]
        retrying = [_time(item["created_at"]) for item, outcome in zip(fresh, outcomes) if outcome.kind == "error"]
        marks = [(_time(item["created_at"]), item["id"]) for item in listed]
        if cursor is not None:
            marks.append(cursor)
        newest = max(marks, default=None)
        if newest is not None:
            # An artifact that will be tried again stays inside the next window.
            when = min([newest[0], *retrying])
            if cursor is not None:
                when = max(when, cursor[0])
            self.db.execute(
                "INSERT INTO cursors (repo, artifact_id, created_at) VALUES (?, ?, ?) ON CONFLICT (repo)"
                " DO UPDATE SET artifact_id = excluded.artifact_id, created_at = excluded.created_at",
                (self.repo.slug, newest[1], when.isoformat()),
            )
        return outcomes

    # One request -----------------------------------------------------------------------------------

    def _record(self, artifact_id: int, outcome: Outcome) -> Outcome:
        with transaction(self.db):
            self.db.execute(
                "INSERT OR REPLACE INTO seen (repo, artifact_id, outcome, reason) VALUES (?, ?, ?, ?)",
                (self.repo.slug, artifact_id, outcome.kind, outcome.reason),
            )
            self.db.execute("DELETE FROM retries WHERE repo = ? AND artifact_id = ?", (self.repo.slug, artifact_id))
        return outcome

    def _retry_or_drop(self, artifact_id: int, reason: str) -> Outcome:
        now = self.clock()
        with transaction(self.db):
            row = self.db.execute(
                "SELECT tries, first_at FROM retries WHERE repo = ? AND artifact_id = ?", (self.repo.slug, artifact_id)
            ).fetchone()
            tries, first = (row[0] + 1, _time(row[1])) if row else (1, now)
            self.db.execute(
                "INSERT OR REPLACE INTO retries (repo, artifact_id, tries, first_at) VALUES (?, ?, ?, ?)",
                (self.repo.slug, artifact_id, tries, first.isoformat()),
            )
        if tries >= MAX_TRIES and now - first >= RETRY_WINDOW:
            return self._record(artifact_id, Outcome(artifact_id, "dropped", f"gave up after {tries} tries: {reason}"))
        return Outcome(artifact_id, "error", reason)

    def consider(self, artifact: Mapping[str, Any]) -> Outcome:
        """Decide one artifact. Nothing raised here escapes: one bad artifact cannot stop the poll."""
        artifact_id = int(artifact["id"])
        try:
            outcome = self._consider(artifact_id, str((artifact.get("workflow_run") or {}).get("id", "")))
        except RequestRefusedError as refused:
            outcome = Outcome(artifact_id, refused.kind, str(refused))
        except ArtifactError as exc:
            outcome = Outcome(artifact_id, "dropped", str(exc))
        except (GitHubError, TransportError) as exc:
            return self._retry_or_drop(artifact_id, f"{type(exc).__name__}: {exc}"[:300])
        except Exception as exc:  # noqa: BLE001 - a malformed artifact is dropped, never fatal
            outcome = Outcome(artifact_id, "dropped", f"unexpected {type(exc).__name__}: {exc}"[:300])
        return self._record(artifact_id, outcome)

    def _consider(self, artifact_id: int, run_id: str) -> Outcome:
        if not run_id.isdigit():
            raise RequestRefusedError("dropped", "the artifact names no workflow run")
        run = self.github.get(f"repos/{self.repo.slug}/actions/runs/{run_id}")
        if not isinstance(run, dict):
            raise RequestRefusedError("dropped", "the workflow run cannot be read")
        run_pr = self._check_run(run)
        files = self.github.artifact_files(artifact_id)
        request, plan = (self._json(files, name) for name in ("request.json", "plan.json"))
        pr, head = self._check_request(request, plan, run_id)
        if run_pr is not None and pr != run_pr:
            raise RequestRefusedError("untrusted", f"run {run_id} is for #{run_pr}, not #{pr}")
        if run.get("event") == "issue_comment":
            self._check_comment(run, pr, request.get("comment_id"))
        self._check_pull(pr, head)
        version, digest = request["engine_version"], request["engine_sha256"]
        held = self.installed.get(version) != digest
        self._store(files, pr, head, run_id)
        planned = Request(
            self.repo.slug, pr, head, run_id, version, digest, request["state_generation"], _time(run["created_at"])
        )
        result = self.queue.enqueue(planned, self.clock(), held=held)
        if result.outcome in ("queued", "held"):
            self._status(result, request)
        return Outcome(artifact_id, result.outcome, "", result)

    @staticmethod
    def _json(files: Mapping[str, bytes], name: str) -> dict[str, Any]:
        try:
            data = json.loads(files[name])
        except (KeyError, ValueError) as exc:
            raise RequestRefusedError("dropped", f"{name} cannot be read: {type(exc).__name__}") from None
        if not isinstance(data, dict):
            raise RequestRefusedError("dropped", f"{name} is not an object")
        return data

    def _check_run(self, run: Mapping[str, Any]) -> int | None:
        """Trust the run before reading anything it uploaded. Returns the run's pull request, if it names one."""
        run_pr: int | None = None
        pulls = None
        if run.get("event") == "pull_request_target":
            numbers = [pull.get("number") for pull in run.get("pull_requests") or [] if isinstance(pull, dict)]
            if len(numbers) != 1 or type(numbers[0]) is not int:
                raise RequestRefusedError("untrusted", "the pull_request_target run does not name one pull request")
            run_pr = numbers[0]
            pulls = self._head_pulls(run)
        trusted = engine_github.trusted_run(
            dict(run),
            self.repo.slug,
            run_pr or 0,
            is_on_base=self._on_base,
            pulls=pulls,
            workflow_path=self.repo.verdict_workflow,
            base_branch=self.repo.base_branch,
        )
        if not trusted:
            raise RequestRefusedError("untrusted", f"run {run.get('id')} is not a trusted plan run")
        return run_pr

    def _check_request(self, request: Mapping[str, Any], plan: Mapping[str, Any], run_id: str) -> tuple[int, str]:
        pr, head = request.get("pr"), request.get("head_sha")
        generation = request.get("state_generation")
        problems = [
            (request.get("schema") != executor.REQUEST_SCHEMA, "an unknown request schema"),
            (str(request.get("repo", "")).casefold() != self.repo.slug.casefold(), "another repository"),
            (request.get("run_id") != run_id or plan.get("run_id") != run_id, "another run"),
            (type(pr) is not int or pr <= 0 or plan.get("pr") != pr, "no valid pull request"),
            (not isinstance(head, str) or not _SHA.fullmatch(head) or plan.get("head_sha") != head, "no valid head"),
            (plan.get("decision") != "review", "a plan that did not decide to review"),
            (plan.get("base_ref") != self.repo.base_branch, "another base branch"),
            (request.get("executor") not in (executor.LOCAL_MODE, executor.PROOF_MODE), "a hosted executor"),
            (not isinstance(request.get("engine_version"), str), "no engine version"),
            (
                not isinstance(request.get("engine_sha256"), str) or not _DIGEST.fullmatch(request["engine_sha256"]),
                "no engine digest",
            ),
            (type(generation) is not int or generation < 0, "no valid state generation"),
            ("comment_id" in request and type(request["comment_id"]) is not int, "a malformed comment"),
        ]
        for failed, what in problems:
            if failed:
                raise RequestRefusedError("dropped", f"the request names {what}")
        assert isinstance(pr, int) and isinstance(head, str)
        return pr, head

    def _on_base(self, repo: str, sha: str) -> bool:
        try:
            branch = self.github.get(f"repos/{repo}/git/ref/heads/{quote(self.repo.base_branch)}")["object"]["sha"]
            comparison = self.github.get(f"repos/{repo}/compare/{sha}...{branch}")
        except (GitHubError, TransportError, KeyError, TypeError):
            return False
        return isinstance(comparison, dict) and comparison.get("status") in ("ahead", "identical")

    def _head_pulls(self, run: Mapping[str, Any]) -> list[engine_github.HeadPull] | None:
        owner = ((run.get("head_repository") or {}).get("owner") or {}).get("login")
        branch = run.get("head_branch")
        if not owner or not branch:
            return None
        found = []
        for pull in self.github.paginate(f"repos/{self.repo.slug}/pulls?state=all&head={quote(f'{owner}:{branch}')}"):
            timeline = self.github.paginate(f"repos/{self.repo.slug}/issues/{pull['number']}/timeline")
            changes = [_time(event["created_at"]) for event in timeline if event.get("event") == "base_ref_changed"]
            found.append(
                engine_github.HeadPull(
                    pull["number"], _time(pull["created_at"]), str(pull["base"]["ref"]), max(changes, default=None)
                )
            )
        return found

    def _command(self, comment: Mapping[str, Any], actor: str, pr: int, started: datetime) -> bool:
        return (
            (comment.get("user") or {}).get("login") == actor
            and str(comment.get("issue_url", f"/issues/{pr}")).endswith(f"/issues/{pr}")
            and str(comment.get("body") or "").strip().startswith(self.repo.review_command)
            and _time(comment["created_at"]) <= started
        )

    def _check_comment(self, run: Mapping[str, Any], pr: int, comment_id: int | None) -> None:
        """The comment behind a comment run must be a review command from a trusted author.

        The run's ``actor`` is the commenter; ``triggering_actor`` changes when someone re-runs the job.
        With a ``comment_id`` in the request that comment is read directly. Older requests do not carry
        one, so the newest review command by the actor on the pull request, made before the run, is used.
        """
        actor = str((run.get("actor") or {}).get("login") or "")
        started = _time(run["created_at"]) + COMMENT_SKEW
        if comment_id is not None:
            comment = self.github.get(f"repos/{self.repo.slug}/issues/comments/{comment_id}")
            if not isinstance(comment, dict) or not actor or not self._command(comment, actor, pr, started):
                raise RequestRefusedError(
                    "untrusted", f"comment {comment_id} is not a review command by the run's actor"
                )
        else:
            commands = [
                comment
                for comment in self.github.paginate(f"repos/{self.repo.slug}/issues/{pr}/comments")
                if self._command(comment, actor, pr, started)
            ]
            if not actor or not commands:
                raise RequestRefusedError(
                    "untrusted", f"no {self.repo.review_command} comment by the run's actor was found"
                )
            comment = max(commands, key=lambda item: _time(item["created_at"]))
        if comment.get("author_association") not in TRUSTED_COMMENTERS:
            raise RequestRefusedError(
                "untrusted", f"the {self.repo.review_command} comment is from an untrusted author"
            )

    def _check_pull(self, pr: int, head: str) -> None:
        pull = self.github.get(f"repos/{self.repo.slug}/pulls/{pr}")
        same_repo = str(((pull.get("head") or {}).get("repo") or {}).get("full_name", "")).casefold()
        problems = [
            (pull.get("state") != "open", "closed"),
            (bool(pull.get("draft")), "a draft"),
            (same_repo != self.repo.slug.casefold(), "from another repository"),
            ((pull.get("base") or {}).get("ref") != self.repo.base_branch, "not on the base branch"),
            ((pull.get("head") or {}).get("sha") != head, "at a newer head"),
        ]
        for failed, what in problems:
            if failed:
                raise RequestRefusedError("dropped", f"#{pr} is {what}")

    # Side effects ----------------------------------------------------------------------------------

    def request_dir(self, pr: int, head: str, run_id: str) -> Path:
        return self.requests_dir / f"{self.repo.slug.replace('/', '--')}-{pr}-{head[:12]}-{run_id}"

    def _store(self, files: Mapping[str, bytes], pr: int, head: str, run_id: str) -> None:
        """Keep the plan, brief and diff where the reviewer wrapper reads them. Rewriting them is harmless."""
        directory = self.request_dir(pr, head, run_id)
        directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        for name, content in files.items():
            temporary = directory / f".{name}.tmp"
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
            os.replace(temporary, directory / name)

    def _status(self, result: Enqueued, request: Mapping[str, Any]) -> None:
        item = result.item
        if result.outcome == "held":
            build = "" if item.engine_version not in self.installed else " (this build)"
            description = (
                f"{executor.HELD_PREFIX} engine {item.engine_version}{build} not installed on the reviewer host"
            )
        else:
            description = f"queued locally (position {self.queue.position(item.id)})"
        context = self.repo.status_context
        if request.get("executor") == executor.PROOF_MODE:
            context = f"{context}-local"
        payload = {
            "sha": item.head_sha,
            "state": "pending",
            "context": context,
            "description": description[:STATUS_LIMIT],
        }
        self.outbox.add(
            f"status-{item.id}-{result.outcome}", outbox_module.STATUS, payload, self.clock(), item_id=item.id
        )

    # Reconciliation --------------------------------------------------------------------------------

    def _known_head(self, pr: int, head: str) -> bool:
        states = (*ACTIVE, DONE)
        marks = ",".join("?" * len(states))
        found = self.db.execute(
            f"SELECT 1 FROM items WHERE repo = ? AND pr = ? AND head_sha = ? AND state IN ({marks})",  # noqa: S608
            (self.repo.slug, pr, head, *states),
        )
        return found.fetchone() is not None

    def _decided(self, pr: int, head: str) -> bool:
        reviews = [
            {
                "id": review.get("id"),
                "login": (review.get("user") or {}).get("login"),
                "user_type": (review.get("user") or {}).get("type"),
                "state": review.get("state"),
                "body": review.get("body") or "",
                "submitted_at": review.get("submitted_at"),
            }
            for review in self.github.paginate(f"repos/{self.repo.slug}/pulls/{pr}/reviews")
        ]
        found = protocol.history(reviews, self.repo.bot_login)
        return found.latest is not None and found.latest.get("head_sha") == head

    def _runs(self, query: str, limit: int) -> list[dict[str, Any]]:
        workflow = Path(self.repo.verdict_workflow).name
        listing = self.github.get(f"repos/{self.repo.slug}/actions/workflows/{workflow}/runs?per_page={limit}{query}")
        return list(listing.get("workflow_runs") or [])

    def _run_requests(self, run: Mapping[str, Any]) -> list[Outcome]:
        listing = self.github.get(
            f"repos/{self.repo.slug}/actions/runs/{run['id']}/artifacts?name={quote(self.repo.request_artifact)}"
        )
        live = [
            item for item in listing.get("artifacts") or [] if not item.get("expired") and not self._seen(item["id"])
        ]
        return [self.consider(item) for item in live]

    def reconcile(self) -> list[Outcome]:
        """Find the newest request of every open pull request whose head is undecided and unknown."""
        outcomes: list[Outcome] = []
        waiting = []
        for pull in self.github.paginate(
            f"repos/{self.repo.slug}/pulls?state=open&base={quote(self.repo.base_branch)}"
        ):
            pr, head = pull["number"], pull["head"]["sha"]
            same_repo = (
                str((pull["head"].get("repo") or {}).get("full_name") or "").casefold() == self.repo.slug.casefold()
            )
            if pull.get("draft") or not same_repo or self._known_head(pr, head) or self._decided(pr, head):
                continue
            waiting.append(pull)
            branch = f"&event=pull_request_target&branch={quote(pull['head']['ref'])}"
            for run in self._runs(branch, RECONCILE_RUNS):
                found = self._run_requests(run)
                outcomes.extend(found)
                if any(outcome.kind in ("queued", "held", "duplicate", "known", "stale") for outcome in found):
                    break
        if any(not self._known_head(pull["number"], pull["head"]["sha"]) for pull in waiting):
            base = quote(self.repo.base_branch)
            for event in BASE_EVENTS:
                for run in self._runs(f"&event={event}&branch={base}", BASE_RUNS):
                    outcomes.extend(self._run_requests(run))
        return outcomes
