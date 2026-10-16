from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .policy import RepositoryConfig
from .retry import State

STATE_FILE = "state.json"
ARTIFACTS_PER_PAGE = 100
MAX_ARTIFACT_PAGES = 10


class GitHubError(RuntimeError):
    pass


def _gh(*args: str, accept: str | None = None) -> str:
    argv = ["gh", "api", *(("-H", f"Accept: {accept}") if accept else ()), *args]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise GitHubError(f"gh api {' '.join(args)} failed: {result.stderr.strip()[:500]}")
    return result.stdout


def get_json(path: str) -> Any:
    return json.loads(_gh(path))


def get_paginated(path: str) -> list[Any]:
    pages = json.loads(_gh("--paginate", "--slurp", path))
    return [item for page in pages for item in page]


def get_diff(repo: str, pr: int) -> str | None:
    try:
        return _gh(f"repos/{repo}/pulls/{pr}", accept="application/vnd.github.v3.diff")
    except GitHubError:
        return None


_THREADS_QUERY = """
query($owner: String!, $name: String!, $number: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          isResolved
          path
          comments(first: 1) { nodes { author { __typename login } body } }
        }
      }
    }
  }
}
"""


def review_threads(repo: str, pr: int) -> list[dict[str, Any]]:
    owner, name = repo.split("/", 1)
    threads: list[dict[str, Any]] = []
    after: str | None = None
    while True:
        args = ["graphql", "-f", f"query={_THREADS_QUERY}", "-f", f"owner={owner}", "-f", f"name={name}"]
        args += ["-F", f"number={pr}", *(("-f", f"after={after}") if after else ())]
        payload = json.loads(_gh(*args))
        if payload.get("errors"):
            raise GitHubError(f"GitHub GraphQL returned errors: {payload['errors']}")
        connection = payload["data"]["repository"]["pullRequest"]["reviewThreads"]
        for node in connection["nodes"]:
            first = (node["comments"]["nodes"] or [{}])[0]
            threads.append(
                {
                    "resolved": node["isResolved"],
                    "path": node.get("path"),
                    "author": (first.get("author") or {}).get("login"),
                    "author_type": (first.get("author") or {}).get("__typename"),
                    "body": first.get("body") or "",
                }
            )
        if not connection["pageInfo"]["hasNextPage"]:
            return threads
        after = connection["pageInfo"]["endCursor"]


def oracle_reviews(repo: str, pr: int) -> list[dict[str, Any]]:
    return [
        {
            "id": item.get("id"),
            "login": (item.get("user") or {}).get("login"),
            "user_type": (item.get("user") or {}).get("type"),
            "state": item.get("state"),
            "body": item.get("body") or "",
            "submitted_at": item.get("submitted_at"),
            "commit_id": item.get("commit_id"),
        }
        for item in get_paginated(f"repos/{repo}/pulls/{pr}/reviews?per_page=100")
    ]


def state_artifact_name(pr: int, prefix: str) -> str:
    return f"{prefix}{pr}"


def list_artifacts(repo: str, name: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for page in range(1, MAX_ARTIFACT_PAGES + 1):
        listing = get_json(f"repos/{repo}/actions/artifacts?name={name}&per_page={ARTIFACTS_PER_PAGE}&page={page}")
        items = listing.get("artifacts", [])
        found.extend(items)
        total = listing.get("total_count")
        if len(items) < ARTIFACTS_PER_PAGE or (isinstance(total, int) and len(found) >= total):
            return found
    raise GitHubError(f"more than {MAX_ARTIFACT_PAGES * ARTIFACTS_PER_PAGE} artifacts are named {name}")


TRUSTED_EVENTS = frozenset({"pull_request_target", "issue_comment", "schedule", "workflow_dispatch"})


def on_base(repo: str, sha: str, base_branch: str) -> bool:
    try:
        branch = get_json(f"repos/{repo}/git/ref/heads/{base_branch}")["object"]["sha"]
        comparison = get_json(f"repos/{repo}/compare/{sha}...{branch}")
    except (GitHubError, KeyError, TypeError):
        return False
    return comparison.get("status") in ("ahead", "identical")


def _targets_base(run: dict[str, Any], pr: int, base_branch: str) -> bool:
    pulls = [pull for pull in run.get("pull_requests") or [] if isinstance(pull, dict)]
    return (
        bool(pulls)
        and all((pull.get("base") or {}).get("ref") == base_branch for pull in pulls)
        and any(pull.get("number") == pr for pull in pulls)
    )


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass(frozen=True)
class HeadPull:
    number: int
    created_at: datetime
    base_ref: str
    base_changed_at: datetime | None


def head_pulls(repo: str, run: dict[str, Any]) -> list[HeadPull]:
    owner = (((run.get("head_repository") or {}).get("owner")) or {}).get("login")
    branch = run.get("head_branch")
    if not owner or not branch:
        raise GitHubError("the run does not name its head branch")
    found: list[HeadPull] = []
    for pull in get_paginated(f"repos/{repo}/pulls?state=all&head={owner}:{branch}&per_page=100"):
        created_at = _parse_time(pull.get("created_at"))
        if created_at is None or not isinstance(pull.get("number"), int):
            raise GitHubError("a pull request for the head branch has no readable creation time")
        changes = [
            _parse_time(event.get("created_at"))
            for event in get_paginated(f"repos/{repo}/issues/{pull['number']}/timeline?per_page=100")
            if event.get("event") == "base_ref_changed"
        ]
        if any(moment is None for moment in changes):
            raise GitHubError(f"a base change on #{pull['number']} has no readable time")
        found.append(
            HeadPull(
                pull["number"],
                created_at,
                str((pull.get("base") or {}).get("ref", "")),
                max(filter(None, changes), default=None),
            )
        )
    return found


def _pull_request_target_trusted(
    run: dict[str, Any], pr: int, pulls: Sequence[HeadPull] | None, base_branch: str
) -> bool:
    started = _parse_time(run.get("created_at"))
    if started is None or pulls is None or not _targets_base(run, pr, base_branch):
        return False
    open_then = [pull for pull in pulls if pull.created_at <= started]
    return any(pull.number == pr for pull in open_then) and all(
        pull.base_ref == base_branch and (pull.base_changed_at is None or pull.base_changed_at < started)
        for pull in open_then
    )


def trusted_run(
    run: dict[str, Any],
    repo: str,
    pr: int,
    is_on_base: Callable[[str, str], bool] | None = None,
    pulls: Sequence[HeadPull] | None = None,
    *,
    workflow_path: str,
    base_branch: str,
) -> bool:
    head_sha = str(run.get("head_sha", ""))
    event = run.get("event")
    if not (
        str(run.get("path", "")).split("@", 1)[0] == workflow_path
        and (run.get("repository") or {}).get("full_name") == repo
        and event in TRUSTED_EVENTS
        and re.fullmatch(r"[0-9a-f]{40}", head_sha) is not None
    ):
        return False
    if event == "pull_request_target":
        return _pull_request_target_trusted(run, pr, pulls, base_branch)
    if is_on_base is None:
        return on_base(repo, head_sha, base_branch)
    return is_on_base(repo, head_sha)


def record_run_trusted(
    run: dict[str, Any], repo: str, pr: int, repository: RepositoryConfig, record_actor: str
) -> bool:
    """A record run is trusted only when the App's bot dispatched it on the base branch itself."""
    return (
        bool(record_actor)
        and run.get("event") == "workflow_dispatch"
        and run.get("head_branch") == repository.base_branch
        and ((run.get("triggering_actor") or {}).get("login")) == record_actor
        and trusted_run(run, repo, pr, workflow_path=repository.workflows.record, base_branch=repository.base_branch)
    )


def plan_run_trusted(run: dict[str, Any], repo: str, pr: int, repository: RepositoryConfig) -> bool:
    pulls: list[HeadPull] | None = None
    if run.get("event") == "pull_request_target":
        try:
            pulls = head_pulls(repo, run)
        except GitHubError:
            return False
    return trusted_run(
        run, repo, pr, pulls=pulls, workflow_path=repository.workflows.verdict, base_branch=repository.base_branch
    )


RECORDED_RUN = "recorded_run"


def _warn(message: str) -> None:
    print(f"::warning::{message}", file=sys.stderr)


MAX_STATE_READS = 3


def latest_state(
    repo: str, pr: int, repository: RepositoryConfig, *, record_actor: str = "", strict: bool = False
) -> State | None:
    """Return the trusted state that wins among the newest few, reading artifacts newest first.

    The highest generation wins, so a record run that finishes late cannot replace a newer generation. At
    equal generations a state accepted by record-state beats one a plan run wrote, and otherwise the newer
    artifact wins. A state without a generation was written by an engine that predates generations: if it
    is the newest readable state, it wins as it always did (this keeps a rollback to such an engine
    working), and nothing older than it is read.

    At most MAX_STATE_READS trusted states are read. The artifact listing filters only by exact name, so
    the generation cannot be put in the name without listing every artifact in the repository; instead,
    writers share one concurrency group per pull request, which keeps generations in time order except
    for the few writes that can race, and those are among the newest.

    A trusted candidate that cannot be read is skipped with a warning, and an error is raised only when
    none could be read. With ``strict``, any unreadable trusted candidate is an error, because a missed
    state could be the current generation.
    """
    name = state_artifact_name(pr, repository.artifacts.state_prefix)
    candidates = sorted(
        (item for item in list_artifacts(repo, name) if not item.get("expired")),
        key=lambda item: item.get("created_at", ""),
        reverse=True,
    )
    best: tuple[tuple[int, bool], State] | None = None
    failures: list[str] = []
    reads = 0
    for candidate in candidates:
        if reads >= MAX_STATE_READS:
            break
        run_id = str((candidate.get("workflow_run") or {}).get("id", ""))
        try:
            run = get_json(f"repos/{repo}/actions/runs/{run_id}")
            recorded = record_run_trusted(run, repo, pr, repository, record_actor)
            if not (recorded or plan_run_trusted(run, repo, pr, repository)):
                continue
            data = download_json(repo, run_id, name, STATE_FILE)
            if recorded and str(data.get(RECORDED_RUN)) != run_id:
                _warn(f"retry state from record run {run_id} is ignored: record-state did not accept it")
                continue
            state = State.from_json(data)
        except (GitHubError, KeyError, TypeError, ValueError, AttributeError) as exc:
            if strict:
                raise GitHubError(f"retry state from run {run_id} cannot be read: {exc}") from exc
            failures.append(run_id)
            _warn(f"retry state from run {run_id} is skipped: {exc}")
            continue
        reads += 1
        if state.predecessor is None:
            return state if best is None else best[1]
        rank = (state.generation, recorded)
        if best is None or rank > best[0]:
            best = (rank, state)
    if best is None and failures:
        raise GitHubError(f"no trusted retry state could be read; runs {', '.join(failures)} failed")
    return best[1] if best else None


def download_json(repo: str, run_id: str, name: str, filename: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        result = subprocess.run(
            ["gh", "run", "download", run_id, "-n", name, "-D", directory, "-R", repo],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise GitHubError(f"could not download {name} from run {run_id}: {result.stderr.strip()[:500]}")
        try:
            data = json.loads((Path(directory) / filename).read_text(encoding="utf-8"))
        except OSError as exc:
            raise GitHubError(f"{filename} is missing from {name} in run {run_id}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{filename} in {name} from run {run_id} is not an object")
    return data


def newest_status(repo: str, sha: str, context: str, creator: str) -> dict[str, Any] | None:
    """The newest status for one context on a commit, posted by the given account."""
    for status in get_json(f"repos/{repo}/commits/{sha}/statuses?per_page=100"):
        if status.get("context") == context and (status.get("creator") or {}).get("login") == creator:
            return status
    return None


HEARTBEAT_COMMITS = 20


def heartbeat(repo: str, base_branch: str, context: str, creator: str) -> datetime | None:
    """The newest successful heartbeat across the last commits of the base branch."""
    newest: datetime | None = None
    for commit in get_json(f"repos/{repo}/commits?sha={base_branch}&per_page={HEARTBEAT_COMMITS}"):
        status = newest_status(repo, str(commit.get("sha", "")), context, creator)
        moment = _parse_time(status.get("updated_at")) if status and status.get("state") == "success" else None
        if moment is not None and (newest is None or moment > newest):
            newest = moment
    return newest


def dispatch(repo: str, workflow: str, pr: int, ref: str) -> None:
    result = subprocess.run(
        ["gh", "workflow", "run", workflow, "--ref", ref, "-f", f"pr={pr}", "-R", repo],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise GitHubError(f"could not dispatch {workflow} for #{pr}: {result.stderr.strip()[:500]}")
