"""An in-memory GitHub for discovery tests, answering the same REST paths the service calls."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from ship_no_ship_service.ghclient import GitHubError

SLUG = "example-owner/example-repo"
BASE = "main"
BASE_SHA = "0" * 40
WORKFLOW = ".github/workflows/oracle-verdict.yml"
ENGINE = ("0.1.0", "e" * 64)


def stamp(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


class FakeGitHub:
    def __init__(self) -> None:
        self.artifacts: list[dict[str, Any]] = []
        self.files: dict[int, dict[str, bytes]] = {}
        self.runs: dict[int, dict[str, Any]] = {}
        self.pulls: dict[int, dict[str, Any]] = {}
        self.comments: dict[int, list[dict[str, Any]]] = {}
        self.reviews: dict[int, list[dict[str, Any]]] = {}
        self.timeline: dict[int, list[dict[str, Any]]] = {}
        self.on_base = {BASE_SHA}
        self.default_branch = BASE
        self.calls: list[str] = []
        self.fail_downloads: dict[int, int] = {}
        self._next = 1000

    # Building the world ----------------------------------------------------------------------------

    def pull(self, pr: int, head: str, created: datetime, **changes: Any) -> dict[str, Any]:
        pull = {
            "number": pr,
            "state": "open",
            "draft": False,
            "created_at": stamp(created - timedelta(hours=1)),
            "head": {"sha": head, "ref": f"topic-{pr}", "repo": {"full_name": SLUG}},
            "base": {"ref": BASE},
        }
        pull.update(changes)
        self.pulls[pr] = pull
        return pull

    def offer(
        self,
        pr: int,
        head: str,
        created: datetime,
        *,
        event: str = "pull_request_target",
        actor: str = "example-dev",
        request: dict[str, Any] | None = None,
        plan: dict[str, Any] | None = None,
        **run_changes: Any,
    ) -> int:
        """A plan run for ``pr`` at ``head`` that uploaded a request artifact; returns the artifact ID."""
        self._next += 1
        run_id, artifact_id = self._next, self._next + 50_000
        if pr not in self.pulls or self.pulls[pr]["head"]["sha"] != head:
            self.pull(pr, head, created)
        run = {
            "id": run_id,
            "path": f"{WORKFLOW}@refs/heads/{BASE}",
            "repository": {"full_name": SLUG},
            "event": event,
            "created_at": stamp(created - timedelta(minutes=1)),
            "head_sha": head if event == "pull_request_target" else BASE_SHA,
            "head_branch": {"pull_request_target": f"topic-{pr}", "issue_comment": self.default_branch}.get(
                event, BASE
            ),
            "head_repository": {"owner": {"login": "example-owner"}},
            "pull_requests": [{"number": pr, "base": {"ref": BASE}}] if event == "pull_request_target" else [],
            "actor": {"login": actor},
            "triggering_actor": {"login": actor},
        }
        run.update(run_changes)
        self.runs[run_id] = run
        base_request = {
            "schema": 1,
            "executor": "local",
            "repo": SLUG,
            "pr": pr,
            "head_sha": head,
            "run_id": str(run_id),
            "engine_version": ENGINE[0],
            "engine_sha256": ENGINE[1],
            "policy_sha256": "f" * 64,
            "state_generation": 0,
        }
        base_plan = {"run_id": str(run_id), "pr": pr, "head_sha": head, "decision": "review", "base_ref": BASE}
        base_plan["status_context"] = "oracle-verdict"
        self.files[artifact_id] = {
            "request.json": json.dumps({**base_request, **(request or {})}).encode(),
            "plan.json": json.dumps({**base_plan, **(plan or {})}).encode(),
            "brief.md": b"brief",
            "diff.patch": b"diff",
        }
        self.artifacts.append(
            {
                "id": artifact_id,
                "name": "oracle-verdict-request",
                "expired": False,
                "created_at": stamp(created),
                "workflow_run": {"id": run_id},
            }
        )
        return artifact_id

    # The REST surface ------------------------------------------------------------------------------

    def _route(self, path: str) -> tuple[list[str], dict[str, str]]:
        self.calls.append(path)
        parts = urlsplit(path)
        query = {key: values[0] for key, values in parse_qs(parts.query).items()}
        segments = [unquote(item) for item in parts.path.split("/")]
        assert segments[:3] == ["repos", *SLUG.split("/")], path
        return segments[3:], query

    def get(self, path: str) -> Any:
        route, query = self._route(path)
        if route == []:
            return {"full_name": SLUG, "default_branch": self.default_branch}
        if route == ["actions", "artifacts"]:
            named = [item for item in self.artifacts if item["name"] == query["name"]]
            ordered = sorted(named, key=lambda item: (item["created_at"], item["id"]), reverse=True)
            size, page = int(query.get("per_page", 30)), int(query.get("page", 1))
            return {"total_count": len(ordered), "artifacts": ordered[(page - 1) * size : page * size]}
        if route[:2] == ["actions", "runs"] and len(route) == 3:
            return self.runs[int(route[2])]
        if route[:2] == ["actions", "runs"] and route[3:] == ["artifacts"]:
            run_id = int(route[2])
            found = [
                item
                for item in self.artifacts
                if item["workflow_run"]["id"] == run_id and item["name"] == query["name"]
            ]
            return {"artifacts": found}
        if route[:2] == ["actions", "workflows"] and route[3:] == ["runs"]:
            runs = [run for run in self.runs.values() if run["path"].split("@")[0].endswith(route[2])]
            for key, field in (("event", "event"), ("branch", "head_branch"), ("head_sha", "head_sha")):
                if key in query:
                    runs = [run for run in runs if run[field] == query[key]]
            runs.sort(key=lambda run: run["created_at"], reverse=True)
            return {"workflow_runs": runs[: int(query.get("per_page", 30))]}
        if route[:2] == ["issues", "comments"]:
            for comments in self.comments.values():
                for comment in comments:
                    if comment["id"] == int(route[2]):
                        return comment
            raise GitHubError("HTTP 404")
        if route[0] == "pulls" and len(route) == 2:
            return self.pulls[int(route[1])]
        if route[:3] == ["git", "ref", "heads"]:
            return {"object": {"sha": BASE_SHA}}
        if route[0] == "compare":
            sha = route[1].split("...")[0]
            return {"status": "ahead" if sha in self.on_base else "diverged"}
        raise AssertionError(f"unexpected GET {path}")

    def paginate(self, path: str) -> list[Any]:
        route, query = self._route(path)
        if route == ["pulls"] and "head" in query:
            branch = query["head"].split(":", 1)[1]
            return [pull for pull in self.pulls.values() if pull["head"]["ref"] == branch]
        if route == ["pulls"]:
            return [
                p for p in self.pulls.values() if p["state"] == query["state"] and p["base"]["ref"] == query["base"]
            ]
        if route[0] == "issues" and route[2] == "timeline":
            return self.timeline.get(int(route[1]), [])
        if route[0] == "issues" and route[2] == "comments":
            return self.comments.get(int(route[1]), [])
        if route[0] == "pulls" and route[2] == "reviews":
            return self.reviews.get(int(route[1]), [])
        raise AssertionError(f"unexpected paginated GET {path}")

    def artifact_files(self, artifact_id: int) -> dict[str, bytes]:
        self.calls.append(f"download {artifact_id}")
        if self.fail_downloads.get(artifact_id, 0) > 0:
            self.fail_downloads[artifact_id] -= 1
            raise GitHubError("the artifact is not ready")
        return self.files[artifact_id]
