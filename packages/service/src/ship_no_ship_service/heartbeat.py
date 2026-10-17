"""The repository heartbeat: a success status on the base branch head saying the service is alive.

It is posted when its content changes and otherwise every 30 minutes. GitHub keeps at most 1,000
statuses per commit and context and refuses more, so a base commit that stays idle would fill its
context in about three weeks and the heartbeat would then look stale. Each description therefore
carries a running count, and after ``ROLLOVER`` posts on one commit the heartbeat moves to the next
numbered context (``<context>/2``, ``<context>/3``, ...), which the engine's sweep also reads.

When the base head changes, or the service starts, the commit's combined status is read once to find
the highest heartbeat context in use, and the commit's status list, newest first, is read until that
context's latest status, whose description holds its count. The combined status names no creator, so
the count is taken only from the list. A context whose count cannot be read is treated as full, so an
unknown count never risks the limit.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from ship_no_ship.engine import executor

from .config import Repository
from .ghclient import MAX_PAGES, PER_PAGE, GitHub

INTERVAL = timedelta(minutes=30)
STATUS_LIMIT = 140
# Well below GitHub's 1,000, leaving room for posts whose response was lost.
ROLLOVER = 900
_COUNT = re.compile(r"alive \S+; beat ([1-9][0-9]*);")


def description(now: datetime, engines: Iterable[str], queued: int, beat: int = 1) -> str:
    stamp = now.astimezone(UTC).strftime("%Y-%m-%dT%H:%MZ")
    text = f"alive {stamp}; beat {beat}; engines {','.join(sorted(engines)) or 'none'}; queue {queued}"
    return text[:STATUS_LIMIT]


def base_head(github: GitHub, repository: Repository) -> str:
    return str(github.get(f"repos/{repository.slug}/git/ref/heads/{quote(repository.base_branch)}")["object"]["sha"])


def _latest(github: GitHub, repository: Repository, sha: str) -> dict[int, Mapping[str, Any]]:
    """The latest status of each heartbeat context on a commit, by context number."""
    found: dict[int, Mapping[str, Any]] = {}
    for page in range(1, MAX_PAGES + 1):
        combined = github.get(f"repos/{repository.slug}/commits/{sha}/status?per_page={PER_PAGE}&page={page}")
        statuses = (combined.get("statuses") or []) if isinstance(combined, dict) else []
        for status in statuses:
            number = executor.heartbeat_number(str(status.get("context", "")), repository.heartbeat_context)
            if number is not None:
                found[number] = status
        if len(statuses) < PER_PAGE:
            break
    return found


def _newest(github: GitHub, repository: Repository, sha: str, context: str) -> Mapping[str, Any] | None:
    """The App's newest status for one context on a commit, read page by page and stopping at the first.

    Statuses others posted to the context are passed over, as the engine does, so they cannot hide
    the count. ``MAX_PAGES`` bounds the search; not finding one treats the context as full.
    """
    for page in range(1, MAX_PAGES + 1):
        statuses = github.get(f"repos/{repository.slug}/commits/{sha}/statuses?per_page={PER_PAGE}&page={page}")
        if not isinstance(statuses, list):
            return None
        for status in statuses:
            if (
                isinstance(status, dict)
                and status.get("context") == context
                and (status.get("creator") or {}).get("login") == repository.bot
            ):
                return status
        if len(statuses) < PER_PAGE:
            return None
    return None


def resume(github: GitHub, repository: Repository, sha: str) -> tuple[int, int]:
    """The context number to post to on ``sha``, and how many heartbeats that context already holds."""
    latest = _latest(github, repository, sha)
    if not latest:
        return 1, 0
    number = max(latest)
    status = _newest(github, repository, sha, executor.heartbeat_context(repository.heartbeat_context, number))
    match = None if status is None else _COUNT.match(str(status.get("description") or ""))
    count = int(match.group(1)) if match else ROLLOVER
    return (number + 1, 0) if count >= ROLLOVER else (number, count)


@dataclass
class Heartbeat:
    repository: Repository
    interval: timedelta = INTERVAL
    _last: tuple[str, tuple[str, ...], int, datetime] | None = None
    _place: tuple[str, int, int] | None = None  # base head, context number, heartbeats posted there

    def due(self, now: datetime, base_sha: str, engines: Iterable[str], queued: int) -> bool:
        """Due on first run, when the base head, engines or queue length change, or after the interval.

        A clock that went backwards also makes it due, so a wrong clock cannot silence the heartbeat.
        """
        if self._last is None:
            return True
        sha, last_engines, last_queued, at = self._last
        changed = (sha, last_engines, last_queued) != (base_sha, tuple(sorted(engines)), queued)
        return changed or now - at >= self.interval or now < at

    def _where(self, github: GitHub, base_sha: str) -> tuple[int, int]:
        if self._place is None or self._place[0] != base_sha:
            self._place = (base_sha, *resume(github, self.repository, base_sha))
        _, number, count = self._place
        if count >= ROLLOVER:
            number, count = number + 1, 0
            self._place = (base_sha, number, count)
        return number, count

    def payload(
        self, github: GitHub, now: datetime, base_sha: str, engines: Iterable[str], queued: int
    ) -> dict[str, Any]:
        """The next heartbeat status. The first one for a base head reads that commit's statuses."""
        number, count = self._where(github, base_sha)
        return {
            "sha": base_sha,
            "state": "success",
            "context": executor.heartbeat_context(self.repository.heartbeat_context, number),
            "description": description(now, engines, queued, count + 1),
        }

    def posted(self, now: datetime, base_sha: str, engines: Iterable[str], queued: int) -> None:
        """Record a heartbeat GitHub accepted; it counts towards its context's limit."""
        self._last = (base_sha, tuple(sorted(engines)), queued, now)
        if self._place is not None and self._place[0] == base_sha:
            sha, number, count = self._place
            self._place = (sha, number, count + 1)
