"""The repository heartbeat: a success status on the base branch head saying the service is alive.

It is posted when its content changes and otherwise every 30 minutes, which keeps an idle base commit
far below GitHub's limit of 1,000 statuses per commit and context. The sweep and the engine-installed
check read the installed engine versions from its description.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from .config import Repository
from .ghclient import GitHub

INTERVAL = timedelta(minutes=30)
STATUS_LIMIT = 140


def description(now: datetime, engines: Iterable[str], queued: int) -> str:
    text = f"alive {now.astimezone(UTC).strftime('%Y-%m-%dT%H:%MZ')}; engines {','.join(sorted(engines)) or 'none'}; queue {queued}"
    return text[:STATUS_LIMIT]


def base_head(github: GitHub, repository: Repository) -> str:
    return str(github.get(f"repos/{repository.slug}/git/ref/heads/{quote(repository.base_branch)}")["object"]["sha"])


@dataclass
class Heartbeat:
    repository: Repository
    interval: timedelta = INTERVAL
    _last: tuple[str, tuple[str, ...], int, datetime] | None = None

    def due(self, now: datetime, base_sha: str, engines: Iterable[str], queued: int) -> bool:
        """Due on first run, when the base head, engines or queue length change, or after the interval.

        A clock that went backwards also makes it due, so a wrong clock cannot silence the heartbeat.
        """
        if self._last is None:
            return True
        sha, last_engines, last_queued, at = self._last
        changed = (sha, last_engines, last_queued) != (base_sha, tuple(sorted(engines)), queued)
        return changed or now - at >= self.interval or now < at

    def payload(self, now: datetime, base_sha: str, engines: Iterable[str], queued: int) -> dict[str, Any]:
        return {
            "sha": base_sha,
            "state": "success",
            "context": self.repository.heartbeat_context,
            "description": description(now, engines, queued),
        }

    def posted(self, now: datetime, base_sha: str, engines: Iterable[str], queued: int) -> None:
        self._last = (base_sha, tuple(sorted(engines)), queued, now)
