"""``health.json``: a small, non-sensitive status file the owner can read without sudo.

Only the fields below are written. They name pull requests, versions, states and times, never a token,
key path, credential or log line.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

SCHEMA = 1
OK = "ok"
FAILED = "failed"
NOT_RUN = "not_run"
AUTH_RESULTS = (OK, FAILED, NOT_RUN)


class HealthError(ValueError):
    pass


@dataclass(frozen=True)
class Held:
    repo: str
    pr: int
    head_sha: str
    engine_version: str


@dataclass(frozen=True)
class Health:
    updated_at: datetime
    service_version: str
    last_poll: datetime | None = None
    last_claim: datetime | None = None
    queue: Mapping[str, int] = field(default_factory=dict)
    engines: Sequence[str] = ()
    auth: Mapping[str, str] = field(default_factory=dict)  # check name -> ok, failed or not_run
    pool_blocked_until: Mapping[str, datetime] = field(default_factory=dict)
    version_skew: Sequence[Held] = ()
    outbox_alerts: int = 0

    def to_json(self) -> dict[str, Any]:
        def moment(value: datetime | None) -> str | None:
            return None if value is None else value.isoformat()

        bad = sorted(name for name, result in self.auth.items() if result not in AUTH_RESULTS)
        if bad:
            raise HealthError(f"auth results must be one of {', '.join(AUTH_RESULTS)}; {', '.join(bad)} are not")
        return {
            "schema": SCHEMA,
            "updated_at": moment(self.updated_at),
            "service_version": self.service_version,
            "last_poll": moment(self.last_poll),
            "last_claim": moment(self.last_claim),
            "queue": dict(sorted(self.queue.items())),
            "engines": sorted(self.engines),
            "auth": dict(sorted(self.auth.items())),
            "pool_blocked_until": {pool: moment(at) for pool, at in sorted(self.pool_blocked_until.items())},
            "version_skew": [asdict(item) for item in self.version_skew],
            "outbox_alerts": self.outbox_alerts,
        }


def write(path: Path, health: Health) -> None:
    """Replace the file atomically with mode 0644, so a reader never sees half of it."""
    data = health.to_json()
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
