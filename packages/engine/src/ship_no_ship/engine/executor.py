"""Where reviews run, and what the plan hands to the local review service.

Under the hosted executor the workflow runs the reviewer jobs itself. Under the local executor the plan
writes a request that the local service discovers, and the workflow runs no reviewer. The proof executor
runs the hosted path and also writes a request for pull requests that carry the proof label.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import ship_no_ship

from .policy import Policy

HOSTED_MODE = "hosted"
PROOF_MODE = "proof"
LOCAL_MODE = "local"
OVERRIDE_ENV = "ORACLE_EXECUTOR"
REQUEST_FILE = "request.json"
QUEUED_STATUS_FILE = "queued-status.json"
REQUEST_SCHEMA = 1

# Status descriptions. The plan's own status says a request exists; only the service's statuses show
# that the service has picked the request up, which is what lets the sweep notice a missed request.
WAITING = "waiting for the local reviewer"
SERVICE_PREFIXES = ("queued locally", "local review running")
HELD_PREFIX = "held:"

HEARTBEAT_FRESH = timedelta(minutes=90)
HEARTBEAT_SKEW = timedelta(minutes=5)
OUTSTANDING = timedelta(minutes=60)
KEEP_ALIVE = timedelta(days=5)
NEVER = datetime.min.replace(tzinfo=UTC)


class ExecutorError(ValueError):
    pass


def resolve(policy: Policy, environ: Mapping[str, str]) -> str:
    """The policy's executor, unless the environment forces the hosted one.

    The override accepts only ``hosted``: it is the rollback switch, so it can move work back to the
    hosted reviewers but never route it anywhere the policy did not choose.
    """
    override = environ.get(OVERRIDE_ENV, "").strip()
    if not override:
        return policy.executor.mode
    if override != HOSTED_MODE:
        raise ExecutorError(f"{OVERRIDE_ENV} may only be {HOSTED_MODE!r} or empty, not {override!r}")
    return HOSTED_MODE


def hands_off(mode: str, policy: Policy, decision: str, labels: list[str]) -> bool:
    if decision != "review":
        return False
    return mode == LOCAL_MODE or (mode == PROOF_MODE and policy.executor.proof_label in labels)


def engine_sha256() -> str:
    """A digest of the installed engine's source files, so the service can refuse a request from another build."""
    root = Path(ship_no_ship.__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item.suffix in (".py", ".typed")):
        data = path.read_bytes()
        digest.update(f"{path.relative_to(root).as_posix()}\0{len(data)}\0".encode())
        digest.update(data)
    return digest.hexdigest()


def request(plan: Mapping[str, Any], mode: str, policy_bytes: bytes) -> dict[str, Any]:
    previous = plan.get("previous_state") or {}
    return {
        "schema": REQUEST_SCHEMA,
        "executor": mode,
        "repo": plan["repo"],
        "pr": plan["pr"],
        "head_sha": plan["head_sha"],
        "run_id": plan["run_id"],
        "engine_version": ship_no_ship.__version__,
        "engine_sha256": engine_sha256(),
        "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "state_generation": int(previous.get("generation") or 0),
    }


def waiting_status(plan: Mapping[str, Any], target_url: str) -> dict[str, Any]:
    return {"state": "pending", "context": plan["status_context"], "description": WAITING, "target_url": target_url}


def _description(status: Mapping[str, Any] | None) -> str:
    return str((status or {}).get("description") or "")


def service_owned(status: Mapping[str, Any] | None, now: datetime, stalled_after: timedelta) -> bool:
    """The service holds this head, or has queued or started it within ``stalled_after``.

    A queued or running status older than that counts as lost, so a re-offer replaces it with a fresh
    waiting status and the head moves to the back of the sweep's queue instead of staying at the front.
    """
    if status is None or status.get("state") != "pending":
        return False
    description = _description(status)
    if description.startswith(HELD_PREFIX):
        return True
    return description.startswith(SERVICE_PREFIXES) and now - status_time(status) < stalled_after


def status_time(status: Mapping[str, Any] | None) -> datetime:
    if status is None:
        return NEVER
    try:
        moment = datetime.fromisoformat(
            str(status.get("updated_at") or status.get("created_at")).replace("Z", "+00:00")
        )
    except ValueError:
        return NEVER
    return moment if moment.tzinfo is not None else NEVER


def heartbeat_fresh(beat: datetime | None, now: datetime) -> bool:
    """Fresh means recent, allowing a few minutes of clock skew; a heartbeat further in the future is stale."""
    return beat is not None and -HEARTBEAT_SKEW <= now - beat < HEARTBEAT_FRESH


def should_reoffer(
    status: Mapping[str, Any] | None, heartbeat_fresh: bool, now: datetime, stalled_after: timedelta
) -> bool:
    """Whether the sweep should dispatch the plan again for a head whose newest oracle status is ``status``.

    A head with no status has never been offered. A head the service has queued or is running is left
    alone while the service is alive, so a re-offer never displaces queued work, until it has waited
    ``stalled_after`` and the service may have lost it; while the service is down, the request is
    renewed only when it nears the artifact retention limit. A head whose request the service
    never picked up despite a fresh heartbeat was missed and is offered again. Held heads wait for the
    owner, and any other status is a result that the retry pass owns.
    """
    if status is None:
        return True
    description = _description(status)
    if status.get("state") != "pending" or description.startswith(HELD_PREFIX):
        return False
    waited = now - status_time(status)
    if waited < OUTSTANDING:
        return False
    if description.startswith(SERVICE_PREFIXES):
        return waited >= stalled_after or (not heartbeat_fresh and waited >= KEEP_ALIVE)
    if description.startswith(WAITING):
        return heartbeat_fresh or waited >= KEEP_ALIVE
    return False


def choose(candidates: Sequence[tuple[Mapping[str, Any] | None, int]], cap: int, now: datetime) -> list[int]:
    """Pick at most ``cap`` pull requests to re-offer from (newest status, number) pairs.

    Heads that waited longest go first. Heads with no status at all may never get one (a plan that skips
    posts nothing), so they cannot be ordered by wait: they are kept to ``cap // 2`` slots while others
    wait, take any slots left over, and rotate hourly so that each gets a turn.
    """
    if cap <= 0:
        return []
    waiting = sorted((status_time(status), number) for status, number in candidates if status is not None)
    unseen = sorted(number for status, number in candidates if status is None)
    if unseen:
        offset = int(now.timestamp() // 3600) % len(unseen)
        unseen = unseen[offset:] + unseen[:offset]
    reserved = min(len(unseen), cap // 2)
    waiting_slots = min(len(waiting), cap - reserved)
    unseen_slots = min(len(unseen), cap - waiting_slots)
    return [number for _, number in waiting[:waiting_slots]] + unseen[:unseen_slots]
