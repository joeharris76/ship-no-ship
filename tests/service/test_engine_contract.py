"""The queue's slot history must replay through the engine the way the execution loop will write it."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ship_no_ship.engine import absence, attempts, selection
from ship_no_ship.engine.absence import Absence
from ship_no_ship.engine.policy import load_policy
from ship_no_ship.engine.selection import SelectionInput, excluded_families
from ship_no_ship_service import queue
from ship_no_ship_service.queue import Queue, Request

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
POLICY = Path(__file__).resolve().parents[1] / "fixtures" / "benchbox" / ".github" / "oracle-reviewers.yml"
RUN_ID = "4242"
HEAD = "a" * 40


def plan_for(tier: str = "medium-high") -> dict:
    policy = load_policy(POLICY)
    return {
        "pr": 7,
        "run_id": RUN_ID,
        "head_sha": HEAD,
        "tier": tier,
        "max_defects": policy.protocol.max_defects,
        "chain": [reviewer.to_json() for reviewer in policy.chain(tier)],
        "diversity_exempt": list(policy.tiers[tier].diversity_exempt),
        "excluded_families": sorted(excluded_families(("author-family:muse",), policy)),
        "max_attempts": policy.max_attempts,
        "pool_blocked_until": {},
        "protocol": None,
        "brief_mode": "inline",
        "findings_delivery": "comment",
        "status_context": policy.status_context,
    }


def verdict() -> dict:
    return {
        "status": "complete",
        "incomplete_reason": "",
        "decision": "SHIP",
        "summary": "ok",
        "files_examined": ["x.py"],
        "defects": [],
        "prior_defects": [],
    }


def test_interrupted_is_an_engine_absence_kind():
    assert queue.INTERRUPTED == absence.INTERRUPTED
    assert absence.INTERRUPTED in absence.KINDS


def test_an_interrupted_slot_then_a_clean_pass_replays_to_a_pass(tmp_path: Path):
    plan = plan_for()
    q = Queue(queue.connect(tmp_path / "state.db"))
    item = q.enqueue(Request("o/r", 7, HEAD, RUN_ID, "0.1.0", "e" * 64, 0, NOW), NOW, held=False).item
    q.claim_next(NOW)
    directory = tmp_path / "captured"
    directory.mkdir()

    def select(slot: int) -> str:
        loaded = attempts.load(directory, plan, RUN_ID)
        step, errors = attempts.decide(SelectionInput.from_plan(plan, NOW), loaded)
        assert errors == [] and step.kind == selection.REVIEW and step.reviewer is not None, (slot, step, errors)
        return step.reviewer.name

    def write(slot: int, reviewer: str, **outcome) -> None:
        artifact = attempts.build_artifact(run_id=RUN_ID, pr=7, head_sha=HEAD, slot=slot, reviewer=reviewer, **outcome)
        (directory / attempts.artifact_name(slot)).write_text(json.dumps(artifact), encoding="utf-8")

    first = select(1)
    q.slot_started(item.id, 1, first, "attempt-0001", NOW)
    q.slot_started(item.id, 1, first, "attempt-0002", NOW)
    assert q.recover(item.id) == [queue.Recovery(1, "attempt-0002", queue.INTERRUPTED)]
    q.slot_interrupted(item.id, 1, "attempt-0002", NOW)
    write(1, first, verdict=None, missing=Absence(absence.INTERRUPTED, "interrupted twice"))

    second = select(2)
    assert second != first
    q.slot_started(item.id, 2, second, "attempt-0003", NOW)
    write(2, second, verdict=verdict(), missing=None)
    q.slot_captured(item.id, 2, "attempt-0003", "f" * 64, queue.CLEAN, NOW)

    loaded = attempts.load(directory, plan, RUN_ID)
    step, errors = attempts.decide(SelectionInput.from_plan(plan, NOW), loaded)
    assert errors == []
    assert step.kind == selection.PASS
    assert [(a.reviewer, a.absence) for a in loaded.attempts] == [(first, absence.INTERRUPTED), (second, None)]
    assert q.move(item.id, queue.POSTING, NOW).state == queue.POSTING
