from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from ship_no_ship.engine import cli
from ship_no_ship.engine.retry import State

from .conftest import POLICY_PATH
from .test_cli_plan import (
    BASE,
    HEAD,
    SOUNDNESS,
    TWO_FILE_DIFF,
    FakeGitHub,
    _env,
    _fake,
    _plan,
    _pull,
    _record,
    _review,
    _strike,
)

pytestmark = [pytest.mark.unit, pytest.mark.fast]

GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "benchbox" / "v1_plan_outcomes.json"
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
README = [{"filename": "README.md", "additions": 1, "deletions": 0}]
GATE = [{"filename": ".github/oracle-reviewers.yml", "additions": 1, "deletions": 0}]
EVIDENCE = [
    *SOUNDNESS,
    {"filename": "benchbox/core/equivalence/gone.py", "additions": 0, "deletions": 3, "status": "removed"},
    {"filename": "docs/notes.md", "additions": 1, "deletions": 0},
]
COMMENT = {"action": "created", "issue": {"number": 7, "pull_request": {}}, "comment": {"body": "/oracle-review"}}

PLANS: dict[str, Callable[[], tuple[FakeGitHub, dict[str, Any]]]] = {
    "review": lambda: (FakeGitHub(_pull(), SOUNDNESS), {}),
    "evidence-files": lambda: (FakeGitHub(_pull(), EVIDENCE), {}),
    "not-soundness": lambda: (FakeGitHub(_pull(), README), {}),
    "gate-file": lambda: (FakeGitHub(_pull(), GATE), {}),
    "tier-label": lambda: (FakeGitHub(_pull(labels=[{"name": "oracle-tier:very-high"}]), SOUNDNESS), {}),
    "fork": lambda: (FakeGitHub(_pull(head={"sha": HEAD, "repo": {"full_name": "someone/BenchBox"}}), SOUNDNESS), {}),
    "closed": lambda: (FakeGitHub(_pull(state="closed"), SOUNDNESS), {}),
    "draft": lambda: (FakeGitHub(_pull(draft=True), SOUNDNESS), {}),
    "other-base": lambda: (FakeGitHub(_pull(base={"ref": "release", "sha": BASE}), SOUNDNESS), {}),
    "stale-event-head": lambda: (
        FakeGitHub(_pull(), SOUNDNESS),
        {"event": {"action": "synchronize", "pull_request": {"head": {"sha": "c" * 40}}}},
    ),
    "comment": lambda: (FakeGitHub(_pull(), SOUNDNESS), {"event_name": "issue_comment", "event": COMMENT}),
    "dispatch-on-base": lambda: (
        FakeGitHub(_pull(), SOUNDNESS),
        {"event_name": "workflow_dispatch", "event": {"inputs": {"pr": "7"}}},
    ),
    "dispatch-off-base": lambda: (
        FakeGitHub(_pull(), SOUNDNESS),
        {"event_name": "workflow_dispatch", "event": {"inputs": {"pr": "7"}}, "ref": "refs/heads/feature"},
    ),
    "decided-head": lambda: (_fake(_review(_record(TWO_FILE_DIFF, "SHIP_WITH_FIXES", head_sha=HEAD))), {}),
    "follow-up": lambda: (_fake(_review(_record(TWO_FILE_DIFF.replace("a\n+", "b\n+"), "SHIP_WITH_FIXES"))), {}),
    "refused": lambda: (_fake(_strike(1), _strike(2), _strike(3)), {}),
}


def _digest(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def collect_outcomes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    monkeypatch.setattr(cli, "_now", lambda: NOW)
    outcomes: dict[str, Any] = {}
    for name, build in PLANS.items():
        fake, options = build()
        workdir = tmp_path / name
        workdir.mkdir()
        code, values, plan = _plan(monkeypatch, workdir, fake, **options)
        outcomes[name] = {
            "code": code,
            "outputs": values,
            "plan": plan,
            "brief_sha256": _digest(workdir / "plan" / "brief.md"),
            "diff_sha256": _digest(workdir / "plan" / "diff.patch"),
        }
    due = State(7, HEAD, "pending", NOW - timedelta(hours=2), pending_cause="all-absent")
    for name, pull in {"sweep-due": _pull(), "sweep-draft": _pull(draft=True)}.items():
        fake = FakeGitHub(pull, SOUNDNESS, due)
        fake.install(monkeypatch)
        _env(monkeypatch, tmp_path, "schedule", {}, "refs/heads/develop")
        code = cli.main(["sweep", "--policy", str(POLICY_PATH)])
        outcomes[name] = {"code": code, "dispatched": fake.dispatched}
    return json.loads(json.dumps(outcomes, sort_keys=True))


def test_benchbox_v1_policy_plans_exactly_as_the_imported_engine(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    actual = collect_outcomes(monkeypatch, tmp_path)
    assert sorted(actual) == sorted(expected)
    for name in expected:
        assert actual[name] == expected[name], name
