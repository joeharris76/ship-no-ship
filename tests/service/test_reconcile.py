from __future__ import annotations

from datetime import timedelta

import pytest

from ship_no_ship.engine import protocol
from ship_no_ship_service.queue import Request

from .fake_github import BASE, ENGINE, SLUG, stamp
from .test_discovery import T0, World, sha, world  # noqa: F401 - the world fixture


def marker_review(head: str) -> dict:
    record = {
        "v": 1, "cycle": 1, "round": 1, "kind": "first", "decision": "SHIP", "head_sha": head,
        "base_ref": BASE, "reviewer": "claude", "tier": "high", "strikes_after": 0, "open_defects": [],
        "next_id": 1, "patch_digest": "", "carried": False, "summary": "",
    }  # fmt: skip
    return {
        "id": 1,
        "user": {"login": "example-bot[bot]", "type": "Bot"},
        "state": "COMMENTED",
        "body": f"Review\n\n{protocol.encode_marker(record)}",
        "submitted_at": stamp(T0),
    }


def queued_prs(outcomes) -> list[tuple[str, int | None]]:
    return [(o.kind, o.enqueued.item.pr if o.enqueued else None) for o in outcomes]


def test_reconciliation_skips_decided_known_draft_and_fork_heads(world: World):
    for n in range(1, 6):
        world.github.offer(n, sha(n), T0 + timedelta(minutes=n))
    # Nothing was polled. PR 5 is already queued from an earlier request.
    world.queue.enqueue(Request(SLUG, 5, sha(5), "1", ENGINE[0], ENGINE[1], 0, T0), T0, held=False)
    world.github.reviews[1] = [marker_review(sha(1))]
    world.github.pulls[2]["draft"] = True
    world.github.pulls[3]["head"]["repo"] = {"full_name": "someone/fork"}
    assert queued_prs(world.discovery.reconcile()) == [("queued", 4)]
    assert not any("/actions/artifacts?" in call for call in world.github.calls)


def test_a_request_listed_outside_the_overlap_is_found_by_reconciliation(world: World):
    world.github.offer(1, sha(1), T0 + timedelta(hours=5))
    world.discovery.poll()
    world.github.offer(3, sha(3), T0 + timedelta(hours=2))
    assert world.discovery.poll() == []
    assert queued_prs(world.discovery.reconcile()) == [("queued", 3)]


@pytest.mark.parametrize("default_branch", [BASE, "trunk"])
def test_dispatch_and_comment_runs_are_found_for_waiting_pull_requests(world: World, default_branch):
    world.github.default_branch = default_branch
    world.github.offer(1, sha(1), T0, event="workflow_dispatch")
    world.github.offer(2, sha(2), T0 + timedelta(minutes=1), event="issue_comment")
    world.github.comments[2] = [
        {
            "id": 9,
            "issue_url": f"https://api.example.test/repos/{SLUG}/issues/2",
            "user": {"login": "example-dev"},
            "body": "/oracle-review",
            "author_association": "OWNER",
            "created_at": stamp(T0 - timedelta(minutes=3)),
        }
    ]
    assert sorted(queued_prs(world.discovery.reconcile())) == [("queued", 1), ("queued", 2)]
    world.github.calls.clear()
    assert world.discovery.reconcile() == []
    assert not any("event=workflow_dispatch" in call for call in world.github.calls)


def test_the_default_branch_is_read_once_and_falls_back_to_the_base_branch(world: World):
    world.github.default_branch = None
    world.github.offer(1, sha(1), T0, event="issue_comment")
    world.github.comments[1] = [
        {
            "id": 9,
            "issue_url": f"https://api.example.test/repos/{SLUG}/issues/1",
            "user": {"login": "example-dev"},
            "body": "/oracle-review",
            "author_association": "OWNER",
            "created_at": stamp(T0 - timedelta(minutes=3)),
        }
    ]
    world.github.pull(2, sha(2), T0)
    assert queued_prs(world.discovery.reconcile()) == [("queued", 1)]
    world.discovery.reconcile()
    assert world.github.calls.count(f"repos/{SLUG}") == 1


def test_a_missing_default_branch_is_logged(world: World, caplog):
    world.github.default_branch = None
    world.github.pull(2, sha(2), T0)
    with caplog.at_level("WARNING"):
        world.discovery.reconcile()
    assert "names no default branch" in caplog.text
