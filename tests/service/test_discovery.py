from __future__ import annotations

import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ship_no_ship_service import queue as q
from ship_no_ship_service.config import Repository
from ship_no_ship_service.discovery import Discovery, DiscoveryError
from ship_no_ship_service.ghclient import ArtifactError
from ship_no_ship_service.outbox import Outbox

from .fake_github import BASE, ENGINE, SLUG, FakeGitHub, stamp

T0 = datetime(2026, 10, 10, 8, 0, tzinfo=UTC)
A, B = "a" * 40, "b" * 40


def sha(n: int) -> str:
    return f"{n:040x}"


class World:
    def __init__(self, tmp_path: Path, clock: datetime = T0, context: str = "oracle-verdict") -> None:
        self.github = FakeGitHub()
        self.now = clock
        db = q.connect(tmp_path / "state" / "state.db")
        self.queue = q.Queue(db)
        self.outbox = Outbox(db)
        repo = Repository(SLUG, 7, 9, tmp_path / "key.pem", "example-bot", BASE, status_context=context)
        self.discovery = Discovery(
            repo,
            self.github,
            self.queue,
            self.outbox,
            requests_dir=tmp_path / "requests",
            installed=dict([ENGINE]),
            clock=lambda: self.now,
        )

    def kinds(self, outcomes) -> list[str]:
        return [outcome.kind for outcome in outcomes]


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


def listing_pages(world: World) -> int:
    return sum(1 for call in world.github.calls if call.startswith(f"repos/{SLUG}/actions/artifacts?"))


def test_more_than_thirty_requests_over_several_days_are_all_queued_oldest_first(world):
    for n in range(1, 251):
        world.github.offer(n, sha(n), T0 + timedelta(minutes=17 * n))
    outcomes = world.discovery.poll()
    assert world.kinds(outcomes) == ["queued"] * 250
    assert listing_pages(world) == 3
    assert [item.pr for item in world.queue.in_state(q.QUEUED)] == list(range(1, 251))
    world.github.calls.clear()
    assert world.discovery.poll() == []
    assert listing_pages(world) == 1


def test_a_multi_day_gap_follows_pages_back_to_the_cursor(world):
    for n in range(1, 11):
        world.github.offer(n, sha(n), T0 + timedelta(minutes=n))
    world.discovery.poll()
    gap_start = T0 + timedelta(days=3)
    for n in range(11, 161):
        world.github.offer(n, sha(n), gap_start + timedelta(minutes=20 * n))
    world.github.calls.clear()
    assert world.kinds(world.discovery.poll()) == ["queued"] * 150
    assert listing_pages(world) == 2
    assert world.queue.counts() == {q.QUEUED: 160}


def test_an_artifact_listed_late_inside_the_overlap_is_found(world):
    world.github.offer(1, sha(1), T0 + timedelta(hours=5))
    world.discovery.poll()
    world.github.offer(2, sha(2), T0 + timedelta(hours=4, minutes=40))
    world.github.offer(3, sha(3), T0 + timedelta(hours=2))
    assert [o.enqueued.item.pr for o in world.discovery.poll() if o.enqueued] == [2]


def test_the_local_clock_plays_no_part_in_the_cursor(tmp_path):
    for clock in (T0 - timedelta(days=400), T0 + timedelta(days=400)):
        world = World(tmp_path / clock.strftime("%Y"), clock)
        world.github.offer(1, sha(1), T0)
        assert world.kinds(world.discovery.poll()) == ["queued"]
        world.github.offer(2, sha(2), T0 + timedelta(minutes=1))
        assert world.kinds(world.discovery.poll()) == ["queued"]


def test_duplicates_and_supersession(world):
    world.github.offer(1, A, T0)
    world.github.offer(1, A, T0 + timedelta(minutes=1), event="workflow_dispatch")
    assert world.kinds(world.discovery.poll()) == ["queued", "duplicate"]
    world.github.offer(1, B, T0 + timedelta(minutes=2))
    [outcome] = world.discovery.poll()
    assert outcome.kind == "queued"
    assert outcome.enqueued is not None and [item.head_sha for item in outcome.enqueued.superseded] == [A]


def test_a_request_for_an_old_head_is_dropped(world):
    world.github.offer(1, A, T0)
    world.github.pull(1, B, T0)
    [outcome] = world.discovery.poll()
    assert (outcome.kind, outcome.reason) == ("dropped", "#1 is at a newer head")


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"state": "closed"}, "closed"),
        ({"draft": True}, "a draft"),
        ({"head": {"sha": A, "ref": "topic-1", "repo": {"full_name": "someone/fork"}}}, "from another repository"),
    ],
)
def test_closed_draft_and_cross_repository_pull_requests_are_dropped(world, changes, reason):
    world.github.offer(1, A, T0)
    world.github.pulls[1].update(changes)
    [outcome] = world.discovery.poll()
    assert (outcome.kind, outcome.reason) == ("dropped", f"#1 is {reason}")


@pytest.mark.parametrize(
    ("request_changes", "plan_changes", "reason"),
    [
        ({}, {"decision": "success"}, "did not decide to review"),
        ({}, {"base_ref": "other"}, "another base branch"),
        ({"executor": "hosted"}, {}, "a hosted executor"),
        ({"run_id": "1"}, {}, "another run"),
        ({"repo": "example-owner/other"}, {}, "another repository"),
        ({"schema": 2}, {}, "unknown request schema"),
    ],
)
def test_requests_that_do_not_ask_for_this_review_are_dropped(world, request_changes, plan_changes, reason):
    world.github.offer(1, A, T0, request=request_changes, plan=plan_changes)
    [outcome] = world.discovery.poll()
    assert outcome.kind == "dropped" and reason in outcome.reason


def test_an_untrusted_workflow_or_a_late_base_change_is_refused(world):
    world.github.offer(1, A, T0, path=".github/workflows/other.yml@refs/heads/main")
    world.github.offer(2, B, T0 + timedelta(minutes=1))
    world.github.timeline[2] = [{"event": "base_ref_changed", "created_at": stamp(T0 + timedelta(hours=1))}]
    assert world.kinds(world.discovery.poll()) == ["untrusted", "untrusted"]


def comment(author: str, association: str, at: datetime, comment_id: int = 501, pr: int = 1) -> dict:
    return {
        "id": comment_id,
        "issue_url": f"https://api.example.test/repos/{SLUG}/issues/{pr}",
        "user": {"login": author},
        "body": "/oracle-review please",
        "author_association": association,
        "created_at": stamp(at),
    }


@pytest.mark.parametrize(
    ("association", "author", "delay", "kind"),
    [
        ("COLLABORATOR", "example-dev", -5, "queued"),
        ("OWNER", "example-dev", 1, "queued"),
        ("CONTRIBUTOR", "example-dev", -5, "untrusted"),
        ("COLLABORATOR", "someone-else", -5, "untrusted"),
        ("COLLABORATOR", "example-dev", 10, "untrusted"),
    ],
)
@pytest.mark.parametrize("by_id", [True, False])
def test_comment_runs_are_checked_against_the_comment_itself(world, association, author, delay, kind, by_id):
    world.github.offer(1, A, T0, event="issue_comment", request={"comment_id": 501} if by_id else {})
    world.github.comments[1] = [comment(author, association, T0 - timedelta(minutes=1) + timedelta(minutes=delay))]
    [outcome] = world.discovery.poll()
    assert outcome.kind == kind


def test_a_named_comment_on_another_pull_request_is_refused(world):
    world.github.offer(1, A, T0, event="issue_comment", request={"comment_id": 501})
    world.github.comments[2] = [comment("example-dev", "OWNER", T0 - timedelta(minutes=5), pr=2)]
    [outcome] = world.discovery.poll()
    assert outcome.kind == "untrusted"


def test_the_commenter_is_the_run_actor_even_after_someone_else_reruns_it(world):
    world.github.offer(1, A, T0, event="issue_comment", triggering_actor={"login": "maintainer"})
    world.github.comments[1] = [comment("example-dev", "COLLABORATOR", T0 - timedelta(minutes=5))]
    [outcome] = world.discovery.poll()
    assert outcome.kind == "queued"


def test_the_newest_command_by_the_actor_decides(world):
    world.github.offer(1, A, T0, event="issue_comment")
    world.github.comments[1] = [
        comment("example-dev", "OWNER", T0 - timedelta(hours=3)),
        comment("example-dev", "CONTRIBUTOR", T0 - timedelta(minutes=2)),
    ]
    [outcome] = world.discovery.poll()
    assert outcome.kind == "untrusted"


def test_a_comment_run_whose_code_is_not_on_the_base_branch_is_refused(world):
    world.github.offer(1, A, T0, event="workflow_dispatch", head_sha=B)
    [outcome] = world.discovery.poll()
    assert outcome.kind == "untrusted"


def test_a_missing_engine_version_or_build_is_held_with_a_status_until_installed(world):
    world.github.offer(1, A, T0, request={"engine_version": "0.2.0"})
    world.github.offer(2, B, T0 + timedelta(minutes=1), request={"engine_sha256": "d" * 64})
    assert world.kinds(world.discovery.poll()) == ["held", "held"]
    assert [row.payload for row in world.outbox.open_rows()] == [
        {"sha": A, "state": "pending", "context": "oracle-verdict", "description": "held: engine 0.2.0 not installed on the reviewer host"},
        {"sha": B, "state": "pending", "context": "oracle-verdict", "description": "held: engine 0.1.0 (this build) not installed on the reviewer host"},
    ]  # fmt: skip
    released = world.queue.release_held({"0.1.0": "d" * 64}, T0)
    assert [item.pr for item in released] == [2]


def test_the_status_context_comes_from_the_service_configuration(tmp_path):
    world = World(tmp_path, context="review-gate")
    world.github.offer(1, A, T0, plan={"status_context": "something-else"})
    world.discovery.poll()
    assert [row.payload["context"] for row in world.outbox.open_rows()] == ["review-gate"]


def test_queued_requests_get_a_status_with_their_position_and_proof_uses_the_local_context(world):
    world.github.offer(1, A, T0)
    world.github.offer(2, B, T0 + timedelta(minutes=1), request={"executor": "proof"})
    world.discovery.poll()
    rows = world.outbox.open_rows()
    assert [(row.payload["context"], row.payload["description"]) for row in rows] == [
        ("oracle-verdict", "queued locally (position 1)"),
        ("oracle-verdict-local", "queued locally (position 2)"),
    ]


def test_request_files_are_stored_for_the_wrapper(world, tmp_path):
    world.github.offer(1, A, T0)
    [outcome] = world.discovery.poll()
    assert outcome.enqueued is not None
    directory = world.discovery.request_dir(1, A, outcome.enqueued.item.plan_run_id)
    assert directory.parent == tmp_path / "requests"
    assert sorted(path.name for path in directory.iterdir()) == ["brief.md", "diff.patch", "plan.json", "request.json"]
    assert stat.S_IMODE((directory / "plan.json").stat().st_mode) == 0o644
    assert json.loads((directory / "request.json").read_text())["pr"] == 1


def test_a_passing_failure_is_retried_on_the_next_poll(world):
    artifact = world.github.offer(1, A, T0)
    world.github.fail_downloads[artifact] = 1
    assert world.kinds(world.discovery.poll()) == ["error"]
    assert world.kinds(world.discovery.poll()) == ["queued"]


def test_an_artifact_that_keeps_failing_is_dropped_after_three_tries_and_an_hour_and_frees_the_cursor(world):
    stuck = world.github.offer(1, A, T0)
    world.github.fail_downloads[stuck] = 99
    assert world.kinds(world.discovery.poll()) == ["error"]
    assert world.kinds(world.discovery.poll()) == ["error"]
    world.now = T0 + timedelta(hours=1)
    [dropped] = world.discovery.poll()
    assert dropped.kind == "dropped" and dropped.reason.startswith("gave up after 3 tries")
    world.github.offer(2, B, T0 + timedelta(hours=3))
    assert world.kinds(world.discovery.poll()) == ["queued"]
    world.github.calls.clear()
    world.discovery.poll()
    assert f"download {stuck}" not in world.github.calls


def test_a_short_outage_does_not_drop_a_request(world):
    artifact = world.github.offer(1, A, T0)
    world.github.fail_downloads[artifact] = 5
    for minute in range(5):
        world.now = T0 + timedelta(minutes=minute)
        assert world.kinds(world.discovery.poll()) == ["error"]
    world.now = T0 + timedelta(minutes=5)
    assert world.kinds(world.discovery.poll()) == ["queued"]


def test_an_artifact_that_fails_once_in_an_hour_is_not_dropped(world):
    stuck = world.github.offer(1, A, T0)
    world.github.fail_downloads[stuck] = 1
    assert world.kinds(world.discovery.poll()) == ["error"]
    world.now = T0 + timedelta(hours=1)
    assert world.kinds(world.discovery.poll()) == ["queued"]


def test_a_listing_too_long_to_read_fully_is_an_error_not_a_partial_poll(world, monkeypatch):
    monkeypatch.setattr("ship_no_ship_service.discovery.MAX_PAGES", 2)
    for n in range(1, 202):
        world.github.offer(n, sha(n), T0 + timedelta(minutes=n))
    with pytest.raises(DiscoveryError, match="more than 200"):
        world.discovery.poll()
    assert world.queue.counts() == {}


def test_a_fork_run_is_refused_before_its_artifact_is_downloaded(world):
    artifact = world.github.offer(1, A, T0, path=".github/workflows/other.yml@refs/heads/main")
    world.github.files[artifact]["request.json"] = b"[]"
    assert world.kinds(world.discovery.poll()) == ["untrusted"]
    assert f"download {artifact}" not in world.github.calls


@pytest.mark.parametrize("content", [b"[]", b"null", b"7", b'"text"', b"{bad"])
def test_a_malformed_request_from_a_trusted_run_is_dropped_and_later_requests_still_queue(world, content):
    bad = world.github.offer(1, A, T0)
    world.github.files[bad]["request.json"] = content
    world.github.offer(2, B, T0 + timedelta(minutes=1))
    assert world.kinds(world.discovery.poll()) == ["dropped", "queued"]
    world.github.offer(3, sha(3), T0 + timedelta(minutes=2))
    assert world.kinds(world.discovery.poll()) == ["queued"]


@pytest.mark.parametrize(
    "changes",
    [
        {"pr": "1"},
        {"state_generation": -1},
        {"state_generation": "0"},
        {"engine_sha256": "short"},
        {"comment_id": "501"},
    ],
)
def test_request_fields_must_have_the_expected_types(world, changes):
    world.github.offer(1, A, T0, request=changes)
    [outcome] = world.discovery.poll()
    assert outcome.kind == "dropped"


def test_an_unexpected_failure_drops_only_that_artifact(world, monkeypatch):
    world.github.offer(1, A, T0)
    world.github.offer(2, B, T0 + timedelta(minutes=1))
    original = world.discovery._check_pull

    def explode(pr, head):
        if pr == 1:
            raise AttributeError("boom")
        return original(pr, head)

    monkeypatch.setattr(world.discovery, "_check_pull", explode)
    outcomes = world.discovery.poll()
    assert world.kinds(outcomes) == ["dropped", "queued"]
    assert outcomes[0].reason == "unexpected AttributeError: boom"


def test_a_pull_request_target_run_must_be_for_the_requested_pull_request(world):
    world.github.offer(1, A, T0, request={"pr": 2}, plan={"pr": 2})
    world.github.pull(2, A, T0)
    [outcome] = world.discovery.poll()
    assert outcome.kind == "untrusted"


def test_a_malformed_artifact_is_dropped_for_good(world, monkeypatch):
    artifact = world.github.offer(1, A, T0)

    def bad(artifact_id):
        raise ArtifactError("the request artifact holds an unexpected or oversize entry 'x'")

    monkeypatch.setattr(world.github, "artifact_files", bad)
    assert world.kinds(world.discovery.poll()) == ["dropped"]
    assert world.discovery.poll() == []
    assert artifact in [row[0] for row in world.queue.db.execute("SELECT artifact_id FROM seen")]


def test_the_installed_engine_is_described_by_the_engines_own_digest():
    import ship_no_ship
    from ship_no_ship.engine import executor
    from ship_no_ship_service.discovery import installed_engines

    assert installed_engines() == {ship_no_ship.__version__: executor.engine_sha256()}
