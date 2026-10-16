from __future__ import annotations

import copy
from typing import Any

import pytest
import yaml

from ship_no_ship.engine.policy import (
    DEFAULT_EXECUTOR,
    V1_REPOSITORY,
    Policy,
    PolicyError,
    parse_policy,
)

from .conftest import POLICY_PATH

pytestmark = [pytest.mark.unit, pytest.mark.fast]

REPOSITORY = {"base_branch": "main", "paths_manifest": "config/review-paths.txt", "bot_login": "review-bot"}


def _v1() -> dict[str, Any]:
    return yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))


def _v2(**repository: Any) -> dict[str, Any]:
    raw = _v1()
    del raw["bot_login"]
    raw["version"] = 2
    raw["repository"] = {**REPOSITORY, **repository}
    return raw


def test_a_version_1_policy_takes_the_benchbox_defaults(policy: Policy) -> None:
    assert policy.version == 1
    assert policy.repository == V1_REPOSITORY
    assert policy.repository.base_branch == "develop"
    assert policy.repository.base_ref == "refs/heads/develop"
    assert policy.repository.paths_manifest == ".github/soundness-paths.txt"
    assert policy.repository.workflows.verdict == ".github/workflows/oracle-verdict.yml"
    assert policy.repository.artifacts.state_prefix == "oracle-verdict-state-"
    assert policy.repository.slug == ""
    assert policy.executor == DEFAULT_EXECUTOR
    assert policy.executor.mode == "hosted"


def test_a_minimal_version_2_policy_names_its_branch_manifest_and_bot() -> None:
    policy = parse_policy(_v2())
    assert policy.version == 2
    assert policy.bot_login == "review-bot"
    assert policy.repository.base_branch == "main"
    assert policy.repository.base_ref == "refs/heads/main"
    assert policy.repository.paths_manifest == "config/review-paths.txt"
    assert policy.repository.workflows == V1_REPOSITORY.workflows
    assert policy.repository.artifacts == V1_REPOSITORY.artifacts
    assert policy.repository.heartbeat_context == "ship-no-ship/heartbeat"
    assert policy.executor == DEFAULT_EXECUTOR


def test_a_full_version_2_policy_overrides_every_name() -> None:
    raw = _v2(
        slug="octo-org/widgets",
        workflows={"verdict": ".github/workflows/verdict.yaml", "record": ".github/workflows/record.yml"},
        artifacts={"plan": "p", "request": "r", "state_prefix": "s-"},
        heartbeat_context="reviews/heartbeat",
    )
    raw["executor"] = {"mode": "proof", "proof_label": "local-proof"}
    policy = parse_policy(raw)
    assert policy.repository.slug == "octo-org/widgets"
    assert policy.repository.workflows.verdict == ".github/workflows/verdict.yaml"
    assert policy.repository.workflows.record == ".github/workflows/record.yml"
    assert (policy.repository.artifacts.plan, policy.repository.artifacts.request) == ("p", "r")
    assert policy.repository.artifacts.state_prefix == "s-"
    assert policy.repository.heartbeat_context == "reviews/heartbeat"
    assert (policy.executor.mode, policy.executor.proof_label) == ("proof", "local-proof")


def test_version_2_keeps_every_version_1_rule() -> None:
    v1 = parse_policy(_v1())
    v2 = parse_policy({**_v2(), "repository": {**REPOSITORY, "bot_login": "benchbox-oracle"}})
    for name in ("reviewers", "tiers", "classifier", "retry", "protocol", "max_attempts", "status_context"):
        assert getattr(v2, name) == getattr(v1, name), name


def _without(key: str) -> dict[str, Any]:
    raw = _v2()
    del raw["repository"][key]
    return raw


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({**_v1(), "version": True}, "version must be one of"),
        ({**_v1(), "version": "2"}, "version must be one of"),
        ({**_v1(), "repository": REPOSITORY}, "repository and executor need policy version 2"),
        ({**_v1(), "executor": {"mode": "local"}}, "repository and executor need policy version 2"),
        ({k: v for k, v in _v2().items() if k != "repository"}, "need a repository mapping"),
        ({**_v2(), "bot_login": "x"}, "set bot_login under repository"),
        (_without("base_branch"), "base_branch must be a branch name"),
        (_without("paths_manifest"), "paths_manifest must be a relative path"),
        (_without("bot_login"), "bot_login must be an App slug"),
        (_v2(base_branch="-main"), "base_branch must be a branch name"),
        (_v2(base_branch="a..b"), "base_branch must be a branch name"),
        (_v2(base_branch="main/"), "base_branch must be a branch name"),
        (_v2(base_branch="main.lock"), "base_branch must be a branch name"),
        (_v2(base_branch="has space"), "base_branch must be a branch name"),
        (_v2(paths_manifest="  "), "paths_manifest must be a relative path"),
        (_v2(slug="no-slash"), "slug must be owner/name"),
        (_v2(owner="x"), "repository keys must be among"),
        (_v2(workflows={"verdict": "verdict.yml"}), "workflows.verdict is not a valid name"),
        (_v2(workflows={"other": ".github/workflows/x.yml"}), "workflows keys must be among"),
        (_v2(artifacts={"state_prefix": "a b"}), "artifacts.state_prefix is not a valid name"),
        (_v2(heartbeat_context=""), "heartbeat_context must be a string"),
        ({**_v2(), "executor": {"mode": "cloud"}}, "executor.mode must be one of"),
        ({**_v2(), "executor": {"proof_label": ""}}, "proof_label must be a label name"),
        ({**_v2(), "executor": {"timeout": 1}}, "executor keys must be among"),
        ({**_v2(), "executor": {"stalled_after_hours": 0}}, "stalled_after_hours must be a positive"),
        ({**_v2(), "executor": {"stalled_after_hours": "24"}}, "stalled_after_hours must be a positive"),
    ],
)
def test_invalid_version_2_settings_are_rejected(raw: dict[str, Any], message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        parse_policy(copy.deepcopy(raw))


@pytest.mark.parametrize("version", [1, 2])
def test_unknown_top_level_keys_are_rejected(version: int) -> None:
    raw = _v1() if version == 1 else _v2()
    raw["reviewer"] = {}
    with pytest.raises(PolicyError, match=r"unknown policy keys: \['reviewer'\]"):
        parse_policy(raw)


@pytest.mark.parametrize("branch", ["refs/heads/main", "HEAD", "", "heads/../main"])
def test_ref_names_and_head_are_not_branch_names(branch: str) -> None:
    with pytest.raises(PolicyError, match="base_branch must be a branch name"):
        parse_policy(_v2(base_branch=branch))


@pytest.mark.parametrize("path", ["/etc/paths.txt", "../paths.txt", "config/../../x", "C:\\paths.txt", " a.txt"])
def test_the_manifest_must_be_a_relative_path_inside_the_repository(path: str) -> None:
    with pytest.raises(PolicyError, match="paths_manifest must be a relative path"):
        parse_policy(_v2(paths_manifest=path))


def test_the_stall_limit_defaults_to_a_day_and_can_be_set() -> None:
    assert parse_policy(_v2()).executor.stalled_after_hours == 24
    assert parse_policy({**_v2(), "executor": {"stalled_after_hours": 6}}).executor.stalled_after_hours == 6
