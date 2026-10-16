from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ship_no_ship.engine.paths import load_manifest
from ship_no_ship.engine.policy import Policy, load_policy

BENCHBOX_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "benchbox"
POLICY_PATH = BENCHBOX_ROOT / ".github" / "oracle-reviewers.yml"
MANIFEST_PATH = BENCHBOX_ROOT / ".github" / "soundness-paths.txt"

is_soundness_path = load_manifest(MANIFEST_PATH).matches


@pytest.fixture(scope="session")
def policy() -> Policy:
    return load_policy(POLICY_PATH)


WINDOWS_SKIP = pytest.mark.skip(
    reason="the oracle reviewer tooling runs on Linux Actions runners: it uses POSIX paths, process groups and shebang CLIs"
)


def pytest_collection_modifyitems(config, items):
    if sys.platform != "win32":
        return
    for item in items:
        if Path(__file__).parent in Path(str(item.path)).parents:
            item.add_marker(WINDOWS_SKIP)
