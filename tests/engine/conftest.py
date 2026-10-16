from __future__ import annotations

import fnmatch
import re
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from ship_no_ship.engine import cli
from ship_no_ship.engine.policy import Policy, load_policy

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "benchbox"
POLICY_PATH = FIXTURES / "oracle-reviewers.yml"
MANIFEST_PATH = FIXTURES / "soundness-paths.txt"


def _manifest_predicate(path: Path) -> Callable[[str], bool]:
    rules: dict[str, list[str]] = {"file": [], "glob": [], "prefix": [], "regex": []}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            kind, pattern = line.split("\t", 1)
            rules[kind].append(pattern)
    files = (*rules["file"], *rules["glob"])
    globs = tuple(rules["glob"])
    prefixes = tuple(rules["prefix"])
    regexes = tuple(re.compile(pattern) for pattern in rules["regex"])

    def matches(candidate: str) -> bool:
        normalized = candidate.strip().replace("\\", "/")
        if not normalized:
            return False
        return (
            any(regex.match(normalized) is not None for regex in regexes)
            or any(
                fnmatch.fnmatchcase(normalized, pattern)
                or ("/**/" in pattern and fnmatch.fnmatchcase(normalized, pattern.replace("/**/", "/")))
                for pattern in globs
            )
            or normalized in files
            or normalized.startswith(prefixes)
        )

    return matches


is_soundness_path = _manifest_predicate(MANIFEST_PATH)


@pytest.fixture(scope="session")
def policy() -> Policy:
    return load_policy(POLICY_PATH)


@pytest.fixture(autouse=True)
def soundness_predicate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_soundness_predicate", lambda: is_soundness_path)


WINDOWS_SKIP = pytest.mark.skip(
    reason="the oracle reviewer tooling runs on Linux Actions runners: it uses POSIX paths, process groups and shebang CLIs"
)


def pytest_collection_modifyitems(config, items):
    if sys.platform != "win32":
        return
    for item in items:
        if Path(__file__).parent in Path(str(item.path)).parents:
            item.add_marker(WINDOWS_SKIP)
