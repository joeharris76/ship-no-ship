from __future__ import annotations

import json
from pathlib import Path

import pytest

from ship_no_ship.engine.paths import ManifestError, Rule, load_manifest, parse_manifest

from .conftest import MANIFEST_PATH

pytestmark = [pytest.mark.unit, pytest.mark.fast]

PARITY = Path(__file__).resolve().parents[1] / "fixtures" / "benchbox" / "soundness_path_parity.json"
MANIFEST = "\n".join(
    [
        "# soundness paths",
        "file\tsrc/exact.py",
        "glob\tdata/**/*.override.json",
        "glob\tsrc/*_rules.yaml",
        "prefix\tsrc/core/",
        "regex\t" + r"^lib/(?:.+/)?validation\.py$",
        "",
    ]
)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/exact.py", True),
        ("src/exact.pyc", False),
        ("data/a/b/c.override.json", True),
        ("data/c.override.json", True),
        ("data/c.json", False),
        ("src/tier_rules.yaml", True),
        ("src/core/x/y.py", True),
        ("src/corex.py", False),
        ("lib/validation.py", True),
        ("lib/a/b/validation.py", True),
        ("lib/validation.pyc", False),
        ("src\\core\\x.py", True),
        ("  src/exact.py  ", True),
        ("", False),
        ("   ", False),
    ],
)
def test_each_rule_kind_matches_as_documented(path: str, expected: bool) -> None:
    assert parse_manifest(MANIFEST).matches(path) is expected


def test_rules_keep_their_order_and_kind() -> None:
    manifest = parse_manifest(MANIFEST)
    assert manifest.rules[0] == Rule("file", "src/exact.py")
    assert [rule.kind for rule in manifest.rules] == ["file", "glob", "glob", "prefix", "regex"]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("file src/x.py", "expected kind<TAB>pattern"),
        ("dir\tsrc/", "unknown rule kind 'dir'"),
        ("prefix\tsrc", "prefix must end with '/'"),
        ("regex\t(unclosed", "invalid regex"),
        ("# only a comment\n\n", "has no rules"),
    ],
)
def test_malformed_manifests_are_rejected_with_their_line(text: str, message: str) -> None:
    with pytest.raises(ManifestError, match=message):
        parse_manifest(text, "m.txt")


def test_errors_name_the_file_and_line() -> None:
    with pytest.raises(ManifestError, match=r"^m\.txt:3: "):
        parse_manifest("file\ta\n# note\nbogus\tb\n", "m.txt")


def test_a_missing_manifest_is_a_manifest_error(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="cannot be read"):
        load_manifest(tmp_path / "absent.txt")


def test_the_benchbox_manifest_agrees_with_benchbox_predicate() -> None:
    expected = json.loads(PARITY.read_text(encoding="utf-8"))
    manifest = load_manifest(MANIFEST_PATH)
    assert {path: manifest.matches(path) for path in expected} == expected
    assert sum(expected.values()) > 100 and len(expected) - sum(expected.values()) > 100
