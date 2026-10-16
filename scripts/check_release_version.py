"""Check that a release tag matches the versions in the package metadata.

The release workflow runs this before it builds anything. It passes only when
the tag is ``v<version>``, both distributions declare that version, and the
service pins the engine to exactly that version, so the two wheels in a
release always install together. On success it prints the version.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TAG = re.compile(r"v(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:(?:a|b|rc)(?:0|[1-9]\d*))?)")
ENGINE = "packages/engine/pyproject.toml"
SERVICE = "packages/service/pyproject.toml"
ENGINE_NAME = "ship-no-ship"


def _project(root: Path, relative: str) -> dict:
    with (root / relative).open("rb") as handle:
        return tomllib.load(handle).get("project", {})


def check(tag: str, root: Path = ROOT) -> tuple[str | None, list[str]]:
    """Return the tag's version and every mismatch found; the version is None for a malformed tag."""
    match = TAG.fullmatch(tag)
    if match is None:
        return None, [f"tag {tag!r} is not v<major>.<minor>.<patch> with an optional a, b or rc suffix"]
    version = match["version"]
    engine = _project(root, ENGINE)
    service = _project(root, SERVICE)
    errors = []
    for relative, project in ((ENGINE, engine), (SERVICE, service)):
        if project.get("version") != version:
            errors.append(f"{relative}: version {project.get('version')!r} does not match tag {tag}")
    if engine.get("name") != ENGINE_NAME:
        errors.append(f"{ENGINE}: name {engine.get('name')!r} is not {ENGINE_NAME!r}")
    pins = [dep for dep in service.get("dependencies", []) if re.match(rf"{ENGINE_NAME}\b(?!-)", dep)]
    if pins != [f"{ENGINE_NAME}=={version}"]:
        errors.append(f"{SERVICE}: engine dependency {pins} is not ['{ENGINE_NAME}=={version}']")
    return version, errors


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check_release_version")
    parser.add_argument("tag", help="the release tag, for example v1.2.3")
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    args = parser.parse_args(argv)
    version, errors = check(args.tag, args.root)
    for error in errors:
        print(f"check_release_version: {error}", file=sys.stderr)
    if errors or version is None:
        return 1
    print(version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
