"""Verify a pure-Python wheel before trusting it.

A repository that vendors a ship-no-ship wheel runs this check on the wheel it
commits, so a tampered or unexpected wheel fails before anything installs it.
The script uses only the standard library so an adopter can copy it as is.

The wheel passes only if all of these hold:

- the file's SHA-256 equals the expected value;
- the file name is ``<name>-<version>-py3-none-any.whl`` and, when given, the
  version equals the expected version;
- every zip member has a plain relative ASCII name, is not a symbolic link, is
  not a duplicate (including a case-only duplicate), and is within the size
  limits;
- every member sits under one of the expected package directories or the
  wheel's own ``.dist-info`` directory, so there is no ``.data`` directory, no
  stray top-level module and no second ``.dist-info``;
- no member is a ``.pth`` file, a compiled extension or compiled bytecode;
- ``RECORD`` lists every member exactly once and nothing else, and each
  entry other than ``RECORD`` itself has a SHA-256 hash and size that match;
- ``WHEEL`` declares a pure-Python ``py3-none-any`` wheel and ``METADATA``
  names the same distribution and version as the file name;
- ``entry_points.txt`` declares exactly the expected console scripts and no
  other entry-point group.

Exit status is 0 when the wheel passes, 1 when it fails and 2 for a usage
error.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import hashlib
import io
import re
import stat
import sys
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from email.parser import HeaderParser
from pathlib import Path

MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 2000
SAFE_NAME = re.compile(r"[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*")
PACKAGE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
FORBIDDEN_SUFFIXES = (".pth", ".so", ".pyd", ".dylib", ".dll", ".pyc", ".pyo", ".exe")
EXPECTED_TAG = "py3-none-any"


class WheelError(Exception):
    """The wheel cannot be checked any further."""


@dataclass(frozen=True)
class Expectation:
    sha256: str
    packages: tuple[str, ...]
    console_scripts: frozenset[str]
    version: str | None = None


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def normalize_entry_point(text: str) -> str:
    name, sep, target = text.partition("=")
    if not sep or not name.strip() or not target.strip():
        raise ValueError(f"console script {text!r} is not NAME=MODULE:FUNCTION")
    return name.strip() + "=" + "".join(target.split())


def record_digest(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_filename(filename: str) -> tuple[str, str]:
    if not filename.endswith(".whl"):
        raise WheelError(f"{filename}: not a .whl file")
    parts = filename[: -len(".whl")].split("-")
    if len(parts) != 5:
        raise WheelError(f"{filename}: expected <name>-<version>-py3-none-any.whl")
    name, version, *tags = parts
    if "-".join(tags) != EXPECTED_TAG:
        raise WheelError(f"{filename}: tag {'-'.join(tags)} is not {EXPECTED_TAG}")
    if not PACKAGE_NAME.fullmatch(name) or not version:
        raise WheelError(f"{filename}: malformed distribution name or version")
    return name, version


def _member_errors(info: zipfile.ZipInfo) -> list[str]:
    name = info.filename
    errors = []
    if not SAFE_NAME.fullmatch(name) or any(part in {".", ".."} for part in name.split("/")):
        errors.append(f"{name!r}: unsafe member name")
    if stat.S_ISLNK(info.external_attr >> 16):
        errors.append(f"{name}: symbolic link")
    if info.file_size > MAX_MEMBER_BYTES:
        errors.append(f"{name}: {info.file_size} bytes exceeds the {MAX_MEMBER_BYTES}-byte limit")
    if name.lower().endswith(FORBIDDEN_SUFFIXES):
        errors.append(f"{name}: forbidden file type")
    return errors


def _read_members(archive: zipfile.ZipFile) -> tuple[dict[str, bytes], list[str]]:
    infos = archive.infolist()
    if len(infos) > MAX_MEMBERS:
        raise WheelError(f"{len(infos)} members exceeds the {MAX_MEMBERS}-member limit")
    errors: list[str] = []
    seen: set[str] = set()
    total = 0
    for info in infos:
        errors.extend(_member_errors(info))
        folded = info.filename.lower()
        if folded in seen:
            errors.append(f"{info.filename}: duplicate member")
        seen.add(folded)
        total += info.file_size
    if total > MAX_TOTAL_BYTES:
        raise WheelError(f"{total} uncompressed bytes exceeds the {MAX_TOTAL_BYTES}-byte limit")
    if errors:
        return {}, errors
    members = {}
    for info in infos:
        with archive.open(info) as handle:
            data = handle.read(MAX_MEMBER_BYTES + 1)
        if len(data) != info.file_size:
            raise WheelError(f"{info.filename}: size does not match the zip directory")
        members[info.filename] = data
    return members, []


def _check_scope(members: dict[str, bytes], packages: Sequence[str], dist_info: str) -> list[str]:
    prefixes = tuple(f"{package}/" for package in packages) + (f"{dist_info}/",)
    return [f"{name}: outside {', '.join(prefixes)}" for name in members if not name.startswith(prefixes)]


def _check_record(members: dict[str, bytes], dist_info: str) -> list[str]:
    record_name = f"{dist_info}/RECORD"
    if record_name not in members:
        return [f"{record_name}: missing"]
    try:
        rows = list(csv.reader(io.StringIO(members[record_name].decode("utf-8"), newline="")))
    except (UnicodeDecodeError, csv.Error) as exc:
        return [f"{record_name}: unreadable ({exc})"]
    errors = []
    listed: set[str] = set()
    for row in rows:
        if not row:
            continue
        if len(row) != 3:
            errors.append(f"{record_name}: malformed row {row!r}")
            continue
        path, digest, size = row
        if path in listed:
            errors.append(f"{path}: listed twice in RECORD")
        listed.add(path)
        if path not in members:
            errors.append(f"{path}: listed in RECORD but not in the wheel")
        elif path == record_name:
            if digest or size:
                errors.append(f"{path}: RECORD must not hash itself")
        elif not digest.startswith("sha256="):
            errors.append(f"{path}: RECORD hash is not SHA-256")
        elif digest != record_digest(members[path]):
            errors.append(f"{path}: RECORD hash does not match")
        elif size != str(len(members[path])):
            errors.append(f"{path}: RECORD size does not match")
    errors.extend(f"{name}: not listed in RECORD" for name in members if name not in listed)
    return errors


def _headers(members: dict[str, bytes], name: str) -> dict[str, list[str]] | None:
    if name not in members:
        return None
    message = HeaderParser().parsestr(members[name].decode("utf-8", errors="replace"))
    headers: dict[str, list[str]] = {}
    for key, value in message.items():
        headers.setdefault(key.lower(), []).append(value.strip())
    return headers


def _check_metadata(members: dict[str, bytes], dist_info: str, name: str, version: str) -> list[str]:
    errors = []
    wheel = _headers(members, f"{dist_info}/WHEEL")
    if wheel is None:
        errors.append(f"{dist_info}/WHEEL: missing")
    else:
        if wheel.get("root-is-purelib") != ["true"]:
            errors.append(f"{dist_info}/WHEEL: Root-Is-Purelib is not true")
        if wheel.get("tag") != [EXPECTED_TAG]:
            errors.append(f"{dist_info}/WHEEL: tags {wheel.get('tag')} are not [{EXPECTED_TAG!r}]")
    metadata = _headers(members, f"{dist_info}/METADATA")
    if metadata is None:
        errors.append(f"{dist_info}/METADATA: missing")
    else:
        if [normalize_name(value) for value in metadata.get("name", [])] != [normalize_name(name)]:
            errors.append(f"{dist_info}/METADATA: Name {metadata.get('name')} does not match the file name")
        if metadata.get("version") != [version]:
            errors.append(f"{dist_info}/METADATA: Version {metadata.get('version')} does not match the file name")
    return errors


class _EntryPointParser(configparser.ConfigParser):
    """Keep entry-point names as written; the default parser lower-cases them."""

    def optionxform(self, optionstr: str) -> str:
        return optionstr


def _check_entry_points(members: dict[str, bytes], dist_info: str, expected: frozenset[str]) -> list[str]:
    path = f"{dist_info}/entry_points.txt"
    if path not in members:
        return [f"{path}: missing; expected {sorted(expected)}"] if expected else []
    parser = _EntryPointParser(interpolation=None, delimiters=("=",))
    try:
        parser.read_string(members[path].decode("utf-8"))
    except (UnicodeDecodeError, configparser.Error) as exc:
        return [f"{path}: unreadable ({exc})"]
    errors = [
        f"{path}: unexpected entry-point group [{group}]" for group in parser.sections() if group != "console_scripts"
    ]
    found: set[str] = set()
    if parser.has_section("console_scripts"):
        found = {normalize_entry_point(f"{key}={value}") for key, value in parser.items("console_scripts")}
    errors.extend(f"{path}: unexpected console script {item}" for item in sorted(found - expected))
    errors.extend(f"{path}: missing console script {item}" for item in sorted(expected - found))
    return errors


def verify_wheel(path: Path, expected: Expectation) -> list[str]:
    """Return every problem found in the wheel at ``path``; an empty list means it passed."""
    actual = file_sha256(path)
    if actual != expected.sha256.lower():
        return [f"{path.name}: SHA-256 {actual} does not match the expected {expected.sha256.lower()}"]
    try:
        name, version = parse_filename(path.name)
        if expected.version is not None and version != expected.version:
            return [f"{path.name}: version {version} is not the expected {expected.version}"]
        with zipfile.ZipFile(path) as archive:
            members, errors = _read_members(archive)
    except WheelError as exc:
        return [str(exc)]
    except (zipfile.BadZipFile, OSError, EOFError) as exc:
        return [f"{path.name}: unreadable zip ({exc})"]
    if errors:
        return errors
    dist_info = f"{name}-{version}.dist-info"
    return [
        *_check_scope(members, expected.packages, dist_info),
        *_check_record(members, dist_info),
        *_check_metadata(members, dist_info, name, version),
        *_check_entry_points(members, dist_info, expected.console_scripts),
    ]


def _sha256_arg(value: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise argparse.ArgumentTypeError("expected 64 hexadecimal characters")
    return value.lower()


def _package_arg(value: str) -> str:
    if not PACKAGE_NAME.fullmatch(value):
        raise argparse.ArgumentTypeError("expected a top-level import package name")
    return value


def _console_script_arg(value: str) -> str:
    try:
        return normalize_entry_point(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verify_wheel", description="Verify a pure-Python wheel before trusting it.")
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--sha256", required=True, type=_sha256_arg, help="expected SHA-256 of the wheel file")
    parser.add_argument(
        "--package",
        dest="packages",
        action="append",
        required=True,
        type=_package_arg,
        help="top-level import package the wheel may contain (repeatable)",
    )
    parser.add_argument(
        "--console-script",
        dest="console_scripts",
        action="append",
        default=[],
        type=_console_script_arg,
        help="expected console script as NAME=MODULE:FUNCTION (repeatable; none means none allowed)",
    )
    parser.add_argument("--version", dest="expected_version", help="expected distribution version")
    args = parser.parse_args(argv)
    expectation = Expectation(
        sha256=args.sha256,
        packages=tuple(args.packages),
        console_scripts=frozenset(args.console_scripts),
        version=args.expected_version,
    )
    if not args.wheel.is_file():
        print(f"verify_wheel: {args.wheel}: not a file", file=sys.stderr)
        return 1
    errors = verify_wheel(args.wheel, expectation)
    for error in errors:
        print(f"verify_wheel: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"verify_wheel: {args.wheel.name} OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
