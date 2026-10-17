"""Verify a pure-Python wheel before trusting it.

A repository that vendors a ship-no-ship wheel runs this check on the wheel it
commits, so a tampered or unexpected wheel fails before anything installs it.
The script uses only the standard library so an adopter can copy it as is.

The wheel passes only if all of these hold:

- the file's SHA-256 equals the expected value;
- the file name is ``<name>-<version>-py3-none-any.whl`` and, when given, the
  version equals the expected version;
- the zip has no leading, trailing or unreferenced bytes: the first local
  header is at offset 0, each entry's data runs straight into the next local
  header, the last entry ends where the central directory starts, the central
  directory ends at the end record (or its zip64 record), and the end record
  ends the file with no archive comment; every local header matches its
  central directory entry; no entry has a file comment or any extra field
  other than zip64, since an unknown extra field can hide arbitrary bytes, even
  a complete second zip; a zip64 extra field appears at most once per header,
  only when a size or offset in that header holds the zip64 sentinel, and is
  exactly 8 bytes for each such field, so it cannot hide bytes either; and no
  entry is encrypted or uses an unknown compression;
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
  names the same distribution and version as the file name and declares
  exactly the expected ``Requires-Dist`` entries (none unless given);
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
import struct
import sys
import tomllib
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
LOCAL_HEADER = struct.Struct("<4sHHHHHIIIHH")
CENTRAL_HEADER = struct.Struct("<4sHHHHHHIIIHHHHHII")
DATA_DESCRIPTOR_SIG = b"PK\x07\x08"
EOCD = struct.Struct("<4sHHHHIIH")
ZIP64_LOCATOR = struct.Struct("<4sIQI")
ZIP64_EOCD = struct.Struct("<4sQHHIIQQQQ")
ZIP64_EXTRA_ID = 0x0001
ZIP64_SENTINEL = 0xFFFFFFFF
ZIP64_DISK_SENTINEL = 0xFFFF


class WheelError(Exception):
    """The wheel cannot be checked any further."""


@dataclass(frozen=True)
class Expectation:
    sha256: str
    packages: tuple[str, ...]
    console_scripts: frozenset[str]
    version: str | None = None
    requires_dist: tuple[str, ...] = ()


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def normalize_entry_point(text: str) -> str:
    name, sep, target = text.partition("=")
    if not sep or not name.strip() or not target.strip():
        raise ValueError(f"console script {text!r} is not NAME=MODULE:FUNCTION")
    return name.strip() + "=" + "".join(target.split())


def normalize_requirement(text: str) -> str:
    """Return a comparable form of a ``Requires-Dist`` value.

    Build backends rewrite requirements (case, spacing, quote style), so both
    sides are compared without whitespace, in lower case, with single quotes
    and with the distribution name normalized.
    """
    compact = "".join(text.split()).replace('"', "'").lower()
    match = re.match(r"[a-z0-9][a-z0-9._-]*", compact)
    if match is None:
        raise ValueError(f"requirement {text!r} does not start with a distribution name")
    return re.sub(r"[-_.]+", "-", match.group()) + compact[match.end() :]


def requires_dist_from_pyproject(path: Path) -> list[str]:
    """Return the ``Requires-Dist`` entries a ``pyproject.toml`` declares, extras included."""
    with path.open("rb") as handle:
        project = tomllib.load(handle).get("project", {})
    entries = list(project.get("dependencies", []))
    for extra, requirements in project.get("optional-dependencies", {}).items():
        marker = f"extra == '{normalize_name(extra).replace('_', '-')}'"
        for requirement in requirements:
            base, sep, existing = requirement.partition(";")
            entries.append(f"{base}; ({existing.strip()}) and {marker}" if sep else f"{requirement}; {marker}")
    return entries


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


def _end_of_central_directory(raw: bytes, count: int) -> tuple[int, list[str]]:
    """Return where the central directory starts, checking it is the only thing between the entries and the end."""
    start = max(0, len(raw) - EOCD.size - 0xFFFF)
    pos = raw.rfind(b"PK\x05\x06", start)
    while pos != -1 and not (
        pos + EOCD.size <= len(raw) and pos + EOCD.size + struct.unpack_from("<H", raw, pos + 20)[0] == len(raw)
    ):
        pos = raw.rfind(b"PK\x05\x06", start, pos)
    if pos == -1:
        return 0, ["no end-of-central-directory record ends the file: trailing bytes or not a zip"]
    _, disk, cd_disk, on_disk, total, cd_size, cd_offset, comment_len = EOCD.unpack_from(raw, pos)
    if comment_len:
        return 0, [f"the archive has a {comment_len}-byte comment"]
    cd_end = pos
    if pos >= ZIP64_LOCATOR.size and raw[pos - ZIP64_LOCATOR.size : pos - ZIP64_LOCATOR.size + 4] == b"PK\x06\x07":
        locator = pos - ZIP64_LOCATOR.size
        _, locator_disk, record, disks = ZIP64_LOCATOR.unpack_from(raw, locator)
        if locator_disk != 0 or disks != 1 or record + ZIP64_EOCD.size > locator:
            return 0, ["malformed zip64 end-of-central-directory locator"]
        sig, size, _, _, disk, cd_disk, on_disk, total, cd_size, cd_offset = ZIP64_EOCD.unpack_from(raw, record)
        if sig != b"PK\x06\x06" or record + 12 + size != locator:
            return 0, ["zip64 end-of-central-directory record is not directly before its locator"]
        cd_end = record
    if disk != 0 or cd_disk != 0 or on_disk != total or total != count:
        return 0, ["end-of-central-directory counts do not match the central directory"]
    if cd_offset + cd_size != cd_end:
        return 0, ["the central directory is not where the end record says: the file has leading or extra bytes"]
    return cd_offset, []


def _extra_fields(extra: bytes) -> list[tuple[int, bytes]] | None:
    """Return the extra fields as (ID, data) pairs, or None when the fields do not exactly fill ``extra``."""
    fields, offset = [], 0
    while offset + 4 <= len(extra):
        header, length = struct.unpack_from("<HH", extra, offset)
        fields.append((header, extra[offset + 4 : offset + 4 + length]))
        offset += 4 + length
    return fields if offset == len(extra) else None


def _extra_errors(name: str, where: str, extra: bytes, sentinels: Sequence[bool]) -> list[str]:
    """Check one header's extra fields.

    ``sentinels`` says, in the order the zip64 extra field stores them (uncompressed size, compressed size,
    local header offset, disk start), which of the header's fields hold the zip64 sentinel. A zip64 extra field
    must hold exactly one 8-byte value for each of those fields and must be absent when there are none, so it
    cannot carry extra bytes.
    """
    fields = _extra_fields(extra)
    if fields is None:
        return [f"{name}: malformed {where} extra field"]
    ids = [header for header, _ in fields]
    errors = [
        f"{name}: duplicate {where} extra field 0x{header:04x}"
        for header in dict.fromkeys(ids)
        if ids.count(header) > 1
    ]
    errors.extend(
        f"{name}: unexpected {where} extra field 0x{header:04x}"
        for header in dict.fromkeys(ids)
        if header != ZIP64_EXTRA_ID
    )
    zip64 = [data for header, data in fields if header == ZIP64_EXTRA_ID]
    needed = 8 * sum(sentinels)
    if not zip64:
        if needed:
            errors.append(f"{name}: {where} header holds a zip64 sentinel but has no zip64 extra field")
    elif not needed:
        errors.append(f"{name}: unneeded {where} zip64 extra field: no size or offset holds the zip64 sentinel")
    elif len(zip64) == 1 and len(zip64[0]) != needed:
        errors.append(f"{name}: {where} zip64 extra field is {len(zip64[0])} bytes, expected {needed}")
    return errors


def _zip64_local_sizes(extra: bytes, file_size: int, compress_size: int) -> tuple[int, int]:
    """Return the local sizes, reading each one that holds the sentinel from the (already checked) zip64 field."""
    values = next((data for header, data in _extra_fields(extra) or [] if header == ZIP64_EXTRA_ID), b"")
    sizes, position = [], 0
    for field in (file_size, compress_size):
        if field == ZIP64_SENTINEL:
            sizes.append(struct.unpack_from("<Q", values, position)[0])
            position += 8
        else:
            sizes.append(field)
    return sizes[0], sizes[1]


def _central_entries(raw: bytes, cd_offset: int, count: int) -> tuple[list[tuple[tuple[bool, ...], bytes]], list[str]]:
    """Return each central directory entry's zip64 sentinel flags and raw extra field, in directory order.

    ``zipfile`` replaces sentinel sizes and offsets with their zip64 values, so the raw entries are read here.
    """
    entries, position = [], cd_offset
    for _ in range(count):
        sig, *_, compress_size, file_size, name_len, extra_len, comment_len, disk, _, _, offset = (
            CENTRAL_HEADER.unpack_from(raw, position)
        )
        if sig != b"PK\x01\x02":
            return [], [f"no central directory entry at offset {position}"]
        extra_start = position + CENTRAL_HEADER.size + name_len
        sentinels = (
            file_size == ZIP64_SENTINEL,
            compress_size == ZIP64_SENTINEL,
            offset == ZIP64_SENTINEL,
            disk == ZIP64_DISK_SENTINEL,
        )
        entries.append((sentinels, raw[extra_start : extra_start + extra_len]))
        position = extra_start + extra_len + comment_len
    return entries, []


def _entry_end(raw: bytes, info: zipfile.ZipInfo, central: tuple[tuple[bool, ...], bytes]) -> tuple[int, list[str]]:
    """Check one local header against its central entry and return where its data (and descriptor) end."""
    offset = info.header_offset
    sig, _, flags, method, _, _, crc, compress_size, file_size, name_len, extra_len = LOCAL_HEADER.unpack_from(
        raw, offset
    )
    if sig != b"PK\x03\x04":
        return 0, [f"{info.filename}: no local header at offset {offset}"]
    name_start = offset + LOCAL_HEADER.size
    name = raw[name_start : name_start + name_len].decode("utf-8" if flags & 0x800 else "cp437", errors="replace")
    extra = raw[name_start + name_len : name_start + name_len + extra_len]
    local_sentinels = (file_size == ZIP64_SENTINEL, compress_size == ZIP64_SENTINEL)
    central_sentinels, central_extra = central
    errors = [
        *_extra_errors(info.filename, "local", extra, local_sentinels),
        *_extra_errors(info.filename, "central", central_extra, central_sentinels),
    ]
    if info.comment:
        errors.append(f"{info.filename}: has a file comment")
    if errors:
        return 0, errors
    if name != info.orig_filename:
        errors.append(f"{info.filename}: local header names {name!r}")
    if flags != info.flag_bits or method != info.compress_type:
        errors.append(f"{info.filename}: local header flags or compression differ from the central directory")
    if flags & 0x1:
        errors.append(f"{info.filename}: encrypted")
    if method not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
        errors.append(f"{info.filename}: unsupported compression method {method}")
    end = name_start + name_len + extra_len + info.compress_size
    if flags & 0x8:
        if raw[end : end + 4] == DATA_DESCRIPTOR_SIG:
            end += 4
        descriptor = struct.Struct("<IQQ" if any(local_sentinels) else "<III")
        crc, compress_size, file_size = descriptor.unpack_from(raw, end)
        end += descriptor.size
    else:
        file_size, compress_size = _zip64_local_sizes(extra, file_size, compress_size)
    if (crc, compress_size, file_size) != (info.CRC, info.compress_size, info.file_size):
        errors.append(f"{info.filename}: local CRC or sizes differ from the central directory")
    return end, errors


def check_layout(raw: bytes, infos: Sequence[zipfile.ZipInfo]) -> list[str]:
    """Check that the zip's entries and directories account for every byte of the file."""
    try:
        cd_offset, errors = _end_of_central_directory(raw, len(infos))
        if errors:
            return errors
        central, errors = _central_entries(raw, cd_offset, len(infos))
        if errors:
            return errors
        expected = 0
        for info, entry in sorted(zip(infos, central), key=lambda pair: pair[0].header_offset):
            if info.header_offset != expected:
                gap = "unreferenced bytes" if info.header_offset > expected else "overlapping entries"
                return [f"{info.filename}: local header at {info.header_offset}, expected {expected} ({gap})"]
            expected, errors = _entry_end(raw, info, entry)
            if errors:
                return errors
        if expected != cd_offset:
            return [f"{cd_offset - expected} unreferenced bytes before the central directory"]
    except struct.error as exc:
        return [f"truncated zip structure ({exc})"]
    return []


def _read_members(archive: zipfile.ZipFile, raw: bytes) -> tuple[dict[str, bytes], list[str]]:
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
    errors = check_layout(raw, infos)
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


def _check_metadata(
    members: dict[str, bytes], dist_info: str, name: str, version: str, requires_dist: Sequence[str]
) -> list[str]:
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
        expected = sorted(normalize_requirement(item) for item in requires_dist)
        try:
            found = sorted(normalize_requirement(item) for item in metadata.get("requires-dist", []))
        except ValueError as exc:
            errors.append(f"{dist_info}/METADATA: {exc}")
        else:
            errors.extend(
                f"{dist_info}/METADATA: unexpected Requires-Dist {item}" for item in found if item not in expected
            )
            errors.extend(
                f"{dist_info}/METADATA: missing Requires-Dist {item}" for item in expected if item not in found
            )
            if not errors and found != expected:
                errors.append(f"{dist_info}/METADATA: Requires-Dist {found} is not {expected}")
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
        for key, value in parser.items("console_scripts"):
            try:
                found.add(normalize_entry_point(f"{key}={value}"))
            except ValueError as exc:
                errors.append(f"{path}: {exc}")
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
        if path.stat().st_size > MAX_TOTAL_BYTES:
            raise WheelError(f"{path.name}: file exceeds the {MAX_TOTAL_BYTES}-byte limit")
        raw = path.read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members, errors = _read_members(archive, raw)
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
        *_check_metadata(members, dist_info, name, version, expected.requires_dist),
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


def _requirement_arg(value: str) -> str:
    try:
        normalize_requirement(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value


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
    parser.add_argument(
        "--requires-dist",
        dest="requires_dist",
        action="append",
        default=[],
        type=_requirement_arg,
        help="expected Requires-Dist entry (repeatable; none means none allowed)",
    )
    parser.add_argument(
        "--requires-dist-from",
        type=Path,
        metavar="PYPROJECT",
        help="also expect every dependency and optional dependency this pyproject.toml declares",
    )
    parser.add_argument("--version", dest="expected_version", help="expected distribution version")
    args = parser.parse_args(argv)
    requires_dist = list(args.requires_dist)
    if args.requires_dist_from is not None:
        try:
            requires_dist.extend(requires_dist_from_pyproject(args.requires_dist_from))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            print(f"verify_wheel: {args.requires_dist_from}: {exc}", file=sys.stderr)
            return 2
    expectation = Expectation(
        sha256=args.sha256,
        packages=tuple(args.packages),
        console_scripts=frozenset(args.console_scripts),
        version=args.expected_version,
        requires_dist=tuple(requires_dist),
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
