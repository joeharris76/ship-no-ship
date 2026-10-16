from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.fast]

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_wheel.py"
DIST_INFO = "ship_no_ship-1.2.3.dist-info"
CONSOLE = "ship-no-ship=ship_no_ship.engine.cli:main"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_wheel", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vw = _load()


def _digest(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _good_files() -> dict[str, bytes]:
    return {
        "ship_no_ship/__init__.py": b"",
        "ship_no_ship/engine/cli.py": b"def main():\n    return 0\n",
        "ship_no_ship/py.typed": b"",
        f"{DIST_INFO}/METADATA": b"Metadata-Version: 2.4\nName: ship-no-ship\nVersion: 1.2.3\n\nLong description.\n",
        f"{DIST_INFO}/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{DIST_INFO}/entry_points.txt": b"[console_scripts]\nship-no-ship = ship_no_ship.engine.cli:main\n",
        f"{DIST_INFO}/licenses/LICENSE": b"MIT\n",
    }


def _record(files: dict[str, bytes]) -> bytes:
    lines = [f"{name},{_digest(data)},{len(data)}" for name, data in files.items()]
    lines.append(f"{DIST_INFO}/RECORD,,")
    return ("\n".join(lines) + "\n").encode()


def _write(
    tmp_path: Path,
    files: dict[str, bytes] | None = None,
    *,
    record: bytes | None = None,
    extra: dict[str, bytes] | None = None,
    name: str = "ship_no_ship-1.2.3-py3-none-any.whl",
    symlink: str | None = None,
) -> Path:
    """Write a wheel whose RECORD covers ``files``; ``extra`` members are added after RECORD is computed."""
    files = _good_files() if files is None else files
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in files.items():
            archive.writestr(member, data)
        for member, data in (extra or {}).items():
            archive.writestr(member, data)
        if symlink is not None:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16) & 0xFFFF0000
            archive.writestr(info, b"/etc/passwd")
        archive.writestr(f"{DIST_INFO}/RECORD", _record(files) if record is None else record)
    return path


def _check(path: Path, *, sha256: str | None = None, version: str | None = "1.2.3", scripts=(CONSOLE,)) -> list[str]:
    expectation = vw.Expectation(
        sha256=sha256 or vw.file_sha256(path),
        packages=("ship_no_ship",),
        console_scripts=frozenset(scripts),
        version=version,
    )
    return vw.verify_wheel(path, expectation)


def _one(errors: list[str], text: str) -> None:
    assert any(text in error for error in errors), errors


def test_a_well_formed_wheel_passes(tmp_path: Path) -> None:
    assert _check(_write(tmp_path)) == []


def test_main_accepts_a_well_formed_wheel(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _write(tmp_path)
    argv = [str(path), "--sha256", vw.file_sha256(path).upper(), "--package", "ship_no_ship"]
    assert (
        vw.main([*argv, "--console-script", " ship-no-ship = ship_no_ship.engine.cli:main", "--version", "1.2.3"]) == 0
    )
    assert "OK" in capsys.readouterr().out


def test_main_rejects_a_hash_mismatch(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _write(tmp_path)
    argv = [str(path), "--sha256", "0" * 64, "--package", "ship_no_ship", "--console-script", CONSOLE]
    assert vw.main(argv) == 1
    assert "does not match the expected" in capsys.readouterr().err


def test_main_reports_a_missing_file(tmp_path: Path) -> None:
    assert vw.main([str(tmp_path / "absent.whl"), "--sha256", "0" * 64, "--package", "ship_no_ship"]) == 1


@pytest.mark.parametrize(
    "argv",
    [
        ["--sha256", "abc", "--package", "ship_no_ship"],
        ["--sha256", "0" * 64, "--package", "ship-no-ship"],
        ["--sha256", "0" * 64, "--package", "ship_no_ship", "--console-script", "no-target"],
        ["--sha256", "0" * 64],
    ],
)
def test_main_rejects_bad_arguments(tmp_path: Path, argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        vw.main([str(tmp_path / "x.whl"), *argv])
    assert exc.value.code == 2


def test_a_hash_mismatch_stops_before_reading_the_zip(tmp_path: Path) -> None:
    path = tmp_path / "ship_no_ship-1.2.3-py3-none-any.whl"
    path.write_bytes(b"not a zip")
    errors = _check(path, sha256="1" * 64)
    assert len(errors) == 1
    _one(errors, "SHA-256")


def test_a_file_that_is_not_a_zip_fails(tmp_path: Path) -> None:
    path = tmp_path / "ship_no_ship-1.2.3-py3-none-any.whl"
    path.write_bytes(b"not a zip")
    _one(_check(path), "unreadable zip")


@pytest.mark.parametrize(
    "name",
    [
        "ship_no_ship-1.2.3-cp311-cp311-linux_x86_64.whl",
        "ship_no_ship-1.2.3-1-py3-none-any.whl",
        "ship_no_ship-1.2.3.zip",
    ],
)
def test_a_wheel_that_is_not_pure_python_by_name_fails(tmp_path: Path, name: str) -> None:
    errors = _check(_write(tmp_path, name=name))
    assert len(errors) == 1


def test_an_unexpected_version_fails(tmp_path: Path) -> None:
    _one(_check(_write(tmp_path), version="1.2.4"), "not the expected 1.2.4")


def test_a_tampered_file_fails_its_record_hash(tmp_path: Path) -> None:
    files = _good_files()
    record = _record(files)
    files["ship_no_ship/engine/cli.py"] = b"import os\nos.system('true')\n"
    _one(_check(_write(tmp_path, files, record=record)), "ship_no_ship/engine/cli.py: RECORD hash does not match")


def test_a_wrong_record_size_fails(tmp_path: Path) -> None:
    files = _good_files()
    data = files["ship_no_ship/py.typed"]
    record = _record(files).replace(f"{_digest(data)},0".encode(), f"{_digest(data)},7".encode())
    _one(_check(_write(tmp_path, files, record=record)), "ship_no_ship/py.typed: RECORD size does not match")


def test_a_member_missing_from_record_fails(tmp_path: Path) -> None:
    errors = _check(_write(tmp_path, extra={"ship_no_ship/hidden.py": b"x = 1\n"}))
    _one(errors, "ship_no_ship/hidden.py: not listed in RECORD")


def test_a_record_entry_without_a_member_fails(tmp_path: Path) -> None:
    files = _good_files()
    record = _record({**files, "ship_no_ship/gone.py": b"x"})
    _one(_check(_write(tmp_path, files, record=record)), "ship_no_ship/gone.py: listed in RECORD but not in the wheel")


def test_a_record_entry_listed_twice_fails(tmp_path: Path) -> None:
    files = _good_files()
    record = _record(files) + _record({"ship_no_ship/__init__.py": b""}).splitlines(keepends=True)[0]
    _one(_check(_write(tmp_path, files, record=record)), "listed twice in RECORD")


def test_a_weak_record_hash_fails(tmp_path: Path) -> None:
    files = _good_files()
    data = files["ship_no_ship/engine/cli.py"]
    md5 = "md5=" + base64.urlsafe_b64encode(hashlib.md5(data).digest()).rstrip(b"=").decode()
    record = _record(files).replace(_digest(data).encode(), md5.encode())
    _one(_check(_write(tmp_path, files, record=record)), "RECORD hash is not SHA-256")


def test_record_must_not_hash_itself(tmp_path: Path) -> None:
    files = _good_files()
    record = _record(files).replace(f"{DIST_INFO}/RECORD,,".encode(), f"{DIST_INFO}/RECORD,sha256=x,1".encode())
    _one(_check(_write(tmp_path, files, record=record)), "RECORD must not hash itself")


def test_a_malformed_record_row_fails(tmp_path: Path) -> None:
    files = _good_files()
    _one(_check(_write(tmp_path, files, record=_record(files) + b"only,two\n")), "malformed row")


def test_a_missing_record_fails(tmp_path: Path) -> None:
    path = tmp_path / "ship_no_ship-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in _good_files().items():
            archive.writestr(member, data)
    _one(_check(path), "RECORD: missing")


@pytest.mark.parametrize(
    "member",
    [
        "evil.py",
        "ship_no_ship_extra/__init__.py",
        "Ship_No_Ship/other.py",
        "ship_no_ship-1.2.3.data/scripts/ship-no-ship",
        "ship_no_ship-1.2.3.data/purelib/other.py",
        "other-0.1.dist-info/METADATA",
    ],
)
def test_a_member_outside_the_expected_paths_fails(tmp_path: Path, member: str) -> None:
    files = {**_good_files(), member: b"x = 1\n"}
    _one(_check(_write(tmp_path, files)), f"{member}: outside")


@pytest.mark.parametrize(
    "member",
    [
        "ship_no_ship/hook.pth",
        "ship_no_ship-hook.pth",
        "ship_no_ship/_speedups.cpython-311-x86_64-linux-gnu.so",
        "ship_no_ship/_speedups.pyd",
        "ship_no_ship/_speedups.dylib",
        "ship_no_ship/engine/__pycache__/cli.cpython-311.pyc",
        "ship_no_ship/HOOK.PTH",
    ],
)
def test_forbidden_file_types_fail(tmp_path: Path, member: str) -> None:
    files = {**_good_files(), member: b"\x00"}
    _one(_check(_write(tmp_path, files)), f"{member}: forbidden file type")


@pytest.mark.parametrize(
    "member",
    ["../ship_no_ship/x.py", "/ship_no_ship/x.py", "ship_no_ship\\x.py", "ship_no_ship/./x.py", "ship_no_ship//x.py"],
)
def test_unsafe_member_names_fail(tmp_path: Path, member: str) -> None:
    files = {**_good_files(), member: b"x = 1\n"}
    _one(_check(_write(tmp_path, files)), "unsafe member name")


def test_a_symbolic_link_fails(tmp_path: Path) -> None:
    _one(_check(_write(tmp_path, symlink="ship_no_ship/link.py")), "ship_no_ship/link.py: symbolic link")


def test_a_case_only_duplicate_fails(tmp_path: Path) -> None:
    files = {**_good_files(), "ship_no_ship/Engine.py": b"", "ship_no_ship/ENGINE.py": b""}
    _one(_check(_write(tmp_path, files)), "duplicate member")


def test_an_exact_duplicate_fails(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="Duplicate name"):
        path = _write(tmp_path, extra={"ship_no_ship/__init__.py": b"import os\n"})
    _one(_check(path), "ship_no_ship/__init__.py: duplicate member")


def test_an_oversized_member_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vw, "MAX_MEMBER_BYTES", 16)
    _one(_check(_write(tmp_path)), "exceeds the 16-byte limit")


def test_an_oversized_wheel_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vw, "MAX_TOTAL_BYTES", 64)
    _one(_check(_write(tmp_path)), "uncompressed bytes exceeds")


def test_too_many_members_fail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vw, "MAX_MEMBERS", 3)
    _one(_check(_write(tmp_path)), "member limit")


@pytest.mark.parametrize(
    ("wheel", "expected"),
    [
        (b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n", "Root-Is-Purelib is not true"),
        (b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: cp311-cp311-linux_x86_64\n", "tags"),
        (b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\nTag: py2-none-any\n", "tags"),
    ],
)
def test_wheel_metadata_must_be_pure_python(tmp_path: Path, wheel: bytes, expected: str) -> None:
    files = {**_good_files(), f"{DIST_INFO}/WHEEL": wheel}
    _one(_check(_write(tmp_path, files)), expected)


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        (b"Metadata-Version: 2.4\nName: other\nVersion: 1.2.3\n", "Name"),
        (b"Metadata-Version: 2.4\nName: ship-no-ship\nVersion: 9.9.9\n", "Version"),
    ],
)
def test_metadata_must_match_the_file_name(tmp_path: Path, metadata: bytes, expected: str) -> None:
    files = {**_good_files(), f"{DIST_INFO}/METADATA": metadata}
    _one(_check(_write(tmp_path, files)), f"METADATA: {expected}")


@pytest.mark.parametrize("missing", ["METADATA", "WHEEL"])
def test_missing_metadata_files_fail(tmp_path: Path, missing: str) -> None:
    files = _good_files()
    del files[f"{DIST_INFO}/{missing}"]
    _one(_check(_write(tmp_path, files)), f"{missing}: missing")


@pytest.mark.parametrize(
    ("entry_points", "expected"),
    [
        (b"[console_scripts]\nship-no-ship = ship_no_ship.engine.cli:main\nsh = os:system\n", "unexpected console"),
        (b"[console_scripts]\nship-no-ship = ship_no_ship.engine.cli:main\n[pytest11]\np = ship_no_ship.x\n", "group"),
        (b"[console_scripts]\nship-no-ship = ship_no_ship.engine.cli:other\n", "missing console script"),
        (b"[gui_scripts]\nship-no-ship = ship_no_ship.engine.cli:main\n", "group [gui_scripts]"),
        (b"not an ini file\n", "unreadable"),
    ],
)
def test_entry_points_must_match_exactly(tmp_path: Path, entry_points: bytes, expected: str) -> None:
    files = {**_good_files(), f"{DIST_INFO}/entry_points.txt": entry_points}
    _one(_check(_write(tmp_path, files)), expected)


def test_missing_entry_points_fail_when_a_console_script_is_expected(tmp_path: Path) -> None:
    files = _good_files()
    del files[f"{DIST_INFO}/entry_points.txt"]
    path = _write(tmp_path, files)
    _one(_check(path), "entry_points.txt: missing")
    assert _check(path, scripts=()) == []


def test_no_console_scripts_are_allowed_unless_expected(tmp_path: Path) -> None:
    _one(_check(_write(tmp_path), scripts=()), "unexpected console script")
