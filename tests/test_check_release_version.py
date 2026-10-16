from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.fast]

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_release_version.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_release_version", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


crv = _load()


def _repo(tmp_path: Path, engine: str = "1.2.3", service: str = "1.2.3", pin: str = "ship-no-ship==1.2.3") -> Path:
    for package, body in (
        ("engine", f'[project]\nname = "ship-no-ship"\nversion = "{engine}"\n'),
        ("service", f'[project]\nname = "ship-no-ship-service"\nversion = "{service}"\ndependencies = ["{pin}"]\n'),
    ):
        directory = tmp_path / "packages" / package
        directory.mkdir(parents=True)
        (directory / "pyproject.toml").write_text(body, encoding="utf-8")
    return tmp_path


def test_the_repository_versions_are_consistent() -> None:
    engine = (ROOT / crv.ENGINE).read_text(encoding="utf-8")
    version = next(line.split('"')[1] for line in engine.splitlines() if line.startswith("version"))
    assert crv.check(f"v{version}") == (version, [])


def test_a_matching_tag_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert crv.main(["v1.2.3", "--root", str(_repo(tmp_path))]) == 0
    assert capsys.readouterr().out == "1.2.3\n"


def test_a_prerelease_tag_passes(tmp_path: Path) -> None:
    root = _repo(tmp_path, "2.0.0rc1", "2.0.0rc1", "ship-no-ship==2.0.0rc1")
    assert crv.check("v2.0.0rc1", root) == ("2.0.0rc1", [])


@pytest.mark.parametrize(
    "tag", ["1.2.3", "v1.2", "v01.2.3", "v1.2.3-rc1", "v1.2.3.post1", "v1.2.3\n", "v1.2.3;id", "release-1.2.3"]
)
def test_a_malformed_tag_fails(tmp_path: Path, tag: str) -> None:
    version, errors = crv.check(tag, _repo(tmp_path))
    assert version is None
    assert len(errors) == 1


def test_a_different_engine_version_fails(tmp_path: Path) -> None:
    _, errors = crv.check("v1.2.3", _repo(tmp_path, engine="1.2.4"))
    assert errors == ["packages/engine/pyproject.toml: version '1.2.4' does not match tag v1.2.3"]


def test_a_different_service_version_fails(tmp_path: Path) -> None:
    _, errors = crv.check("v1.2.3", _repo(tmp_path, service="1.2.4"))
    assert errors == ["packages/service/pyproject.toml: version '1.2.4' does not match tag v1.2.3"]


@pytest.mark.parametrize("pin", ["ship-no-ship", "ship-no-ship>=1.2.3", "ship-no-ship==1.2.2", "ship-no-ship-extra"])
def test_the_service_must_pin_the_engine_exactly(tmp_path: Path, pin: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert crv.main(["v1.2.3", "--root", str(_repo(tmp_path, pin=pin))]) == 1
    assert "engine dependency" in capsys.readouterr().err
