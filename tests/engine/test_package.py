from __future__ import annotations

import importlib
from importlib.metadata import distribution, entry_points, version

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.fast]


@pytest.mark.parametrize("name", ["ship_no_ship", "ship_no_ship_service"])
def test_packages_import(name: str) -> None:
    assert importlib.import_module(name).__name__ == name


def test_the_console_script_runs_the_engine_cli() -> None:
    (script,) = entry_points(group="console_scripts", name="ship-no-ship")
    assert script.value == "ship_no_ship.engine.cli:main"
    assert script.dist is not None and script.dist.name == "ship-no-ship"
    assert script.load() is importlib.import_module("ship_no_ship.engine.cli").main


def test_the_engine_is_the_ship_no_ship_distribution_and_reports_its_version() -> None:
    import ship_no_ship

    assert ship_no_ship.DISTRIBUTION == "ship-no-ship"
    assert distribution(ship_no_ship.DISTRIBUTION).metadata["Name"] == "ship-no-ship"
    assert ship_no_ship.__version__ == version("ship-no-ship")
