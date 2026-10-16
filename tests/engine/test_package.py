from __future__ import annotations

import importlib

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.fast]


@pytest.mark.parametrize("name", ["ship_no_ship", "ship_no_ship_service"])
def test_packages_import(name: str) -> None:
    assert importlib.import_module(name).__name__ == name
