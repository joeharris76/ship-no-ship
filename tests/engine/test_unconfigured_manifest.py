from __future__ import annotations

from pathlib import Path

import pytest

from ship_no_ship.engine import cli

from .conftest import UNCONFIGURED_PREDICATE
from .test_cli_plan import SOUNDNESS, FakeGitHub, _plan, _pull

pytestmark = [pytest.mark.unit, pytest.mark.fast]


def test_plan_fails_closed_without_a_soundness_path_manifest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "_soundness_predicate", UNCONFIGURED_PREDICATE)
    with pytest.raises(SystemExit, match="no soundness path manifest is configured"):
        _plan(monkeypatch, tmp_path, FakeGitHub(_pull(), SOUNDNESS))
    assert not (tmp_path / "plan" / "plan.json").exists()
