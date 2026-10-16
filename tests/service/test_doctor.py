from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from ship_no_ship_service import doctor
from ship_no_ship_service.doctor import PathAudit, Rule
from ship_no_ship_service.probes import FAIL, NOT_RUN, PASS, Probes


class FakeAccounts:
    """Every service account (and root) is the test user, unless a test says otherwise."""

    def __init__(
        self,
        missing: frozenset[str] = frozenset(),
        others: frozenset[str] = frozenset(),
        other_groups: frozenset[str] = frozenset(),
    ) -> None:
        self.missing = missing
        self.others = others
        self.other_groups = other_groups

    def uid(self, name: str) -> int | None:
        if name in self.missing:
            return None
        return os.getuid() + 1 if name in self.others else os.getuid()

    def gid(self, name: str) -> int | None:
        if name in self.missing:
            return None
        return os.getgid() + 1 if name in self.others | self.other_groups else os.getgid()


def build(root: Path) -> tuple[Path, Path, Path]:
    """A temp tree laid out and moded like an installation."""
    data, libexec, logs = root / "data", root / "libexec", root / "logs"
    rules = [rule for rule in doctor.table(data, libexec, logs) if rule.path.is_relative_to(root)]
    for rule in rules:
        if rule.directory:
            rule.path.mkdir(parents=True, exist_ok=True)
        else:
            rule.path.parent.mkdir(parents=True, exist_ok=True)
            rule.path.write_text("x", encoding="utf-8")
    (libexec / "bin").mkdir()
    tool = libexec / "bin" / "gh"
    tool.write_bytes(b"tool")
    tool.chmod(0o755)
    (libexec / doctor.TOOLCHAIN_LOCK).write_text(
        json.dumps({"tools": {"gh": {"sha256": hashlib.sha256(b"tool").hexdigest()}}}), encoding="utf-8"
    )
    (libexec / doctor.TOOLCHAIN_LOCK).chmod(0o644)
    (libexec / "bin").chmod(0o755)
    (data / "keys" / "example.pem").write_text("k", encoding="utf-8")
    (data / "keys" / "example.pem").chmod(0o400)
    for rule in rules:
        rule.path.chmod(rule.mode)
    for path in (root, root / "data" / "home"):
        path.chmod(0o755)
    return data, libexec, logs


@pytest.fixture
def tree(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    root = tmp_path.resolve()
    return (root, *build(root))


def local_rules(root: Path, data: Path, libexec: Path, logs: Path) -> list[Rule]:
    return [rule for rule in doctor.table(data, libexec, logs) if rule.path.is_relative_to(root)]


def run(tree, accounts=None) -> list:
    root, data, libexec, logs = tree
    return doctor.run(
        accounts=accounts or FakeAccounts(),
        rules=local_rules(root, data, libexec, logs),
        libexec=libexec,
        checks=Probes(),
        root=root,
    )


def failures(results) -> dict[str, str]:
    return {result.name: result.detail for result in results if result.status == FAIL}


def test_a_correct_installation_passes_and_unavailable_probes_are_not_run(tree):
    results = run(tree)
    assert failures(results) == {}
    assert {result.status for result in results if result.name.startswith("path")} == {PASS}
    assert [r.status for r in results if r.name == "tool gh"] == [PASS]
    assert {r.status for r in results if r.name.startswith(("auth", "codex", "record"))} == {NOT_RUN}
    assert doctor.exit_code(results) == 0


@pytest.mark.parametrize("mode", [0o777, 0o775])
def test_a_planted_writable_parent_fails_every_path_below_it(tree, mode):
    _, data, _, _ = tree
    os.chmod(data, mode)
    groups = frozenset({"wheel", "admin", doctor.DAEMON, *(doctor.role_user(c) for c in doctor.CLIS)})
    found = failures(run(tree, FakeAccounts(other_groups=groups)))
    below = [name for name in found if name.startswith(f"path {data}/")]
    assert len(below) >= 10
    assert all("writable by" in found[name] for name in below)


def test_a_parent_owned_by_someone_outside_the_service_fails(tree):
    root, data, _, _ = tree
    rule = Rule(data / "requests", doctor.DAEMON, doctor.DAEMON, 0o755, True)
    accounts = FakeAccounts(others=frozenset({"root", doctor.DAEMON, *(doctor.role_user(c) for c in doctor.CLIS)}))
    result = PathAudit(accounts, root).check(rule)
    assert result.status == FAIL and "not root or a service user" in result.detail


def test_the_walk_goes_past_the_tree_up_to_the_filesystem_root(tmp_path):
    root = tmp_path.resolve()
    target = root / "x"
    target.mkdir(mode=0o700)
    result = PathAudit(FakeAccounts(), Path("/")).check(Rule(target, "root", "wheel", 0o700, True))
    # The fake trusts only the test user, so the real root-owned "/" (or a world-writable /tmp) fails.
    assert result.status == FAIL
    assert not result.detail.startswith(str(root))


def world_writable_health(data: Path, lib: Path) -> None:
    health = data / "run" / "health.json"
    health.write_text("{}", encoding="utf-8")
    health.chmod(0o666)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d, lib: (d / "state").chmod(0o750), "mode 0750, not 0700"),
        (lambda d, lib: (d / "keys" / "example.pem").chmod(0o440), "mode 0440, not 0400"),
        (world_writable_health, "mode 0666"),
        (lambda d, lib: (lib / "bin" / "gh").chmod(0o775), "0775"),
        (lambda d, lib: (lib / "bin" / "link").symlink_to("/bin/sh"), "is a symlink"),
    ],
)
def test_wrong_modes_and_symlinks_fail(tree, change, message):
    _, data, libexec, _ = tree
    change(data, libexec)
    assert any(message in detail for detail in failures(run(tree)).values())


def test_a_listed_path_that_is_a_symlink_fails(tree):
    _, data, _, _ = tree
    toml = data / "config" / "service.toml"
    toml.chmod(0o600)
    toml.unlink()
    toml.symlink_to(data / "run")
    assert "is a symlink" in failures(run(tree))[f"path {toml}"]


def test_missing_paths_and_accounts(tree):
    root, data, _, _ = tree
    (data / "mirror").rmdir()
    (data / "requests").rmdir()
    results = {r.name: r for r in run(tree, FakeAccounts(missing=frozenset({doctor.role_user("muse")})))}
    assert results[f"path {data / 'mirror'}"].status == PASS
    assert results[f"path {data / 'requests'}"].status == FAIL
    assert results[f"path {data / 'home' / 'muse'}"].status == NOT_RUN


def test_toolchain_pins(tree):
    _, _, libexec, _ = tree
    (libexec / "bin" / "gh").chmod(0o644)
    (libexec / "bin" / "gh").write_bytes(b"other")
    assert "is not the pin" in doctor.toolchain(libexec, doctor.read_pins(libexec))[0].detail
    assert doctor.toolchain(libexec, {"uv": "0" * 64})[0].status == FAIL
    assert doctor.toolchain(libexec, None)[0].status == NOT_RUN
    (libexec / doctor.TOOLCHAIN_LOCK).chmod(0o600)
    (libexec / doctor.TOOLCHAIN_LOCK).write_text("[]", encoding="utf-8")
    assert "cannot be read" in failures(run(tree))["toolchain"]


def test_post_reboot_runs_only_the_reboot_checks(tree):
    _, _, libexec, _ = tree
    results = doctor.run(accounts=FakeAccounts(), rules=[], libexec=libexec, checks=Probes(), post_reboot=True)
    assert [result.name for result in results] == ["auth claude", "auth agy", "headless claude", "headless agy"]


def test_main_runs_read_only_against_the_real_system(tmp_path, capsys):
    code = doctor.main(["--data-dir", str(tmp_path / "data"), "--libexec", str(tmp_path / "libexec")])
    assert code in (0, 1)
    out = capsys.readouterr().out
    assert "path " in out and "auth claude" in out
    assert list(tmp_path.iterdir()) == []


def test_a_directory_this_user_cannot_read_is_not_run(tree, monkeypatch):
    _, data, _, _ = tree

    def refuse(path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(doctor.os, "listdir", refuse)
    results = {r.name: r for r in run(tree)}
    assert results[f"path {data / 'keys'}"].status == NOT_RUN
    assert "daemon user" in results[f"path {data / 'keys'}"].detail
