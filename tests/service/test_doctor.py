from __future__ import annotations

import hashlib
import json
import os
import plistlib
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from ship_no_ship_service import cli, doctor, fsinfo
from ship_no_ship_service.doctor import FAIL, NOT_RUN, PASS, PathAudit, Rule

ME, MY_GROUP = os.getuid(), os.getgid()
OTHER = ME + 1


class FakeAccounts:
    """Every account is the test user unless remapped; members are configurable."""

    def __init__(
        self,
        uids: Mapping[str, int | None] | None = None,
        gids: Mapping[str, int | None] | None = None,
        members: Mapping[str, list[str] | None] | None = None,
    ) -> None:
        self.uids = uids or {}
        self.gids = gids or {}
        self.group_members = members or {}

    def uid(self, name: str) -> int | None:
        return self.uids.get(name, ME)

    def gid(self, name: str) -> int | None:
        return self.gids.get(name, MY_GROUP)

    def members(self, group: str) -> list[str] | None:
        return self.group_members.get(group, ["root"])


class FakeFiles:
    def __init__(self, grants: dict[Path, list[str]] | None = None, ignoring: set[Path] | None = None) -> None:
        self.grants = grants or {}
        self.ignoring = ignoring or set()

    def write_grants(self, path: Path) -> list[str]:
        return self.grants.get(path, [])

    def ignores_ownership(self, path: Path) -> bool:
        return path in self.ignoring


class Install:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.data, self.libexec, self.logs = root / "data", root / "libexec", root / "logs"
        self.plist = root / "LaunchDaemons" / f"{doctor.LABEL}.plist"
        self.rules = [
            rule
            for rule in doctor.table(self.data, self.libexec, self.logs, self.plist)
            if rule.path.is_relative_to(root)
        ]
        for rule in self.rules:
            if rule.directory:
                rule.path.mkdir(parents=True, exist_ok=True)
            else:
                rule.path.parent.mkdir(parents=True, exist_ok=True)
                rule.path.write_bytes(b"x")
        self.plist.chmod(0o644)
        self.plist.write_bytes(
            plistlib.dumps(
                {
                    "Label": doctor.LABEL,
                    "ProgramArguments": [str(self.libexec / "bin" / "ship-no-ship-service"), "run"],
                    "UserName": doctor.DAEMON,
                    "GroupName": doctor.DAEMON,
                    "RunAtLoad": True,
                    "KeepAlive": {"SuccessfulExit": False},
                    "ThrottleInterval": 30,
                    "ProcessType": "Background",
                    "StandardOutPath": str(self.logs / "daemon.log"),
                    "StandardErrorPath": str(self.logs / "daemon.log"),
                }
            )
        )
        self.pin("ship-no-ship-service", b"#!" + str(self.libexec / "venvs" / "service" / "bin" / "python").encode())
        venv = self.libexec / "venvs" / "service"
        (venv / "bin").mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text(f"home = {self.libexec / 'python' / 'bin'}\n", encoding="utf-8")
        (self.data / "keys" / "example.pem").write_text("k", encoding="utf-8")
        for rule in self.rules:
            rule.path.chmod(rule.mode)
        (self.data / "keys" / "example.pem").chmod(0o400)
        for path in (root, self.data / "home", self.plist.parent, venv, venv / "bin", self.libexec / "venvs"):
            path.chmod(0o755)
        (venv / "pyvenv.cfg").chmod(0o644)

    def pin(self, name: str, content: bytes) -> None:
        tool = self.libexec / "bin" / name
        tool.parent.mkdir(parents=True, exist_ok=True)
        tool.parent.chmod(0o755)
        tool.write_bytes(content)
        tool.chmod(0o755)
        lock = self.libexec / doctor.TOOLCHAIN_LOCK
        pins = json.loads(lock.read_text(encoding="utf-8"))["tools"] if lock.exists() else {}
        pins[name] = {"sha256": hashlib.sha256(content).hexdigest()}
        lock.write_text(json.dumps({"tools": pins}), encoding="utf-8")
        lock.chmod(0o644)

    def run(self, accounts=None, files=None, strict=True) -> list[doctor.Result]:
        return doctor.run(
            accounts=accounts or FakeAccounts(),
            files=files or FakeFiles(),
            rules=self.rules,
            libexec=self.libexec,
            plist=self.plist,
            logs=self.logs,
            strict=strict,
            root=self.root,
        )


@pytest.fixture
def install(tmp_path: Path) -> Install:
    return Install(tmp_path.resolve())


def failures(results) -> dict[str, str]:
    return {result.name: result.detail for result in results if result.status == FAIL}


def test_a_correct_installation_passes(install):
    results = install.run()
    assert failures(results) == {}
    assert doctor.exit_code(results) == 0


@pytest.mark.parametrize(("mode", "message"), [(0o777, "writable by everyone"), (0o775, "writable by group")])
def test_a_planted_writable_parent_fails_every_path_below_it(install, mode, message):
    os.chmod(install.data, mode)
    groups = dict.fromkeys(("wheel", "admin", *doctor.SERVICE_USERS), OTHER)
    found = failures(install.run(FakeAccounts(gids=groups)))
    below = [name for name in found if name.startswith(f"path {install.data}/")]
    assert len(below) >= 10 and all(message in found[name] for name in below)


def test_a_parent_owned_by_someone_outside_the_service_fails(install):
    rule = Rule(install.data / "requests", doctor.DAEMON, doctor.DAEMON, 0o755, True)
    accounts = FakeAccounts(uids={"root": OTHER, doctor.DAEMON: OTHER + 1})
    result = PathAudit(accounts, FakeFiles(), install.root).check(rule)
    assert result.status == FAIL and "may not own a parent" in result.detail


def test_a_root_owned_path_may_not_sit_under_a_service_user_directory(tmp_path):
    root = tmp_path.resolve()
    owned = root / "owned-by-daemon"
    (owned / "sub").mkdir(parents=True)
    accounts = FakeAccounts(uids={"root": OTHER, doctor.DAEMON: ME})
    audit = PathAudit(accounts, FakeFiles(), root)
    root_rule = audit.check(Rule(owned / "sub", "root", "wheel", 0o755, True))
    assert root_rule.status == FAIL and "may not own a parent" in root_rule.detail
    daemon_rule = audit.check(Rule(owned / "sub", doctor.DAEMON, "wheel", (owned / "sub").stat().st_mode & 0o777, True))
    assert "may not own a parent" not in daemon_rule.detail


def test_a_symlink_on_the_way_fails_even_to_a_trusted_place(tmp_path):
    root = tmp_path.resolve()
    (root / "real").mkdir()
    (root / "real" / "tool").write_bytes(b"x")
    (root / "lnk").symlink_to(root / "real")
    result = PathAudit(FakeAccounts(), FakeFiles(), root).check(
        Rule(root / "lnk" / "tool", "root", "wheel", 0o644, False)
    )
    assert result.status == FAIL and result.detail == f"{root / 'lnk'} is a symlink"


def test_system_symlinks_are_followed_and_their_targets_checked(tmp_path):
    accounts = FakeAccounts(uids={"root": 0}, gids={"wheel": 0})
    audit = PathAudit(accounts, FakeFiles(), Path("/"))
    assert audit._parents(Path("/etc/hosts"), {0}, {0}) is None
    assert audit._parents(Path(tmp_path.resolve()) / "x", {0}, {0}) is not None


@pytest.mark.parametrize("where", ["parent", "path", "tree"])
def test_an_acl_granting_write_fails(install, where):
    target = {
        "parent": install.data,
        "path": install.data / "requests",
        "tree": install.libexec / "bin" / "ship-no-ship-service",
    }[where]
    found = failures(install.run(files=FakeFiles(grants={target: ["user:someone allow write"]})))
    assert any("has an ACL that grants user:someone allow write" in detail for detail in found.values())


def test_a_volume_that_ignores_ownership_fails(install):
    found = failures(install.run(files=FakeFiles(ignoring={install.data / "keys"})))
    assert found[f"path {install.data / 'keys'}"].endswith("ignores ownership")


def test_a_person_in_a_trusted_group_fails(install):
    found = failures(install.run(FakeAccounts(members={"wheel": ["root", "someone"], doctor.DAEMON: [doctor.DAEMON]})))
    assert found == {"group wheel": "has members someone"}


def test_missing_accounts_and_lock_fail_once_installed_and_are_not_run_before(install):
    (install.libexec / doctor.TOOLCHAIN_LOCK).unlink()
    accounts = FakeAccounts(uids={doctor.role_user("muse"): None}, members={doctor.role_user("muse"): None})
    strict = {r.name: r.status for r in install.run(accounts)}
    early = install.run(accounts, strict=False)
    loose = {r.name: r.status for r in early}
    muse = f"path {install.data / 'home' / 'muse'}"
    assert (strict[muse], strict["toolchain"], strict["group _ssnsmuse"]) == (FAIL, FAIL, FAIL)
    assert (loose[muse], loose["toolchain"], loose["group _ssnsmuse"]) == (NOT_RUN, NOT_RUN, NOT_RUN)
    assert doctor.exit_code(early) == doctor.INCOMPLETE
    assert doctor.exit_code(early, allow_not_run=True) == 0


def test_a_directory_this_user_cannot_read_fails_once_installed(install, monkeypatch):
    def refuse(path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(doctor.os, "listdir", refuse)
    keys = f"path {install.data / 'keys'}"
    assert {r.name: r for r in install.run()}[keys].status == FAIL
    assert {r.name: r for r in install.run(strict=False)}[keys].status == NOT_RUN


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"#!/opt/homebrew/bin/python3\n", "outside the toolchain"),
        (b"#!/usr/bin/env python3\n", "outside the toolchain"),
        (b'#!/bin/sh\nexec /opt/homebrew/bin/gh "$@"\n', "outside the toolchain"),
        (b'#!/bin/sh\n/opt/homebrew/bin/node cli.js "$@"\n', "not an exec of an absolute program"),
        (b"#!/usr/bin/../../Users/someone/python\n", "outside the toolchain"),
        (b'#!/bin/sh\nexec /usr/bin/../../opt/x "$@"\n', "outside the toolchain"),
        (b"#!/bin/sh\nexec /bin/true\nexec /bin/true\n", "more than one command"),
        (b"#!/bin/sh\nexec /bin/true; /opt/x\n", "not an exec of an absolute program"),
        (b"#!/bin/sh -c x y\n", "not one absolute interpreter"),
        (b"\x7fELF\x02\x01", "neither a Mach-O binary nor a shim"),
        (b'#!/bin/sh\nexec /usr/bin/python3 /opt/someone/evil.py "$@"\n', "neither a flag nor a path inside"),
        (b"#!/usr/bin/python3 /opt/someone/evil.py\n", "neither a flag nor a path inside"),
        (b"#!/bin/sh\nexec /bin/sh /opt/someone/x.sh\n", "neither a flag nor a path inside"),
        (b'#!/bin/sh\nexec /usr/bin/python3 evil.py "$@"\n', "neither a flag nor a path inside"),
    ],
)
def test_tools_may_run_only_toolchain_programs(install, content, message):
    install.pin("gh", content)
    assert message in failures(install.run())["tool gh"]


@pytest.mark.parametrize(
    "content",
    [
        b"\xcf\xfa\xed\xfe" + b"\x00" * 16,
        b"\xca\xfe\xba\xbe" + b"\x00" * 16,
        b'#!/bin/sh\n# shim\nexec /bin/true "$@"\n',
        b'#!/bin/sh -e\nexec /usr/bin/python3 -I LIBEXEC/venvs/service/app.py "$@"\n',
    ],
)
def test_pinned_binaries_and_strict_shims_pass(install, content):
    install.pin("gh", content.replace(b"LIBEXEC", str(install.libexec).encode()))
    assert "tool gh" not in failures(install.run())


def test_a_shim_target_that_links_out_of_the_toolchain_fails(install):
    (install.libexec / "bin" / "real").symlink_to("/opt/homebrew/bin/gh")
    install.pin("gh", f'#!/bin/sh\nexec {install.libexec / "bin" / "real"} "$@"\n'.encode())
    assert "outside the toolchain" in failures(install.run())["tool gh"]


def test_an_unpinned_or_changed_tool_fails(install):
    (install.libexec / "bin" / "extra").write_bytes(b"x")
    (install.libexec / "bin" / "extra").chmod(0o755)
    (install.libexec / "bin" / "ship-no-ship-service").write_bytes(b"changed")
    found = failures(install.run())
    assert found["tool extra"] == "is not pinned"
    assert found["tool ship-no-ship-service"] == "does not match its pin"


def test_a_venv_interpreter_from_outside_the_toolchain_fails(install):
    cfg = install.libexec / "venvs" / "service" / "pyvenv.cfg"
    cfg.write_text("home = /opt/homebrew/bin\n", encoding="utf-8")
    assert "outside" in failures(install.run())["venv service"]


def test_tree_links_must_stay_inside(install):
    link = install.libexec / "venvs" / "service" / "bin" / "python"
    link.symlink_to("/usr/bin/python3")
    assert "links outside" in failures(install.run())[f"path {install.libexec}"]
    link.unlink()
    link.symlink_to(install.libexec / "bin" / "ship-no-ship-service")
    assert f"path {install.libexec}" not in failures(install.run())


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"UserName": "root"}, "does not run as _ssnsd"),
        ({"ProgramArguments": ["/opt/homebrew/bin/python3"]}, "ProgramArguments are not exactly"),
        ({"ProgramArguments": []}, "ProgramArguments are not exactly"),
        ({"Program": "/bin/sh"}, "outside the allowed set: Program"),
        (
            {"WorkingDirectory": "/tmp", "StandardInPath": "/tmp/in"},
            "outside the allowed set: StandardInPath, WorkingDirectory",
        ),
        ({"StandardOutPath": "/tmp/out.log"}, "StandardOutPath must be inside"),
        ({"StandardErrorPath": "/Library/Logs/ship-no-ship/../x"}, "StandardErrorPath must be inside"),
        ({"Label": "other"}, "Label is not"),
        ({"EnvironmentVariables": {"DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"}}, "EnvironmentVariables"),
    ],
)
def test_the_launch_daemon_runs_the_toolchain_as_the_daemon_user(install, changes, message):
    data = plistlib.loads(install.plist.read_bytes())
    install.plist.write_bytes(plistlib.dumps({**data, **changes}))
    assert message in failures(install.run())[f"launchd {doctor.LABEL}"]


def test_extra_daemon_arguments_are_refused(install):
    data = plistlib.loads(install.plist.read_bytes())
    data["ProgramArguments"] = [*data["ProgramArguments"], "--debug"]
    install.plist.write_bytes(plistlib.dumps(data))
    assert "ProgramArguments are not exactly" in failures(install.run())[f"launchd {doctor.LABEL}"]


def test_missing_paths_are_not_run_before_installation(install):
    (install.data / "requests").rmdir()
    loose = {r.name: r.status for r in install.run(strict=False)}
    assert loose[f"path {install.data / 'requests'}"] == NOT_RUN
    assert {r.name: r.status for r in install.run()}[f"path {install.data / 'requests'}"] == FAIL


def test_a_missing_launch_daemon_fails_once_installed(install):
    install.plist.unlink()
    assert "not installed" in failures(install.run())[f"launchd {doctor.LABEL}"]


# acl_to_text output captured from macOS, including inherited and inheritable entries.
EVERYONE = "group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12"


@pytest.mark.parametrize(
    ("text", "grants"),
    [
        (f"!#acl 1\n{EVERYONE}:allow:write,append\n", ["group:everyone allow append,write"]),
        (f"!#acl 1\n{EVERYONE}:allow,inherited:write\n", ["group:everyone allow write"]),
        (f"!#acl 1\n{EVERYONE}:allow,file_inherit,directory_inherit:write\n", ["group:everyone allow write"]),
        (
            f"!#acl 1\n{EVERYONE}:allow,inherited,file_inherit,directory_inherit:add_subdirectory\n",
            ["group:everyone allow add_subdirectory"],
        ),
        (f"!#acl 1\n{EVERYONE}:allow:read,execute\n", []),
        (f"!#acl 1\n{EVERYONE}:deny:write\n", []),
        ("", []),
    ],
)
def test_acl_text_parsing(text, grants):
    assert fsinfo.write_grants(text) == grants


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACLs")
def test_a_real_inherited_acl_is_caught(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    subprocess.run(["/bin/chmod", "+a", "everyone allow write,file_inherit,directory_inherit", str(parent)], check=True)
    child = parent / "child"
    child.write_text("x", encoding="utf-8")
    assert doctor.SystemFileSystem().write_grants(child) == ["group:everyone allow write"]


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACLs and statfs")
def test_real_macos_acls_and_volume_flags_are_read(tmp_path):
    target = tmp_path / "file"
    target.write_text("x", encoding="utf-8")
    files = doctor.SystemFileSystem()
    assert files.write_grants(target) == []
    subprocess.run(["/bin/chmod", "+a", "everyone allow write,append", str(target)], check=True)
    assert files.write_grants(target) == ["group:everyone allow append,write"]
    assert files.ignores_ownership(tmp_path) is False


def test_main_and_cli_run_read_only(tmp_path, capsys):
    args = ["--data-dir", str(tmp_path / "d"), "--libexec", str(tmp_path / "l"), "--plist", str(tmp_path / "p")]
    assert doctor.main(args) == 1
    assert doctor.main([*args, "--allow-not-run"]) in (0, 1)
    assert "path " in capsys.readouterr().out
    assert cli.main(["doctor", *args]) == 1
    assert cli.main([]) == 2
    assert list(tmp_path.iterdir()) == []
