from __future__ import annotations

import hashlib
import json
import os
import plistlib
import pwd
import struct
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from ship_no_ship_service import cli, doctor, fsinfo, macho, membership
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
        logins: Mapping[str, tuple[str, str] | None] | None = None,
        data: Path | None = None,
        nested: Mapping[str, list[str] | None] | None = None,
        shared: Mapping[str, list[str]] | None = None,
    ) -> None:
        self.nested_groups = nested or {}
        self.shared = shared or {}
        self.uids = uids or {}
        self.gids = gids or {}
        self.group_members = members or {}
        self.logins = logins or {}
        self.data = data

    def uid(self, name: str) -> int | None:
        return self.uids.get(name, ME)

    def gid(self, name: str) -> int | None:
        return self.gids.get(name, MY_GROUP)

    def members(self, group: str) -> list[str] | None:
        return self.group_members.get(group, [group] if group in doctor.SERVICE_USERS else ["root"])

    def nested(self, group: str) -> list[str] | None:
        return self.nested_groups.get(group, [])

    def sharing_gid(self, group: str) -> list[str]:
        return self.shared.get(group, [])

    def login(self, name: str) -> tuple[str, str] | None:
        if name in self.logins:
            return self.logins[name]
        return str(doctor.home_of(name, self.data or Path("/nonexistent"))), doctor.NO_SHELL


class FakeFiles:
    """``grants`` are ready-made write grants; ``acls`` are raw acl_to_text output, parsed for real."""

    def __init__(
        self,
        grants: dict[Path, list[str]] | None = None,
        ignoring: set[Path] | None = None,
        acls: dict[Path, str] | None = None,
    ) -> None:
        self.grants = grants or {}
        self.ignoring = ignoring or set()
        self.acls = acls or {}

    def write_grants(self, path: Path) -> list[str]:
        return self.grants.get(path, []) + fsinfo.write_grants(self.acls.get(path, ""))

    def access_grants(self, path: Path) -> list[str]:
        return self.grants.get(path, []) + fsinfo.access_grants(self.acls.get(path, ""))

    def inheritable_grants(self, path: Path) -> list[str]:
        return fsinfo.inheritable_grants(self.acls.get(path, ""))

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

    def pin_path(self, relative: str, content: bytes) -> None:
        target = self.libexec / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(0o755)
        lock = self.libexec / doctor.TOOLCHAIN_LOCK
        pins = json.loads(lock.read_text(encoding="utf-8"))["tools"]
        pins[relative] = {"sha256": hashlib.sha256(content).hexdigest()}
        lock.write_text(json.dumps({"tools": pins}), encoding="utf-8")

    def run(self, accounts=None, files=None, strict=True, in_cache=lambda path: True) -> list[doctor.Result]:
        if accounts is not None and accounts.data is None:
            accounts.data = self.data
        return doctor.run(
            accounts=accounts or FakeAccounts(data=self.data),
            files=files or FakeFiles(),
            rules=self.rules,
            libexec=self.libexec,
            plist=self.plist,
            data=self.data,
            logs=self.logs,
            strict=strict,
            root=self.root,
            in_cache=in_cache,
        )


@pytest.fixture
def install(tmp_path: Path) -> Install:
    return Install(tmp_path.resolve())


def _padded(text: str) -> bytes:
    raw = text.encode() + b"\0"
    return raw + b"\0" * (-len(raw) % 8)


def macho_image(
    libraries: Sequence[str] = (),
    rpaths: Sequence[str] = (),
    dylinker: str | None = None,
    weak: Sequence[str] = (),
    filetype: int = 2,
    extra: Sequence[tuple[int, str]] = (),
) -> bytes:
    """A synthetic little-endian 64-bit Mach-O image with the given load commands."""
    commands = []
    named = [*((item, macho.LC_LOAD_DYLIB) for item in libraries), *((item, macho.LC_LOAD_WEAK_DYLIB) for item in weak)]
    for name, cmd in named:
        body = _padded(name)
        commands.append(struct.pack("<IIIIII", cmd, 24 + len(body), 24, 2, 0x10000, 0x10000) + body)
    for cmd, text in [*((macho.LC_RPATH, path) for path in rpaths), *extra]:
        body = _padded(text)
        commands.append(struct.pack("<III", cmd, 12 + len(body), 12) + body)
    if dylinker:
        body = _padded(dylinker)
        commands.append(struct.pack("<III", macho.LC_LOAD_DYLINKER, 12 + len(body), 12) + body)
    area = b"".join(commands)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, filetype, len(commands), len(area), 0, 0)
    return header + area


def fat_image(slices: list[bytes]) -> bytes:
    offset = 4096
    arches, body = [], b""
    for image in slices:
        arches.append(struct.pack(">IIIII", 0x0100000C, 0, offset + len(body), len(image), 12))
        body += image + b"\0" * (-len(image) % 4096)
    header = struct.pack(">II", 0xCAFEBABE, len(slices)) + b"".join(arches)
    return header + b"\0" * (offset - len(header)) + body


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


# A real acl_to_text line: tag, uuid, name, id, kind, permissions.
SOMEONE = "user:ABCDEFAB-CDEF-ABCD-EFAB-CDEF000001F5:someone:501"


@pytest.mark.parametrize("permissions", ["read", "list", "search", "execute", "readattr,readextattr", "write"])
@pytest.mark.parametrize(
    "where",
    ["keys", "key file", "state", "config", "service.toml", "captured", "home"],
)
def test_confidential_paths_refuse_any_acl_access(install, where, permissions):
    (install.data / "captured").mkdir(exist_ok=True)
    (install.data / "captured").chmod(0o700)
    target = {
        "keys": install.data / "keys",
        "key file": install.data / "keys" / "example.pem",
        "state": install.data / "state",
        "config": install.data / "config",
        "service.toml": install.data / "config" / "service.toml",
        "captured": install.data / "captured",
        "home": install.data / "home" / "claude",
    }[where]
    acl = f"!#acl 1\n{SOMEONE}:allow:{permissions}\n"
    found = failures(install.run(files=FakeFiles(acls={target: acl})))
    assert [detail for detail in found.values() if "has an ACL that grants user:someone allow" in detail]


@pytest.mark.parametrize("target", ["requests", "run", "work"])
def test_ordinary_paths_still_allow_a_read_acl(install, target):
    acl = f"!#acl 1\n{SOMEONE}:allow:read,list,search\n"
    assert failures(install.run(files=FakeFiles(acls={install.data / target: acl}))) == {}


@pytest.mark.parametrize("flags", ["file_inherit", "directory_inherit", "file_inherit,directory_inherit"])
@pytest.mark.parametrize("permissions", ["read", "list,search"])
def test_an_inheritable_read_acl_above_a_confidential_path_fails(install, flags, permissions):
    acl = f"!#acl 1\n{SOMEONE}:allow,{flags}:{permissions}\n"
    found = failures(install.run(files=FakeFiles(acls={install.data: acl})))
    private = [f"path {install.data / name}" for name in ("config", "keys", "state", "captured")]
    assert all("has an inheritable ACL that grants user:someone allow" in found[name] for name in private)
    assert f"path {install.data / 'requests'}" not in found  # not confidential


def test_a_plain_read_acl_above_a_confidential_path_is_fine(install):
    acl = f"!#acl 1\n{SOMEONE}:allow:read,list,search\n{SOMEONE}:allow,inherited:read\n"
    assert failures(install.run(files=FakeFiles(acls={install.data: acl}))) == {}


def test_captured_output_must_exist_once_installed(install):
    (install.data / "captured").rmdir()
    assert failures(install.run())[f"path {install.data / 'captured'}"] == "missing"


def test_a_deny_entry_on_a_confidential_path_is_fine(install):
    acl = f"!#acl 1\n{SOMEONE}:deny:read,write\n"
    assert failures(install.run(files=FakeFiles(acls={install.data / "keys": acl}))) == {}


def test_a_volume_that_ignores_ownership_fails(install):
    found = failures(install.run(files=FakeFiles(ignoring={install.data / "keys"})))
    assert found[f"path {install.data / 'keys'}"].endswith("ignores ownership")


def test_a_person_in_a_trusted_group_fails(install):
    found = failures(install.run(FakeAccounts(members={"wheel": ["root", "someone"], doctor.DAEMON: [doctor.DAEMON]})))
    assert found == {"group wheel": "has members someone"}


CLAUDE = doctor.role_user("claude")


@pytest.mark.parametrize(
    ("members", "expected"),
    [
        ({"wheel": ["root", CLAUDE]}, {"group wheel": f"has members {CLAUDE}"}),
        ({"wheel": ["root", doctor.DAEMON]}, {"group wheel": f"has members {doctor.DAEMON}"}),
        ({CLAUDE: [CLAUDE, doctor.DAEMON]}, {f"group {CLAUDE}": f"has members {doctor.DAEMON}"}),
        ({doctor.DAEMON: [doctor.DAEMON, "root"]}, {f"group {doctor.DAEMON}": "has members root"}),
        ({"staff": ["root", "someone", CLAUDE]}, {"group staff": f"has service users {CLAUDE}"}),
        ({"admin": ["root", doctor.DAEMON]}, {"group admin": f"has service users {doctor.DAEMON}"}),
    ],
)
def test_service_users_stay_out_of_other_groups(install, members, expected):
    assert {k: v for k, v in failures(install.run(FakeAccounts(members=members))).items() if k.startswith("group")} == (
        expected
    )


def test_people_in_staff_and_admin_are_fine_but_a_missing_group_is_not(install):
    assert failures(install.run(FakeAccounts(members={"staff": ["someone"], "admin": ["someone"]}))) == {}
    accounts = FakeAccounts(members={"staff": None})
    assert failures(install.run(accounts))["group staff"] == "does not exist"
    assert {r.name: r.status for r in install.run(accounts, strict=False)}["group staff"] == NOT_RUN


def _user(name: str, uid: int, gid: int):
    return type("User", (), {"pw_name": name, "pw_uid": uid, "pw_gid": gid})


def test_effective_membership_counts_primary_groups_and_what_the_system_says(monkeypatch):
    entry = type("Group", (), {"gr_gid": 20, "gr_mem": ["root"]})
    users = [_user(CLAUDE, 300, 20), _user("other", 301, 1), _user("nested", 302, 1)]
    daemon = _user(doctor.DAEMON, 303, 1)

    def getpwnam(name):
        if name == doctor.DAEMON:
            return daemon
        raise KeyError(name)

    monkeypatch.setattr(doctor.grp, "getgrnam", lambda name: entry)
    monkeypatch.setattr(doctor.pwd, "getpwall", lambda: users)
    monkeypatch.setattr(doctor.pwd, "getpwnam", getpwnam)
    # Only the system knows about nesting: "nested" and the daemon are members through a nested group.
    monkeypatch.setattr(doctor.membership, "is_member", lambda uid, gid: uid in (302, 303) and gid == 20)
    assert doctor.SystemAccounts().members("staff") == sorted(["root", CLAUDE, "nested", doctor.DAEMON])


@pytest.mark.parametrize(
    ("accounts", "group", "detail"),
    [
        (FakeAccounts(nested={"admin": ["ABC-UUID"]}), "admin", "has nested groups ABC-UUID"),
        (FakeAccounts(nested={doctor.DAEMON: ["ABC-UUID"]}), doctor.DAEMON, "has nested groups ABC-UUID"),
        (FakeAccounts(shared={"wheel": ["wheel2"]}), "wheel", "shares its GID with wheel2"),
        (FakeAccounts(shared={CLAUDE: ["copy"]}), CLAUDE, "shares its GID with copy"),
        (
            FakeAccounts(members={"staff": [CLAUDE]}, nested={"staff": ["X"]}),
            "staff",
            f"has service users {CLAUDE}; has nested groups X",
        ),
    ],
)
def test_nested_groups_and_shared_gids_fail(install, accounts, group, detail):
    assert failures(install.run(accounts))[f"group {group}"] == detail


def test_unreadable_nested_groups_fail_once_installed(install):
    accounts = FakeAccounts(nested={"wheel": None})
    assert failures(install.run(accounts))["group wheel"] == "its nested groups cannot be read"
    assert {r.name: r.status for r in install.run(accounts, strict=False)}["group wheel"] == NOT_RUN


@pytest.mark.parametrize(
    ("text", "values"),
    [
        ("NestedGroups: ABC-1\n", ["ABC-1"]),
        ("NestedGroups:\n ABC-1\n ABC-2\n", ["ABC-1", "ABC-2"]),
        ("NestedGroups: ABC-1 ABC-2\nPrimaryGroupID: 204\n", ["ABC-1", "ABC-2"]),
        ("something else\n", None),
    ],
)
def test_dscl_nested_groups_parsing(text, values):
    assert membership.parse_nested(text) == values


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS directory services")
def test_real_nested_groups_and_membership_are_read():
    assert membership.nested_groups("_developer")  # stock macOS nests admin in _developer
    assert membership.nested_groups("wheel") == []
    assert membership.is_member(0, 0) is True
    www = pwd.getpwnam("_www")
    assert membership.is_member(www.pw_uid, 80) is False


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


NOT_A_FORM = "is not a Mach-O binary, a toolchain Python script or a /bin/sh shim"
NOT_A_SHIM = 'is a shim whose only command is not exec <pinned path> "$@"'


@pytest.mark.parametrize(
    ("content", "message"),
    [
        # Interpreter flags that load code from the current directory or home.
        (b'#!/bin/sh\nexec /usr/bin/python3 -mfoo "$@"\n', NOT_A_SHIM),
        (b"#!/usr/bin/perl -MEvil\n", NOT_A_FORM),
        (b'#!/bin/sh\nexec /usr/bin/ruby -rfoo "$@"\n', NOT_A_SHIM),
        (b'#!/bin/zsh -l\nexec /bin/true "$@"\n', NOT_A_FORM),
        (b'#!/bin/sh\nexec python3 "$@"\n', NOT_A_SHIM),
        # System interpreters and programs outside the pinned toolchain.
        (b"#!/usr/bin/python3\nprint(1)\n", NOT_A_FORM),
        (b'#!/bin/sh\nexec /usr/bin/python3 "$@"\n', "which is not a pinned file in the toolchain"),
        (b'#!/bin/sh\nexec /opt/homebrew/bin/gh "$@"\n', "which is not a pinned file in the toolchain"),
        (b'#!/bin/sh\nexec LIBEXEC/bin/../../../opt/x "$@"\n', "which is not a pinned file in the toolchain"),
        (b'#!/bin/sh\nexec LIBEXEC/venvs/service/unpinned "$@"\n', "which is not a pinned file in the toolchain"),
        (b'#!/bin/sh -e\nexec LIBEXEC/bin/ship-no-ship-service "$@"\n', NOT_A_FORM),
        (b"#!/bin/sh\nexec LIBEXEC/bin/ship-no-ship-service\n", NOT_A_SHIM),
        (b'#!/bin/sh\nexec LIBEXEC/bin/ship-no-ship-service -x "$@"\n', NOT_A_SHIM),
        (b'#!/bin/sh\nexec LIBEXEC/bin/ship-no-ship-service "$@"\nexec /bin/true\n', NOT_A_SHIM),
        (b'#!/bin/sh\n/opt/homebrew/bin/node cli.js "$@"\n', NOT_A_SHIM),
        (b"#!LIBEXEC/venvs/service/bin/python -E\n", NOT_A_FORM),
        (b"#!LIBEXEC/venvs/service/bin/python -I -mfoo\n", NOT_A_FORM),
        (b"#!/opt/x/venvs/service/bin/python\n", "not a toolchain virtual environment"),
        (b"\x7fELF\x02\x01", NOT_A_FORM),
    ],
)
def test_only_the_three_allowed_forms_pass(install, content, message):
    install.pin("gh", content.replace(b"LIBEXEC", str(install.libexec).encode()))
    assert message in failures(install.run())["tool gh"]


@pytest.mark.parametrize(
    "content",
    [
        "THIN",
        "FAT",
        b"#!LIBEXEC/venvs/service/bin/python\nimport sys\nfrom ship_no_ship_service.cli import main\nsys.exit(main())\n",
        b"#!LIBEXEC/venvs/service/bin/python -I\nimport sys\n",
        b'#!/bin/sh\n# shim\nexec LIBEXEC/bin/ship-no-ship-service "$@"\n',
        b'#!/bin/sh\nexec LIBEXEC/venvs/service/bin/tool "$@"\n',
    ],
)
def test_the_three_allowed_forms_pass(install, content):
    install.pin_path("venvs/service/bin/tool", macho_image(["/usr/lib/libSystem.B.dylib"]))
    if content == "THIN":
        content = macho_image(["/usr/lib/libSystem.B.dylib"], dylinker="/usr/lib/dyld")
    elif content == "FAT":
        content = fat_image([macho_image(["/usr/lib/libc++.1.dylib"]), macho_image(["/System/Library/Frameworks/x"])])
    install.pin("gh", content.replace(b"LIBEXEC", str(install.libexec).encode()))
    assert [name for name in failures(install.run()) if name.startswith("tool")] == []


def test_a_shim_target_that_links_out_of_the_toolchain_fails(install):
    (install.libexec / "bin" / "real").symlink_to("/opt/homebrew/bin/gh")
    install.pin("gh", f'#!/bin/sh\nexec {install.libexec / "bin" / "real"} "$@"\n'.encode())
    assert "not a pinned file in the toolchain" in failures(install.run())["tool gh"]


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


@pytest.mark.parametrize(
    ("text", "grants"),
    [
        (f"!#acl 1\n{SOMEONE}:allow:read,write\n", ["user:someone allow read,write"]),
        (f"!#acl 1\n{EVERYONE}:allow:list,search\n", ["group:everyone allow list,search"]),
        (f"!#acl 1\n{EVERYONE}:allow,inherited:readsecurity\n", ["group:everyone allow readsecurity"]),
        (f"!#acl 1\n{EVERYONE}:deny:read\n", []),
        ("", []),
    ],
)
def test_access_grants_include_read(text, grants):
    assert fsinfo.access_grants(text) == grants


def test_inheritable_grants_need_an_inherit_flag():
    text = (
        f"!#acl 1\n{EVERYONE}:allow,file_inherit:read\n{EVERYONE}:allow,inherited:read\n"
        f"{EVERYONE}:deny,directory_inherit:read\n{EVERYONE}:allow:write\n"
    )
    assert fsinfo.inheritable_grants(text) == ["group:everyone allow read"]


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
    subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(target)], check=True)
    assert (files.write_grants(target), files.access_grants(target)) == ([], ["group:everyone allow read"])
    subprocess.run(["/bin/chmod", "-a", "everyone allow read", str(target)], check=True)
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


def test_the_command_checks_accounts_and_role_homes(install, monkeypatch, capsys):
    bad = FakeAccounts(logins={CLAUDE: ("/opt/elsewhere", "/bin/zsh")}, data=install.data)
    monkeypatch.setattr(doctor, "SystemAccounts", lambda: bad)
    monkeypatch.setattr(doctor, "SystemFileSystem", FakeFiles)
    (install.data / "home" / "codex" / ".zshrc").write_text("x", encoding="utf-8")
    args = ["--data-dir", str(install.data), "--libexec", str(install.libexec), "--plist", str(install.plist)]
    assert doctor.main([*args, "--logs-dir", str(install.logs)]) == 1
    out = capsys.readouterr().out.splitlines()
    assert (
        f"fail     account {CLAUDE}: home is /opt/elsewhere, not {install.data / 'home' / 'claude'}; shell is /bin/zsh, not {doctor.NO_SHELL}"
        in out
    )
    assert "fail     home codex: has .zshrc, which shells or Python load automatically; has unexpected .zshrc" in out
    assert f"pass     account {doctor.DAEMON}" in out


@pytest.mark.parametrize(
    ("login", "message"),
    [
        (None, "does not exist"),
        (("/opt/elsewhere/x", doctor.NO_SHELL), "home is /opt/elsewhere/x"),
        ((str(doctor.DAEMON_HOME), "/bin/zsh"), "shell is /bin/zsh"),
    ],
)
def test_service_accounts_have_their_planned_home_and_no_shell(install, login, message):
    found = failures(install.run(FakeAccounts(logins={doctor.DAEMON: login})))
    assert message in found[f"account {doctor.DAEMON}"]


@pytest.mark.parametrize(
    "entry", [".zshrc", ".profile", ".bashrc", ".pythonrc.py", "sitecustomize.py", "Library/Python"]
)
def test_role_homes_must_not_hold_files_that_load_automatically(install, entry):
    target = install.data / "home" / "claude" / entry
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x", encoding="utf-8")
    assert "load automatically" in failures(install.run())["home claude"]


def test_role_homes_hold_only_their_clis_entries(install):
    home = install.data / "home" / "codex"
    (home / ".codex").mkdir()
    (home / "Library").mkdir()
    assert "home codex" not in failures(install.run())
    (home / "notes.txt").write_text("x", encoding="utf-8")
    assert failures(install.run())["home codex"] == "has unexpected notes.txt"


def contents(install, in_cache=lambda path: True) -> dict[str, str]:
    found = failures(install.run(in_cache=in_cache))
    return {name: detail for name, detail in found.items() if name.startswith("toolchain file")}


@pytest.mark.parametrize(
    ("image", "message"),
    [
        (lambda lib: macho_image(["/opt/homebrew/opt/libuv/lib/libuv.1.dylib"]), "outside the toolchain"),
        (lambda lib: macho_image(weak=["/opt/homebrew/lib/libx.dylib"]), "outside the toolchain"),
        (
            lambda lib: macho_image(["@rpath/libuv.1.dylib"], rpaths=["/opt/homebrew/lib"]),
            "has rpath /opt/homebrew/lib",
        ),
        (lambda lib: macho_image(["@rpath/libuv.1.dylib"]), "cannot be resolved"),
        (lambda lib: macho_image(["@executable_path/../../../../opt/x.dylib"]), "outside the toolchain"),
        (lambda lib: macho_image(["libuv.dylib"]), "cannot be resolved"),
        (lambda lib: macho_image(["/usr/lib/../../opt/x.dylib"]), "outside the toolchain"),
        (lambda lib: macho_image([], dylinker="/opt/dyld"), "outside the toolchain"),
        (
            lambda lib: fat_image(
                [macho_image(["/usr/lib/libc++.1.dylib"]), macho_image(["/opt/homebrew/lib/x.dylib"])]
            ),
            "outside the toolchain",
        ),
        (lambda lib: macho_image(["/usr/lib/libSystem.B.dylib"])[:40], "cannot be read as Mach-O"),
        (
            lambda lib: macho_image(extra=[(macho.LC_DYLD_ENVIRONMENT, "DYLD_LIBRARY_PATH=/opt/evil")]),
            "LC_DYLD_ENVIRONMENT",
        ),
        (lambda lib: macho_image(extra=[(0x3A, "x")]), "not on the known-safe list"),
        (lambda lib: macho_image(["/System/Volumes/Data/opt/x.dylib"]), "outside the toolchain"),
        (lambda lib: macho_image(["/System/Library/../Volumes/Data/x.dylib"]), "outside the toolchain"),
        (lambda lib: macho_image(["/System/Applications/x.dylib"]), "outside the toolchain"),
        (lambda lib: macho_image(["@executable_path/libuv.dylib"], filetype=6), "uses @executable_path"),
        (lambda lib: macho_image([], rpaths=["@executable_path/../lib"], filetype=8), "uses @executable_path"),
    ],
)
def test_toolchain_binaries_may_load_only_toolchain_and_system_libraries(install, image, message):
    install.pin_path("venvs/service/lib/node", image(install.libexec))
    [(name, detail)] = contents(install).items()
    assert name == "toolchain file venvs/service/lib/node" and message in detail


def test_toolchain_relative_libraries_pass(install):
    install.pin_path("venvs/service/lib/libuv.1.dylib", macho_image(["/usr/lib/libSystem.B.dylib"]))
    image = macho_image(
        ["@rpath/libuv.1.dylib", "@loader_path/../lib/libuv.1.dylib", "/usr/lib/libSystem.B.dylib"],
        rpaths=["@loader_path/../lib", str(install.libexec / "venvs" / "service" / "lib")],
    )
    install.pin_path("venvs/service/bin/node", image)
    assert contents(install) == {}


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("/opt/homebrew/lib/python3.12/site-packages", "outside the toolchain"),
        ("../../../../../opt/elsewhere", "outside the toolchain"),
        ("import os; exec(open('/tmp/x').read())", "runs code at start-up"),
        ("import\tsite", "runs code at start-up"),
    ],
)
def test_pth_files_may_only_add_toolchain_directories(install, line, message):
    site = install.libexec / "venvs" / "service" / "lib" / "site-packages"
    site.mkdir(parents=True)
    (site / "evil.pth").write_text(f"# comment\n{line}\n", encoding="utf-8")
    assert message in contents(install)["toolchain file venvs/service/lib/site-packages/evil.pth"]


def test_a_pth_inside_the_toolchain_passes(install):
    site = install.libexec / "venvs" / "service" / "lib" / "site-packages"
    (site / "extra").mkdir(parents=True)
    (site / "ok.pth").write_text("extra\n", encoding="utf-8")
    assert contents(install) == {}


def test_python_start_up_hooks_are_refused_even_when_pinned(install):
    hook = install.libexec / "venvs" / "service" / "lib" / "sitecustomize.py"
    hook.parent.mkdir(parents=True)
    hook.write_text("import os\n", encoding="utf-8")
    assert contents(install) == {"toolchain file venvs/service/lib/sitecustomize.py": doctor.HOOK_REFUSED}
    install.pin_path("venvs/service/lib/sitecustomize.py", b"import os\n")
    assert contents(install) == {"toolchain file venvs/service/lib/sitecustomize.py": doctor.HOOK_REFUSED}


@pytest.mark.parametrize(("editable", "fails"), [(True, True), (False, False)])
def test_editable_installs_are_refused(install, editable, fails):
    info = install.libexec / "venvs" / "service" / "lib" / "pkg-1.0.dist-info"
    info.mkdir(parents=True)
    (info / "direct_url.json").write_text(
        json.dumps({"url": "file:///opt/src", "dir_info": {"editable": editable}}), encoding="utf-8"
    )
    assert bool(contents(install)) is fails


def test_the_macho_reader_reads_every_slice():
    image = fat_image(
        [
            macho_image(["/usr/lib/a.dylib"], rpaths=["@loader_path"]),
            macho_image(["/usr/lib/b.dylib"], dylinker="/usr/lib/dyld"),
        ]
    )
    info = macho.load_info(image)
    assert (info.libraries, info.rpaths, info.dylinkers) == (
        ["/usr/lib/a.dylib", "/usr/lib/b.dylib"],
        ["@loader_path"],
        ["/usr/lib/dyld"],
    )


@pytest.mark.skipif(not Path("/bin/ls").exists() or sys.platform != "darwin", reason="a real macOS binary")
def test_the_macho_reader_reads_a_real_system_binary():
    info = macho.load_info(Path("/bin/ls").read_bytes())
    assert any(name.startswith("/usr/lib/") for name in info.libraries)


def test_an_executable_may_use_its_own_folder_through_executable_path(install):
    install.pin_path("venvs/service/lib/libuv.1.dylib", macho_image(["/usr/lib/libSystem.B.dylib"], filetype=6))
    image = macho_image(["@executable_path/../lib/libuv.1.dylib", "/System/Library/Frameworks/CoreFoundation"])
    install.pin_path("venvs/service/bin/node", image)
    assert contents(install) == {}


@pytest.mark.parametrize(
    "image",
    [
        macho_image(["/usr/lib/libSystem.B.dylib"], rpaths=["@loader_path"], dylinker="/usr/lib/dyld"),
        fat_image([macho_image(["/usr/lib/a.dylib"]), macho_image(["/usr/lib/b.dylib"])]),
    ],
    ids=["thin", "fat"],
)
def test_every_truncation_is_a_clean_error_or_a_parse(image):
    for length in range(len(image) + 1):
        try:
            macho.load_info(image[:length])
        except macho.MachOError:
            pass


def test_a_corrupted_fat_header_is_a_clean_error():
    with pytest.raises(macho.MachOError):
        macho.load_info(struct.pack(">II", 0xCAFEBABE, 2) + b"\0" * 12)


def test_a_start_up_hook_package_is_refused_even_when_pinned(install):
    package = install.libexec / "venvs" / "service" / "lib" / "sitecustomize"
    package.mkdir(parents=True)
    install.pin_path("venvs/service/lib/sitecustomize/__init__.py", b"import os\n")
    assert contents(install) == {"toolchain file venvs/service/lib/sitecustomize": doctor.HOOK_REFUSED}


@pytest.mark.parametrize("name", ["evil.pth", "sitecustomize.py", "usercustomize.py", "sitecustomize", "usercustomize"])
@pytest.mark.parametrize("inside", [True, False], ids=["target-inside", "target-outside"])
def test_a_symlinked_start_up_file_fails_whatever_its_target(install, name, inside):
    site = install.libexec / "venvs" / "service" / "lib" / "site-packages"
    site.mkdir(parents=True)
    if inside:
        target = site / ("real" if name in ("sitecustomize", "usercustomize") else "real.txt")
        if target.name == "real":
            target.mkdir()
        else:
            target.write_text("extra\n", encoding="utf-8")
    else:
        target = install.root / "outside"
        target.write_text("import os\n", encoding="utf-8")
    (site / name).symlink_to(target)
    relative = f"toolchain file venvs/service/lib/site-packages/{name}"
    assert contents(install)[relative] == "is a Python start-up file that is a symlink"


def test_a_pinned_start_up_hook_still_fails_as_a_symlink(install):
    install.pin_path("venvs/service/lib/real.py", b"import os\n")
    (install.libexec / "venvs" / "service" / "lib" / "sitecustomize.py").symlink_to("real.py")
    install.pin_path("venvs/service/lib/sitecustomize.py", b"import os\n")
    assert "symlink" in contents(install)["toolchain file venvs/service/lib/sitecustomize.py"]


LIB = "venvs/service/lib"


@pytest.mark.parametrize(
    "image",
    [
        lambda lib: macho_image([f"{lib}/{LIB}/libmissing.dylib"]),
        lambda lib: macho_image(weak=[f"{lib}/{LIB}/libmissing.dylib"]),
        lambda lib: macho_image(weak=["@loader_path/libmissing.dylib"]),
        lambda lib: macho_image(["@rpath/libmissing.dylib"], rpaths=["@loader_path", f"{lib}/{LIB}"]),
        lambda lib: macho_image([f"{lib}/{LIB}/folder.dylib"]),
        lambda lib: macho_image([], dylinker=f"{lib}/{LIB}/dyld"),
    ],
    ids=["absolute", "weak", "weak-loader-path", "rpath", "directory", "dylinker"],
)
def test_a_toolchain_library_that_does_not_exist_fails(install, image):
    (install.libexec / LIB / "folder.dylib").mkdir(parents=True)
    install.pin_path(f"{LIB}/node", image(install.libexec))
    [(name, detail)] = contents(install).items()
    assert name == f"toolchain file {LIB}/node" and "which is not a file in the toolchain" in detail


def test_an_rpath_library_found_in_any_toolchain_rpath_passes(install):
    install.pin_path(f"{LIB}/real/libuv.1.dylib", macho_image(["/usr/lib/libSystem.B.dylib"]))
    (install.libexec / LIB / "libalias.dylib").symlink_to("real/libuv.1.dylib")
    image = macho_image(
        ["@rpath/libuv.1.dylib", "@loader_path/libalias.dylib"],
        weak=["@rpath/libuv.1.dylib"],
        rpaths=["@loader_path", "@loader_path/real"],
    )
    install.pin_path(f"{LIB}/node", image)
    assert contents(install) == {}


CACHE = {"/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"}
NOT_THERE = "which is not a file in the toolchain or a system library on disk or in the dyld shared cache"


@pytest.mark.parametrize(
    ("image", "fails"),
    [
        (macho_image(["/usr/lib/libSystem.B.dylib"]), False),
        (macho_image(["/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"]), False),
        (macho_image(["/usr/lib/libdoesnotexist.dylib"]), True),
        (macho_image(weak=["/usr/lib/libdoesnotexist.dylib"]), True),
        (macho_image(["@rpath/libdoesnotexist.dylib"], rpaths=["/usr/lib"]), True),
        (macho_image(["/System/Library/Frameworks/Made.framework/Made"]), True),
    ],
    ids=["cached", "cached-framework", "missing", "missing-weak", "missing-rpath", "missing-framework"],
)
def test_a_system_library_must_be_on_disk_or_in_the_shared_cache(install, image, fails):
    install.pin_path(f"{LIB}/node", image)
    found = contents(install, in_cache=lambda path: path in CACHE)
    assert found == (
        {f"toolchain file {LIB}/node": f"loads {macho.load_info(image).libraries[0]}, {NOT_THERE}"} if fails else {}
    )


def test_without_a_shared_cache_lookup_system_paths_are_accepted_by_path(install):
    install.pin_path(f"{LIB}/node", macho_image(["/usr/lib/libdoesnotexist.dylib"]))
    assert contents(install, in_cache=lambda path: None) == {}


@pytest.mark.skipif(not Path("/usr/lib/dyld").is_file(), reason="a system library file on disk")
def test_a_system_library_on_disk_passes_without_the_cache(install):
    install.pin_path(f"{LIB}/node", macho_image([], dylinker="/usr/lib/dyld"))
    assert contents(install, in_cache=lambda path: False) == {}


@pytest.mark.skipif(sys.platform != "darwin", reason="the real dyld shared cache")
def test_the_real_shared_cache_is_consulted(tmp_path):
    assert macho.shared_cache_contains("/usr/lib/libSystem.B.dylib") is True
    assert macho.shared_cache_contains("/usr/lib/libdoesnotexist.dylib") is False
    libexec = tmp_path.resolve()
    good, bad = libexec / "good", libexec / "bad"
    good.write_bytes(macho_image(["/usr/lib/libSystem.B.dylib"]))
    bad.write_bytes(macho_image(["/usr/lib/libdoesnotexist.dylib"]))
    assert doctor.macho_problem(good, libexec) is None
    assert NOT_THERE in (doctor.macho_problem(bad, libexec) or "")


@pytest.mark.skipif(sys.platform == "darwin", reason="elsewhere the cache cannot be asked")
def test_the_shared_cache_is_unknown_off_macos():
    assert macho.shared_cache_contains("/usr/lib/libSystem.B.dylib") is None


@pytest.mark.parametrize(
    "relative",
    [
        "site-packages/sitecustomize.pyc",
        "site-packages/usercustomize.pyc",
        "site-packages/sitecustomize.cpython-312-darwin.so",
        "site-packages/sitecustomize.abi3.so",
        "site-packages/usercustomize.cpython-312-darwin.so",
        "site-packages/__pycache__/sitecustomize.cpython-312.pyc",
        "site-packages/__pycache__/usercustomize.cpython-311.opt-1.pyc",
    ],
)
def test_every_form_of_a_start_up_hook_is_refused(install, relative):
    path = install.libexec / LIB / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x00hook")
    assert contents(install) == {f"toolchain file {LIB}/{relative}": doctor.HOOK_REFUSED}
    install.pin_path(f"{LIB}/{relative}", b"\x00hook")
    assert contents(install) == {f"toolchain file {LIB}/{relative}": doctor.HOOK_REFUSED}


def test_a_tampered_cache_beside_a_pinned_hook_fails(install):
    install.pin_path(f"{LIB}/site-packages/sitecustomize.py", b"import os\n")
    cached = install.libexec / LIB / "site-packages" / "__pycache__" / "sitecustomize.cpython-312.pyc"
    cached.parent.mkdir()
    cached.write_bytes(b"tampered")
    found = contents(install)
    assert found == {
        f"toolchain file {LIB}/site-packages/sitecustomize.py": doctor.HOOK_REFUSED,
        f"toolchain file {LIB}/site-packages/__pycache__/sitecustomize.cpython-312.pyc": doctor.HOOK_REFUSED,
    }


@pytest.mark.parametrize("name", ["sitecustomize.pyc", "sitecustomize.cpython-312-darwin.so"])
def test_a_symlinked_compiled_hook_fails(install, name):
    install.pin_path(f"{LIB}/real.bin", b"x")
    (install.libexec / LIB / name).symlink_to("real.bin")
    assert contents(install)[f"toolchain file {LIB}/{name}"] == "is a Python start-up file that is a symlink"


def test_a_pinned_compiled_hook_is_refused(install):
    install.pin_path(f"{LIB}/sitecustomize.abi3.so", macho_image(["/usr/lib/libSystem.B.dylib"]))
    assert contents(install) == {f"toolchain file {LIB}/sitecustomize.abi3.so": doctor.HOOK_REFUSED}


def write_config(install, key_path: str) -> Path:
    config = install.data / "config" / "service.toml"
    config.chmod(0o640)
    config.write_text(
        "[[repositories]]\n"
        'slug = "example-owner/example-repo"\n'
        "app_id = 7\n"
        "installation_id = 9\n"
        f"key_path = {json.dumps(key_path)}\n"
        'bot_login = "example-bot"\n'
        'base_branch = "main"\n',
        encoding="utf-8",
    )
    return config


def key_results(install, key_path: str) -> dict[str, tuple[str, str]]:
    config = write_config(install, key_path)
    return {r.name: (r.status, r.detail) for r in doctor.key_paths_check(config, install.data, True)}


def test_the_app_key_must_be_a_pem_in_the_keys_directory(install):
    good = str(install.data / "keys" / "example.pem")
    assert key_results(install, good) == {"app key example-owner/example-repo": (PASS, "")}


@pytest.mark.parametrize(
    ("where", "message"),
    [
        ("/var/empty/key.pem", "is not"),
        ("DATA/state/state.db", "is not"),
        ("DATA/keys/Example.pem", "is not"),
        ("DATA/keys/example.PEM", "is not"),
        ("DATA/keys/sub/example.pem", "is not"),
        ("DATA/keys/link.pem", "passes through a symlink"),
        ("DATA/keys/absent.pem", "is not installed"),
    ],
)
def test_an_app_key_anywhere_else_fails(install, where, message):
    (install.data / "keys" / "link.pem").symlink_to(install.data / "keys" / "example.pem")
    [(status, detail)] = key_results(install, where.replace("DATA", str(install.data))).values()
    assert status == FAIL and message in detail


def test_an_app_key_under_a_symlinked_parent_fails(install, tmp_path):
    linked = install.root / "linked"
    linked.symlink_to(install.data)
    config = write_config(install, str(linked / "keys" / "example.pem"))
    [result] = doctor.key_paths_check(config, linked, True)
    assert result.status == FAIL and "passes through a symlink" in result.detail


def test_an_unreadable_or_missing_config_follows_strictness(install, monkeypatch):
    config = install.data / "config" / "absent.toml"
    assert doctor.key_paths_check(config, install.data, True)[0].status == FAIL
    assert doctor.key_paths_check(config, install.data, False)[0].status == NOT_RUN
    bad = install.data / "config" / "service.toml"
    assert doctor.key_paths_check(bad, install.data, False)[0].status == FAIL  # "x" is not a valid config


@pytest.mark.parametrize("name", ["Other.pem", "other.PEM", "notes.txt", "sub"])
def test_the_keys_directory_holds_only_lowercase_pem_files(install, name):
    entry = install.data / "keys" / name
    if name == "sub":
        entry.mkdir()
    else:
        entry.write_text("k", encoding="utf-8")
        entry.chmod(0o400)
    found = failures(install.run())
    assert found[f"path {install.data / 'keys'}"] == f"{install.data / 'keys'} has unexpected entries {name}"


def test_a_symlinked_pem_in_the_keys_directory_fails(install):
    (install.data / "keys" / "other.pem").symlink_to(install.data / "keys" / "example.pem")
    assert "is a symlink" in failures(install.run())[f"path {install.data / 'keys'}"]


APP = "venvs/service/app"


def program_and_framework(install, framework_needs: str, framework_rpaths=()) -> None:
    """A program with rpath @executable_path/../Frameworks loading a framework that relies on it."""
    install.pin_path(f"{APP}/Frameworks/Bar.framework/Bar", macho_image(["/usr/lib/libSystem.B.dylib"], filetype=6))
    framework = macho_image([framework_needs], rpaths=framework_rpaths, filetype=6)
    install.pin_path(f"{APP}/Frameworks/Foo.framework/Foo", framework)
    program = macho_image(["@rpath/Foo.framework/Foo"], rpaths=["@executable_path/../Frameworks"])
    install.pin_path(f"{APP}/MacOS/app", program)


def test_a_framework_may_use_its_programs_rpaths(install):
    program_and_framework(install, "@rpath/Bar.framework/Bar")
    assert contents(install) == {}


def test_a_framework_whose_own_rpaths_miss_falls_back_to_its_programs(install):
    program_and_framework(install, "@rpath/Bar.framework/Bar", framework_rpaths=["@loader_path/../nowhere"])
    assert contents(install) == {}


def test_a_library_found_through_no_rpath_still_fails(install):
    program_and_framework(install, "@rpath/Missing.framework/Missing")
    found = contents(install)
    assert list(found) == [f"toolchain file {APP}/Frameworks/Foo.framework/Foo"]
    assert "which is not a file in the toolchain" in found[f"toolchain file {APP}/Frameworks/Foo.framework/Foo"]


def test_a_programs_rpath_outside_the_toolchain_is_not_borrowed(install):
    install.pin_path(f"{APP}/Frameworks/Foo.framework/Foo", macho_image(["@rpath/libx.dylib"], filetype=6))
    install.pin_path(f"{APP}/MacOS/app", macho_image([], rpaths=["/opt/homebrew/lib"]))
    found = contents(install)
    assert "has rpath /opt/homebrew/lib" in found[f"toolchain file {APP}/MacOS/app"]
    assert "outside the toolchain" in found[f"toolchain file {APP}/Frameworks/Foo.framework/Foo"]
