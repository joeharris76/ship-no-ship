"""``doctor``: read-only checks that the installed service is safe to activate.

It checks the path, owner and mode table, the trusted groups, the pinned toolchain and the
LaunchDaemon definition. It changes nothing. Run it with sudo once the service is installed, so it can
read the daemon's private directories. Each check reports ``pass``, ``fail``, ``warn`` or ``not_run``.
With ``--allow-not-run`` (only before installation) a missing account, lock file or unreadable path is
``not_run``; otherwise it is a failure. Exit codes: 0 all passed, 1 something failed, 3 some check did
not run.

The path rule. Each listed path must have exactly its table owner, group and mode and must not be a
symlink. The path and every directory above it, walked literally from ``/``:

- must be owned by root, or, above a path a service user owns, by that user;
- must not be group-writable unless the group is wheel or the path's own service group;
- must not be world-writable or carry an ACL entry that grants any kind of write;
- if it is confidential (keys, state, config, captured output, role homes), the path and its listed
  children must not carry an ACL entry that grants any access at all, including read and search,
  and no directory above it may carry an inheritable entry that grants any access;
- must not be a symlink, except the system links ``/etc``, ``/tmp`` and ``/var``, whose targets are
  walked the same way;
- must not sit on a volume that ignores ownership.
"""

from __future__ import annotations

import argparse
import configparser
import fnmatch
import grp
import hashlib
import json
import os
import plistlib
import pwd
import re
import stat
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from . import config as service_config, fsinfo, macho, membership

PASS = "pass"
FAIL = "fail"
WARN = "warn"
NOT_RUN = "not_run"
INCOMPLETE = 3

DEFAULT_LIBEXEC = Path("/usr/local/libexec/ship-no-ship")
DEFAULT_DATA = Path("/Library/Application Support/ship-no-ship")
DEFAULT_LOGS = Path("/Library/Logs/ship-no-ship")
LABEL = "ship-no-ship.daemon"
DEFAULT_PLIST = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
TOOLCHAIN_LOCK = "toolchain.lock.json"
DAEMON = "_ssnsd"
CLIS = ("claude", "codex", "muse", "agy")
SYMLINK_ALLOW = frozenset({"/etc", "/tmp", "/var"})


@dataclass(frozen=True)
class Result:
    name: str
    status: str
    detail: str = ""


def role_user(cli: str) -> str:
    return f"_ssns{cli}"


SERVICE_USERS = (DAEMON, *(role_user(cli) for cli in CLIS))


class MembershipError(Exception):
    """The system could not say whether a user is a member of a group."""


class Accounts(Protocol):
    def uid(self, name: str) -> int | None: ...

    def gid(self, name: str) -> int | None: ...

    def members(self, group: str) -> list[str] | None:
        """Every effective member of the group, or None when it does not exist.

        Raises MembershipError when membership cannot be decided for some user.
        """
        ...

    def nested(self, group: str) -> list[str] | None:
        """The groups nested in the group ([] when none), or None when that cannot be read."""
        ...

    def sharing_gid(self, group: str) -> list[str]:
        """Other group records with the same GID."""
        ...

    def login(self, name: str) -> tuple[str, str] | None:
        """The account's home directory and shell, or None when it does not exist."""
        ...


class SystemAccounts:
    def uid(self, name: str) -> int | None:
        try:
            return pwd.getpwnam(name).pw_uid
        except KeyError:
            return None

    def gid(self, name: str) -> int | None:
        try:
            return grp.getgrnam(name).gr_gid
        except KeyError:
            return None

    def members(self, group: str) -> list[str] | None:
        try:
            entry = grp.getgrnam(group)
        except KeyError:
            return None
        users = {user.pw_name: user for user in pwd.getpwall()}
        for name in SERVICE_USERS:
            try:
                users.setdefault(name, pwd.getpwnam(name))
            except KeyError:
                pass
        primary = [name for name, user in users.items() if user.pw_gid == entry.gr_gid]
        # macOS also counts nested groups; ask it for every user, not only the listed members.
        effective = []
        for name, user in users.items():
            answer = membership.is_member(user.pw_uid, entry.gr_gid)
            if answer is None:
                raise MembershipError(f"cannot tell whether {name} is a member")
            if answer:
                effective.append(name)
        return sorted({*entry.gr_mem, *primary, *effective})

    def nested(self, group: str) -> list[str] | None:
        return membership.nested_groups(group)

    def sharing_gid(self, group: str) -> list[str]:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            return []
        return sorted({entry.gr_name for entry in grp.getgrall() if entry.gr_gid == gid} - {group})

    def login(self, name: str) -> tuple[str, str] | None:
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            return None
        return entry.pw_dir, entry.pw_shell


class FileSystem(Protocol):
    def write_grants(self, path: Path) -> list[str]: ...

    def access_grants(self, path: Path) -> list[str]:
        """ACL allow entries that grant any read, search or write access."""
        ...

    def inheritable_grants(self, path: Path) -> list[str]:
        """ACL allow entries that pass any access on to new files or directories below."""
        ...

    def ignores_ownership(self, path: Path) -> bool: ...


class SystemFileSystem:
    def write_grants(self, path: Path) -> list[str]:
        return fsinfo.write_grants(fsinfo.acl_text(path))

    def access_grants(self, path: Path) -> list[str]:
        return fsinfo.access_grants(fsinfo.acl_text(path))

    def inheritable_grants(self, path: Path) -> list[str]:
        return fsinfo.inheritable_grants(fsinfo.acl_text(path))

    def ignores_ownership(self, path: Path) -> bool:
        return fsinfo.ignores_ownership(path)


@dataclass(frozen=True)
class Rule:
    path: Path
    owner: str
    group: str
    mode: int
    directory: bool
    required: bool = True
    children: str | None = None  # a glob of files under the directory that share ``child_mode``
    child_mode: int | None = None
    tree: bool = False  # every entry below: same owner, dirs 0755, files 0755 or 0644, links stay inside
    private: bool = False  # confidential: no ACL entry may grant even read or search, here or on children
    only: str | None = None  # a regular expression every entry in the directory must match


# An App key file name: lowercase, ending in .pem. Nothing else may sit in the keys directory.
KEY_NAME = r"[a-z0-9][a-z0-9._-]*\.pem"


def table(
    data: Path = DEFAULT_DATA, libexec: Path = DEFAULT_LIBEXEC, logs: Path = DEFAULT_LOGS, plist: Path = DEFAULT_PLIST
) -> list[Rule]:
    """The installed path, owner and mode table (also in the service README)."""
    rules = [
        Rule(libexec, "root", "wheel", 0o755, True, tree=True),
        Rule(Path("/etc/sudoers.d/ship-no-ship"), "root", "wheel", 0o440, False),
        Rule(Path("/etc/newsyslog.d/ship-no-ship.conf"), "root", "wheel", 0o644, False),
        Rule(plist, "root", "wheel", 0o644, False),
        Rule(data, "root", "wheel", 0o755, True),
        Rule(data / "config", "root", DAEMON, 0o750, True, private=True),
        Rule(data / "config" / "service.toml", "root", DAEMON, 0o440, False, private=True),
        Rule(
            data / "keys", DAEMON, DAEMON, 0o700, True, children="*.pem", child_mode=0o400, private=True, only=KEY_NAME
        ),
        Rule(data / "state", DAEMON, DAEMON, 0o700, True, children="state.db*", child_mode=0o600, private=True),
        Rule(data / "mirror", DAEMON, DAEMON, 0o755, True, required=False),
        Rule(data / "requests", DAEMON, DAEMON, 0o755, True),
        Rule(data / "work", "root", "wheel", 0o755, True),
        Rule(data / "captured", DAEMON, DAEMON, 0o700, True, private=True),
        Rule(data / "run", DAEMON, DAEMON, 0o755, True, children="*.json", child_mode=0o644),
        # The supervisor's process records sit under a root-owned parent, so the daemon cannot swap them.
        Rule(data / "attempts", "root", "wheel", 0o700, True),
        Rule(logs, DAEMON, "admin", 0o750, True),
    ]
    rules += [Rule(data / "home" / cli, role_user(cli), role_user(cli), 0o700, True, private=True) for cli in CLIS]
    return rules


def _inside(path: Path, top: Path) -> bool:
    return path == top or top in path.parents


class PathAudit:
    """Checks rules against the filesystem. ``root`` is where the parent walk stops: ``/`` when installed."""

    def __init__(self, accounts: Accounts, files: FileSystem, root: Path = Path("/"), strict: bool = True) -> None:
        self.accounts = accounts
        self.files = files
        self.root = root
        self.strict = strict
        self.missing = FAIL if strict else NOT_RUN

    def _chain(self, path: Path) -> list[Path]:
        """Every directory above ``path``, literally, from the nearest up to ``root``."""
        chain = []
        for element in path.parents:
            chain.append(element)
            if element == self.root:
                break
        return chain

    def _element(self, path: Path, owners: set[int], groups: set[int], private: bool = False) -> str | None:
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid not in owners:
            return f"{path} is owned by uid {info.st_uid}, which may not own a parent of this path"
        if stat.S_ISLNK(info.st_mode):
            return None if str(path) in SYMLINK_ALLOW else f"{path} is a symlink"
        if mode & stat.S_IWOTH:
            return f"{path} is writable by everyone"
        if mode & stat.S_IWGRP and info.st_gid not in groups:
            return f"{path} is writable by group {info.st_gid}"
        grants = self.files.write_grants(path)
        if grants:
            return f"{path} has an ACL that grants {'; '.join(grants)}"
        # Above a confidential path, an inherited entry would reach anything created there later.
        inherited = self.files.inheritable_grants(path) if private else []
        if inherited:
            return f"{path} has an inheritable ACL that grants {'; '.join(inherited)}"
        return None

    def _parents(self, path: Path, owners: set[int], groups: set[int], private: bool = False) -> str | None:
        pending = self._chain(path)
        while pending:
            element = pending.pop(0)
            problem = self._element(element, owners, groups, private)
            if problem:
                return problem
            if element.is_symlink():
                target = element.resolve()
                pending = [target, *self._chain(target), *pending]
        return None

    def _exact(
        self, path: Path, owner: int, group: int, mode: int, directory: bool, private: bool = False
    ) -> str | None:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            return f"{path} is a symlink"
        if directory != stat.S_ISDIR(info.st_mode) or not (directory or stat.S_ISREG(info.st_mode)):
            return f"{path} is not a {'directory' if directory else 'regular file'}"
        if (info.st_uid, info.st_gid) != (owner, group):
            return f"{path} is owned by {info.st_uid}:{info.st_gid}, not {owner}:{group}"
        if stat.S_IMODE(info.st_mode) != mode:
            return f"{path} has mode {stat.S_IMODE(info.st_mode):04o}, not {mode:04o}"
        grants = self.files.access_grants(path) if private else self.files.write_grants(path)
        if grants:
            return f"{path} has an ACL that grants {'; '.join(grants)}"
        return None

    def check(self, rule: Rule) -> Result:
        name = f"path {rule.path}"
        try:
            return self._check(rule)
        except PermissionError:
            return Result(name, self.missing, "cannot be inspected as this user; run doctor with sudo")
        except OSError as exc:
            return Result(name, FAIL, f"cannot be inspected: {exc.strerror or exc}")

    def _check(self, rule: Rule) -> Result:
        name = f"path {rule.path}"
        owner, group = self.accounts.uid(rule.owner), self.accounts.gid(rule.group)
        root_uid, wheel = self.accounts.uid("root"), self.accounts.gid("wheel")
        if owner is None or group is None or root_uid is None or wheel is None:
            return Result(name, self.missing, f"account {rule.owner}:{rule.group} does not exist")
        if not rule.path.exists() and not rule.path.is_symlink():
            if not rule.required:
                return Result(name, PASS, "absent (optional)")
            return Result(name, self.missing, "missing")
        owners = {root_uid, owner}
        groups = {wheel, group} if rule.group in SERVICE_USERS else {wheel}
        problem = self._parents(rule.path, owners, groups, rule.private) or self._exact(
            rule.path, owner, group, rule.mode, rule.directory, rule.private
        )
        if problem is None and self.files.ignores_ownership(rule.path):
            problem = f"{rule.path} is on a volume that ignores ownership"
        if problem is None and rule.only is not None:
            unexpected = [entry for entry in sorted(os.listdir(rule.path)) if re.fullmatch(rule.only, entry) is None]
            if unexpected:
                problem = f"{rule.path} has unexpected entries {', '.join(unexpected)}"
        if problem is None and rule.children and rule.child_mode is not None:
            # listdir, not glob: glob hides a directory this user cannot read, which would look clean.
            for entry in sorted(fnmatch.filter(os.listdir(rule.path), rule.children)):
                problem = self._exact(rule.path / entry, owner, group, rule.child_mode, False, rule.private)
                if problem:
                    break
        if problem is None and rule.tree:
            problem = self._tree(rule.path, owner, group)
        return Result(name, FAIL if problem else PASS, problem or "")

    def _tree(self, top: Path, owner: int, group: int) -> str | None:
        real_top = top.resolve()
        for directory, names, files in os.walk(top, followlinks=False):
            for entry in [*names, *files]:
                path = Path(directory) / entry
                info = path.lstat()
                if (info.st_uid, info.st_gid) != (owner, group):
                    return f"{path} is owned by {info.st_uid}:{info.st_gid}"
                if stat.S_ISLNK(info.st_mode):
                    if not _inside(path.resolve(), real_top):
                        return f"{path} links outside {top}"
                    continue
                allowed = (0o755,) if stat.S_ISDIR(info.st_mode) else (0o755, 0o644)
                if stat.S_IMODE(info.st_mode) not in allowed:
                    return f"{path} has mode {stat.S_IMODE(info.st_mode):04o}"
                grants = self.files.write_grants(path)
                if grants:
                    return f"{path} has an ACL that grants {'; '.join(grants)}"
        return None


# Groups that give their members power over the machine or the owner's files. No service user may be in them.
PRIVILEGED_GROUPS = ("staff", "admin")


def groups_check(accounts: Accounts, strict: bool) -> list[Result]:
    """Only root may be in wheel, each service group holds only its own user, and no service user is staff or admin.

    Membership is effective membership: listed members, users whose primary group it is, and, on
    macOS, whoever the system counts as a member. Wheel and the service groups may not nest other groups,
    and none of these groups may share its GID.
    """
    expected = {"wheel": {"root"}, **{user: {user} for user in SERVICE_USERS}}
    results = []
    for group in (*expected, *PRIVILEGED_GROUPS):
        name = f"group {group}"
        try:
            members = accounts.members(group)
        except MembershipError as exc:
            results.append(Result(name, FAIL if strict else NOT_RUN, f"membership cannot be checked: {exc}"))
            continue
        if members is None:
            results.append(Result(name, FAIL if strict else NOT_RUN, "does not exist"))
            continue
        if group in expected:
            extra = sorted(set(members) - expected[group])
            problems = [f"has members {', '.join(extra)}"] if extra else []
        else:
            extra = sorted(set(members) & set(SERVICE_USERS))
            problems = [f"has service users {', '.join(extra)}"] if extra else []
        # Members of a nested group, or of another record with the same GID, are members too. Staff and
        # admin often nest directory groups on managed Macs; for them the system's own membership answer
        # above already covers the service users.
        nested = accounts.nested(group) if group in expected else []
        shared = accounts.sharing_gid(group)
        problems += [f"has nested groups {', '.join(nested)}"] if nested else []
        problems += [f"shares its GID with {', '.join(shared)}"] if shared else []
        if problems:
            results.append(Result(name, FAIL, "; ".join(problems)))
        elif nested is None:
            results.append(Result(name, FAIL if strict else NOT_RUN, "its nested groups cannot be read"))
        else:
            results.append(Result(name, PASS))
    return results


DAEMON_HOME = Path("/var/empty")
NO_SHELL = "/usr/bin/false"
# Files that shells and Python load on their own from a home directory. Role homes must not have them.
AUTOLOADED = (
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".profile",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".pythonrc",
    ".pythonrc.py",
    "sitecustomize.py",
    "usercustomize.py",
    "Library/Python",
    ".local/lib",
)
# What each CLI keeps in its role home (documented in the README table); everything else is unexpected.
CLI_HOME_ENTRIES = {
    "claude": (".claude", ".claude.json", "Library"),
    "codex": (".codex", "Library"),
    "muse": (".config", ".muse", "Library"),
    "agy": (".gemini", ".config", "Library"),
}


def home_of(name: str, data: Path) -> Path:
    return DAEMON_HOME if name == DAEMON else data / "home" / name.removeprefix("_ssns")


def accounts_check(accounts: Accounts, data: Path, strict: bool) -> list[Result]:
    """Each service user has its planned home and no login shell."""
    results = []
    for name in SERVICE_USERS:
        login = accounts.login(name)
        if login is None:
            results.append(Result(f"account {name}", FAIL if strict else NOT_RUN, "does not exist"))
            continue
        home, shell = login
        problems = []
        if Path(home) != home_of(name, data):
            problems.append(f"home is {home}, not {home_of(name, data)}")
        if shell != NO_SHELL:
            problems.append(f"shell is {shell}, not {NO_SHELL}")
        results.append(Result(f"account {name}", FAIL if problems else PASS, "; ".join(problems)))
    return results


def homes_check(data: Path, strict: bool) -> list[Result]:
    """Role homes hold only their CLI's expected entries, and nothing a shell or Python loads on its own."""
    results = []
    for cli in CLIS:
        home, name = data / "home" / cli, f"home {cli}"
        try:
            entries = sorted(os.listdir(home))
        except FileNotFoundError:
            continue  # the path table reports a missing home
        except PermissionError:
            results.append(
                Result(name, FAIL if strict else NOT_RUN, "cannot be read as this user; run doctor with sudo")
            )
            continue
        loaded = [item for item in AUTOLOADED if os.path.lexists(home / item)]
        unexpected = [item for item in entries if item not in CLI_HOME_ENTRIES[cli]]
        problems = [f"has {', '.join(loaded)}, which shells or Python load automatically"] if loaded else []
        problems += [f"has unexpected {', '.join(unexpected)}"] if unexpected else []
        results.append(Result(name, FAIL if problems else PASS, "; ".join(problems)))
    return results


def read_pins(libexec: Path) -> dict[str, str] | None:
    path = libexec / TOOLCHAIN_LOCK
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(name): str(item["sha256"]) for name, item in data["tools"].items()}


MACH_O = (
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)
_SHIM_EXEC = re.compile(r'exec (/[^\s"\'$;&|`()<>\\]+) "\$@"')


def _pinned_path(target: str, libexec: Path, pins: Mapping[str, str]) -> bool:
    """An absolute path, without "..", to a file pinned in the lock, after resolving links."""
    path = Path(target)
    if not path.is_absolute() or ".." in path.parts:
        return False
    real, top = Path(os.path.realpath(path)), Path(os.path.realpath(libexec))
    if not _inside(real, top):
        return False
    relative = real.relative_to(top).as_posix()
    return relative in pins or (relative.startswith("bin/") and relative[4:] in pins)


def form_problem(content: bytes, libexec: Path, pins: Mapping[str, str]) -> str | None:
    """Why a toolchain bin file is not one of the three allowed forms, or None.

    - a Mach-O binary;
    - a Python console script whose first line is exactly ``#!<libexec>/venvs/<name>/bin/python``,
      optionally followed by `` -I``;
    - a shell shim whose first line is exactly ``#!/bin/sh`` and whose only command is
      ``exec <pinned file in the toolchain> "$@"``.

    No other interpreter, flag or argument is accepted: interpreter flags can load code from the
    current directory or the user's home.
    """
    if content[:4] in MACH_O:
        return None
    lines = content.decode("utf-8", "replace").splitlines() or [""]
    first = lines[0]
    python = re.fullmatch(r"#!(/\S+/venvs/[A-Za-z0-9._-]+/bin/python)( -I)?", first)
    if python is not None:
        interpreter = Path(python.group(1))
        if ".." in interpreter.parts or interpreter.parent.parent.parent != libexec / "venvs":
            return f"uses {interpreter}, which is not a toolchain virtual environment"
        return None
    if first != "#!/bin/sh":
        return "is not a Mach-O binary, a toolchain Python script or a /bin/sh shim"
    commands = [line.strip() for line in lines[1:] if line.strip() and not line.strip().startswith("#")]
    match = _SHIM_EXEC.fullmatch(commands[0]) if len(commands) == 1 else None
    if match is None:
        return 'is a shim whose only command is not exec <pinned path> "$@"'
    if not _pinned_path(match.group(1), libexec, pins):
        return f"execs {match.group(1)}, which is not a pinned file in the toolchain"
    return None


def toolchain(libexec: Path, pins: Mapping[str, str] | None, strict: bool) -> list[Result]:
    """Every file in ``<libexec>/bin`` is pinned, matches its hash and has an allowed form.

    Lock keys without a slash name files in ``bin/``; keys with one are paths relative to the toolchain,
    for files a shim may exec.
    """
    if pins is None:
        return [Result("toolchain", FAIL if strict else NOT_RUN, f"no {TOOLCHAIN_LOCK} is installed")]
    results = []
    present = {entry.name for entry in (libexec / "bin").iterdir()} if (libexec / "bin").is_dir() else set()
    results += [Result(f"tool {name}", FAIL, "is not pinned") for name in sorted(present - set(pins))]
    for key, expected in sorted(pins.items()):
        relative = key if "/" in key else f"bin/{key}"
        name = f"tool {key}"
        if ".." in Path(relative).parts or Path(relative).is_absolute():
            results.append(Result(name, FAIL, "is not a path inside the toolchain"))
            continue
        try:
            content = (libexec / relative).read_bytes()
        except OSError as exc:
            results.append(Result(name, FAIL, f"cannot be read: {exc.strerror or exc}"))
            continue
        if hashlib.sha256(content).hexdigest() != expected:
            problem: str | None = "does not match its pin"
        else:
            problem = form_problem(content, libexec, pins)
        results.append(Result(name, FAIL if problem else PASS, problem or ""))
    return results


SYSTEM_LIBRARIES = (Path("/usr/lib"), Path("/System/Library"))
# The data volume is writable; nothing on it counts as a system library.
UNTRUSTED_SYSTEM = (Path("/System/Volumes"),)
HOOK_MODULES = ("sitecustomize", "usercustomize")


def _hook_name(name: str) -> bool:
    """A site or user customize hook in any form Python imports: a .py, .pyc or extension module, a
    package, or a cached ``__pycache__/<hook>.cpython-3XX.pyc``. The module name is before the first dot."""
    return name.split(".", 1)[0] in HOOK_MODULES


def _start_up_name(name: str) -> bool:
    """A name Python's site module loads on its own: a .pth file or a site or user customize hook."""
    return name.endswith(".pth") or _hook_name(name)


def _system_library(path: Path) -> bool:
    """Under /usr/lib or /System/Library. These may exist only in the dyld shared cache, so they are
    matched by normalised path."""
    normal = Path(os.path.normpath(path))
    trusted = any(_inside(normal, top) for top in SYSTEM_LIBRARIES)
    return trusted and not any(_inside(normal, top) for top in UNTRUSTED_SYSTEM)


def _toolchain_file(path: Path, libexec: Path) -> bool:
    """An existing regular file inside the toolchain, after resolving links."""
    real = Path(os.path.realpath(path))
    return _inside(real, Path(os.path.realpath(libexec))) and real.is_file()


CacheLookup = Callable[[str], bool | None]
"""Whether the dyld shared cache holds a path; None when that cannot be asked (not macOS 11+)."""


def _system_present(path: Path, in_cache: CacheLookup) -> bool:
    """A system library that dyld will find: a regular file on disk under the system paths, or in the
    shared cache. When the cache cannot be asked, the path alone is accepted, as before macOS 11."""
    real = Path(os.path.realpath(path))
    if _system_library(real) and real.is_file():
        return True
    return in_cache(os.path.normpath(path)) is not False


def _library_problem(path: Path, libexec: Path) -> str | None:
    """A library path must stay in the toolchain, or be a system library under /usr/lib or /System."""
    if _system_library(path):
        return None
    if _inside(Path(os.path.realpath(os.path.normpath(path))), Path(os.path.realpath(libexec))):
        return None
    return f"loads {path}, outside the toolchain and the system libraries"


def _present(item: Path, libexec: Path, in_cache: CacheLookup) -> bool:
    """Whether dyld would find a library at ``item``: a system library it can load, or a toolchain file."""
    return _system_present(item, in_cache) if _system_library(item) else _toolchain_file(item, libexec)


def macho_problem(
    path: Path,
    libexec: Path,
    in_cache: CacheLookup = macho.shared_cache_contains,
    loader_chains: Sequence[Sequence[Path]] = (),
) -> str | None:
    """Why a Mach-O file in the toolchain could load code from outside it, or None.

    dyld resolves an ``@rpath`` library with the image's own rpaths, then with those of the images
    that loaded it, up to the main program. ``loader_chains`` holds, for each distinct way a program
    loads this image, the loaders' rpaths in search order. When the image's own rpaths find no file,
    every chain must find one, since dyld uses whichever chain loaded the image. Every candidate must
    stay inside the toolchain or the system paths.
    """
    try:
        info = macho.load_info(path.read_bytes())
    except macho.MachOError as exc:
        return f"cannot be read as Mach-O: {exc}"
    if info.refused:
        return f"has {info.refused[0]}"
    names = [*info.rpaths, *info.libraries, *info.dylinkers]
    if not info.executable_only and any(name.startswith("@executable_path") for name in names):
        return "is a library or bundle that uses @executable_path, which depends on the program loading it"
    origin = path.parent
    for rpath in info.rpaths:
        expanded = macho.resolve(rpath, origin, [])
        if expanded is None:
            return f"has rpath {rpath}, which cannot be resolved"
        problem = _library_problem(expanded[0], libexec)
        if problem:
            return f"has rpath {rpath}: {problem}"

    def present(items: Sequence[Path]) -> bool:
        return any(_present(item, libexec, in_cache) for item in items)

    missing = "which is not a file in the toolchain or a system library on disk or in the dyld shared cache"
    for name in [*info.libraries, *info.dylinkers]:
        by_rpath = name.startswith("@rpath/")
        candidates = [] if by_rpath and not info.rpaths else macho.resolve(name, origin, info.rpaths)
        if candidates is None or (by_rpath and not info.rpaths and not loader_chains):
            return f"loads {name}, which cannot be resolved inside the toolchain"
        for candidate in candidates:
            problem = _library_problem(candidate, libexec)
            if problem:
                return problem
        # When a library is missing, dyld looks for its file name in /usr/local/lib and /usr/lib, which
        # the toolchain does not control. Weak libraries are searched for the same way.
        if present(candidates):
            continue
        if not by_rpath or not loader_chains:
            return f"loads {name}, {missing}"
        for chain in loader_chains:
            through = [base / name.removeprefix("@rpath/") for base in chain]
            for candidate in through:
                problem = _library_problem(candidate, libexec)
                if problem:
                    return problem
            if not present(through):
                return f"loads {name}, {missing}, through the rpaths of a program that loads it"
    return None


def pth_problem(path: Path, libexec: Path) -> str | None:
    """A .pth file may only add directories inside the toolchain; import lines run code at start-up."""
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("import ", "import\t")):
            return f"runs code at start-up: {line[:60]!r}"
        target = Path(line) if Path(line).is_absolute() else path.parent / line
        if not _inside(Path(os.path.realpath(target)), Path(os.path.realpath(libexec))):
            return f"adds {line[:80]}, outside the toolchain"
    return None


def editable_problem(path: Path) -> str | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return "cannot be read"
    if isinstance(data, dict) and (data.get("dir_info") or {}).get("editable") is True:
        return "is an editable install, which loads code from outside the toolchain"
    return None


HOOK_REFUSED = "is a Python start-up hook, which is not allowed in the toolchain"


def toolchain_contents(libexec: Path, in_cache: CacheLookup = macho.shared_cache_contains) -> list[Result]:
    """Nothing in the toolchain may load code from outside it: Mach-O libraries, .pth files, site hooks."""
    results: list[Result] = []
    images: list[tuple[Path, str]] = []
    for directory, folders, files in os.walk(libexec, followlinks=False):
        # A link has no content of its own to audit, and its target can change without the link changing.
        for entry in sorted({*folders, *files}):
            path = Path(directory) / entry
            if _start_up_name(entry) and path.is_symlink():
                relative = path.relative_to(libexec).as_posix()
                results.append(
                    Result(f"toolchain file {relative}", FAIL, "is a Python start-up file that is a symlink")
                )
        for folder in sorted(folders):
            hook = Path(directory) / folder
            if _hook_name(folder) and not hook.is_symlink():
                results.append(Result(f"toolchain file {hook.relative_to(libexec).as_posix()}", FAIL, HOOK_REFUSED))
        for entry in sorted(files):
            path = Path(directory) / entry
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(libexec).as_posix()
            problem = None
            if _hook_name(entry):
                problem = HOOK_REFUSED
            elif entry.endswith(".pth"):
                problem = pth_problem(path, libexec)
            elif entry == "direct_url.json" and Path(directory).name.endswith(".dist-info"):
                problem = editable_problem(path)
            else:
                with path.open("rb") as handle:
                    head = handle.read(4)
                if macho.is_macho(head):
                    images.append((path, relative))
            if problem:
                results.append(Result(f"toolchain file {relative}", FAIL, problem))
    loaders = _loader_rpaths([path for path, _ in images], libexec, in_cache)
    for path, relative in images:
        problem = macho_problem(path, libexec, in_cache, loaders.get(Path(os.path.realpath(path)), []))
        if problem:
            results.append(Result(f"toolchain file {relative}", FAIL, problem))
    return results or [Result("toolchain contents", PASS)]


def _loader_rpaths(images: Sequence[Path], libexec: Path, in_cache: CacheLookup) -> dict[Path, list[tuple[Path, ...]]]:
    """For each library, the distinct loader rpath lists it is loaded with, walking from each main program.

    dyld resolves an ``@rpath`` name with the referencing image's own rpaths, then its loader's, up to
    the main program, and follows the first candidate that exists. Each distinct rpath list that
    reaches a library is kept separately, because dyld uses one of them per load. A main program has
    no loader, and a library that no program reaches gets none. Keys are real paths.
    """
    infos: dict[Path, macho.LoadInfo] = {}
    for path in images:
        try:
            infos[Path(os.path.realpath(path))] = macho.load_info(path.read_bytes())
        except macho.MachOError:
            continue  # reported by macho_problem
    chains: dict[Path, list[tuple[Path, ...]]] = {}

    def own(path: Path, info: macho.LoadInfo) -> list[Path]:
        resolved = [macho.resolve(rpath, path.parent, []) for rpath in info.rpaths]
        return [item[0] for item in resolved if item is not None]

    def visit(path: Path, loaders: tuple[Path, ...]) -> None:
        info = infos[path]
        chain = tuple(dict.fromkeys([*own(path, info), *loaders]))
        for name in info.libraries:
            if name.startswith("@rpath/"):
                candidates = [base / name.removeprefix("@rpath/") for base in chain]
            else:
                candidates = macho.resolve(name, path.parent, []) or []
            found = next((item for item in candidates if _present(item, libexec, in_cache)), None)
            if found is None or _system_library(found):
                continue
            dependency = Path(os.path.realpath(found))
            if dependency not in infos or infos[dependency].executable_only:
                continue
            known = chains.setdefault(dependency, [])
            if chain in known:
                continue
            known.append(chain)
            visit(dependency, chain)

    for path, info in infos.items():
        if info.executable_only:
            visit(path, ())
    return chains


def venvs(libexec: Path) -> list[Result]:
    """Each virtual environment's interpreter must come from inside the toolchain tree."""
    results = []
    for config in sorted(libexec.rglob("pyvenv.cfg")):
        parser = configparser.ConfigParser()
        parser.read_string("[venv]\n" + config.read_text(encoding="utf-8"))
        home = parser.get("venv", "home", fallback="")
        path = Path(home)
        ok = (
            path.is_absolute()
            and ".." not in path.parts
            and _inside(Path(os.path.realpath(path)), Path(os.path.realpath(libexec)))
        )
        detail = "" if ok else f"home {home or '(none)'} is outside {libexec}"
        results.append(Result(f"venv {config.parent.name}", PASS if ok else FAIL, detail))
    return results


DAEMON_ARGUMENTS = ("run",)
# The keys the daemon's plist may set. Anything else (WorkingDirectory, StandardInPath,
# EnvironmentVariables, Program, ...) could change what runs or what it reads.
PLIST_KEYS = frozenset(
    {
        "Label",
        "ProgramArguments",
        "UserName",
        "GroupName",
        "RunAtLoad",
        "KeepAlive",
        "ThrottleInterval",
        "ProcessType",
        "StandardOutPath",
        "StandardErrorPath",
    }
)


def launch_daemon(plist: Path, libexec: Path, logs: Path, strict: bool) -> Result:
    """The daemon runs exactly the toolchain's service program, as the daemon user, logging under ``logs``."""
    name = f"launchd {LABEL}"
    try:
        data: Any = plistlib.loads(plist.read_bytes())
    except FileNotFoundError:
        return Result(name, FAIL if strict else NOT_RUN, f"{plist} is not installed")
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        return Result(name, FAIL, f"{plist} cannot be read: {exc}")
    if not isinstance(data, dict):
        return Result(name, FAIL, f"{plist} is not a dictionary")
    expected = [str(libexec / "bin" / "ship-no-ship-service"), *DAEMON_ARGUMENTS]
    extra = sorted(set(data) - PLIST_KEYS)
    bad_logs = [
        key
        for key in ("StandardOutPath", "StandardErrorPath")
        if key in data
        and (
            ".." in Path(str(data[key])).parts
            or not _inside(Path(str(data[key])), logs)
            or Path(str(data[key])) == logs
        )
    ]
    problems = [
        (data.get("Label") != LABEL, f"Label is not {LABEL}"),
        (data.get("UserName") != DAEMON or data.get("GroupName") != DAEMON, f"it does not run as {DAEMON}"),
        (data.get("ProgramArguments") != expected, f"ProgramArguments are not exactly {expected}"),
        (bool(extra), f"it sets keys outside the allowed set: {', '.join(extra)}"),
        (bool(bad_logs), f"{', '.join(bad_logs)} must be inside {logs}"),
    ]
    failed = [what for bad, what in problems if bad]
    return Result(name, FAIL if failed else PASS, "; ".join(failed))


def key_paths_check(config: Path, data: Path, strict: bool) -> list[Result]:
    """Each App key the service reads is ``<data>/keys/<name>.pem`` itself, reached through no symlink.

    doctor reads the key as root on the daemon user's behalf, so the configured path must not lead
    anywhere else the daemon user owns a file.
    """
    missing = FAIL if strict else NOT_RUN
    try:
        settings = service_config.load(config)
    except service_config.ConfigError as exc:
        cause = exc.__cause__
        if isinstance(cause, PermissionError):
            return [Result("app keys", missing, f"{config} cannot be read as this user; run doctor with sudo")]
        if isinstance(cause, FileNotFoundError):
            return [Result("app keys", missing, f"{config} is not installed")]
        return [Result("app keys", FAIL, str(exc))]
    keys, results = data / "keys", []
    for repository in settings.repositories:
        name, key = f"app key {repository.slug}", repository.key_path
        if key.parent != keys or re.fullmatch(KEY_NAME, key.name) is None:
            results.append(Result(name, FAIL, f"key_path {key} is not {keys}/<lowercase name>.pem"))
            continue
        if os.path.realpath(key) != str(key):
            results.append(Result(name, FAIL, f"key_path {key} passes through a symlink"))
            continue
        try:
            info = key.lstat()
        except PermissionError:
            results.append(Result(name, missing, "cannot be inspected as this user; run doctor with sudo"))
            continue
        except FileNotFoundError:
            results.append(Result(name, missing, f"{key} is not installed"))
            continue
        regular = stat.S_ISREG(info.st_mode)
        results.append(Result(name, PASS if regular else FAIL, "" if regular else f"{key} is not a regular file"))
    return results


def run(
    *,
    accounts: Accounts,
    files: FileSystem,
    rules: Sequence[Rule],
    libexec: Path,
    plist: Path | None,
    data: Path | None = None,
    logs: Path = DEFAULT_LOGS,
    strict: bool = True,
    root: Path = Path("/"),
    probes: Callable[[], Iterable[Result]] | None = None,
    in_cache: CacheLookup = macho.shared_cache_contains,
    config: Path | None = None,
) -> list[Result]:
    audit = PathAudit(accounts, files, root, strict)
    results = [audit.check(rule) for rule in rules]
    results += groups_check(accounts, strict)
    if data is not None:
        results += accounts_check(accounts, data, strict) + homes_check(data, strict)
        if config is not None:
            results += key_paths_check(config, data, strict)
    try:
        pins = read_pins(libexec)
        results += toolchain(libexec, pins, strict)
        if libexec.is_dir():
            results += venvs(libexec)
            results += toolchain_contents(libexec, in_cache)
    except PermissionError:
        results.append(Result("toolchain", FAIL if strict else NOT_RUN, "cannot be read as this user"))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        results.append(Result("toolchain", FAIL, f"{TOOLCHAIN_LOCK} cannot be read: {exc}"))
    if plist is not None:
        results.append(launch_daemon(plist, libexec, logs, strict))
    if probes is not None:
        results += list(probes())
    return results


def render(results: Sequence[Result]) -> str:
    return "\n".join(f"{item.status:8} {item.name}{': ' + item.detail if item.detail else ''}" for item in results)


def exit_code(results: Sequence[Result], allow_not_run: bool = False) -> int:
    if any(item.status == FAIL for item in results):
        return 1
    if any(item.status == NOT_RUN for item in results) and not allow_not_run:
        return INCOMPLETE
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ship-no-ship-service doctor", description=__doc__.splitlines()[0])
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--libexec", type=Path, default=DEFAULT_LIBEXEC)
    parser.add_argument("--plist", type=Path, default=DEFAULT_PLIST)
    parser.add_argument("--logs-dir", type=Path, default=DEFAULT_LOGS)
    parser.add_argument("--config", type=Path, help="service.toml (default: <data-dir>/config/service.toml)")
    parser.add_argument("--post-reboot", action="store_true", help="only the keychain checks for after a reboot")
    parser.add_argument("--actor-probe", action="store_true", help="run the record-actor activation check")
    parser.add_argument("--probe-plan-run", help="a proof plan run on a test pull request, for --actor-probe")
    parser.add_argument(
        "--allow-not-run",
        action="store_true",
        help="before installation only: report missing pieces as not_run and exit 0 if nothing failed",
    )
    args = parser.parse_args(argv)
    if args.actor_probe and not args.probe_plan_run:
        parser.error("--actor-probe needs --probe-plan-run")
    checks = _probes(args)
    if args.post_reboot:
        results = checks.post_reboot()
    else:
        results = run(
            accounts=SystemAccounts(),
            files=SystemFileSystem(),
            rules=table(args.data_dir, args.libexec, args.logs_dir, args.plist),
            libexec=args.libexec,
            plist=args.plist,
            data=args.data_dir,
            logs=args.logs_dir,
            config=args.config or args.data_dir / "config" / "service.toml",
            strict=not args.allow_not_run,
            probes=checks.all,
        )
    print(render(results))
    skipped = sum(item.status == NOT_RUN for item in results)
    if skipped:
        print(f"doctor: incomplete: {skipped} check(s) did not run")
    if any(item.status == WARN for item in results):
        print("doctor: warn means the owner must decide before activation")
    return exit_code(results, args.allow_not_run)


def _probes(args: argparse.Namespace) -> Any:
    """The CLI and App probes, wired to sudo and the App when doctor runs as root with a service config."""
    from . import config as service_config, probes
    from .appauth import InstallationTokens
    from .ghclient import RestClient
    from .transport import UrllibTransport

    runner = probes.SudoRunner(args.data_dir, args.libexec) if os.geteuid() == 0 else None
    checks = probes.Probes(runner=runner, strict=not args.allow_not_run)
    if args.actor_probe:
        settings = service_config.load(args.config or args.data_dir / "config" / "service.toml")
        repository = settings.repositories[0]
        transport = UrllibTransport()
        tokens = InstallationTokens(repository, transport, api_url=settings.api_url)
        checks.actor_probe = probes.RecordActorProbe(
            repository,
            RestClient(tokens, transport, settings.api_url),
            probes.app_dispatch(repository, tokens, transport, settings.api_url),
            probes.ask,
            args.probe_plan_run,
        )
    return checks


if __name__ == "__main__":
    raise SystemExit(main())
