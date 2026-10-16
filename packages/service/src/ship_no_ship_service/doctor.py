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

from . import fsinfo

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


class Accounts(Protocol):
    def uid(self, name: str) -> int | None: ...

    def gid(self, name: str) -> int | None: ...

    def members(self, group: str) -> list[str] | None: ...

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
        primary = [user.pw_name for user in pwd.getpwall() if user.pw_gid == entry.gr_gid]
        return sorted({*entry.gr_mem, *primary})

    def login(self, name: str) -> tuple[str, str] | None:
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            return None
        return entry.pw_dir, entry.pw_shell


class FileSystem(Protocol):
    def write_grants(self, path: Path) -> list[str]: ...

    def ignores_ownership(self, path: Path) -> bool: ...


class SystemFileSystem:
    def write_grants(self, path: Path) -> list[str]:
        return fsinfo.write_grants(fsinfo.acl_text(path))

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
        Rule(data / "config", "root", DAEMON, 0o750, True),
        Rule(data / "config" / "service.toml", "root", DAEMON, 0o440, False),
        Rule(data / "keys", DAEMON, DAEMON, 0o700, True, children="*.pem", child_mode=0o400),
        Rule(data / "state", DAEMON, DAEMON, 0o700, True, children="state.db*", child_mode=0o600),
        Rule(data / "mirror", DAEMON, DAEMON, 0o755, True, required=False),
        Rule(data / "requests", DAEMON, DAEMON, 0o755, True),
        Rule(data / "work", "root", "wheel", 0o755, True),
        Rule(data / "captured", DAEMON, DAEMON, 0o700, True, required=False),
        Rule(data / "run", DAEMON, DAEMON, 0o755, True, children="*.json", child_mode=0o644),
        # The supervisor's process records sit under a root-owned parent, so the daemon cannot swap them.
        Rule(data / "attempts", "root", "wheel", 0o700, True),
        Rule(logs, DAEMON, "admin", 0o750, True),
    ]
    rules += [Rule(data / "home" / cli, role_user(cli), role_user(cli), 0o700, True) for cli in CLIS]
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

    def _element(self, path: Path, owners: set[int], groups: set[int]) -> str | None:
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
        return None

    def _parents(self, path: Path, owners: set[int], groups: set[int]) -> str | None:
        pending = self._chain(path)
        while pending:
            element = pending.pop(0)
            problem = self._element(element, owners, groups)
            if problem:
                return problem
            if element.is_symlink():
                target = element.resolve()
                pending = [target, *self._chain(target), *pending]
        return None

    def _exact(self, path: Path, owner: int, group: int, mode: int, directory: bool) -> str | None:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            return f"{path} is a symlink"
        if directory != stat.S_ISDIR(info.st_mode) or not (directory or stat.S_ISREG(info.st_mode)):
            return f"{path} is not a {'directory' if directory else 'regular file'}"
        if (info.st_uid, info.st_gid) != (owner, group):
            return f"{path} is owned by {info.st_uid}:{info.st_gid}, not {owner}:{group}"
        if stat.S_IMODE(info.st_mode) != mode:
            return f"{path} has mode {stat.S_IMODE(info.st_mode):04o}, not {mode:04o}"
        grants = self.files.write_grants(path)
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
        problem = self._parents(rule.path, owners, groups) or self._exact(
            rule.path, owner, group, rule.mode, rule.directory
        )
        if problem is None and self.files.ignores_ownership(rule.path):
            problem = f"{rule.path} is on a volume that ignores ownership"
        if problem is None and rule.children and rule.child_mode is not None:
            # listdir, not glob: glob hides a directory this user cannot read, which would look clean.
            for entry in sorted(fnmatch.filter(os.listdir(rule.path), rule.children)):
                problem = self._exact(rule.path / entry, owner, group, rule.child_mode, False)
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


def groups_check(accounts: Accounts, strict: bool) -> list[Result]:
    """No person may be in a group the service trusts for writes or ownership."""
    allowed = {"root", *SERVICE_USERS}
    results = []
    for group in ("wheel", *SERVICE_USERS):
        members = accounts.members(group)
        name = f"group {group}"
        if members is None:
            results.append(Result(name, FAIL if strict else NOT_RUN, "does not exist"))
            continue
        people = sorted(set(members) - allowed)
        results.append(Result(name, FAIL if people else PASS, f"has members {', '.join(people)}" if people else ""))
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
) -> list[Result]:
    audit = PathAudit(accounts, files, root, strict)
    results = [audit.check(rule) for rule in rules]
    results += groups_check(accounts, strict)
    if data is not None:
        results += accounts_check(accounts, data, strict) + homes_check(data, strict)
    try:
        pins = read_pins(libexec)
        results += toolchain(libexec, pins, strict)
        results += venvs(libexec) if libexec.is_dir() else []
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
    parser.add_argument(
        "--allow-not-run",
        action="store_true",
        help="before installation only: report missing pieces as not_run and exit 0 if nothing failed",
    )
    args = parser.parse_args(argv)
    results = run(
        accounts=SystemAccounts(),
        files=SystemFileSystem(),
        rules=table(args.data_dir, args.libexec, plist=args.plist),
        libexec=args.libexec,
        plist=args.plist,
        strict=not args.allow_not_run,
    )
    print(render(results))
    skipped = sum(item.status == NOT_RUN for item in results)
    if skipped:
        print(f"doctor: incomplete: {skipped} check(s) did not run")
    if any(item.status == WARN for item in results):
        print("doctor: warn means the owner must decide before activation")
    return exit_code(results, args.allow_not_run)


if __name__ == "__main__":
    raise SystemExit(main())
