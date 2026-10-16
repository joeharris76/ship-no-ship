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
SYSTEM_BIN = (Path("/usr/bin"), Path("/bin"))


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
            return Result(name, FAIL if rule.required else PASS, "missing" if rule.required else "absent (optional)")
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


def read_pins(libexec: Path) -> dict[str, str] | None:
    path = libexec / TOOLCHAIN_LOCK
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(name): str(item["sha256"]) for name, item in data["tools"].items()}


def _targets(content: bytes) -> list[str]:
    """The interpreter of a script and the programs its ``exec`` lines run."""
    if not content.startswith(b"#!"):
        return []
    lines = content.decode("utf-8", "replace").splitlines()
    found = [lines[0][2:].strip().split()[0]] if lines[0][2:].strip() else []
    found += [line.split()[1] for line in lines[1:] if line.strip().startswith("exec ") and len(line.split()) > 1]
    return [item.strip("\"'") for item in found]


def toolchain(libexec: Path, pins: Mapping[str, str] | None, strict: bool) -> list[Result]:
    """Every file in ``<libexec>/bin`` is pinned and matches, and runs only programs from the toolchain."""
    if pins is None:
        return [Result("toolchain", FAIL if strict else NOT_RUN, f"no {TOOLCHAIN_LOCK} is installed")]
    results = []
    present = {entry.name for entry in (libexec / "bin").iterdir()} if (libexec / "bin").is_dir() else set()
    results += [Result(f"tool {name}", FAIL, "is not pinned") for name in sorted(present - set(pins))]
    for tool, expected in sorted(pins.items()):
        path = libexec / "bin" / tool
        try:
            content = path.read_bytes()
        except OSError as exc:
            results.append(Result(f"tool {tool}", FAIL, f"cannot be read: {exc.strerror or exc}"))
            continue
        problem = None
        if hashlib.sha256(content).hexdigest() != expected:
            problem = "does not match its pin"
        for target in _targets(content):
            # env would pick the program from PATH at run time, so it never counts as inside.
            outside = not any(_inside(Path(target), top) for top in (libexec, *SYSTEM_BIN))
            if target.startswith("$") or Path(target).name == "env" or outside:
                problem = f"runs {target}, outside the toolchain"
        results.append(Result(f"tool {tool}", FAIL if problem else PASS, problem or ""))
    return results


def venvs(libexec: Path) -> list[Result]:
    """Each virtual environment's interpreter must come from inside the toolchain tree."""
    results = []
    for config in sorted(libexec.rglob("pyvenv.cfg")):
        parser = configparser.ConfigParser()
        parser.read_string("[venv]\n" + config.read_text(encoding="utf-8"))
        home = parser.get("venv", "home", fallback="")
        ok = bool(home) and _inside(Path(home).resolve(), libexec.resolve())
        detail = "" if ok else f"home {home or '(none)'} is outside {libexec}"
        results.append(Result(f"venv {config.parent.name}", PASS if ok else FAIL, detail))
    return results


def launch_daemon(plist: Path, libexec: Path, strict: bool) -> Result:
    """The daemon runs the toolchain's program as the daemon user."""
    name = f"launchd {LABEL}"
    try:
        data: Any = plistlib.loads(plist.read_bytes())
    except FileNotFoundError:
        return Result(name, FAIL if strict else NOT_RUN, f"{plist} is not installed")
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        return Result(name, FAIL, f"{plist} cannot be read: {exc}")
    if not isinstance(data, dict):
        return Result(name, FAIL, f"{plist} is not a dictionary")
    arguments = data.get("ProgramArguments")
    program = str(arguments[0]) if isinstance(arguments, list) and arguments else ""
    problems = [
        (data.get("Label") != LABEL, f"Label is not {LABEL}"),
        (data.get("UserName") != DAEMON or data.get("GroupName") != DAEMON, f"it does not run as {DAEMON}"),
        (
            ".." in Path(program).parts or not program or not _inside(Path(program), libexec),
            f"it runs {program or 'nothing'}, outside {libexec}",
        ),
        ("Program" in data, "it sets Program, which overrides ProgramArguments"),
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
    strict: bool = True,
    root: Path = Path("/"),
    probes: Callable[[], Iterable[Result]] | None = None,
) -> list[Result]:
    audit = PathAudit(accounts, files, root, strict)
    results = [audit.check(rule) for rule in rules]
    results += groups_check(accounts, strict)
    try:
        pins = read_pins(libexec)
        results += toolchain(libexec, pins, strict)
        results += venvs(libexec) if libexec.is_dir() else []
    except PermissionError:
        results.append(Result("toolchain", FAIL if strict else NOT_RUN, "cannot be read as this user"))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        results.append(Result("toolchain", FAIL, f"{TOOLCHAIN_LOCK} cannot be read: {exc}"))
    if plist is not None:
        results.append(launch_daemon(plist, libexec, strict))
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
