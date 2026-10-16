"""``doctor``: read-only checks that the installed service is safe to activate.

It checks the path, owner and mode table, the pinned toolchain, and runs the probes in ``probes``. It
needs no sudo and changes nothing. Every check reports ``pass``, ``fail``, ``warn`` or ``not_run``; a
check whose prerequisites are missing (a role user not yet created, a wrapper not yet installed) says
``not_run`` and why, rather than passing.

The path rule: each listed path must have exactly its table owner, group and mode, and must not be a
symlink. The path and every directory above it, up to the filesystem root, must be owned by root or
a service user, never group-writable unless the group is wheel or a service group, and never
world-writable. So nothing the owner's login account (or an agent running as it) can write sits on the
way to a file the service trusts. ACLs are not inspected.
"""

from __future__ import annotations

import argparse
import fnmatch
import grp
import hashlib
import json
import os
import pwd
import stat
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from . import probes
from .probes import FAIL, NOT_RUN, PASS, WARN, Result

DEFAULT_LIBEXEC = Path("/usr/local/libexec/ship-no-ship")
DEFAULT_DATA = Path("/Library/Application Support/ship-no-ship")
DEFAULT_LOGS = Path("/Library/Logs/ship-no-ship")
TOOLCHAIN_LOCK = "toolchain.lock.json"
DAEMON = "_ssnsd"
CLIS = ("claude", "codex", "muse", "agy")
TRUSTED_GROUPS = ("wheel",)


def role_user(cli: str) -> str:
    return f"_ssns{cli}"


class Accounts(Protocol):
    def uid(self, name: str) -> int | None: ...

    def gid(self, name: str) -> int | None: ...


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
    tree: bool = False  # every entry below must be owned the same way, dirs 0755, files 0755 or 0644


def table(data: Path = DEFAULT_DATA, libexec: Path = DEFAULT_LIBEXEC, logs: Path = DEFAULT_LOGS) -> list[Rule]:
    """The path, owner and mode table from the threat model, for one installation."""
    rules = [
        Rule(libexec, "root", "wheel", 0o755, True, tree=True),
        Rule(Path("/etc/sudoers.d/ship-no-ship"), "root", "wheel", 0o440, False),
        Rule(Path("/etc/newsyslog.d/ship-no-ship.conf"), "root", "wheel", 0o644, False),
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
        Rule(data / "run" / "attempts", "root", "wheel", 0o700, True),
        Rule(logs, DAEMON, "admin", 0o750, True),
    ]
    rules += [Rule(data / "home" / cli, role_user(cli), role_user(cli), 0o700, True) for cli in CLIS]
    return rules


class PathAudit:
    """Checks rules against the filesystem. ``root`` is where the parent walk stops: ``/`` when installed."""

    def __init__(self, accounts: Accounts, root: Path = Path("/")) -> None:
        self.accounts = accounts
        self.root = root

    def _ids(self, names: Iterable[str], lookup) -> set[int]:
        return {found for found in (lookup(name) for name in names) if found is not None}

    def trusted(self) -> tuple[set[int], set[int]]:
        users = ["root", DAEMON, *(role_user(cli) for cli in CLIS)]
        groups = [*TRUSTED_GROUPS, DAEMON, *(role_user(cli) for cli in CLIS)]
        return self._ids(users, self.accounts.uid), self._ids(groups, self.accounts.gid)

    def _element(self, path: Path, info: os.stat_result, users: set[int], groups: set[int]) -> str | None:
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid not in users:
            return f"{path} is owned by uid {info.st_uid}, not root or a service user"
        if mode & stat.S_IWOTH:
            return f"{path} is writable by everyone"
        if mode & stat.S_IWGRP and info.st_gid not in groups:
            return f"{path} is writable by group {info.st_gid}, which is not a service group"
        return None

    def _parents(self, path: Path, users: set[int], groups: set[int]) -> str | None:
        resolved = path.parent.resolve()
        chain = [resolved, *resolved.parents]
        for element in chain:
            problem = self._element(element, element.stat(), users, groups)
            if problem:
                return problem
            if element == self.root:
                return None
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
        return None

    def check(self, rule: Rule) -> Result:
        try:
            return self._check(rule)
        except PermissionError:
            return Result(
                f"path {rule.path}", NOT_RUN, "cannot be inspected as this user; run doctor as the daemon user"
            )
        except OSError as exc:
            return Result(f"path {rule.path}", FAIL, f"cannot be inspected: {exc.strerror or exc}")

    def _check(self, rule: Rule) -> Result:
        name = f"path {rule.path}"
        owner, group = self.accounts.uid(rule.owner), self.accounts.gid(rule.group)
        if owner is None or group is None:
            return Result(name, NOT_RUN, f"account {rule.owner}:{rule.group} does not exist yet")
        if not rule.path.exists() and not rule.path.is_symlink():
            return Result(name, FAIL if rule.required else PASS, "missing" if rule.required else "absent (optional)")
        users, groups = self.trusted()
        problem = self._parents(rule.path, users, groups) or self._exact(
            rule.path, owner, group, rule.mode, rule.directory
        )
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
        for directory, names, files in os.walk(top, followlinks=False):
            for entry in [*names, *files]:
                path = Path(directory) / entry
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    return f"{path} is a symlink"
                allowed = (0o755,) if stat.S_ISDIR(info.st_mode) else (0o755, 0o644)
                if (info.st_uid, info.st_gid) != (owner, group) or stat.S_IMODE(info.st_mode) not in allowed:
                    return f"{path} is {info.st_uid}:{info.st_gid} {stat.S_IMODE(info.st_mode):04o}"
        return None


def toolchain(libexec: Path, pins: Mapping[str, str] | None) -> list[Result]:
    """Each pinned tool in ``<libexec>/bin`` must exist and match its SHA-256."""
    if pins is None:
        return [Result("toolchain", NOT_RUN, f"no {TOOLCHAIN_LOCK} is installed")]
    results = []
    for tool, expected in sorted(pins.items()):
        path = libexec / "bin" / tool
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            results.append(Result(f"tool {tool}", FAIL, f"cannot be read: {exc.strerror or exc}"))
            continue
        ok = digest == expected
        results.append(
            Result(f"tool {tool}", PASS if ok else FAIL, "" if ok else f"sha256 {digest[:12]} is not the pin")
        )
    return results


def read_pins(libexec: Path) -> dict[str, str] | None:
    path = libexec / TOOLCHAIN_LOCK
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(name): str(item["sha256"]) for name, item in data["tools"].items()}


def run(
    *,
    accounts: Accounts,
    rules: Sequence[Rule],
    libexec: Path,
    checks: probes.Probes,
    post_reboot: bool = False,
    root: Path = Path("/"),
) -> list[Result]:
    if post_reboot:
        return checks.post_reboot()
    audit = PathAudit(accounts, root)
    results = [audit.check(rule) for rule in rules]
    try:
        pins = read_pins(libexec)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        results.append(Result("toolchain", FAIL, f"{TOOLCHAIN_LOCK} cannot be read: {exc}"))
    else:
        results += toolchain(libexec, pins)
    return results + checks.all()


def render(results: Sequence[Result]) -> str:
    return "\n".join(f"{item.status:8} {item.name}{': ' + item.detail if item.detail else ''}" for item in results)


def exit_code(results: Sequence[Result]) -> int:
    return 1 if any(item.status == FAIL for item in results) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ship-no-ship-service doctor", description=__doc__.splitlines()[0])
    parser.add_argument("--post-reboot", action="store_true", help="only the checks for after a reboot")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--libexec", type=Path, default=DEFAULT_LIBEXEC)
    args = parser.parse_args(argv)
    results = run(
        accounts=SystemAccounts(),
        rules=table(args.data_dir, args.libexec),
        libexec=args.libexec,
        checks=probes.Probes(),
        post_reboot=args.post_reboot,
    )
    print(render(results))
    if any(item.status == WARN for item in results):
        print("warn means the owner must decide before activation; see the threat model.", file=sys.stderr)
    return exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
