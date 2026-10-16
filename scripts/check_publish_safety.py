from __future__ import annotations

import argparse
import fnmatch
import hashlib
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

PLACEHOLDER_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")
PLACEHOLDER_EMAILS = frozenset({"a@b.com", "noreply@github.com"})
PLACEHOLDER_EMAIL_SUFFIXES = (".example", *("." + domain for domain in PLACEHOLDER_EMAIL_DOMAINS))
NOREPLY_SUFFIX = "@users.noreply.github.com"
ALLOWED_IPS = frozenset({"0.0.0.0", "127.0.0.1"})
ALLOWLIST = Path(__file__).with_name("publish-safety-allow.txt")
SUBMODULE_MODE = "160000"

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
CREDENTIAL_RULES = (
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("API key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)
TEXT_RULES = (
    ("home path", re.compile(r"(?<![\w.])/(?:Users|home)/[A-Za-z0-9_.-]+|[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+")),
)
HOST_RULES = (
    ("IP address", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")),
    (
        "IPv6 address",
        re.compile(
            r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){4,7}[0-9A-Fa-f]{1,4}(?![\w:])"
            r"|(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?(?![\w:])"
        ),
    ),
    ("numeric App or installation ID", re.compile(r"(?i)\b(?:app|installation)[_ -]?id\W{0,3}\d{2,}")),
    (
        "private host name",
        re.compile(r"(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:local|lan|internal|localdomain|home\.arpa|ts\.net)\b"),
    ),
)


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str
    text: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.text}"


@dataclass(frozen=True)
class Allowlist:
    host_rule_paths: tuple[str, ...] = ()
    commit_email_hashes: frozenset[str] = frozenset()

    def exempt_from_host_rules(self, path: str) -> bool:
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in self.host_rule_paths)


@dataclass
class Report:
    violations: list[Violation] = field(default_factory=list)
    skipped_binary: list[str] = field(default_factory=list)
    allowed_commit_emails: Counter[str] = field(default_factory=Counter)


def load_allowlist(path: Path = ALLOWLIST) -> Allowlist:
    paths: list[str] = []
    hashes: set[str] = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        kind, _, value = line.partition("\t")
        if kind == "host-rules" and value:
            paths.append(value)
        elif kind == "commit-email-sha256" and re.fullmatch(r"[0-9a-f]{64}", value):
            hashes.add(value)
        else:
            raise ValueError(f"{path}:{number}: expected host-rules<TAB>glob or commit-email-sha256<TAB>hex")
    return Allowlist(tuple(paths), frozenset(hashes))


def email_hash(address: str) -> str:
    return hashlib.sha256(address.strip().lower().encode("utf-8")).hexdigest()


def _placeholder_email(address: str, domain: str) -> bool:
    domain = domain.lower()
    return (
        address.lower() in PLACEHOLDER_EMAILS
        or domain in PLACEHOLDER_EMAIL_DOMAINS
        or domain.endswith(PLACEHOLDER_EMAIL_SUFFIXES)
    )


def _plausible(rule: str, text: str) -> bool:
    if rule == "IPv6 address":
        return max(len(group) for group in text.split(":")) >= 3
    return text not in ALLOWED_IPS


def _mask(text: str) -> str:
    return text[:4] + "****"


def scan_text(path: str, text: str, allowlist: Allowlist | None = None) -> list[Violation]:
    exempt = allowlist is not None and allowlist.exempt_from_host_rules(path)
    rules = TEXT_RULES + (() if exempt else HOST_RULES)
    found: list[Violation] = []
    for number, line in enumerate(text.splitlines(), 1):
        for name, pattern in CREDENTIAL_RULES:
            found.extend(Violation(path, number, name, _mask(match.group(0))) for match in pattern.finditer(line))
        for name, pattern in rules:
            found.extend(
                Violation(path, number, name, match.group(0))
                for match in pattern.finditer(line)
                if _plausible(name, match.group(0))
            )
        found.extend(
            Violation(path, number, "email address", match.group(0))
            for match in EMAIL.finditer(line)
            if not _placeholder_email(match.group(0), match.group(1))
        )
    return found


def _git(root: Path, *args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(["git", "-C", str(root), *args], input=stdin, check=True, capture_output=True).stdout


def read_blobs(root: Path, shas: Iterable[str]) -> Iterator[tuple[str, bytes]]:
    wanted = list(dict.fromkeys(shas))
    if not wanted:
        return
    output = _git(root, "cat-file", "--batch", stdin="".join(sha + "\n" for sha in wanted).encode("ascii"))
    offset = 0
    for sha in wanted:
        end = output.index(b"\n", offset)
        size = int(output[offset:end].split(b" ")[2])
        yield sha, output[end + 1 : end + 1 + size]
        offset = end + 1 + size + 1


def index_entries(root: Path) -> list[tuple[str, str]]:
    entries = []
    for record in _git(root, "ls-files", "-s", "-z").decode("utf-8").split("\0"):
        if not record:
            continue
        meta, path = record.split("\t", 1)
        mode, sha, _ = meta.split(" ")
        if mode != SUBMODULE_MODE:
            entries.append((sha, path))
    return entries


def history_entries(root: Path) -> list[tuple[str, str]]:
    named: dict[str, str] = {}
    for line in _git(root, "rev-list", "--objects", "--all").decode("utf-8").splitlines():
        sha, _, path = line.partition(" ")
        if sha not in named or (path and not named[sha]):
            named[sha] = path
    if not named:
        return []
    query = "".join(sha + "\n" for sha in named).encode("ascii")
    checked = _git(root, "cat-file", "--batch-check=%(objectname) %(objecttype)", stdin=query).decode("utf-8")
    blobs = [line.split(" ")[0] for line in checked.splitlines() if line.endswith(" blob")]
    return [(sha, named[sha] or sha) for sha in blobs]


def scan_blobs(root: Path, entries: list[tuple[str, str]], allowlist: Allowlist, report: Report) -> None:
    paths: dict[str, list[str]] = {}
    for sha, path in entries:
        paths.setdefault(sha, []).append(path)
    for sha, data in read_blobs(root, paths):
        for path in paths[sha]:
            if b"\0" in data:
                report.skipped_binary.append(path)
                continue
            report.violations.extend(scan_text(path, data.decode("utf-8", errors="replace"), allowlist))


def scan_commit_emails(root: Path, allowlist: Allowlist, report: Report) -> None:
    log = _git(root, "log", "--all", "--format=%H%x00%ae%x00%ce").decode("utf-8")
    for line in log.splitlines():
        commit, *addresses = line.split("\0")
        for address in dict.fromkeys(addresses):
            match = EMAIL.fullmatch(address)
            if address.lower().endswith(NOREPLY_SUFFIX) or (match and _placeholder_email(address, match.group(1))):
                continue
            if email_hash(address) in allowlist.commit_email_hashes:
                report.allowed_commit_emails[address] += 1
            else:
                report.violations.append(Violation(f"commit {commit[:12]}", 0, "commit email address", address))


def scan(root: Path, history: bool, allowlist: Allowlist) -> Report:
    report = Report()
    scan_blobs(root, history_entries(root) if history else index_entries(root), allowlist, report)
    if history:
        scan_commit_emails(root, allowlist, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check_publish_safety")
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args(argv)
    report = scan(Path(args.root), args.history, load_allowlist())
    scope = "any commit" if args.history else "tracked files"
    for violation in report.violations:
        print(violation)
    for path in sorted(set(report.skipped_binary)):
        print(f"publish-safety: skipped binary file {path}")
    for address, count in sorted(report.allowed_commit_emails.items()):
        print(f"publish-safety: allowed commit email {address} on {count} commit(s); decide before going public")
    if report.violations:
        print(f"publish-safety: {len(report.violations)} problem(s) in {scope}", file=sys.stderr)
        return 1
    print(f"publish-safety: no problems in {scope}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
