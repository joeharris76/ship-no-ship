from __future__ import annotations

import argparse
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
RECORD = "\x1e"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: re.Pattern[str]
    secret: bool = False


EMAIL = Rule(
    "email", "email address", re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
)
SECRET_RULES = (
    Rule("url-credentials", "URL credentials", re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@"), True),
    Rule(
        "github-token",
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
        True,
    ),
    Rule("aws-key", "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), True),
    Rule("private-key", "private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), True),
    Rule("api-key", "API key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}"), True),
    Rule("slack-token", "Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), True),
    Rule("google-key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), True),
)
TEXT_RULES = (
    Rule(
        "home-path",
        "home path",
        re.compile(r"(?<![\w.])/(?:Users|home)/[A-Za-z0-9_.-]+|[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+"),
    ),
    Rule("ip", "IP address", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")),
    Rule(
        "ipv6",
        "IPv6 address",
        re.compile(
            r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){4,7}[0-9A-Fa-f]{1,4}(?![\w:])"
            r"|(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?(?![\w:])"
        ),
    ),
    Rule("app-id", "numeric App or installation ID", re.compile(r"(?i)\b(?:app|installation)[_ -]?id\W{0,3}\d{2,}")),
    Rule(
        "host",
        "private host name",
        re.compile(r"(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:local|lan|internal|localdomain|home\.arpa|ts\.net)\b"),
    ),
)
RULE_IDS = frozenset(rule.id for rule in (EMAIL, *SECRET_RULES, *TEXT_RULES))


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
    blob_rules: frozenset[tuple[str, str]] = frozenset()
    commit_email_hashes: frozenset[str] = frozenset()

    def exempt(self, blob: str) -> frozenset[str]:
        return frozenset(rule for sha, rule in self.blob_rules if sha == blob)


@dataclass
class Report:
    violations: list[Violation] = field(default_factory=list)
    skipped_binary: list[str] = field(default_factory=list)
    allowed_commit_emails: Counter[str] = field(default_factory=Counter)


def load_allowlist(path: Path = ALLOWLIST) -> Allowlist:
    blobs: set[tuple[str, str]] = set()
    hashes: set[str] = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if (
            len(fields) == 3
            and fields[0] == "blob"
            and re.fullmatch(r"[0-9a-f]{40}", fields[1])
            and fields[2] in RULE_IDS
        ):
            blobs.add((fields[1], fields[2]))
        elif len(fields) == 2 and fields[0] == "commit-email-sha256" and re.fullmatch(r"[0-9a-f]{64}", fields[1]):
            hashes.add(fields[1])
        else:
            raise ValueError(f"{path}:{number}: expected blob<TAB>sha<TAB>rule or commit-email-sha256<TAB>hex")
    return Allowlist(frozenset(blobs), frozenset(hashes))


def email_hash(address: str) -> str:
    return hashlib.sha256(address.strip().lower().encode("utf-8")).hexdigest()


def _placeholder_email(address: str) -> bool:
    match = EMAIL.pattern.fullmatch(address)
    if match is None:
        return False
    domain = match.group(1).lower()
    return (
        address.lower() in PLACEHOLDER_EMAILS
        or address.lower().endswith(NOREPLY_SUFFIX)
        or domain in PLACEHOLDER_EMAIL_DOMAINS
        or domain.endswith(PLACEHOLDER_EMAIL_SUFFIXES)
    )


def _plausible(rule: Rule, text: str) -> bool:
    if rule.id == "ipv6":
        return max(len(group) for group in text.split(":")) >= 3
    return text not in ALLOWED_IPS


def mask_secret(text: str) -> str:
    return text[:4] + "****"


def mask_email(address: str) -> str:
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain}"


def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    return any(span[0] < end and start < span[1] for start, end in spans)


def scan_text(path: str, text: str, exempt: frozenset[str] = frozenset()) -> list[Violation]:
    found: list[Violation] = []
    for number, line in enumerate(text.splitlines(), 1):
        secrets: list[tuple[int, int]] = []
        for rule in SECRET_RULES:
            if rule.id in exempt:
                continue
            for match in rule.pattern.finditer(line):
                secrets.append(match.span())
                found.append(Violation(path, number, rule.name, mask_secret(match.group(0))))
        for rule in TEXT_RULES:
            if rule.id in exempt:
                continue
            found.extend(
                Violation(path, number, rule.name, match.group(0))
                for match in rule.pattern.finditer(line)
                if _plausible(rule, match.group(0)) and not _overlaps(match.span(), secrets)
            )
        if EMAIL.id not in exempt:
            found.extend(
                Violation(path, number, EMAIL.name, mask_email(match.group(0)))
                for match in EMAIL.pattern.finditer(line)
                if not _placeholder_email(match.group(0)) and not _overlaps(match.span(), secrets)
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
    named: dict[str, set[str]] = {}
    for line in _git(root, "rev-list", "--objects", "--all").decode("utf-8").splitlines():
        sha, _, path = line.partition(" ")
        named.setdefault(sha, set()).update([path] if path else [])
    if not named:
        return []
    query = "".join(sha + "\n" for sha in named).encode("ascii")
    checked = _git(root, "cat-file", "--batch-check=%(objectname) %(objecttype)", stdin=query).decode("utf-8")
    blobs = [line.split(" ")[0] for line in checked.splitlines() if line.endswith(" blob")]
    return [(sha, path) for sha in blobs for path in sorted(named[sha]) or [sha]]


def scan_blobs(root: Path, entries: list[tuple[str, str]], allowlist: Allowlist, report: Report) -> None:
    paths: dict[str, list[str]] = {}
    for sha, path in entries:
        paths.setdefault(sha, []).append(path)
    for sha, data in read_blobs(root, paths):
        names = sorted(paths[sha])
        label = names[0] if len(names) == 1 else f"{names[0]} (and {len(names) - 1} other path(s))"
        if b"\0" in data:
            report.skipped_binary.append(label)
            continue
        report.violations.extend(scan_text(label, data.decode("utf-8", errors="replace"), allowlist.exempt(sha)))


def _check_address(where: str, address: str, allowlist: Allowlist, report: Report) -> None:
    if not address or _placeholder_email(address):
        return
    if email_hash(address) in allowlist.commit_email_hashes:
        report.allowed_commit_emails[address] += 1
    else:
        report.violations.append(Violation(where, 0, "metadata email address", mask_email(address)))


def scan_commits(root: Path, allowlist: Allowlist, report: Report) -> None:
    log = _git(root, "log", "--all", f"--format=%H%x00%ae%x00%ce%x00%B{RECORD}").decode("utf-8", errors="replace")
    for record in log.split(RECORD):
        record = record.lstrip("\n")
        if not record:
            continue
        commit, author, committer, message = record.split("\0", 3)
        where = f"commit {commit[:12]}"
        for address in dict.fromkeys((author, committer)):
            _check_address(where, address, allowlist, report)
        report.violations.extend(scan_text(f"{where} message", message))


def scan_tags(root: Path, allowlist: Allowlist, report: Report) -> None:
    refs = _git(
        root, "for-each-ref", f"--format=%(refname)%00%(objecttype)%00%(taggeremail)%00%(contents){RECORD}", "refs/tags"
    ).decode("utf-8", errors="replace")
    for record in refs.split(RECORD):
        record = record.lstrip("\n")
        if not record:
            continue
        name, kind, tagger, message = record.split("\0", 3)
        if kind != "tag":
            continue
        _check_address(name, tagger.strip("<>"), allowlist, report)
        report.violations.extend(scan_text(f"{name} message", message))


def scan(root: Path, history: bool, allowlist: Allowlist) -> Report:
    report = Report()
    scan_blobs(root, history_entries(root) if history else index_entries(root), allowlist, report)
    if history:
        scan_commits(root, allowlist, report)
        scan_tags(root, allowlist, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check_publish_safety")
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args(argv)
    report = scan(Path(args.root), args.history, load_allowlist())
    scope = "any commit, tag or reachable file" if args.history else "tracked files"
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
