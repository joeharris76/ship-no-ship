from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

PLACEHOLDER_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")
PLACEHOLDER_EMAILS = frozenset({"a@b.com"})
PLACEHOLDER_EMAIL_SUFFIXES = (".example", *("." + domain for domain in PLACEHOLDER_EMAIL_DOMAINS))
TEMPLATE_PREFIXES = ("examples/", "macos/")

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
EVERYWHERE = (
    ("home path", re.compile(r"(?<![\w.])/(?:Users|home)/[A-Za-z0-9_.-]+|[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("API key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)
TEMPLATES_ONLY = (
    ("IP address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("numeric App or installation ID", re.compile(r"(?i)\b(?:app|installation)[_ -]?id\W{0,3}\d{2,}")),
    ("local host name", re.compile(r"\b[A-Za-z0-9-]+\.local\b")),
)


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str
    text: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.text}"


def _email_allowed(address: str, domain: str) -> bool:
    domain = domain.lower()
    return (
        address.lower() in PLACEHOLDER_EMAILS
        or domain in PLACEHOLDER_EMAIL_DOMAINS
        or domain.endswith(PLACEHOLDER_EMAIL_SUFFIXES)
    )


def scan_text(path: str, text: str) -> list[Violation]:
    rules = EVERYWHERE + (TEMPLATES_ONLY if path.startswith(TEMPLATE_PREFIXES) else ())
    found: list[Violation] = []
    for number, line in enumerate(text.splitlines(), 1):
        for name, pattern in rules:
            found.extend(Violation(path, number, name, match.group(0)) for match in pattern.finditer(line))
        found.extend(
            Violation(path, number, "email address", match.group(0))
            for match in EMAIL.finditer(line)
            if not _email_allowed(match.group(0), match.group(1))
        )
    return found


def tracked_files(root: Path) -> list[str]:
    listing = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True)
    return [name for name in listing.stdout.decode("utf-8").split("\0") if name]


def scan_files(root: Path, paths: Iterable[str]) -> list[Violation]:
    found: list[Violation] = []
    for path in paths:
        file = root / path
        if not file.is_file():
            continue
        data = file.read_bytes()
        if b"\0" in data:
            continue
        found.extend(scan_text(path, data.decode("utf-8", errors="replace")))
    return found


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    root = Path(args[0]) if args else Path.cwd()
    found = scan_files(root, tracked_files(root))
    for violation in found:
        print(violation)
    if found:
        print(f"publish-safety: {len(found)} problem(s) in tracked files", file=sys.stderr)
        return 1
    print("publish-safety: no problems in tracked files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
