from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

KINDS = ("file", "glob", "prefix", "regex")


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    kind: str
    pattern: str


@dataclass(frozen=True)
class Manifest:
    rules: tuple[Rule, ...]

    def _patterns(self, *kinds: str) -> tuple[str, ...]:
        return tuple(rule.pattern for rule in self.rules if rule.kind in kinds)

    def matches(self, path: str) -> bool:
        normalized = normalize_path(path)
        if not normalized:
            return False
        return (
            any(re.match(pattern, normalized) is not None for pattern in self._patterns("regex"))
            or any(_glob_matches(normalized, pattern) for pattern in self._patterns("glob"))
            or normalized in self._patterns("file", "glob")
            or normalized.startswith(self._patterns("prefix"))
        )


def normalize_path(path: str) -> str:
    return path.strip().replace("\\", "/")


def _glob_matches(path: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(path, pattern) or (
        "/**/" in pattern and fnmatch.fnmatchcase(path, pattern.replace("/**/", "/"))
    )


def parse_manifest(text: str, source: str = "manifest") -> Manifest:
    rules: list[Rule] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        kind, tab, pattern = line.partition("\t")
        where = f"{source}:{number}"
        if not tab:
            raise ManifestError(f"{where}: expected kind<TAB>pattern")
        if kind not in KINDS:
            raise ManifestError(f"{where}: unknown rule kind {kind!r}")
        if kind == "prefix" and not pattern.endswith("/"):
            raise ManifestError(f"{where}: prefix must end with '/': {pattern!r}")
        if kind == "regex":
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ManifestError(f"{where}: invalid regex {pattern!r}: {exc}") from exc
        rules.append(Rule(kind, pattern))
    if not rules:
        raise ManifestError(f"{source}: the path manifest has no rules")
    return Manifest(tuple(rules))


def load_manifest(path: Path) -> Manifest:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"{path}: the path manifest cannot be read: {exc.strerror or exc}") from exc
    return parse_manifest(text, str(path))
