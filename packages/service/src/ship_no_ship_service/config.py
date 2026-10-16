"""The service configuration, read once at start-up from ``service.toml``.

The file names the repositories the service reviews and where their App keys live. It holds no
secret itself: each App key stays in its own file, readable only by the daemon user.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ship_no_ship.engine.policy import DEFAULT_ARTIFACTS, DEFAULT_HEARTBEAT_CONTEXT, DEFAULT_WORKFLOWS

DEFAULT_DATA_DIR = Path("/Library/Application Support/ship-no-ship")
DEFAULT_API_URL = "https://api.github.com"
DEFAULT_REVIEW_COMMAND = "/oracle-review"

_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")
_LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")
# No leading "-", so a branch name can never be read as an option by git or gh.
_BRANCH = re.compile(r"(?!refs/)(?!HEAD$)(?!-)[A-Za-z0-9._/-]{1,200}")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Repository:
    slug: str
    app_id: int
    installation_id: int
    key_path: Path
    bot_login: str
    base_branch: str
    verdict_workflow: str = DEFAULT_WORKFLOWS.verdict
    record_workflow: str = DEFAULT_WORKFLOWS.record
    request_artifact: str = DEFAULT_ARTIFACTS.request
    state_prefix: str = DEFAULT_ARTIFACTS.state_prefix
    heartbeat_context: str = DEFAULT_HEARTBEAT_CONTEXT
    review_command: str = DEFAULT_REVIEW_COMMAND

    @property
    def name(self) -> str:
        return self.slug.split("/", 1)[1]

    @property
    def bot(self) -> str:
        return f"{self.bot_login}[bot]"


@dataclass(frozen=True)
class ServiceConfig:
    repositories: tuple[Repository, ...]
    data_dir: Path = DEFAULT_DATA_DIR
    api_url: str = DEFAULT_API_URL
    poll_seconds: int = 60
    overlap_minutes: int = 30
    reconcile_minutes: int = 15
    heartbeat_minutes: int = 30

    @property
    def state_db(self) -> Path:
        return self.data_dir / "state" / "state.db"

    @property
    def requests_dir(self) -> Path:
        return self.data_dir / "requests"

    @property
    def run_dir(self) -> Path:
        return self.data_dir / "run"

    @property
    def health_path(self) -> Path:
        return self.run_dir / "health.json"

    def repository(self, slug: str) -> Repository:
        for repository in self.repositories:
            if repository.slug.casefold() == slug.casefold():
                return repository
        raise ConfigError(f"{slug} is not configured")


_SERVICE_INTS = ("poll_seconds", "overlap_minutes", "reconcile_minutes", "heartbeat_minutes")
_REPO_TEXT = {
    "verdict_workflow": r"\.github/workflows/[A-Za-z0-9._-]+\.ya?ml",
    "record_workflow": r"\.github/workflows/[A-Za-z0-9._-]+\.ya?ml",
    "request_artifact": r"[A-Za-z0-9._-]{1,100}",
    "state_prefix": r"[A-Za-z0-9._-]{1,100}",
    "heartbeat_context": r"[A-Za-z0-9._/-]{1,100}",
    "review_command": r"/[a-z0-9-]{1,50}",
}


def _check_keys(table: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ConfigError(f"{where}: unknown keys {', '.join(unknown)}")


def _int(table: Mapping[str, Any], key: str, where: str) -> int:
    value = table[key]
    if type(value) is not int or value <= 0:
        raise ConfigError(f"{where}.{key} must be a positive integer")
    return value


def _text(table: Mapping[str, Any], key: str, pattern: re.Pattern[str] | str, where: str) -> str:
    value = table[key]
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ConfigError(f"{where}.{key} is not valid: {value!r}")
    return value


def _repository(table: Any, index: int) -> Repository:
    where = f"repositories[{index}]"
    if not isinstance(table, dict):
        raise ConfigError(f"{where} must be a table")
    required = {"slug", "app_id", "installation_id", "key_path", "bot_login", "base_branch"}
    _check_keys(table, required | set(_REPO_TEXT), where)
    missing = sorted(required - set(table))
    if missing:
        raise ConfigError(f"{where}: missing keys {', '.join(missing)}")
    key_path = table["key_path"]
    if not isinstance(key_path, str) or not Path(key_path).is_absolute() or ".." in Path(key_path).parts:
        raise ConfigError(f"{where}.key_path must be an absolute path without '..'")
    bot_login = _text(table, "bot_login", _LOGIN, where)
    optional = {key: _text(table, key, pattern, where) for key, pattern in _REPO_TEXT.items() if key in table}
    return Repository(
        slug=_text(table, "slug", _SLUG, where),
        app_id=_int(table, "app_id", where),
        installation_id=_int(table, "installation_id", where),
        key_path=Path(key_path),
        bot_login=bot_login,
        base_branch=_text(table, "base_branch", _BRANCH, where),
        **optional,
    )


def parse(data: Mapping[str, Any]) -> ServiceConfig:
    _check_keys(data, {"service", "repositories"}, "service.toml")
    service = data.get("service", {})
    if not isinstance(service, dict):
        raise ConfigError("[service] must be a table")
    _check_keys(service, {"data_dir", "api_url", *_SERVICE_INTS}, "service")
    values: dict[str, Any] = {key: _int(service, key, "service") for key in _SERVICE_INTS if key in service}
    if "data_dir" in service:
        data_dir = service["data_dir"]
        if not isinstance(data_dir, str) or not Path(data_dir).is_absolute() or ".." in Path(data_dir).parts:
            raise ConfigError("service.data_dir must be an absolute path without '..'")
        values["data_dir"] = Path(data_dir)
    if "api_url" in service:
        values["api_url"] = _text(
            service, "api_url", r"https://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[A-Za-z0-9._/-]*)?", "service"
        )
        values["api_url"] = values["api_url"].rstrip("/")
    tables = data.get("repositories")
    if not isinstance(tables, list) or not tables:
        raise ConfigError("service.toml must list at least one [[repositories]] entry")
    repositories = tuple(_repository(table, index) for index, table in enumerate(tables))
    slugs = [repository.slug.casefold() for repository in repositories]
    if len(set(slugs)) != len(slugs):
        raise ConfigError("a repository is listed twice")
    return ServiceConfig(repositories=repositories, **values)


def load(path: Path) -> ServiceConfig:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path} cannot be read: {exc}") from exc
    return parse(data)
