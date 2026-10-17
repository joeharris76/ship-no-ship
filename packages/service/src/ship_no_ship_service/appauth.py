"""GitHub App authentication: a short RS256 JWT exchanged for narrowly scoped installation tokens.

Each token covers one repository and only the permissions one kind of call needs. Tokens live only in
this process's memory and are reused while more than ten minutes of validity remain, so a long review
never posts with a token that is about to expire. The App key is read from its file for each JWT and
not kept.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from types import MappingProxyType

import jwt

from .config import Repository
from .transport import Response, Transport

# One permission set per kind of call. Only the record dispatch asks for actions: write.
READ = MappingProxyType({"actions": "read", "contents": "read", "pull_requests": "read", "statuses": "read"})
STATUS = MappingProxyType({"statuses": "write"})
POST = MappingProxyType({"statuses": "write", "pull_requests": "write"})
DISPATCH = MappingProxyType({"actions": "write"})

REFRESH_MARGIN = timedelta(minutes=10)
JWT_BACKDATE = timedelta(seconds=60)
JWT_LIFETIME = timedelta(minutes=9)
SKEW_TOLERANCE = timedelta(seconds=30)
MAX_SKEW = timedelta(minutes=15)
MAX_LIFETIME = timedelta(hours=1)
KEY_MODES = (0o400, 0o600)
API_VERSION = "2022-11-28"
# GitHub adds metadata: read to every installation token.
IMPLIED = {"metadata": "read"}


class AppAuthError(RuntimeError):
    pass


def app_jwt(app_id: int, key_pem: bytes, now: datetime) -> str:
    """A JWT that identifies the App, valid for nine minutes and backdated one minute for clock drift."""
    issued = now - JWT_BACKDATE
    claims = {"iat": int(issued.timestamp()), "exp": int((now + JWT_LIFETIME).timestamp()), "iss": str(app_id)}
    return jwt.encode(claims, key_pem, algorithm="RS256")


@dataclass(frozen=True)
class Token:
    value: str = field(repr=False)
    permissions: tuple[tuple[str, str], ...]
    expires_at: datetime

    def fresh(self, now: datetime) -> bool:
        return self.expires_at - now > REFRESH_MARGIN


def _server_time(response: Response) -> datetime | None:
    value = response.header("Date")
    if not value:
        return None
    try:
        moment = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo is not None else None


def read_key(path: Path) -> bytes:
    """The App key, only from a regular file (not a symlink) owned by this user with mode 0400 or 0600."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise AppAuthError(f"the App key {path} cannot be opened: {exc.strerror or exc}") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise AppAuthError(f"the App key {path} is not a regular file")
        if info.st_uid != os.geteuid():
            raise AppAuthError(f"the App key {path} is not owned by the service user")
        if stat.S_IMODE(info.st_mode) not in KEY_MODES:
            raise AppAuthError(f"the App key {path} has mode {stat.S_IMODE(info.st_mode):04o}; use 0400 or 0600")
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            return handle.read()
    finally:
        os.close(descriptor)


def _key(permissions: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(permissions.items()))


class InstallationTokens:
    def __init__(
        self,
        repository: Repository,
        transport: Transport,
        *,
        api_url: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.transport = transport
        self.api_url = api_url
        self.clock = clock
        self._tokens: dict[tuple[tuple[str, str], ...], Token] = {}
        self._offset = timedelta(0)

    def token(self, permissions: Mapping[str, str]) -> str:
        """A token for exactly these permissions, minted again when ten minutes or less remain."""
        key = _key(permissions)
        cached = self._tokens.get(key)
        if cached is not None and cached.fresh(self.clock()):
            return cached.value
        self._tokens.pop(key, None)
        minted = self._mint(permissions)
        self._tokens[key] = minted
        return minted.value

    def forget(self) -> None:
        """Drop every cached token, for example after GitHub rejects one."""
        self._tokens.clear()

    def _exchange(self, permissions: Mapping[str, str]) -> tuple[Response, datetime]:
        started = self.clock()
        key_pem = read_key(self.repository.key_path)
        body = json.dumps({"repositories": [self.repository.name], "permissions": dict(permissions)}).encode()
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt(self.repository.app_id, key_pem, started + self._offset)}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": API_VERSION,
        }
        url = f"{self.api_url}/app/installations/{self.repository.installation_id}/access_tokens"
        return self.transport("POST", url, headers=headers, body=body), started

    def _mint(self, permissions: Mapping[str, str]) -> Token:
        response, started = self._exchange(permissions)
        if response.status == 401:
            # A JWT is refused when this machine's clock is off. Mint once more on GitHub's clock, but
            # only for a modest error: a larger one needs the clock fixed, not worked around.
            server = _server_time(response)
            if server is not None and abs(server - self.clock()) > SKEW_TOLERANCE:
                offset = server - self.clock()
                if abs(offset) > MAX_SKEW:
                    raise AppAuthError(f"this machine's clock differs from GitHub's by {offset}; fix the clock")
                self._offset = offset
                response, started = self._exchange(permissions)
                if response.status != 201:
                    self._offset = timedelta(0)
        if response.status != 201:
            raise AppAuthError(
                f"GitHub refused an installation token for {self.repository.slug}: HTTP {response.status}"
            )
        return self._accept(response, started, permissions)

    def _accept(self, response: Response, started: datetime, permissions: Mapping[str, str]) -> Token:
        try:
            data = response.json()
            value = data["token"]
            expires_at = datetime.fromisoformat(str(data["expires_at"]).replace("Z", "+00:00"))
            granted = dict(data["permissions"])
            repositories = [str(item["full_name"]).casefold() for item in data["repositories"]]
        except (ValueError, KeyError, TypeError) as exc:
            raise AppAuthError(f"the installation token response cannot be read: {type(exc).__name__}") from None
        extra = {key: level for key, level in granted.items() if IMPLIED.get(key) != level}
        if extra != dict(permissions):
            raise AppAuthError(f"GitHub granted {sorted(granted.items())}, not {sorted(permissions.items())}")
        if repositories != [self.repository.slug.casefold()]:
            raise AppAuthError(f"the installation token is not limited to {self.repository.slug}")
        if not isinstance(value, str) or not value:
            raise AppAuthError("the installation token is empty")
        # Measure validity on GitHub's clock and count it from when the request started on ours.
        server = _server_time(response) or started
        lifetime = min(expires_at - server, MAX_LIFETIME)
        return Token(value, _key(permissions), started + lifetime)
