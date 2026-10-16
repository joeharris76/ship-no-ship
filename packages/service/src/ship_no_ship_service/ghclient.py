"""Read-only GitHub REST calls for discovery, made with a read-scoped installation token."""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Mapping
from typing import Any, Protocol

from . import appauth
from .config import Repository
from .transport import Transport

PER_PAGE = 100
MAX_PAGES = 10
ETAG_CACHE = 256
# The files a plan directory may hold, with a size cap for each.
REQUEST_FILES = {
    "plan.json": 1024 * 1024,
    "request.json": 64 * 1024,
    "brief.md": 1024 * 1024,
    "diff.patch": 16 * 1024 * 1024,
    "queued-status.json": 64 * 1024,
}


class GitHubError(RuntimeError):
    pass


class ArtifactError(GitHubError):
    """The artifact itself is unacceptable; fetching it again will not help."""


class TokenSource(Protocol):
    """What the client needs from ``appauth.InstallationTokens``."""

    repository: Repository

    def token(self, permissions: Mapping[str, str]) -> str: ...

    def forget(self) -> None: ...


class GitHub(Protocol):
    def get(self, path: str) -> Any: ...

    def paginate(self, path: str) -> list[Any]: ...

    def artifact_files(self, artifact_id: int) -> dict[str, bytes]: ...


def read_request_zip(data: bytes) -> dict[str, bytes]:
    """The known files of a request artifact. Anything else, or anything too large, refuses the artifact."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        members = archive.infolist()
        files: dict[str, bytes] = {}
        for member in members:
            limit = REQUEST_FILES.get(member.filename)
            if limit is None or member.is_dir() or member.file_size > limit:
                raise ArtifactError(f"the request artifact holds an unexpected or oversize entry {member.filename!r}")
            content = archive.open(member).read(limit + 1)
            if len(content) > limit:
                raise ArtifactError(f"{member.filename} in the request artifact is larger than declared")
            files[member.filename] = content
    except (zipfile.BadZipFile, OSError, EOFError) as exc:
        raise ArtifactError(f"the request artifact is not a readable zip: {exc}") from exc
    return files


class RestClient:
    """GitHub REST reads for one repository, with conditional requests so unchanged listings cost nothing."""

    def __init__(self, tokens: TokenSource, transport: Transport, api_url: str) -> None:
        self.tokens = tokens
        self.transport = transport
        self.api_url = api_url
        self._etags: dict[str, tuple[str, bytes]] = {}

    def _request(self, path: str, accept: str = "application/vnd.github+json") -> bytes:
        headers = {
            "Accept": accept,
            "Authorization": f"Bearer {self.tokens.token(appauth.READ)}",
            "X-GitHub-Api-Version": appauth.API_VERSION,
        }
        cached = self._etags.get(path)
        if cached is not None:
            headers["If-None-Match"] = cached[0]
        response = self.transport("GET", f"{self.api_url}/{path}", headers=headers)
        if response.status == 304 and cached is not None:
            return cached[1]
        if response.status == 401:
            self.tokens.forget()
        if response.status != 200:
            raise GitHubError(f"GET {path.split('?', 1)[0]} returned HTTP {response.status}")
        etag = response.header("ETag")
        if etag and accept == "application/vnd.github+json":
            self._etags.pop(path, None)
            self._etags[path] = (etag, response.body)
            while len(self._etags) > ETAG_CACHE:
                del self._etags[next(iter(self._etags))]
        return response.body

    def get(self, path: str) -> Any:
        try:
            return json.loads(self._request(path))
        except ValueError as exc:
            raise GitHubError(f"GET {path.split('?', 1)[0]} returned malformed JSON") from exc

    def paginate(self, path: str) -> list[Any]:
        joiner = "&" if "?" in path else "?"
        found: list[Any] = []
        for page in range(1, MAX_PAGES + 1):
            items = self.get(f"{path}{joiner}per_page={PER_PAGE}&page={page}")
            if not isinstance(items, list):
                raise GitHubError(f"GET {path.split('?', 1)[0]} did not return a list")
            found.extend(items)
            if len(items) < PER_PAGE:
                return found
        raise GitHubError(f"GET {path.split('?', 1)[0]} has more than {MAX_PAGES} pages")

    def artifact_files(self, artifact_id: int) -> dict[str, bytes]:
        slug = self.tokens.repository.slug
        return read_request_zip(self._request(f"repos/{slug}/actions/artifacts/{artifact_id}/zip", "application/zip"))
