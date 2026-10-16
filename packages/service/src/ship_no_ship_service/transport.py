"""The one place the service makes HTTP requests, so tests can replace it with a fake."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

MAX_BODY = 32 * 1024 * 1024


class TransportError(RuntimeError):
    pass


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def json(self) -> Any:
        return json.loads(self.body or b"null")


class Transport(Protocol):
    def __call__(self, method: str, url: str, *, headers: Mapping[str, str], body: bytes | None = None) -> Response: ...


class UrllibTransport:
    """HTTPS requests through the standard library.

    The ``Authorization`` header is never sent on a redirect: artifact downloads redirect to storage
    on another host, which must not see the token.
    """

    def __init__(self, timeout: float = 30.0, max_body: int = MAX_BODY) -> None:
        self.timeout = timeout
        self.max_body = max_body

    def __call__(self, method: str, url: str, *, headers: Mapping[str, str], body: bytes | None = None) -> Response:
        if not url.startswith("https://"):
            raise TransportError("only https URLs are allowed")
        request = urllib.request.Request(url, data=body, method=method)
        for key, value in headers.items():
            if key.lower() == "authorization":
                request.add_unredirected_header(key, value)
            else:
                request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as reply:  # noqa: S310 - https only
                return Response(reply.status, dict(reply.headers.items()), self._read(reply))
        except urllib.error.HTTPError as exc:
            return Response(exc.code, dict(exc.headers.items()), self._read(exc))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(f"{method} {url.split('?', 1)[0]} failed: {exc}") from exc

    def _read(self, stream: Any) -> bytes:
        data = stream.read(self.max_body + 1)
        if len(data) > self.max_body:
            raise TransportError(f"the response is larger than {self.max_body} bytes")
        return data
