from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from ship_no_ship_service.config import Repository
from ship_no_ship_service.ghclient import ArtifactError, GitHubError, RestClient, read_request_zip
from ship_no_ship_service.transport import Response

from .fake_github import SLUG

REPO = Repository(SLUG, 7, 9, Path("/var/empty/key.pem"), "example-bot", "main")


def zipped(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_request_zips_hold_only_known_bounded_files():
    assert read_request_zip(zipped({"plan.json": b"{}", "request.json": b"{}"})) == {
        "plan.json": b"{}",
        "request.json": b"{}",
    }
    for files in (
        {"plan.json": b"{}", "run.sh": b"x"},
        {"../plan.json": b"{}"},
        {"request.json": b"x" * (64 * 1024 + 1)},
    ):
        with pytest.raises(ArtifactError, match="unexpected or oversize"):
            read_request_zip(zipped(files))
    with pytest.raises(ArtifactError, match="not a readable zip"):
        read_request_zip(b"not a zip")


class Tokens:
    repository = REPO

    def __init__(self) -> None:
        self.forgotten = 0

    def token(self, permissions) -> str:
        assert dict(permissions) == {"actions": "read", "contents": "read", "pull_requests": "read"}
        return "read-token"

    def forget(self) -> None:
        self.forgotten += 1


class Server:
    def __init__(self, responses: list[Response]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, dict]] = []

    def __call__(self, method, url, *, headers, body=None) -> Response:
        self.requests.append((url, dict(headers)))
        return self.responses.pop(0)


def test_rest_reads_use_etags_and_forget_tokens_on_401():
    server = Server(
        [Response(200, {"ETag": '"v1"'}, b'{"a": 1}'), Response(304), Response(401), Response(200, {}, b"[1]")]
    )
    tokens = Tokens()
    client = RestClient(tokens, server, "https://api.example.test")
    assert client.get("repos/x") == {"a": 1}
    assert client.get("repos/x") == {"a": 1}
    assert server.requests[1][1]["If-None-Match"] == '"v1"'
    assert server.requests[0][1]["Authorization"] == "Bearer read-token"
    with pytest.raises(GitHubError, match="HTTP 401"):
        client.get("repos/y")
    assert tokens.forgotten == 1
    assert client.paginate("repos/z") == [1]
    assert server.requests[-1][0] == "https://api.example.test/repos/z?per_page=100&page=1"
