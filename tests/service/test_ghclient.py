from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from ship_no_ship_service import ghclient
from ship_no_ship_service.config import Repository
from ship_no_ship_service.ghclient import ArtifactError, GitHubError, RestClient, read_request_zip
from ship_no_ship_service.transport import BodyTooLargeError, Response

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


def test_a_request_zip_may_name_each_file_once():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive, pytest.warns(UserWarning, match="Duplicate name"):
        archive.writestr("request.json", b"{}")
        archive.writestr("request.json", b'{"pr": 2}')
    with pytest.raises(ArtifactError, match="'request.json' more than once"):
        read_request_zip(buffer.getvalue())


def test_a_request_zip_holds_at_most_one_entry_per_known_file():
    files = dict.fromkeys(ghclient.REQUEST_FILES, b"{}")
    assert read_request_zip(zipped(files)) == files
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in ghclient.REQUEST_FILES:
            archive.writestr(name, b"{}")
        archive.writestr("plan.json/", b"")
    with pytest.raises(ArtifactError, match="6 entries, more than 5"):
        read_request_zip(buffer.getvalue())


def test_a_request_zip_is_bounded_in_total_and_in_download_size(monkeypatch):
    assert sum(ghclient.REQUEST_FILES.values()) == ghclient.REQUEST_BYTES
    monkeypatch.setattr(ghclient, "REQUEST_BYTES", 100)
    with pytest.raises(ArtifactError, match="more than 100 bytes in all"):
        read_request_zip(zipped({"plan.json": b"x" * 60, "brief.md": b"y" * 60}))
    assert set(read_request_zip(zipped({"plan.json": b"x" * 60, "brief.md": b"y" * 40}))) == {"plan.json", "brief.md"}
    with pytest.raises(ArtifactError, match="larger than"):
        read_request_zip(b"\0" * (ghclient.REQUEST_ZIP_BYTES + 1))


def test_the_artifact_download_alone_is_read_under_the_zip_cap():
    archive = zipped({"plan.json": b"{}"})
    oversize = b"z" * (ghclient.REQUEST_ZIP_BYTES + 1)
    server = Server([Response(200, {}, b"{}"), Response(200, {}, archive), Response(200, {}, oversize)])
    client = RestClient(Tokens(), server, "https://api.example.test")
    client.get("repos/x")
    assert client.artifact_files(5) == {"plan.json": b"{}"}
    assert server.limits == [{}, {"max_body": ghclient.REQUEST_ZIP_BYTES}]
    with pytest.raises(ArtifactError, match="download is larger than"):
        client.artifact_files(6)


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
        self.limits: list[dict] = []

    def __call__(self, method, url, *, headers, body=None, **limits) -> Response:
        self.requests.append((url, dict(headers)))
        self.limits.append(limits)
        response = self.responses.pop(0)
        if "max_body" in limits and len(response.body) > limits["max_body"]:
            raise BodyTooLargeError("too large")
        return response


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
