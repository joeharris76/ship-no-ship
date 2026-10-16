from __future__ import annotations

import io
import urllib.error
import urllib.request
from email.message import Message

import pytest

from ship_no_ship_service import transport
from ship_no_ship_service.transport import Response, TransportError, UrllibTransport


class Reply(io.BytesIO):
    status = 200

    def __init__(self, body: bytes) -> None:
        super().__init__(body)
        self.headers = Message()
        self.headers["ETag"] = '"v1"'


def test_the_token_is_never_forwarded_on_a_redirect(monkeypatch):
    seen: list[urllib.request.Request] = []

    def urlopen(request, timeout):
        seen.append(request)
        return Reply(b"{}")

    monkeypatch.setattr(transport.urllib.request, "urlopen", urlopen)
    response = UrllibTransport()(
        "GET", "https://api.example.test/x", headers={"Authorization": "token t", "Accept": "a"}
    )
    assert response.status == 200 and response.header("etag") == '"v1"'
    assert seen[0].unredirected_hdrs == {"Authorization": "token t"}
    assert "Authorization" not in seen[0].headers


def test_http_errors_become_responses(monkeypatch):
    def urlopen(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 304, "Not Modified", Message(), io.BytesIO(b""))

    monkeypatch.setattr(transport.urllib.request, "urlopen", urlopen)
    assert UrllibTransport()("GET", "https://api.example.test/x", headers={}).status == 304


def test_plain_http_and_oversize_bodies_are_refused(monkeypatch):
    with pytest.raises(TransportError, match="https"):
        UrllibTransport()("GET", "http://api.example.test/x", headers={})
    monkeypatch.setattr(transport.urllib.request, "urlopen", lambda request, timeout: Reply(b"x" * 11))
    with pytest.raises(TransportError, match="larger"):
        UrllibTransport(max_body=10)("GET", "https://api.example.test/x", headers={})


def test_network_failures_name_the_path_without_the_query(monkeypatch):
    def urlopen(request, timeout):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(transport.urllib.request, "urlopen", urlopen)
    with pytest.raises(TransportError) as raised:
        UrllibTransport()("GET", "https://api.example.test/x?secret=1", headers={})
    assert "secret" not in str(raised.value)


def test_response_json_and_header_lookup():
    assert Response(200, {"Content-Type": "x"}, b'{"a": 1}').json() == {"a": 1}
    assert Response(204).json() is None
    assert Response(200).header("missing") is None
