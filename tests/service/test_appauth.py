from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import jwt
import pytest

from ship_no_ship_service import appauth
from ship_no_ship_service.appauth import AppAuthError, InstallationTokens
from ship_no_ship_service.transport import Response

from .conftest import SLUG

START = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class TokenEndpoint:
    """GitHub's access-token endpoint, checking each JWT against its own clock and the App's public key."""

    def __init__(self, public_key, server_clock: Clock, lifetime: timedelta = timedelta(hours=1)) -> None:
        self.public_key = public_key
        self.server_clock = server_clock
        self.lifetime = lifetime
        self.requests: list[dict] = []
        self.grant: Mapping[str, str] | None = None
        self.repositories: list[str] | None = None

    def __call__(self, method, url, *, headers, body=None) -> Response:
        now = self.server_clock()
        date = {"Date": format_datetime(now, usegmt=True)}
        assert method == "POST" and url == "https://api.example.test/app/installations/9/access_tokens"
        token = headers["Authorization"].removeprefix("Bearer ")
        claims = jwt.decode(
            token, self.public_key, algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False}
        )
        if not claims["iat"] <= now.timestamp() < claims["exp"] or claims["exp"] - claims["iat"] > 600:
            return Response(401, date, b'{"message": "bad JWT"}')
        assert body is not None
        request = json.loads(body)
        self.requests.append({"claims": claims, **request})
        payload = {
            "token": f"tok-{len(self.requests)}",
            "expires_at": (now + self.lifetime).isoformat().replace("+00:00", "Z"),
            "permissions": dict(request["permissions"] if self.grant is None else self.grant) | {"metadata": "read"},
            "repositories": [{"full_name": name} for name in (self.repositories or [SLUG])],
        }
        return Response(201, date, json.dumps(payload).encode())


@pytest.fixture
def clock() -> Clock:
    return Clock(START)


@pytest.fixture
def endpoint(rsa_key, clock) -> TokenEndpoint:
    return TokenEndpoint(rsa_key.public_key(), clock)


def tokens(repository, endpoint, clock) -> InstallationTokens:
    return InstallationTokens(repository, endpoint, api_url="https://api.example.test", clock=clock)


def test_jwt_is_rs256_backdated_and_short(rsa_key, key_file):
    token = appauth.app_jwt(7, key_file.read_bytes(), START)
    assert jwt.get_unverified_header(token)["alg"] == "RS256"
    claims = jwt.decode(
        token, rsa_key.public_key(), algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False}
    )
    assert claims == {"iss": "7", "iat": int(START.timestamp()) - 60, "exp": int(START.timestamp()) + 540}


def test_each_call_kind_gets_a_token_scoped_to_its_permissions_and_one_repository(repository, endpoint, clock):
    auth = tokens(repository, endpoint, clock)
    values = {
        name: auth.token(perms)
        for name, perms in [
            ("read", appauth.READ),
            ("status", appauth.STATUS),
            ("post", appauth.POST),
            ("dispatch", appauth.DISPATCH),
        ]
    }
    assert len(set(values.values())) == 4
    assert [request["permissions"] for request in endpoint.requests] == [
        {"actions": "read", "contents": "read", "pull_requests": "read"},
        {"statuses": "write"},
        {"statuses": "write", "pull_requests": "write"},
        {"actions": "write"},
    ]
    assert all(request["repositories"] == ["example-repo"] for request in endpoint.requests)
    assert all(request["claims"]["iss"] == "7" for request in endpoint.requests)


def test_actions_write_is_only_in_the_dispatch_set():
    sets = [appauth.READ, appauth.STATUS, appauth.POST]
    assert all(perms.get("actions") != "write" for perms in sets)
    assert dict(appauth.DISPATCH) == {"actions": "write"}


def test_a_token_is_reused_while_more_than_ten_minutes_remain_and_then_refreshed(repository, endpoint, clock):
    auth = tokens(repository, endpoint, clock)
    first = auth.token(appauth.STATUS)
    clock.now = START + timedelta(minutes=49, seconds=59)
    assert auth.token(appauth.STATUS) == first
    clock.now = START + timedelta(minutes=50)
    assert auth.token(appauth.STATUS) != first
    assert len(endpoint.requests) == 2


def test_forget_drops_cached_tokens(repository, endpoint, clock):
    auth = tokens(repository, endpoint, clock)
    first = auth.token(appauth.READ)
    auth.forget()
    assert auth.token(appauth.READ) != first


def test_validity_is_measured_on_githubs_clock_when_ours_is_behind(repository, endpoint, rsa_key):
    local = Clock(START)
    server = Clock(START + timedelta(minutes=20))
    endpoint = TokenEndpoint(rsa_key.public_key(), server)
    auth = tokens(repository, endpoint, local)
    first = auth.token(appauth.POST)
    # The token's expires_at is 13:20 by GitHub's clock, which is 13:00 on ours: refresh by 12:50 local.
    local.now = START + timedelta(minutes=49)
    server.now = local.now + timedelta(minutes=20)
    assert auth.token(appauth.POST) == first
    local.now = START + timedelta(minutes=51)
    server.now = local.now + timedelta(minutes=20)
    assert auth.token(appauth.POST) != first


def test_a_jwt_refused_for_clock_skew_is_minted_again_on_githubs_clock(repository, rsa_key):
    local = Clock(START)
    server = Clock(START + timedelta(minutes=15))
    endpoint = TokenEndpoint(rsa_key.public_key(), server)
    auth = tokens(repository, endpoint, local)
    assert auth.token(appauth.READ) == "tok-1"
    assert endpoint.requests[0]["claims"]["iat"] == int(server.now.timestamp()) - 60


@pytest.mark.parametrize(
    ("grant", "repos", "message"),
    [
        ({"statuses": "write", "contents": "write"}, None, "granted"),
        ({}, None, "granted"),
        (None, [SLUG, "example-owner/other"], "not limited"),
        (None, ["example-owner/other"], "not limited"),
    ],
)
def test_a_token_wider_or_narrower_than_requested_is_refused(repository, endpoint, clock, grant, repos, message):
    endpoint.grant = grant
    endpoint.repositories = repos
    with pytest.raises(AppAuthError, match=message):
        tokens(repository, endpoint, clock).token(appauth.STATUS)


def test_a_refusal_does_not_echo_the_response(repository, clock):
    def refuse(method, url, *, headers, body=None):
        return Response(403, {}, b'{"message": "secret-looking text"}')

    with pytest.raises(AppAuthError) as raised:
        tokens(repository, refuse, clock).token(appauth.READ)
    assert "secret-looking" not in str(raised.value)
    assert "HTTP 403" in str(raised.value)


def test_an_unreadable_key_is_reported_without_its_path_contents(repository, endpoint, clock):
    repository.key_path.chmod(0o600)
    repository.key_path.unlink()
    with pytest.raises(AppAuthError, match="App key cannot be read"):
        tokens(repository, endpoint, clock).token(appauth.READ)


def test_token_repr_hides_the_value():
    token = appauth.Token("tok-hidden", (("statuses", "write"),), START)
    assert "tok-hidden" not in repr(token)
