"""Proves the cookie-scoped GET /api/my-grades proxy in lti-server.

This route's whole risk is one property: a student must never be able
to make it name another student's session. The session comes from the
signed lti_session cookie or, when the LMS iframe has blocked it, from
the launch token this page was rendered with, which is random and
resolves server-side. No session identifier supplied by the client is
read: not a query parameter, not a path segment, not a header naming a
session, not a JSON body field.

Every adversarial test below sets the session cookie to SESSION_A, then
supplies SESSION_B every way a client could offer an identifier, and
asserts the upstream call to lab-api still names SESSION_A. The launch
token is held to the same rule: it is not an identifier, it resolves to
one, and a cookie already present outranks it.

Reuses the load/discard fresh-import pattern from
test_lti_main_consumers.py and test_session_secret.py: lti/main.py
unconditionally imports asyncpg and redis and calls redis.from_url(...)
at import time, and SESSION_SECRET is read from the environment once, at
import time, so each test needs its own fresh import with the
environment (and here, a known secret so a matching cookie can be
minted) already in place.
"""

import json
import sys
import types
from base64 import b64encode

import httpx
import itsdangerous
import pytest
from starlette.testclient import TestClient

from api.service_auth import SERVICE_TOKEN_HEADER

SESSION_COOKIE_NAME = "lti_session"
SESSION_SECRET = "a-real-configured-secret-for-tests"
SESSION_A = "session-A"
SESSION_B = "session-B"


def _signed_session_cookie(secret_key, session_data):
    """Mints a cookie value in exactly the shape Starlette's
    SessionMiddleware produces and verifies (see
    starlette.middleware.sessions.SessionMiddleware), so these tests can
    supply a valid cookie without driving a real login/launch flow."""
    signer = itsdangerous.TimestampSigner(str(secret_key))
    data = b64encode(json.dumps(session_data).encode("utf-8"))
    return signer.sign(data).decode("utf-8")


@pytest.fixture
def load_lti_main(monkeypatch):
    for name, attrs in (
        ("asyncpg", {}),
        ("redis", {"from_url": lambda *a, **kw: None}),
    ):
        if name not in sys.modules:
            try:
                __import__(name)
            except ImportError:
                stub = types.ModuleType(name)
                for attr, value in attrs.items():
                    setattr(stub, attr, value)
                monkeypatch.setitem(sys.modules, name, stub)

    monkeypatch.setenv("SESSION_SECRET", SESSION_SECRET)

    def _load():
        sys.modules.pop("lti.main", None)
        import lti.main as lti_main

        return lti_main

    yield _load

    sys.modules.pop("lti.main", None)


class FakeResponse:
    def __init__(self, json_body, status_code=200):
        self._json_body = json_body
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "http://lab-api:8000/x")
            raise httpx.HTTPStatusError(
                f"status {self.status_code}",
                request=request,
                response=httpx.Response(self.status_code, request=request),
            )

    def json(self):
        return self._json_body


class FakeAsyncClient:
    """Stands in for httpx.AsyncClient. Records every call made through
    .get(...) so a test can inspect exactly what session_id, if any,
    reached the upstream request."""

    def __init__(self, calls, *, json_body=None, status_code=200, raise_exc=None):
        self.calls = calls
        self._json_body = json_body if json_body is not None else {"grades": []}
        self._status_code = status_code
        self._raise_exc = raise_exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        if self._raise_exc is not None:
            raise self._raise_exc
        return FakeResponse(self._json_body, self._status_code)


def _patch_http(monkeypatch, lti_main, calls, **client_kwargs):
    monkeypatch.setattr(
        lti_main.httpx,
        "AsyncClient",
        lambda *a, **kw: FakeAsyncClient(calls, **client_kwargs),
    )


def _cookie_for(lti_main, session_id):
    return _signed_session_cookie(
        lti_main.SESSION_SECRET, {"current_session_id": session_id}
    )


def _client_with_session(lti_main, session_id):
    """A TestClient carrying a signed session cookie naming session_id,
    set on the client instance rather than per-request so it survives
    whatever else a test attaches to an individual call."""
    client = TestClient(lti_main.app)
    client.cookies.set(SESSION_COOKIE_NAME, _cookie_for(lti_main, session_id))
    return client


def test_no_cookie_and_no_launch_token_is_refused_not_answered_empty(
    monkeypatch, load_lti_main
):
    """This route used to answer an empty grade list here, and that is how it
    hid the fact that it never worked inside an LMS iframe: the cookie is
    third-party there and blocked, so every real student took this path, the
    panel saw no grades and hid itself, and nothing anywhere said why. A caller
    with no resolvable session is now refused. The page ignores an error from
    the grade poll, so nothing is lost by saying so."""
    lti_main = load_lti_main()
    calls = []
    _patch_http(monkeypatch, lti_main, calls)
    client = TestClient(lti_main.app)

    response = client.get("/api/my-grades")

    assert response.status_code == 403
    assert calls == []


def test_launch_token_resolves_the_session_when_the_cookie_is_blocked(
    monkeypatch, load_lti_main
):
    """The iframe case. No cookie, one launch token, and the grades that come
    back belong to the session that token resolves to."""
    lti_main = load_lti_main()
    monkeypatch.setattr(
        lti_main, "session_key_for_page_token", lambda token: "guid:user:course"
    )
    calls = []
    _patch_http(
        monkeypatch,
        lti_main,
        calls,
        json_body={"session_id": SESSION_A},
    )
    client = TestClient(lti_main.app)

    client.get("/api/my-grades", headers={"X-Lab-Page-Token": "a-live-token"})

    # One lookup by key, then the grade fetch for the session it named.
    assert len(calls) == 2
    assert calls[0]["url"].endswith("/api/session/by-key/guid%3Auser%3Acourse")
    assert calls[1]["url"] == (
        f"{lti_main.ORCHESTRATOR_API}/api/session/{SESSION_A}/grades"
    )


def test_an_unissued_launch_token_resolves_to_nothing(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    monkeypatch.setattr(lti_main, "session_key_for_page_token", lambda token: None)
    calls = []
    _patch_http(monkeypatch, lti_main, calls)
    client = TestClient(lti_main.app)

    response = client.get(
        "/api/my-grades", headers={"X-Lab-Page-Token": "never-issued"}
    )

    assert response.status_code == 403
    assert calls == []


def test_the_cookie_wins_over_a_launch_token_naming_another_session(
    monkeypatch, load_lti_main
):
    """A student holding their own cookie cannot be redirected to someone
    else's session by a token presented alongside it."""
    lti_main = load_lti_main()
    monkeypatch.setattr(
        lti_main, "session_key_for_page_token", lambda token: "guid:other:course"
    )
    calls = []
    _patch_http(monkeypatch, lti_main, calls)
    client = _client_with_session(lti_main, SESSION_A)

    client.get("/api/my-grades", headers={"X-Lab-Page-Token": "someone-elses-token"})

    assert len(calls) == 1
    assert calls[0]["url"] == (
        f"{lti_main.ORCHESTRATOR_API}/api/session/{SESSION_A}/grades"
    )


def test_valid_cookie_calls_lab_api_for_exactly_that_session(
    monkeypatch, load_lti_main
):
    lti_main = load_lti_main()
    calls = []
    _patch_http(
        monkeypatch,
        lti_main,
        calls,
        json_body={"grades": [{"slug": "cli-review", "state": "delivered"}]},
    )
    client = _client_with_session(lti_main, SESSION_A)

    response = client.get("/api/my-grades")

    assert response.status_code == 200
    assert response.json() == {
        "grades": [{"slug": "cli-review", "state": "delivered"}]
    }
    assert len(calls) == 1
    assert calls[0]["url"] == f"{lti_main.ORCHESTRATOR_API}/api/session/{SESSION_A}/grades"


def test_query_parameter_session_id_is_ignored(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    calls = []
    _patch_http(monkeypatch, lti_main, calls)
    client = _client_with_session(lti_main, SESSION_A)

    client.get(
        "/api/my-grades",
        params={
            "session_id": SESSION_B,
            "course_session_id": SESSION_B,
            "sid": SESSION_B,
        },
    )

    assert len(calls) == 1
    assert calls[0]["url"] == f"{lti_main.ORCHESTRATOR_API}/api/session/{SESSION_A}/grades"
    assert SESSION_B not in calls[0]["url"]
    assert SESSION_B not in str(calls[0].get("params"))


def test_header_session_id_is_ignored(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    calls = []
    _patch_http(monkeypatch, lti_main, calls)
    client = _client_with_session(lti_main, SESSION_A)

    client.get(
        "/api/my-grades",
        headers={
            "X-Session-Id": SESSION_B,
            "X-Course-Session-Id": SESSION_B,
            "X-LabsConnect-Session-Id": SESSION_B,
            "Session-Id": SESSION_B,
        },
    )

    assert len(calls) == 1
    assert calls[0]["url"] == f"{lti_main.ORCHESTRATOR_API}/api/session/{SESSION_A}/grades"
    assert SESSION_B not in calls[0]["url"]


def test_json_body_session_id_is_ignored(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    calls = []
    _patch_http(monkeypatch, lti_main, calls)
    client = _client_with_session(lti_main, SESSION_A)

    client.request(
        "GET",
        "/api/my-grades",
        json={"session_id": SESSION_B, "course_session_id": SESSION_B},
    )

    assert len(calls) == 1
    assert calls[0]["url"] == f"{lti_main.ORCHESTRATOR_API}/api/session/{SESSION_A}/grades"
    assert SESSION_B not in calls[0]["url"]


def test_path_segment_session_id_has_no_route_to_accept_it(
    monkeypatch, load_lti_main
):
    """/api/my-grades takes no path parameter. Appending a segment must
    not route anywhere that could read it as a session id."""
    lti_main = load_lti_main()
    calls = []
    _patch_http(monkeypatch, lti_main, calls)
    client = _client_with_session(lti_main, SESSION_A)

    response = client.get(f"/api/my-grades/{SESSION_B}")

    assert response.status_code == 404
    assert calls == []


def test_upstream_network_error_returns_empty_list_not_a_failure(
    monkeypatch, load_lti_main
):
    lti_main = load_lti_main()
    calls = []
    _patch_http(monkeypatch, lti_main, calls, raise_exc=httpx.ConnectTimeout("timed out"))
    client = _client_with_session(lti_main, SESSION_A)

    response = client.get("/api/my-grades")

    assert response.status_code == 200
    assert response.json() == {"grades": []}


def test_upstream_error_status_returns_empty_list_not_a_failure(
    monkeypatch, load_lti_main
):
    lti_main = load_lti_main()
    calls = []
    _patch_http(monkeypatch, lti_main, calls, status_code=500)
    client = _client_with_session(lti_main, SESSION_A)

    response = client.get("/api/my-grades")

    assert response.status_code == 200
    assert response.json() == {"grades": []}


def test_upstream_call_carries_the_service_token(monkeypatch, load_lti_main):
    """The browser never reaches lab-api directly; lti-server must
    authenticate to it the same way POST /api/cells and GET
    /api/grade-events already do."""
    monkeypatch.setenv("LAB_API_SERVICE_TOKEN", "svc-token-secret")
    lti_main = load_lti_main()
    calls = []
    _patch_http(monkeypatch, lti_main, calls)
    client = _client_with_session(lti_main, SESSION_A)

    client.get("/api/my-grades")

    assert calls[0]["headers"].get(SERVICE_TOKEN_HEADER) == "svc-token-secret"


def test_service_token_never_appears_in_the_response_to_the_browser(
    monkeypatch, load_lti_main
):
    monkeypatch.setenv("LAB_API_SERVICE_TOKEN", "svc-token-secret")
    lti_main = load_lti_main()
    calls = []
    _patch_http(
        monkeypatch,
        lti_main,
        calls,
        json_body={"grades": [{"slug": "cli-review", "state": "delivered"}]},
    )
    client = _client_with_session(lti_main, SESSION_A)

    response = client.get("/api/my-grades")

    assert "svc-token-secret" not in response.text
