"""Proves the cookie-scoped POST /api/my-desktop in lti-server.

This route hands a browser the one reference that opens an RDP desktop, so
its whole risk is the same property /api/my-grades holds: a student must
never be able to make it name another student's session. session_id comes
only from request.session, Starlette's signed cookie, and the route reads no
identifier from the client by any path.

Every adversarial test below sets the cookie to SESSION_A, supplies SESSION_B
every way a client could, and asserts the upstream mint still names SESSION_A.

Reuses the fresh-import and signed-cookie helpers from
test_my_grades_route.py, which lti/main.py requires because it reads
SESSION_SECRET once at import time.
"""

import json
import pathlib
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
SERVICE_TOKEN = "a-configured-service-token"
REFERENCE = "a-single-use-reference"
GATEWAY_URL = "https://rdp.example.org"


def _signed_session_cookie(secret_key, session_data):
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
    monkeypatch.setenv("LAB_API_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.setenv("RDP_GATEWAY_URL", GATEWAY_URL)

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
            request = httpx.Request("POST", "http://lab-api:8000/x")
            raise httpx.HTTPStatusError(
                f"status {self.status_code}",
                request=request,
                response=httpx.Response(self.status_code, request=request),
            )

    def json(self):
        return self._json_body


class FakeAsyncClient:
    def __init__(self, calls, *, json_body=None, status_code=200, raise_exc=None):
        self.calls = calls
        self._json_body = (
            json_body if json_body is not None else {"token": REFERENCE, "expires_in": 60}
        )
        self._status_code = status_code
        self._raise_exc = raise_exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, **kwargs):
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


def _client_with_session(lti_main, session_id):
    client = TestClient(lti_main.app)
    client.cookies.set(
        SESSION_COOKIE_NAME,
        _signed_session_cookie(lti_main.SESSION_SECRET, {"current_session_id": session_id}),
    )
    return client


# --- the identifier can only come from the cookie ---------------------


def test_without_a_cookie_nothing_is_minted(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    calls = []
    _patch_http(monkeypatch, lti_main, calls)

    response = TestClient(lti_main.app).post("/api/my-desktop")

    assert response.status_code == 403
    assert calls == []


def test_the_cookie_alone_names_the_session(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    calls = []
    _patch_http(monkeypatch, lti_main, calls)

    response = _client_with_session(lti_main, SESSION_A).post("/api/my-desktop")

    assert response.status_code == 200
    assert SESSION_A in calls[0]["url"]
    assert SESSION_B not in calls[0]["url"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"params": {"session_id": SESSION_B}},
        {"json": {"session_id": SESSION_B}},
        {"headers": {"X-Session-Id": SESSION_B}},
        {"params": {"current_session_id": SESSION_B}},
    ],
)
def test_no_client_supplied_identifier_can_redirect_the_mint(
    monkeypatch, load_lti_main, kwargs
):
    lti_main = load_lti_main()
    calls = []
    _patch_http(monkeypatch, lti_main, calls)

    response = _client_with_session(lti_main, SESSION_A).post(
        "/api/my-desktop", **kwargs
    )

    assert response.status_code == 200
    assert SESSION_A in calls[0]["url"]
    assert SESSION_B not in calls[0]["url"]


# --- what the browser gets --------------------------------------------


def test_the_reference_is_returned_inside_a_gateway_url(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    _patch_http(monkeypatch, lti_main, [])

    body = _client_with_session(lti_main, SESSION_A).post("/api/my-desktop").json()

    assert body["url"].startswith(GATEWAY_URL)
    assert REFERENCE in body["url"]


def test_the_response_names_no_session_and_no_target(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    _patch_http(monkeypatch, lti_main, [])

    body = _client_with_session(lti_main, SESSION_A).post("/api/my-desktop").json()

    assert set(body) == {"url", "expires_in"}
    assert SESSION_A not in body["url"]


def test_the_mint_is_called_with_the_service_token(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    calls = []
    _patch_http(monkeypatch, lti_main, calls)

    _client_with_session(lti_main, SESSION_A).post("/api/my-desktop")

    assert calls[0]["headers"][SERVICE_TOKEN_HEADER] == SERVICE_TOKEN


# --- degradation ------------------------------------------------------


def test_a_session_without_a_desktop_record_is_refused_cleanly(
    monkeypatch, load_lti_main
):
    lti_main = load_lti_main()
    _patch_http(monkeypatch, lti_main, [], status_code=404, json_body={})

    response = _client_with_session(lti_main, SESSION_A).post("/api/my-desktop")

    assert response.status_code == 409
    assert "url" not in response.json()


def test_an_unreachable_lab_api_does_not_leak_its_error(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    _patch_http(
        monkeypatch,
        lti_main,
        [],
        raise_exc=httpx.ConnectError("lab-api down"),
    )

    response = _client_with_session(lti_main, SESSION_A).post("/api/my-desktop")

    assert response.status_code == 503
    assert "lab-api" not in response.text


# --- what the launch page does with it --------------------------------

TEMPLATE = (
    pathlib.Path(__file__).resolve().parents[1]
    / "lti"
    / "templates"
    / "lab_loading.html"
)


def test_the_desktop_button_starts_disabled():
    """It is enabled only by a status payload that reports a desktop, so a
    page served before provisioning cannot offer one."""
    markup = TEMPLATE.read_text()
    button = markup.split('id="open-desktop-btn"', 1)[1].split(">", 1)[0]

    assert "disabled" in button


def test_the_page_mints_through_the_cookie_scoped_route():
    assert "'/api/my-desktop'" in TEMPLATE.read_text()


def test_the_page_never_reads_a_token_or_a_target_from_the_status_payload():
    """The status payload carries availability only. If the page starts
    reading a token or a host out of it, the payload has grown something the
    unauthenticated proxy should not be relaying."""
    markup = TEMPLATE.read_text()

    for forbidden in (
        "desktop.token",
        "desktop.hostname",
        "desktop.password",
        "access.desktop.url",
    ):
        assert forbidden not in markup
