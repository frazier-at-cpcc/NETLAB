"""Proves the desktop mint survives an LTI iframe without trusting a guess.

The launch page renders inside a Brightspace iframe, where the lti_session
cookie is third-party and browsers block it. SameSite=None with Secure is
necessary and not sufficient. Every cookie-only route therefore fails in the
place the tool is actually used, which is how the desktop button reached
"Desktop could not be opened" against a working server.

The page cannot simply present its session key instead. course_session_key is
"{guid}:{user_id}:{course_id}", so a student who knows another student's LTI
user id can construct it and mint a reference to that student's desktop. The
page carries an unguessable token instead, stored server-side exactly as the
instructor token already is.
"""

import json
import sys
import types
from base64 import b64encode

import httpx
import itsdangerous
import pytest
from starlette.testclient import TestClient

SESSION_COOKIE = "lti_session"
SESSION_SECRET = "a-real-configured-secret-for-tests"
GATEWAY = "https://rdp.example.org"
REFERENCE = "a-single-use-reference"
COURSE_KEY = "brightspace.example:student-a:course-1"
GUESSABLE = "brightspace.example:student-b:course-1"


def _cookie(secret, data):
    return itsdangerous.TimestampSigner(str(secret)).sign(
        b64encode(json.dumps(data).encode())
    ).decode()


@pytest.fixture
def load_lti_main(monkeypatch):
    store: dict[str, str] = {}

    class _Redis:
        def setex(self, key, ttl, value): store[key] = value
        def get(self, key): return store.get(key)
        def ttl(self, key): return 3600

    for name, attrs in (("asyncpg", {}), ("redis", {"from_url": lambda *a, **k: _Redis()})):
        if name not in sys.modules:
            try:
                __import__(name)
            except ImportError:
                stub = types.ModuleType(name)
                for attr, value in attrs.items():
                    setattr(stub, attr, value)
                monkeypatch.setitem(sys.modules, name, stub)
    monkeypatch.setenv("SESSION_SECRET", SESSION_SECRET)
    monkeypatch.setenv("LAB_API_SERVICE_TOKEN", "a-service-token")
    monkeypatch.setenv("RDP_GATEWAY_URL", GATEWAY)

    def _load():
        sys.modules.pop("lti.main", None)
        import lti.main as lti_main
        lti_main.redis_client = _Redis()
        return lti_main

    yield _load
    sys.modules.pop("lti.main", None)


class _Response:
    def __init__(self, body, status=200):
        self._body, self.status_code = body, status
    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://lab-api:8000/x")
            raise httpx.HTTPStatusError("x", request=request,
                                        response=httpx.Response(self.status_code, request=request))
    def json(self): return self._body


class _Client:
    def __init__(self, calls): self.calls = calls
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def get(self, url, **kw):
        self.calls.append(url)
        if "/by-key/" in url:
            return _Response({"session_id": "sess-a", "status": "running"})
        return _Response({})
    async def post(self, url, **kw):
        self.calls.append(url)
        return _Response({"token": REFERENCE, "expires_in": 60})


def _patch(monkeypatch, lti_main, calls):
    monkeypatch.setattr(lti_main.httpx, "AsyncClient", lambda *a, **k: _Client(calls))


def test_a_page_token_mints_without_any_cookie(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    calls = []
    _patch(monkeypatch, lti_main, calls)
    token = lti_main.issue_page_token(COURSE_KEY)
    client = TestClient(lti_main.app, follow_redirects=False)

    response = client.post("/api/my-desktop", json={"page_token": token})

    assert response.status_code == 200
    assert REFERENCE in response.json()["url"]


def test_the_guessable_session_key_is_not_accepted(monkeypatch, load_lti_main):
    """course_session_key is guid:user_id:course_id. Accepting it would let a
    student mint against a classmate's session by changing the user id."""
    lti_main = load_lti_main()
    calls = []
    _patch(monkeypatch, lti_main, calls)
    client = TestClient(lti_main.app, follow_redirects=False)

    for supplied in (COURSE_KEY, GUESSABLE):
        response = client.post("/api/my-desktop", json={"page_token": supplied})
        assert response.status_code == 403, supplied
    assert calls == [], "nothing may reach lab-api on a rejected token"


def test_an_unknown_token_is_refused(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    _patch(monkeypatch, lti_main, [])
    client = TestClient(lti_main.app, follow_redirects=False)

    assert client.post("/api/my-desktop", json={"page_token": "never-issued"}).status_code == 403


def test_the_cookie_still_works_when_the_browser_sends_it(monkeypatch, load_lti_main):
    """First-party contexts, such as a link opening in a new window, keep the
    stricter path."""
    lti_main = load_lti_main()
    _patch(monkeypatch, lti_main, [])
    client = TestClient(lti_main.app, follow_redirects=False)
    client.cookies.set(SESSION_COOKIE,
                       _cookie(lti_main.SESSION_SECRET, {"current_session_id": "sess-a"}))

    assert client.post("/api/my-desktop", json={}).status_code == 200


def test_a_token_is_unguessable(load_lti_main):
    lti_main = load_lti_main()

    tokens = {lti_main.issue_page_token(COURSE_KEY) for _ in range(32)}

    assert len(tokens) == 32
    assert all(len(t) >= 32 for t in tokens)
