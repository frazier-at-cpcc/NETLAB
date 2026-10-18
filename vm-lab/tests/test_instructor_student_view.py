"""Proves GET /instructor/student-view.

The route exists because an instructor launch returns the dashboard and never
reaches ``check_or_provision_vm``'s student path, so an instructor cannot
otherwise see the page their students see.

Two properties carry the risk, and every test below covers one of them.

The first is access. The route renders a student page and issues a page token,
so an unauthenticated caller, or a caller holding a non-instructor token, must
be refused rather than handed either.

The second is which session it renders. It renders the instructor's own demo
VM and nothing else. Calling the student path with the instructor's identity
would mint a session under a real course session key, and on a graded link an
outcome handle, which puts a preview one step from writing to a gradebook. The
page token it issues must therefore name the demo session key, never a
student's, because a page token for a student's key would let an instructor
read that student's session through the student endpoints.

Reuses the load/discard fresh-import fixture from test_my_grades_route.py:
lti/main.py imports asyncpg and redis and calls redis.from_url(...) at import
time, and reads SESSION_SECRET from the environment once, at import time.
"""

import sys
import types

import pytest
from starlette.testclient import TestClient

SESSION_SECRET = "a-real-configured-secret-for-tests"
DEMO_SESSION_ID = "demo-session-1"
DEMO_SESSION_KEY = "demo:instructor-9:course-7:abcd1234"
STUDENT_SESSION_KEY = "guid:student-1:course-7:link-3"
INSTRUCTOR_TOKEN = "instructor-token-value"


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

    def json(self):
        return self._json_body


class FakeAsyncClient:
    def __init__(self, json_body, status_code=200):
        self._json_body = json_body
        self._status_code = status_code

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, **kwargs):
        return FakeResponse(self._json_body, self._status_code)


def _wire(monkeypatch, lti_main, *, session_data, vm_session, issued=None):
    """Stand in for the instructor token store, the orchestrator, and the
    page-token minter, recording every key a token is issued for."""
    monkeypatch.setattr(
        lti_main, "get_instructor_session", lambda token: session_data
    )
    monkeypatch.setattr(
        lti_main.httpx, "AsyncClient", lambda *a, **kw: FakeAsyncClient(vm_session)
    )
    if issued is not None:
        monkeypatch.setattr(
            lti_main,
            "issue_page_token",
            lambda key: issued.append(key) or "page-token-value",
        )
    return TestClient(lti_main.app)


def _instructor(**overrides):
    data = {
        "instructor": True,
        "user_id": "instructor-9",
        "user_email": "instructor@example.edu",
        "user_name": "An Instructor",
        "course_id": "course-7",
        "course_title": "Linux Single User",
        "demo_vm_session_id": DEMO_SESSION_ID,
        "demo_vm_session_key": DEMO_SESSION_KEY,
    }
    data.update(overrides)
    return data


def test_no_token_is_refused(monkeypatch, load_lti_main):
    lti_main = load_lti_main()
    client = _wire(monkeypatch, lti_main, session_data=None, vm_session={})
    assert client.get("/instructor/student-view").status_code == 403


def test_a_non_instructor_token_is_refused(monkeypatch, load_lti_main):
    """A token that resolves but does not carry instructor is not enough."""
    lti_main = load_lti_main()
    client = _wire(
        monkeypatch,
        lti_main,
        session_data={"instructor": False, "user_id": "student-1"},
        vm_session={},
    )
    response = client.get(f"/instructor/student-view?_token={INSTRUCTOR_TOKEN}")
    assert response.status_code == 403


def test_no_demo_vm_is_reported_rather_than_provisioning_one(
    monkeypatch, load_lti_main
):
    """The route never provisions. Without a demo VM there is nothing to show."""
    issued = []
    lti_main = load_lti_main()
    client = _wire(
        monkeypatch,
        lti_main,
        session_data=_instructor(demo_vm_session_id=None),
        vm_session={},
        issued=issued,
    )
    response = client.get(f"/instructor/student-view?_token={INSTRUCTOR_TOKEN}")
    assert response.status_code == 409
    assert issued == [], "no page token may be issued when there is no session"


def test_a_stopped_demo_vm_is_reported_rather_than_rendered(
    monkeypatch, load_lti_main
):
    issued = []
    lti_main = load_lti_main()
    client = _wire(
        monkeypatch,
        lti_main,
        session_data=_instructor(),
        vm_session={"status": "destroyed", "url": ""},
        issued=issued,
    )
    response = client.get(f"/instructor/student-view?_token={INSTRUCTOR_TOKEN}")
    assert response.status_code == 409
    assert issued == []


def test_a_running_demo_vm_renders_the_student_page(monkeypatch, load_lti_main):
    issued = []
    lti_main = load_lti_main()
    client = _wire(
        monkeypatch,
        lti_main,
        session_data=_instructor(),
        vm_session={
            "status": "running",
            "url": "https://lab-demo-session-1.example.edu",
            "vm_ip": "172.18.8.99",
        },
        issued=issued,
    )
    response = client.get(f"/instructor/student-view?_token={INSTRUCTOR_TOKEN}")
    assert response.status_code == 200
    # The student page is the only one carrying these controls.
    assert "Open Terminal" in response.text
    assert DEMO_SESSION_ID in response.text


def test_the_page_token_names_the_demo_key_never_a_student_key(
    monkeypatch, load_lti_main
):
    """The property that keeps this route from reading a student's session.

    A page token resolves server-side to a lab session. One issued for a
    student's course session key would let an instructor drive the student
    endpoints against that student.
    """
    issued = []
    lti_main = load_lti_main()
    client = _wire(
        monkeypatch,
        lti_main,
        session_data=_instructor(),
        vm_session={"status": "running", "url": "https://x.example.edu"},
        issued=issued,
    )
    client.get(f"/instructor/student-view?_token={INSTRUCTOR_TOKEN}")

    assert issued == [DEMO_SESSION_KEY]
    assert STUDENT_SESSION_KEY not in issued
    assert all(key.startswith("demo:") for key in issued)


def test_a_client_supplied_session_key_is_ignored(monkeypatch, load_lti_main):
    """The route reads the demo session from the token store, not the request."""
    issued = []
    lti_main = load_lti_main()
    client = _wire(
        monkeypatch,
        lti_main,
        session_data=_instructor(),
        vm_session={"status": "running", "url": "https://x.example.edu"},
        issued=issued,
    )
    client.get(
        f"/instructor/student-view?_token={INSTRUCTOR_TOKEN}"
        f"&session_key={STUDENT_SESSION_KEY}"
        f"&session_id=some-other-session"
    )
    assert issued == [DEMO_SESSION_KEY]
