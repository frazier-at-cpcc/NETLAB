"""Proves the POST /api/cells launch path schedules the LRS grade
backfill correctly.

Three things matter here, per the spec (section 3: "Execution |
Background, never on the launch path | A slow store cannot delay a
virtual machine the student is waiting for"):

  1. A disabled or half-configured feature never schedules the attempt.
  2. A fully configured feature schedules it after a successful upsert.
  3. An exception raised inside the scheduled work can never affect the
     response the LTI server receives for POST /api/cells.

BACKFILL_CONFIG is built once, at api.main import time, from os.environ,
so each test forces a fresh import with the environment already set --
the same concern and the same fix test_lrs_backfill_config.py and
test_lti_main_consumers.py already establish.
"""

import logging
import sys
import types

import pytest
from starlette.testclient import TestClient

BACKFILL_ENV_VARS = (
    "LRS_BACKFILL_ENABLED",
    "LRS_READ_URL",
    "LRS_READ_AUTH",
    "LRS_BACKFILL_CUTOFF",
    "LRS_BACKFILL_DOMAINS",
)

REQUEST_BODY = {
    "course_session_id": "course-session-1",
    "lab_slug": "rhel-storage-basics",
    "resource_link_id": "link-1",
    "outcome_service_url": "https://lms.example/outcomes",
    "sourcedid": "sourcedid-1",
    "consumer_key": "cpcc-canvas",
}

SERVICE_TOKEN = "svc-token"


@pytest.fixture
def load_api_main(monkeypatch):
    for name, attrs in (("asyncpg", {}), ("proxmoxer", {"ProxmoxAPI": object})):
        if name not in sys.modules:
            try:
                __import__(name)
            except ImportError:
                stub = types.ModuleType(name)
                for attr, value in attrs.items():
                    setattr(stub, attr, value)
                monkeypatch.setitem(sys.modules, name, stub)

    for var in BACKFILL_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LAB_API_SERVICE_TOKEN", SERVICE_TOKEN)

    def _load():
        sys.modules.pop("api.main", None)
        import api.main as lab_api_main

        return lab_api_main

    yield _load

    sys.modules.pop("api.main", None)


class FakeCellPool:
    """Stands in for app.state.db. Only fetchrow (upsert_grade_cell's one
    call) is exercised; attempt_backfill itself is monkeypatched out in
    every test below, so its own db usage never runs here."""

    def __init__(self, cell_id=101, previous_sourcedid=None):
        self.cell_id = cell_id
        self.previous_sourcedid = previous_sourcedid
        self.calls = []

    async def fetchrow(self, sql, *args):
        self.calls.append((sql, args))
        return {"id": self.cell_id, "previous_sourcedid": self.previous_sourcedid}


def _post_cells(lab_api_main, pool, body=None):
    lab_api_main.app.state.db = pool
    client = TestClient(lab_api_main.app)
    return client.post(
        "/api/cells",
        json=body or REQUEST_BODY,
        headers={"X-LabsConnect-Service-Token": SERVICE_TOKEN},
    )


def _patch_attempt_backfill(monkeypatch, lab_api_main, calls, *, side_effect=None):
    async def fake_attempt_backfill(db, http, cell_id, *, config):
        calls.append({"cell_id": cell_id, "config": config})
        if side_effect is not None:
            raise side_effect
        return "delivered"

    monkeypatch.setattr(lab_api_main, "attempt_backfill", fake_attempt_backfill)


def test_disabled_feature_does_not_schedule_a_backfill_attempt(monkeypatch, load_api_main):
    lab_api_main = load_api_main()  # every backfill env var cleared by the fixture -> disabled
    calls = []
    _patch_attempt_backfill(monkeypatch, lab_api_main, calls)

    response = _post_cells(lab_api_main, FakeCellPool(cell_id=101))

    assert response.status_code == 200
    assert response.json() == {"id": 101}
    assert calls == []


def test_half_configured_feature_does_not_schedule(monkeypatch, load_api_main):
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")
    monkeypatch.delenv("LRS_READ_AUTH", raising=False)  # missing credential -> off regardless of flag
    lab_api_main = load_api_main()
    calls = []
    _patch_attempt_backfill(monkeypatch, lab_api_main, calls)

    response = _post_cells(lab_api_main, FakeCellPool(cell_id=102))

    assert response.status_code == 200
    assert response.json() == {"id": 102}
    assert calls == []


def test_fully_configured_feature_schedules_the_attempt(monkeypatch, load_api_main):
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")
    lab_api_main = load_api_main()
    calls = []
    _patch_attempt_backfill(monkeypatch, lab_api_main, calls)

    response = _post_cells(lab_api_main, FakeCellPool(cell_id=202))

    assert response.status_code == 200
    assert response.json() == {"id": 202}
    assert len(calls) == 1
    assert calls[0]["cell_id"] == 202
    assert calls[0]["config"] is lab_api_main.BACKFILL_CONFIG


def test_no_cell_identifier_does_not_schedule(monkeypatch, load_api_main):
    """upsert_grade_cell returns None when lab_slug or sourcedid is
    missing; the handler answers 204 in that case and there is no cell
    to backfill."""
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")
    lab_api_main = load_api_main()
    calls = []
    _patch_attempt_backfill(monkeypatch, lab_api_main, calls)
    body = dict(REQUEST_BODY)
    body["lab_slug"] = None

    response = _post_cells(lab_api_main, FakeCellPool(cell_id=303), body=body)

    assert response.status_code == 204
    assert calls == []


def test_a_failure_inside_the_scheduled_work_does_not_affect_the_response(monkeypatch, load_api_main):
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")
    lab_api_main = load_api_main()
    calls = []
    _patch_attempt_backfill(
        monkeypatch, lab_api_main, calls, side_effect=RuntimeError("store is unreachable")
    )

    response = _post_cells(lab_api_main, FakeCellPool(cell_id=404))

    assert response.status_code == 200
    assert response.json() == {"id": 404}
    assert len(calls) == 1  # it really was scheduled and really did run


def test_a_failure_carrying_the_credential_in_its_own_message_is_never_logged(
    monkeypatch, load_api_main, caplog
):
    """An underlying httpx error can embed the request URL, and this
    request's query string carries the student's candidate mailbox and
    could in principle carry other sensitive text. The background
    wrapper must never let the exception's own string representation
    reach the log, only the cell id."""
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")
    lab_api_main = load_api_main()
    calls = []
    _patch_attempt_backfill(
        monkeypatch,
        lab_api_main,
        calls,
        side_effect=RuntimeError(
            "GET https://lrs.example/xapi/statements?agent="
            '{"mbox":"mailto:student@email.cpcc.edu"} '
            "Authorization: Basic cmVhZG9ubHk= failed"
        ),
    )

    with caplog.at_level(logging.WARNING):
        response = _post_cells(lab_api_main, FakeCellPool(cell_id=505))

    assert response.status_code == 200
    assert "cmVhZG9ubHk=" not in caplog.text
    assert "student@email.cpcc.edu" not in caplog.text
