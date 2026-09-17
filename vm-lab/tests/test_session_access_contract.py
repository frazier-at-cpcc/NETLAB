"""Proves the access map is additive and that `url` remains a faithful alias.

The launch page and the instructor dashboard read `url`. Adding an access
map must not change what those clients already receive, so every test here
asserts the old field alongside the new one. The alias is derived from the
same value rather than assigned twice, which is what keeps the two from
drifting as later phases fill the desktop mode in.

The desktop mode is declared but not yet provisioned. Until the gateway
broker lands it reports itself unavailable with a reason, and it carries no
token, host, port, or credential of any kind. That last property is the one
this file exists to hold: the status payload is relayed to the browser by an
unauthenticated proxy.
"""

import sys
import types
from pathlib import Path

import pytest
from starlette.testclient import TestClient

SESSION_ID = "a1b2c3d4"
TERMINAL_URL = "https://lab-a1b2c3d4.example.org/"
MIGRATION = Path(__file__).resolve().parents[1] / "migrations" / "005_session_access.sql"


def _load_api_main():
    for name, attrs in (("asyncpg", {}), ("proxmoxer", {"ProxmoxAPI": object})):
        if name not in sys.modules:
            try:
                __import__(name)
            except ImportError:
                stub = types.ModuleType(name)
                for attr, value in attrs.items():
                    setattr(stub, attr, value)
                sys.modules[name] = stub
    import api.main as lab_api_main

    return lab_api_main


class _FakeDb:
    def __init__(self, row):
        self._row = row

    async def fetchrow(self, _query, *_args):
        return self._row


def _row(status):
    return {
        "session_id": SESSION_ID,
        "url": TERMINAL_URL,
        "vm_ip": "10.10.10.42",
        "status": status,
        "status_message": None,
        "user_name": "Student One",
        "course_title": "NOS 120",
        "assignment_title": "Lab 3",
        "created_at": None,
        "expires_at": None,
        "started_at": None,
    }


def _status(status="running"):
    api_main = _load_api_main()
    api_main.app.state.db = _FakeDb(_row(status))
    response = TestClient(api_main.app).get(f"/api/session/{SESSION_ID}/status")
    assert response.status_code == 200
    return response.json()


def test_url_still_carries_the_terminal_url_when_ready():
    assert _status()["url"] == TERMINAL_URL


def test_url_is_still_absent_until_the_session_is_ready():
    assert _status("starting")["url"] is None


def test_terminal_access_matches_the_compatibility_alias_exactly():
    payload = _status()
    assert payload["access"]["terminal"]["url"] == payload["url"]


def test_terminal_access_is_empty_until_the_session_is_ready():
    payload = _status("starting")
    assert payload["access"]["terminal"]["url"] == payload["url"] is None


def test_desktop_is_unavailable_with_a_reason_while_the_flag_is_off(monkeypatch):
    api_main = _load_api_main()
    monkeypatch.setattr(api_main, "BROWSER_RDP_ENABLED", False)
    desktop = _status()["access"]["desktop"]
    assert desktop["available"] is False
    assert desktop["reason"] == api_main.DESKTOP_DISABLED


def test_desktop_reports_pending_before_the_session_is_ready(monkeypatch):
    api_main = _load_api_main()
    monkeypatch.setattr(api_main, "BROWSER_RDP_ENABLED", True)
    desktop = _status("starting")["access"]["desktop"]
    assert desktop["available"] is False
    assert desktop["reason"] == api_main.DESKTOP_PENDING


def test_desktop_reports_no_access_record_once_ready(monkeypatch):
    api_main = _load_api_main()
    monkeypatch.setattr(api_main, "BROWSER_RDP_ENABLED", True)
    desktop = _status()["access"]["desktop"]
    assert desktop["available"] is False
    assert desktop["reason"] == api_main.DESKTOP_NOT_PROVISIONED


@pytest.mark.parametrize("flag", [False, True])
def test_desktop_carries_nothing_but_availability_and_a_reason(monkeypatch, flag):
    """The payload reaches the browser through an unauthenticated proxy. No
    token, host, port, username, or password may ever appear in it."""
    api_main = _load_api_main()
    monkeypatch.setattr(api_main, "BROWSER_RDP_ENABLED", flag)
    assert set(_status()["access"]["desktop"]) == {"available", "reason"}


def test_session_model_also_carries_the_access_map():
    api_main = _load_api_main()
    session = api_main.Session(
        session_id=SESSION_ID, url=TERMINAL_URL, status="running"
    )
    assert session.model_dump()["access"]["terminal"]["url"] == TERMINAL_URL


def test_session_model_still_carries_url_for_existing_clients():
    api_main = _load_api_main()
    session = api_main.Session(
        session_id=SESSION_ID, url=TERMINAL_URL, status="running"
    )
    assert session.model_dump()["url"] == TERMINAL_URL


def test_migration_creates_the_access_table_with_one_row_per_mode():
    sql = MIGRATION.read_text()
    assert "vm_session_access" in sql
    assert "UNIQUE (session_id, mode)" in sql


def test_migration_stores_a_token_hash_and_never_a_plaintext_token():
    sql = MIGRATION.read_text().lower()
    assert "token_hash" in sql
    assert "token_plaintext" not in sql
