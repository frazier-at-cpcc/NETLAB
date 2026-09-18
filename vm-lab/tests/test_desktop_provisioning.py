"""Proves desktop access is registered with the VM and revoked before it.

Two properties matter here.

A desktop that cannot be registered must not cost the student their
terminal. Every refusal path below returns rather than raises, because a
raise inside the provisioning flow would fail a VM that is otherwise
healthy.

Teardown revokes first. A reference that outlives the VM it names is a
reference that could be redeemed against whatever next occupies that
address, so revocation runs before the container and the VM go away, not
after.
"""

import sys
import types

import pytest
from starlette.testclient import TestClient

SESSION_ID = "a1b2c3d4"
VM_IP = "10.10.10.42"
RDP_PASSWORD = "an-uncommon-desktop-password"


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


class _RecordingDb:
    """Records every statement in the order it was issued, so a test can
    assert what ran before what."""

    def __init__(self, journal=None, rows=()):
        self.journal = journal if journal is not None else []
        self._rows = list(rows)

    async def execute(self, query, *args):
        self.journal.append(("sql", query, args))
        return "UPDATE 1"

    async def fetchrow(self, query, *args):
        self.journal.append(("sql", query, args))
        return self._rows.pop(0) if self._rows else None

    async def fetchval(self, query, *args):
        self.journal.append(("sql", query, args))
        return self._rows.pop(0) if self._rows else None


@pytest.fixture
def api_main(monkeypatch):
    module = _load_api_main()
    monkeypatch.setenv("LAB_RDP_PASSWORD", RDP_PASSWORD)
    monkeypatch.setattr(module, "BROWSER_RDP_ENABLED", True)
    return module


async def _register(api_main, db, vm_ip=VM_IP):
    return await api_main.register_desktop_access(db, SESSION_ID, vm_ip)


# --- registration -----------------------------------------------------


@pytest.mark.anyio
async def test_registration_writes_the_target_and_a_credential_reference(api_main):
    db = _RecordingDb()

    assert await _register(api_main, db) is True

    (_, query, args) = db.journal[0]
    assert "vm_session_access" in query
    assert SESSION_ID in args
    assert VM_IP in args
    assert "env:LAB_RDP_PASSWORD" in args


@pytest.mark.anyio
async def test_registration_never_stores_the_password_itself(api_main):
    db = _RecordingDb()

    await _register(api_main, db)

    assert all(RDP_PASSWORD not in str(arg) for (_, _, args) in db.journal for arg in args)


@pytest.mark.anyio
async def test_registration_is_skipped_while_the_flag_is_off(api_main, monkeypatch):
    monkeypatch.setattr(api_main, "BROWSER_RDP_ENABLED", False)
    db = _RecordingDb()

    assert await _register(api_main, db) is False
    assert db.journal == []


@pytest.mark.anyio
async def test_registration_declines_when_the_credential_is_unset(
    api_main, monkeypatch
):
    monkeypatch.delenv("LAB_RDP_PASSWORD", raising=False)
    db = _RecordingDb()

    assert await _register(api_main, db) is False
    assert db.journal == []


@pytest.mark.anyio
async def test_registration_declines_a_target_that_is_not_private(api_main):
    db = _RecordingDb()

    assert await _register(api_main, db, vm_ip="8.8.8.8") is False
    assert db.journal == []


@pytest.mark.anyio
async def test_a_declined_registration_does_not_raise(api_main, monkeypatch):
    """The provisioning flow calls this after the VM is healthy. A raise here
    would destroy a working terminal over a missing desktop."""
    monkeypatch.delenv("LAB_RDP_PASSWORD", raising=False)

    assert await _register(api_main, _RecordingDb(), vm_ip="not-an-address") is False


# --- teardown ---------------------------------------------------------


@pytest.mark.anyio
async def test_teardown_revokes_before_the_container_and_the_vm_go_away(
    api_main, monkeypatch
):
    journal = []
    monkeypatch.setattr(
        api_main, "finalize_recording", _async_noop(journal, "finalize")
    )
    monkeypatch.setattr(
        api_main, "destroy_ttyd_container", _sync_noop(journal, "ttyd")
    )
    monkeypatch.setattr(api_main, "destroy_vm", _sync_noop(journal, "vm"))
    monkeypatch.setattr(api_main, "proxmox_api", object())
    monkeypatch.setattr(api_main, "log_event", _async_noop(journal, "event"))
    db = _RecordingDb(journal)

    await api_main.destroy_session_internal(db, SESSION_ID, vm_id=101)

    steps = [entry[1] if entry[0] != "sql" else "sql:" + entry[1] for entry in journal]
    revoked = next(i for i, s in enumerate(steps) if "revoked_at" in s)
    assert revoked < steps.index("ttyd")
    assert revoked < steps.index("vm")


def test_revocation_clears_the_reference_as_well_as_marking_the_row():
    """A revoked row whose token_hash survived would still satisfy the
    redemption statement's token_hash match on its way to the revoked_at
    check. Clearing both removes any doubt."""
    from api import access

    sql = access.REVOKE_SESSION_ACCESS_SQL
    assert "revoked_at = CURRENT_TIMESTAMP" in sql
    assert "token_hash = NULL" in sql


# --- reported availability --------------------------------------------


def _status(api_main, desktop_rows):
    session_row = {
        "session_id": SESSION_ID,
        "url": "https://lab-a1b2c3d4.example.org/",
        "vm_ip": VM_IP,
        "status": "running",
        "status_message": None,
        "user_name": "Student One",
        "course_title": "NOS 120",
        "assignment_title": "Lab 3",
        "created_at": None,
        "expires_at": None,
        "started_at": None,
    }
    api_main.app.state.db = _RecordingDb(rows=[session_row, *desktop_rows])
    response = TestClient(api_main.app).get(f"/api/session/{SESSION_ID}/status")
    assert response.status_code == 200
    return response.json()["access"]["desktop"]


def test_desktop_reports_available_once_a_record_exists(api_main):
    desktop = _status(api_main, [{"exists": True}])

    assert desktop["available"] is True
    assert desktop["reason"] is None


def test_desktop_still_reports_no_record_when_none_was_written(api_main):
    desktop = _status(api_main, [])

    assert desktop["available"] is False
    assert desktop["reason"] == api_main.DESKTOP_NOT_PROVISIONED


def test_availability_still_carries_no_target_detail(api_main):
    assert set(_status(api_main, [{"exists": True}])) == {"available", "reason"}


def _async_noop(journal, label):
    async def _recorded(*_args, **_kwargs):
        journal.append((label, label))

    return _recorded


def _sync_noop(journal, label):
    def _recorded(*_args, **_kwargs):
        journal.append((label, label))

    return _recorded


@pytest.fixture
def anyio_backend():
    return "asyncio"


# --- the container actually receives what the code reads ------------------


def test_compose_forwards_every_variable_the_desktop_feature_reads():
    """Unit tests pass whatever compose does, so nothing else catches this.

    The feature was fully implemented and inert in a real deployment because
    docker-compose.yml never passed BROWSER_RDP_ENABLED, the credential, the
    snapshot name, or the API token variables into lab-api. Setting them in
    .env had no effect at all.
    """
    from pathlib import Path

    compose = (Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text()
    lab_api = compose.split("  lab-api:", 1)[1].split("\n  guacd:", 1)[0]

    for variable in (
        "BROWSER_RDP_ENABLED",
        "RDP_USERNAME",
        "RDP_PORT",
        "RDP_SECURITY",
        "LAB_RDP_PASSWORD",
        "PROXMOX_TEMPLATE_SNAPSHOT",
        "PROXMOX_TOKEN_NAME",
        "PROXMOX_TOKEN_VALUE",
    ):
        assert f"{variable}=" in lab_api, (
            f"docker-compose.yml must pass {variable} to lab-api, "
            "or the code reads its default and the setting is silently ignored"
        )
