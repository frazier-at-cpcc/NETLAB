"""Proves the student-facing session status payload carries no private VM address.

GET /api/session/{session_id}/status is relayed to the browser verbatim by
the lti-server proxy at lti/main.py, which documents itself as requiring no
authentication because the loading page calls it before the session is
established. Its only credential is session_id, eight characters drawn from
lowercase letters and digits by generate_session_id(). Anything this payload
carries is therefore reachable by anyone holding or guessing that value, and
the private address of a student's lab VM does not belong in it.

The instructor-facing Session model and the service-token routes keep vm_ip.
Only this student-facing payload loses it.

Reuses the asyncpg/proxmoxer stubbing pattern from test_get_vm_ip.py, which
api/main.py requires because it imports both at module load while calling
neither in this route.
"""

import sys
import types
from pathlib import Path

import pytest
from starlette.testclient import TestClient

SESSION_ID = "a1b2c3d4"
PRIVATE_VM_IP = "10.10.10.42"


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
    """Returns one running session row, shaped as get_session_status selects it."""

    def __init__(self, row):
        self._row = row

    async def fetchrow(self, _query, *_args):
        return self._row


@pytest.fixture
def status_payload():
    api_main = _load_api_main()
    row = {
        "session_id": SESSION_ID,
        "url": "https://lab-a1b2c3d4.example.org/",
        "vm_ip": PRIVATE_VM_IP,
        "status": "running",
        "status_message": None,
        "user_name": "Student One",
        "course_title": "NOS 120",
        "assignment_title": "Lab 3",
        "created_at": None,
        "expires_at": None,
        "started_at": None,
    }
    api_main.app.state.db = _FakeDb(row)
    client = TestClient(api_main.app)
    response = client.get(f"/api/session/{SESSION_ID}/status")
    assert response.status_code == 200
    return response


def test_status_payload_has_no_vm_ip_key(status_payload):
    assert "vm_ip" not in status_payload.json()


def test_status_payload_does_not_contain_the_address_anywhere(status_payload):
    """Guards against the address reappearing under a renamed key or inside
    a status message, which a key-name assertion alone would not catch."""
    assert PRIVATE_VM_IP not in status_payload.text


def test_session_status_model_declares_no_vm_ip_field():
    api_main = _load_api_main()
    assert "vm_ip" not in api_main.SessionStatus.model_fields


def test_loading_page_never_reads_vm_ip_from_the_status_response():
    template = (
        Path(__file__).resolve().parents[1]
        / "lti"
        / "templates"
        / "lab_loading.html"
    )
    assert "vm_ip" not in template.read_text()
