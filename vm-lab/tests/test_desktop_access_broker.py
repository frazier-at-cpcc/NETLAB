"""Proves the desktop access broker: mint, single-use redeem, and revoke.

The browser holds one opaque reference and nothing else. Everything that
could open an RDP session to a student's VM lives in vm_session_access and
leaves lab-api only over a service-token-authenticated call from the
gateway.

Redemption is one SQL statement. A token is consumed by the same UPDATE
that reads it, so two concurrent redemptions of one token cannot both
return a connection. The test for that asserts the statement's shape
rather than racing it, because a race that passes once proves nothing.

The password reaches guacd and must never reach a log line. This project
has already shipped a credential-leak test that passed while the leak was
live, so the redaction test below drives the real route and reads the real
captured records.
"""

import sys
import types

import pytest
from starlette.testclient import TestClient

from api.service_auth import SERVICE_TOKEN_HEADER

SESSION_ID = "a1b2c3d4"
SERVICE_TOKEN = "a-configured-service-token"
VM_IP = "10.10.10.42"
RDP_PASSWORD = "an-uncommon-desktop-password"
CREDENTIAL_ENV = "LAB_RDP_PASSWORD"


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
    """Returns each queued row once, then None, which is how the database
    behaves after a single-use token has been consumed."""

    def __init__(self, rows=()):
        self._rows = list(rows)
        self.statements = []

    async def fetchrow(self, query, *args):
        self.statements.append((query, args))
        return self._rows.pop(0) if self._rows else None

    async def execute(self, query, *args):
        self.statements.append((query, args))
        return "UPDATE 1"


def _access_row():
    return {
        "session_id": SESSION_ID,
        "rdp_host": VM_IP,
        "rdp_port": 3389,
        "rdp_username": "student",
        "rdp_security": "any",
        "credential_ref": f"env:{CREDENTIAL_ENV}",
    }


@pytest.fixture
def api_main(monkeypatch):
    module = _load_api_main()
    monkeypatch.setenv(CREDENTIAL_ENV, RDP_PASSWORD)
    monkeypatch.setenv("LAB_API_SERVICE_TOKEN", SERVICE_TOKEN)
    return module


def _redeem(api_main, db, token="a-reference", headers=None):
    api_main.app.state.db = db
    if headers is None:
        headers = {SERVICE_TOKEN_HEADER: SERVICE_TOKEN}
    return TestClient(api_main.app).post(
        "/api/access/desktop/redeem", json={"token": token}, headers=headers
    )


# --- token primitives -------------------------------------------------


def test_minted_tokens_are_distinct():
    from api import access

    assert len({access.mint_desktop_token() for _ in range(64)}) == 64


def test_token_hash_is_stable_and_fits_the_column():
    from api import access

    digest = access.hash_token("a-reference")
    assert digest == access.hash_token("a-reference")
    assert len(digest) == 64
    assert digest != access.hash_token("another-reference")


def test_hashing_does_not_return_the_token():
    from api import access

    assert access.hash_token("a-reference") != "a-reference"


# --- the atomic redemption statement ----------------------------------


def test_redemption_consumes_the_token_in_the_statement_that_reads_it():
    from api import access

    sql = access.REDEEM_DESKTOP_TOKEN_SQL
    assert sql.strip().upper().startswith("UPDATE")
    assert sql.count(";") == 0, "one statement, so redemption cannot interleave"
    assert "token_hash = NULL" in sql
    assert "RETURNING" in sql


def test_every_column_the_builder_reads_is_returned_by_the_statement():
    """The row shape is dictated by RETURNING. If the builder starts reading
    a column the statement does not return, this catches it here rather than
    as a KeyError on a live student connect."""
    from api import access

    returning = access.REDEEM_DESKTOP_TOKEN_SQL.split("RETURNING", 1)[1]
    for column in _access_row():
        assert column in returning


def test_redemption_refuses_revoked_and_expired_rows():
    from api import access

    sql = access.REDEEM_DESKTOP_TOKEN_SQL
    assert "revoked_at IS NULL" in sql
    assert "expires_at" in sql


# --- credential resolution --------------------------------------------


def test_credential_reference_resolves_from_the_server_side_environment(
    monkeypatch,
):
    from api import access

    monkeypatch.setenv(CREDENTIAL_ENV, RDP_PASSWORD)
    assert access.resolve_credential(f"env:{CREDENTIAL_ENV}") == RDP_PASSWORD


def test_unknown_credential_scheme_is_refused():
    from api import access

    with pytest.raises(access.CredentialUnavailable):
        access.resolve_credential("plaintext:hunter2")


def test_unset_credential_is_refused_rather_than_defaulted(monkeypatch):
    from api import access

    monkeypatch.delenv(CREDENTIAL_ENV, raising=False)
    with pytest.raises(access.CredentialUnavailable):
        access.resolve_credential(f"env:{CREDENTIAL_ENV}")


# --- the redeem route -------------------------------------------------


def test_redeem_requires_the_service_token(api_main):
    response = _redeem(api_main, _FakeDb([_access_row()]), headers={})
    assert response.status_code == 403


def test_redeem_returns_guacamole_parameters_for_a_live_token(api_main):
    response = _redeem(api_main, _FakeDb([_access_row()]))

    assert response.status_code == 200
    body = response.json()
    assert body["session_id"] == SESSION_ID
    assert body["protocol"] == "rdp"
    assert body["parameters"]["hostname"] == VM_IP
    assert body["parameters"]["username"] == "student"
    assert body["parameters"]["password"] == RDP_PASSWORD


def test_a_consumed_token_cannot_be_redeemed_again(api_main):
    db = _FakeDb([_access_row()])

    assert _redeem(api_main, db).status_code == 200
    replay = _redeem(api_main, db)

    assert replay.status_code == 404
    assert "password" not in replay.text


def test_redeem_refuses_a_target_that_is_not_a_private_address(api_main):
    """8.8.8.8 rather than a documentation address, because Python treats
    203.0.113.0/24 and its siblings as private: they are reserved and not
    globally reachable, so ip_address().is_private returns True for them."""
    row = _access_row()
    row["rdp_host"] = "8.8.8.8"

    response = _redeem(api_main, _FakeDb([row]))

    assert response.status_code == 502


def test_redeem_never_writes_the_password_to_the_log(api_main, caplog):
    caplog.set_level(0)

    response = _redeem(api_main, _FakeDb([_access_row()]))

    assert response.status_code == 200
    assert RDP_PASSWORD not in caplog.text
