import sys
import types

import pytest

from api.service_auth import SERVICE_TOKEN_HEADER, ServiceTokenError, check_service_token


def test_absent_configuration_refuses_every_caller():
    with pytest.raises(ServiceTokenError) as exc:
        check_service_token(configured="", presented="anything")
    assert exc.value.status_code == 503


def test_wrong_token_is_refused():
    with pytest.raises(ServiceTokenError) as exc:
        check_service_token(configured="right", presented="wrong")
    assert exc.value.status_code == 403


def test_missing_token_is_refused():
    with pytest.raises(ServiceTokenError) as exc:
        check_service_token(configured="right", presented=None)
    assert exc.value.status_code == 403


def test_matching_token_is_accepted():
    check_service_token(configured="right", presented="right")


def test_whitespace_only_configuration_is_treated_as_unset():
    """A configured value that is empty after stripping is not "set". It must
    fail closed with 503 exactly like a genuinely missing environment
    variable, rather than being compared as if it were a real secret."""
    with pytest.raises(ServiceTokenError) as exc:
        check_service_token(configured="   ", presented="anything")
    assert exc.value.status_code == 503


def _load_lab_api_app():
    """Import the real api.main FastAPI app so tests can drive the actual
    require_service_token dependency through Starlette's header parsing,
    the same way the reviewer reproduced the non-ASCII crash.

    api/main.py unconditionally imports asyncpg and proxmoxer at module
    load, but only calls them inside functions (the app's lifespan/startup
    handler), never at import time. Those two packages are not part of this
    ambient test environment's dependency set, so a bare-bones stub module
    is enough to satisfy the import statements; nothing in this test
    triggers the app's lifespan, so the stubs are never actually called.
    """
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

    return lab_api_main.app


def test_non_ascii_presented_token_yields_403_through_the_real_dependency(monkeypatch):
    """Drive the real request path: a raw non-ASCII byte in the header,
    decoded by Starlette as latin-1 (which never raises), must reach
    require_service_token and come back as a clean 403 rather than an
    uncaught TypeError that FastAPI turns into a 500."""
    monkeypatch.setenv("LAB_API_SERVICE_TOKEN", "correcttoken")
    app = _load_lab_api_app()
    from starlette.testclient import TestClient

    client = TestClient(app)
    response = client.get(
        "/api/grade-events",
        headers=[(SERVICE_TOKEN_HEADER.encode("ascii"), b"\xe9")],
    )
    assert response.status_code == 403
