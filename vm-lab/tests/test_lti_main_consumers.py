"""Proves the inbound half of the broker grade path: that lti/main.py's
LTI11_CONSUMERS actually picks up LTI11_LTIBROKER_SECRET from the
environment and admits "ltibroker" as a known consumer for launch
validation.

LTI11_CONSUMERS is built once, at module import time, directly from
os.getenv(...). Setting the environment variable after lti.main has
already been imported (e.g. via os.environ[...] = ... in a test body)
would prove nothing: the dict was already frozen by an earlier import,
possibly triggered by test collection itself or by another test module.
So each test here forces a fresh import of lti.main with the environment
already patched, and discards that import afterward so later tests (and
any other test file) do not inherit a module cached with this test's
environment baked into it.
"""

import sys
import types

import pytest


@pytest.fixture
def load_lti_main(monkeypatch):
    """Yields a loader that imports the real lti.main fresh, then tears
    the import back down.

    lti/main.py unconditionally imports asyncpg and redis at module load,
    and calls redis.from_url(...) at import time to populate a
    module-level client. Neither package is part of this ambient test
    environment's dependency set. test_service_auth.py's
    _load_lab_api_app already establishes the pattern for the analogous
    api.main case (stubbing asyncpg and proxmoxer there): substitute a
    bare-bones stub module before importing, matching only the attributes
    the module touches at import time. Nothing in these tests calls the
    app's lifespan handler (the only place asyncpg.create_pool is used)
    or exercises redis_client, so the stubs are never asked to do
    anything beyond letting the import statements succeed.
    """
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

    def _load():
        # Discard any cached copy (from an earlier test, or from test
        # collection) so this import re-executes lti/main.py's top-level
        # code against the environment as this test just set it, rather
        # than reusing a dict built under a different environment.
        sys.modules.pop("lti.main", None)
        import lti.main as lti_main

        return lti_main

    yield _load

    # Leave no residue: a later test file that imports lti.main for real
    # should get its own fresh import, not this test's cached module.
    sys.modules.pop("lti.main", None)


def test_ltibroker_consumer_secret_is_recognised_for_inbound_launches(
    monkeypatch, load_lti_main
):
    monkeypatch.setenv("LTI11_LTIBROKER_SECRET", "shared-broker-secret")

    lti_main = load_lti_main()

    assert lti_main.LTI11_CONSUMERS["ltibroker"] == "shared-broker-secret"


def test_ltibroker_is_absent_when_the_secret_is_unset(monkeypatch, load_lti_main):
    monkeypatch.delenv("LTI11_LTIBROKER_SECRET", raising=False)

    lti_main = load_lti_main()

    assert "ltibroker" not in lti_main.LTI11_CONSUMERS
