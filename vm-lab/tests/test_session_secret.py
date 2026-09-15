"""Proves lti/main.py never hands Starlette's SessionMiddleware an empty
secret_key.

docker-compose.yml declares ``- SESSION_SECRET=${SESSION_SECRET}``. When an
operator has no SESSION_SECRET line in their .env, docker compose does not
omit the variable from the container's environment; it supplies it as an
empty string. SESSION_SECRET is built once, at module import time, directly
from os.getenv(...), so (like LTI11_CONSUMERS in test_lti_main_consumers.py)
setting the environment variable after lti.main has already been imported
would prove nothing. Each test here forces a fresh import of lti.main with
the environment already patched, reusing the same load/discard approach as
test_lti_main_consumers.py's load_lti_main fixture, and discards that import
afterward so later tests do not inherit a module cached with this test's
environment baked into it.
"""

import sys
import types

import pytest


@pytest.fixture
def load_lti_main(monkeypatch):
    """Yields a loader that imports the real lti.main fresh, then tears
    the import back down. See test_lti_main_consumers.py for why the
    asyncpg/redis stubs are needed and why the module is discarded on
    both sides of the import.
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
        sys.modules.pop("lti.main", None)
        import lti.main as lti_main

        return lti_main

    yield _load

    sys.modules.pop("lti.main", None)


def test_session_secret_set_to_empty_string_refuses_to_start(
    monkeypatch, load_lti_main
):
    """docker-compose supplies "" (not an absent variable) for an
    unconfigured SESSION_SECRET. That must not reach SessionMiddleware as
    a signing key anyone can reproduce: import must fail loudly instead of
    silently proceeding, the same way an empty LTI11_LTIBROKER_SECRET is
    refused rather than silently accepted as a consumer secret.
    """
    monkeypatch.setenv("SESSION_SECRET", "")

    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        load_lti_main()


def test_session_secret_unset_falls_back_to_a_generated_value(
    monkeypatch, load_lti_main
):
    """A genuinely absent SESSION_SECRET (no docker-compose involved, e.g.
    a bare local run) is unambiguous: the operator simply did not set one.
    That case keeps the original per-process random fallback rather than
    refusing to start.
    """
    monkeypatch.delenv("SESSION_SECRET", raising=False)

    lti_main = load_lti_main()

    assert lti_main.SESSION_SECRET
    assert isinstance(lti_main.SESSION_SECRET, str)


def test_session_secret_configured_value_is_used_verbatim(
    monkeypatch, load_lti_main
):
    monkeypatch.setenv("SESSION_SECRET", "a-real-configured-secret")

    lti_main = load_lti_main()

    assert lti_main.SESSION_SECRET == "a-real-configured-secret"
