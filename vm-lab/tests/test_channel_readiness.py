"""Which VM channels get a published route.

A route to a port that nothing answers returns 502, which a student reads as
a broken lab rather than as a service that is not running. So a channel is
probed before it is published, with one deliberate exception.
"""

import inspect
import pathlib
import socket
import time
import sys
import types

import pytest


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


@pytest.fixture
def listening_port():
    """A real socket, so the probe is exercised rather than mocked."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    yield srv.getsockname()[1]
    srv.close()


@pytest.fixture
def closed_port():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.close()
    return port


# --- the probe ---------------------------------------------------------


def test_an_answering_port_is_open(listening_port):
    assert _load_api_main().port_open("127.0.0.1", listening_port) is True


def test_a_closed_port_is_not_open(closed_port):
    assert _load_api_main().port_open("127.0.0.1", closed_port, timeout=0.5) is False


def test_an_unroutable_address_does_not_raise():
    """A probe that throws would fail provisioning for a working lab."""
    assert _load_api_main().port_open("192.0.2.1", 8888, timeout=0.5) is False


# --- which channels are probed ----------------------------------------


def test_jupyter_is_probed_because_it_should_already_be_up():
    api_main = _load_api_main()
    assert "jupyter" in api_main.PROBED_CHANNELS


def test_the_app_channel_is_never_probed():
    """Open WebUI stays stopped until the student starts it in Lab 7.
    Probing it would drop the route every student needs."""
    api_main = _load_api_main()
    assert "app" not in api_main.PROBED_CHANNELS


# --- selection ---------------------------------------------------------


def test_a_closed_jupyter_is_dropped_and_the_app_survives(closed_port):
    """The fault case: the student gets a terminal and the app route, not a
    notebook route that 502s."""
    api_main = _load_api_main()
    api_main.VM_CHANNEL_PORTS["jupyter"] = closed_port
    try:
        assert api_main.ready_channels("127.0.0.1", ["jupyter", "app"], timeout=0) == ["app"]
    finally:
        api_main.VM_CHANNEL_PORTS["jupyter"] = 8888


def test_an_answering_jupyter_is_published(listening_port):
    api_main = _load_api_main()
    api_main.VM_CHANNEL_PORTS["jupyter"] = listening_port
    try:
        assert api_main.ready_channels("127.0.0.1", ["jupyter", "app"]) == ["jupyter", "app"]
    finally:
        api_main.VM_CHANNEL_PORTS["jupyter"] = 8888


def test_without_an_address_only_unprobed_channels_survive():
    api_main = _load_api_main()
    assert api_main.ready_channels(None, ["jupyter", "app"], timeout=0) == ["app"]


def test_an_unknown_channel_is_refused():
    """A typo must not publish a route to a port nobody chose."""
    api_main = _load_api_main()
    assert api_main.ready_channels("127.0.0.1", ["jupyter-typo"], timeout=0) == []


def test_asking_for_nothing_publishes_nothing():
    """Every NOS session passes no channels and must stay that way."""
    api_main = _load_api_main()
    assert api_main.ready_channels("127.0.0.1", []) == []


def test_the_probe_timeout_is_short_because_it_blocks():
    """spawn_ttyd_container is synchronous, so this probe holds the event
    loop for its duration."""
    api_main = _load_api_main()
    assert api_main.CHANNEL_PROBE_TIMEOUT_SECONDS <= 5


def test_provisioning_probes_before_publishing():
    """A route to a closed port 502s, which reads to a student as a broken
    lab rather than a service that is not running."""
    m = _load_api_main()
    src = inspect.getsource(m)
    assert "ready_channels, vm_ip, template_choice.channels" in src


def test_the_probe_runs_off_the_event_loop():
    """Each probe is a blocking connect, and provisioning is async."""
    m = _load_api_main()
    src = inspect.getsource(m)
    assert "await asyncio.to_thread(\n                ready_channels" in src


def test_the_published_channels_are_what_gets_routed():
    """spawn no longer probes; it writes exactly what it is handed, so the
    probe result cannot be bypassed."""
    m = _load_api_main()
    spawn = inspect.getsource(m.spawn_ttyd_container)
    assert "channels=tuple(channels)" in spawn
    assert "ready_channels" not in spawn
    assert "channels=tuple(published_channels)" in inspect.getsource(m)


def test_the_family_decides_which_channels_exist():
    m = _load_api_main()
    assert m._parse_channels("jupyter,app") == ("jupyter", "app")
    assert m._parse_channels(" jupyter , app ") == ("jupyter", "app")


def test_a_course_with_no_channels_publishes_only_the_terminal():
    """Every NOS course stores NULL and must stay terminal-only."""
    m = _load_api_main()
    assert m._parse_channels(None) == ()
    assert m._parse_channels("") == ()


def test_notebooks_are_reported_only_for_a_course_that_uses_them():
    """Tri-state. A NOS student must never be told notebooks are missing
    from a course that never had them."""
    m = _load_api_main()
    src = inspect.getsource(m)
    assert 'if "jupyter" in template_choice.channels:' in src
    assert m.SessionStatus.model_fields["notebooks_available"].default is None


def test_a_closed_notebook_port_is_an_error_not_a_shrug():
    """JupyterLab is enabled at boot, so a closed 8888 is a real fault."""
    m = _load_api_main()
    src = inspect.getsource(m)
    assert "enabled at boot, so this is a fault on the VM" in src


def test_the_migration_gives_csc228_both_channels():
    sql = pathlib.Path("migrations/015_session_channels.sql").read_text()
    assert "channels = 'jupyter,app'" in sql
    assert "notebooks_available BOOLEAN" in sql
    assert "WHERE slug_prefix = 'csc228-'" in sql


def test_the_probe_waits_rather_than_firing_once(listening_port):
    """A single probe immediately after SSH is a race, and it lost: systemd
    marks a service active before it binds, so the first real run found 8888
    closed four seconds after the unit went active, withheld the route for
    the whole session, and logged a fault on a healthy VM."""
    api_main = _load_api_main()
    assert api_main.wait_for_port("127.0.0.1", listening_port, timeout=0) is True


def test_waiting_gives_up_eventually(closed_port):
    """A genuinely dead port must not hold provisioning open."""
    api_main = _load_api_main()
    assert api_main.wait_for_port("127.0.0.1", closed_port, timeout=0) is False


def test_the_wait_budget_is_long_enough_for_a_service_to_bind():
    api_main = _load_api_main()
    assert api_main.CHANNEL_READY_TIMEOUT_SECONDS >= 30


def test_the_budget_is_configurable_and_forwarded():
    api_main = _load_api_main()
    assert 'os.getenv("CHANNEL_READY_TIMEOUT_SECONDS"' in inspect.getsource(api_main)
    assert "CHANNEL_READY_TIMEOUT_SECONDS=" in pathlib.Path("docker-compose.yml").read_text()


def test_a_channel_that_binds_a_moment_later_is_still_published():
    """The regression test for the real failure.

    systemd marked csc228-jupyter active and the port was not listening yet.
    A single probe found it closed, withheld the route for the whole session,
    and logged a fault on a healthy VM. So bind the port AFTER the call
    starts: a waiting probe catches it, a single-shot probe does not.
    """
    import socket as _socket
    import threading

    api_main = _load_api_main()
    srv = _socket.socket()
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.close()

    started = threading.Event()
    holder = {}

    def bind_late():
        started.wait()
        time.sleep(1.5)
        s = _socket.socket()
        s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(1)
        holder["sock"] = s

    t = threading.Thread(target=bind_late, daemon=True)
    t.start()
    api_main.VM_CHANNEL_PORTS["jupyter"] = port
    try:
        started.set()
        result = api_main.ready_channels("127.0.0.1", ["jupyter"], timeout=20)
        assert result == ["jupyter"], (
            "a channel that binds shortly after provisioning must still be "
            "published; this fails if the probe fires only once"
        )
    finally:
        api_main.VM_CHANNEL_PORTS["jupyter"] = 8888
        if "sock" in holder:
            holder["sock"].close()
