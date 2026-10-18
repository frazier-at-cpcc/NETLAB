"""Which VM channels get a published route.

A route to a port that nothing answers returns 502, which a student reads as
a broken lab rather than as a service that is not running. So a channel is
probed before it is published, with one deliberate exception.
"""

import inspect
import socket
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
        assert api_main.ready_channels("127.0.0.1", ["jupyter", "app"]) == ["app"]
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
    assert api_main.ready_channels(None, ["jupyter", "app"]) == ["app"]


def test_an_unknown_channel_is_refused():
    """A typo must not publish a route to a port nobody chose."""
    api_main = _load_api_main()
    assert api_main.ready_channels("127.0.0.1", ["jupyter-typo"]) == []


def test_asking_for_nothing_publishes_nothing():
    """Every NOS session passes no channels and must stay that way."""
    api_main = _load_api_main()
    assert api_main.ready_channels("127.0.0.1", []) == []


def test_the_probe_timeout_is_short_because_it_blocks():
    """spawn_ttyd_container is synchronous, so this probe holds the event
    loop for its duration."""
    api_main = _load_api_main()
    assert api_main.CHANNEL_PROBE_TIMEOUT_SECONDS <= 5


def test_selection_is_not_yet_wired_into_provisioning():
    """Honest marker. Channels are still never published, so this logic is
    inert until the go-live wiring passes vm_ip and channels through. Delete
    this test when that lands."""
    api_main = _load_api_main()
    spawn = inspect.getsource(api_main.spawn_ttyd_container)
    assert "write_traefik_route(session_id, container_name, domain)" in spawn
    assert "ready_channels" not in spawn
