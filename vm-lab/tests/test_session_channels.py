"""Per-session browser channels.

The terminal routes to a container; JupyterLab and the app channel route to
ports on the VM itself. The rule this file holds is that a course asking for
no channels gets exactly the file it got before channels existed, because
every NOS course on this deployment asks for none and shares the platform
with CSC 228.
"""

import sys
import types

import pytest

SESSION = "a1b2c3d4"
DOMAIN = "lab.labsconnect.org"
CONTAINER = "ttyd-a1b2c3d4"
VM_IP = "172.18.8.57"


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
def written(tmp_path, monkeypatch):
    api_main = _load_api_main()
    monkeypatch.setattr(api_main, "TRAEFIK_DYNAMIC_DIR", str(tmp_path))

    def _write(**kwargs):
        api_main.write_traefik_route(SESSION, CONTAINER, DOMAIN, **kwargs)
        return (tmp_path / f"session-{SESSION}.yml").read_text()

    return _write


def test_a_course_asking_for_nothing_gets_the_terminal_only(written):
    """Every NOS course on this deployment asks for no channels and must be
    untouched by the change that added them."""
    cfg = written()
    assert f"Host(`lab-{SESSION}.{DOMAIN}`)" in cfg
    assert f"http://{CONTAINER}:7681" in cfg
    assert "jupyter-" not in cfg
    assert "app-" not in cfg


def test_jupyter_and_app_route_to_the_vm_not_the_container(written):
    cfg = written(vm_ip=VM_IP, channels=("jupyter", "app"))
    assert f"http://{VM_IP}:8888" in cfg
    assert f"http://{VM_IP}:3000" in cfg
    assert f"http://{CONTAINER}:7681" in cfg


def test_the_app_channel_avoids_the_port_the_student_server_uses(written):
    """Labs 3, 7 and 8 run llama-server, and the Lab 8 container, on 8080
    inside the VM. Publishing Open WebUI there would route the app hostname
    at the student's own server in the one lab that needs both at once."""
    cfg = written(vm_ip=VM_IP, channels=("app",))
    assert f"http://{VM_IP}:3000" in cfg
    assert ":8080" not in cfg


def test_each_channel_is_its_own_one_label_hostname(written):
    """The tunnel ingress is a wildcard one label deep. A nested hostname or
    a path prefix would miss it, and Open WebUI and JupyterLab both expect
    to be served at the root."""
    cfg = written(vm_ip=VM_IP, channels=("jupyter", "app"))
    assert f"Host(`jupyter-{SESSION}.{DOMAIN}`)" in cfg
    assert f"Host(`app-{SESSION}.{DOMAIN}`)" in cfg
    assert "PathPrefix" not in cfg


def test_a_channel_without_a_vm_address_is_refused_not_guessed(written):
    """A route to an empty host would be a 502 that looks like the service
    is broken rather than unrouted."""
    cfg = written(channels=("jupyter",))
    assert "jupyter-" not in cfg
    assert f"http://{CONTAINER}:7681" in cfg


def test_an_unknown_channel_is_skipped_and_the_rest_still_route(written):
    cfg = written(vm_ip=VM_IP, channels=("jupyter", "nonsense"))
    assert f"http://{VM_IP}:8888" in cfg
    assert "nonsense" not in cfg


def test_every_router_has_a_service_of_the_same_name(written):
    """A router naming a service that was never written is a 404 Traefik
    reports as a missing route rather than a misconfiguration."""
    cfg = written(vm_ip=VM_IP, channels=("jupyter", "app"))
    routers, services = cfg.split("  services:")
    for name in (f"ttyd-{SESSION}", f"jupyter-{SESSION}", f"app-{SESSION}"):
        assert f"    {name}:" in routers
        assert f"    {name}:" in services


def test_the_file_is_one_write_per_session(written, tmp_path):
    """Traefik reloads on file change. Two passes would reload a session's
    routes mid-provision."""
    written(vm_ip=VM_IP, channels=("jupyter", "app"))
    assert len(list(tmp_path.glob("session-*.yml"))) == 1


def test_a_vm_address_alone_does_not_publish_channels(written):
    """The guarantee is opt-in, not merely address-gated. Every NOS session
    supplies a vm_ip, so if the default ever flipped to channels-on they
    would silently gain two routes to ports their image does not serve.
    The earlier no-argument test cannot catch that, because without an
    address the channels are refused for the other reason."""
    cfg = written(vm_ip=VM_IP)
    assert "jupyter-" not in cfg
    assert "app-" not in cfg
    assert f"http://{CONTAINER}:7681" in cfg
