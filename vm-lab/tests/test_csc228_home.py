"""The grant and revoke pair for CSC 228 persistent homes.

The rule this file holds is that a grant is always paired with a revoke, and
that neither a refused grant nor a failed revoke may change what happens to
the session or the VM. A refused grant means a session without persistence,
not a failed launch. A failed revoke means a logged error, not a VM that
survives teardown holding 24 GB of a twelve-slot pool.
"""

import asyncio

import pytest

from api import csc228_home as home

NODE = "pve"
NAS_VMID = 2281
VM_VMID = 9001
VM_IP = "172.18.8.57"
KEY = "0123456789abcdef0123456789abcdef"


class _Agent:
    """Fake guest agent. Records the argv it was asked to run."""

    def __init__(self, outcome, calls, ifaces=None):
        self._outcome = outcome
        self._calls = calls
        self._ifaces = ifaces
        self.exec = type("E", (), {"post": self._post})()

    def _post(self, command):
        self._calls.append(command)
        return {"pid": 1234}

    def __call__(self, what):
        if what == "exec-status":
            return type("S", (), {"get": lambda _s, pid: self._outcome})()
        if what == "network-get-interfaces":
            return type("N", (), {"get": lambda _s: {"result": self._ifaces or []}})()
        raise AssertionError(what)


def _proxmox(outcome=None, calls=None, ifaces=None):
    agent = _Agent(outcome or {"exited": 1, "exitcode": 0, "out-data": "OK"},
                   calls if calls is not None else [], ifaces)
    qemu = type("Q", (), {"agent": agent})()
    node = type("N", (), {"qemu": lambda _s, _v: qemu})()
    return type("P", (), {"nodes": lambda _s, _n: node})()


# --- the key ----------------------------------------------------------


def test_the_home_key_is_derived_from_the_subject_and_the_issuer():
    a = home.home_key("lti11:brightspace-prod", "student-001")
    assert a == home.home_key("lti11:brightspace-prod", "student-001")
    assert a != home.home_key("lti11:brightspace-prod", "student-002")
    assert a != home.home_key("lti11:other", "student-001")
    assert len(a) == 32


def test_a_missing_subject_is_refused_rather_than_hashed():
    """An empty subject would hash to one shared directory, putting every
    student with a withheld subject into the same home."""
    with pytest.raises(ValueError):
        home.home_key("lti11:brightspace-prod", "")


# --- grant ------------------------------------------------------------


def test_a_grant_names_the_student_directory_and_the_single_vm_address():
    calls = []
    prox = _proxmox({"exited": 1, "exitcode": 0, "out-data": f"GRANTED {KEY} to {VM_IP}"}, calls)
    assert asyncio.run(home.grant_home(prox, NODE, NAS_VMID, VM_IP, KEY)) is True
    assert calls == [[home.GRANT_SCRIPT, VM_IP, KEY]]


def test_a_refused_grant_is_reported_rather_than_raised():
    """Exit 2 is DENIED. The session still has to start, on a local home."""
    prox = _proxmox({"exited": 1, "exitcode": 2, "out-data": "DENIED no such key"})
    assert asyncio.run(home.grant_home(prox, NODE, NAS_VMID, VM_IP, KEY)) is False


# --- attach -----------------------------------------------------------


def test_an_attach_sends_the_discovered_nas_address_and_the_export():
    calls = []
    prox = _proxmox({"exited": 1, "exitcode": 0, "out-data": f"ATTACHED {KEY}"}, calls)
    assert asyncio.run(home.attach_home(prox, NODE, VM_VMID, "172.18.8.9", KEY)) is True
    assert calls == [[home.ATTACH_SCRIPT, "172.18.8.9", home.NAS_EXPORT_PATH, KEY]]


def test_a_local_home_is_reported_as_not_persisting():
    """LOCAL-HOME exits non-zero. The session works and the student has to be
    told, because silently losing a session's work is the worse failure."""
    prox = _proxmox({"exited": 1, "exitcode": 1, "out-data": "LOCAL-HOME mount refused"})
    assert asyncio.run(home.attach_home(prox, NODE, VM_VMID, "172.18.8.9", KEY)) is False


# --- revoke -----------------------------------------------------------


def test_a_revoke_names_only_the_address():
    calls = []
    prox = _proxmox({"exited": 1, "exitcode": 0, "out-data": "REVOKED"}, calls)
    assert asyncio.run(home.revoke_home(prox, NODE, NAS_VMID, VM_IP)) is True
    assert calls == [[home.REVOKE_SCRIPT, VM_IP]]


def test_a_revoke_that_cannot_run_never_raises():
    """Teardown calls this before destroying the VM. Raising would leave the
    VM alive, which costs a slot out of twelve and leaks the grant anyway."""

    class _Exploding:
        def nodes(self, _n):
            raise RuntimeError("proxmox unreachable")

    assert asyncio.run(home.revoke_home(_Exploding(), NODE, NAS_VMID, VM_IP)) is False


def test_a_revoke_the_nas_rejects_is_reported_not_raised():
    prox = _proxmox({"exited": 1, "exitcode": 3, "out-data": "ERROR busy"})
    assert asyncio.run(home.revoke_home(prox, NODE, NAS_VMID, VM_IP)) is False


# --- NAS address ------------------------------------------------------


def test_the_nas_address_is_read_from_the_guest_agent():
    """Never hardcoded. A NAS that reboots onto a new lease must not strand
    every later mount."""
    ifaces = [
        {"name": "lo", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "127.0.0.1"}]},
        {"name": "ens18", "ip-addresses": [
            {"ip-address-type": "ipv6", "ip-address": "fe80::1"},
            {"ip-address-type": "ipv4", "ip-address": "172.18.8.9"},
        ]},
    ]
    prox = _proxmox(ifaces=ifaces)
    assert home.nas_address(prox, NODE, NAS_VMID) == "172.18.8.9"


def test_the_nas_is_found_whatever_its_interface_is_called():
    """An interface name is a property of the guest's kernel and udev rules.
    A rebuilt or differently virtualised NAS answers on enp0s18 while being
    the same host on the same network."""
    ifaces = [{"name": "enp0s18", "ip-addresses": [
        {"ip-address-type": "ipv4", "ip-address": "172.18.8.21"}]}]
    assert home.nas_address(_proxmox(ifaces=ifaces), NODE, NAS_VMID) == "172.18.8.21"


def test_an_address_outside_the_lab_subnet_is_not_the_nas():
    """Loopback and any second NIC on another network cannot be mounted from
    a student VM, so returning one would strand every mount with an address
    that looks plausible."""
    ifaces = [
        {"name": "lo", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "127.0.0.1"}]},
        {"name": "eth1", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "10.0.0.5"}]},
    ]
    with pytest.raises(RuntimeError):
        home.nas_address(_proxmox(ifaces=ifaces), NODE, NAS_VMID)


def test_a_nas_with_no_address_is_an_error_rather_than_a_guess():
    prox = _proxmox(ifaces=[{"name": "ens18", "ip-addresses": []}])
    with pytest.raises(RuntimeError):
        home.nas_address(prox, NODE, NAS_VMID)


# --- the confirmed script contract ------------------------------------


def test_an_exit_one_abort_is_a_refusal_not_a_success():
    """A script aborting under set -e exits 1 with no status prefix. Only an
    exit-0 GRANTED counts, so the unrecognised case cannot read as success."""
    prox = _proxmox({"exited": 1, "exitcode": 1, "out-data": ""})
    assert asyncio.run(home.grant_home(prox, NODE, NAS_VMID, VM_IP, KEY)) is False


def test_a_zero_exit_without_the_prefix_is_still_a_refusal():
    prox = _proxmox({"exited": 1, "exitcode": 0, "out-data": "something else"})
    assert asyncio.run(home.grant_home(prox, NODE, NAS_VMID, VM_IP, KEY)) is False


def test_revoke_is_idempotent_when_no_grant_existed():
    """The NAS returns REVOKED even with nothing to revoke, so a second
    teardown of the same session is not an error."""
    prox = _proxmox({"exited": 1, "exitcode": 0, "out-data": f"REVOKED {VM_IP}"})
    assert asyncio.run(home.revoke_home(prox, NODE, NAS_VMID, VM_IP)) is True


# --- the order ---------------------------------------------------------


def _ordered_proxmox(calls, outcomes):
    """Fake that answers each exec in turn from `outcomes`."""

    class _Agent:
        def __init__(self):
            self.exec = type("E", (), {"post": self._post})()

        def _post(self, command):
            calls.append(command[0])
            return {"pid": len(calls)}

        def __call__(self, what):
            if what == "network-get-interfaces":
                return type("N", (), {"get": lambda _s: {"result": [
                    {"name": "ens18", "ip-addresses": [
                        {"ip-address-type": "ipv4", "ip-address": "172.18.8.9"}]}]}})()
            return type("S", (), {"get": lambda _s, pid: outcomes[pid - 1]})()

    agent = _Agent()
    qemu = type("Q", (), {"agent": agent})()
    node = type("N", (), {"qemu": lambda _s, _v: qemu})()
    return type("P", (), {"nodes": lambda _s, _n: node})()


def test_the_grant_runs_before_the_attach():
    """Load-bearing. The grant creates the student's directory; attach-home
    only mounts and cannot create, because the session VM cannot see the
    export root. Attaching first fails every student's first ever launch and
    succeeds for everyone after, which reaches production looking like a
    flake."""
    calls = []
    prox = _ordered_proxmox(calls, [
        {"exited": 1, "exitcode": 0, "out-data": f"GRANTED {KEY} to {VM_IP}"},
        {"exited": 1, "exitcode": 0, "out-data": f"ATTACHED {KEY}"},
    ])
    assert asyncio.run(
        home.provision_home(prox, NODE, NAS_VMID, VM_VMID, VM_IP, KEY)
    ) is True
    assert calls == [home.GRANT_SCRIPT, home.ATTACH_SCRIPT]


def test_a_refused_grant_does_not_attempt_the_attach():
    """Mounting a directory the NAS has not exported cannot succeed, and the
    failure it produces describes the mount rather than the grant."""
    calls = []
    prox = _ordered_proxmox(calls, [{"exited": 1, "exitcode": 2, "out-data": "DENIED bad key"}])
    assert asyncio.run(
        home.provision_home(prox, NODE, NAS_VMID, VM_VMID, VM_IP, KEY)
    ) is False
    assert calls == [home.GRANT_SCRIPT]


def test_an_unreachable_nas_leaves_the_session_without_persistence():
    """Never raises. The student gets a working session and has to be told
    it will not persist."""

    class _Exploding:
        def nodes(self, _n):
            raise RuntimeError("no route to NAS")

    assert asyncio.run(
        home.provision_home(_Exploding(), NODE, NAS_VMID, VM_VMID, VM_IP, KEY)
    ) is False
