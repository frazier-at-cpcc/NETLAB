"""Proves get_vm_ip() only ever returns syntactically valid IPv4 addresses.

vm_ip comes from the Proxmox guest agent's reported network interfaces, on
a virtual machine where the student holds root. It is later interpolated
into a command string that reaches `script -c`, which hands its argument
to `/bin/sh -c` inside the ttyd container. That container mounts the SSH
private key directory. A crafted interface address containing a shell
metacharacter must never survive get_vm_ip(), or it becomes shell
execution next to the fleet SSH key.

The existing MGMT_NETWORK_PREFIX check is not a defence: it is a plain
`str.startswith`, so a crafted address that merely starts with the
configured management prefix satisfies it without being a real address.
The malicious candidate below is built to start with the default
MGMT_NETWORK_PREFIX ("172.16.120.") for exactly that reason.
"""

import sys
import types

import pytest


def _load_api_main():
    """Import the real api.main so get_vm_ip is exercised directly rather
    than reimplemented in the test. api/main.py unconditionally imports
    asyncpg and proxmoxer at module load but only calls them inside
    functions never triggered here; test_service_auth.py already
    establishes this stubbing pattern for the same two packages."""
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


class _FakeGet:
    def __init__(self, payload):
        self._payload = payload

    def get(self):
        return self._payload


class _FakeAgent:
    def __init__(self, interfaces):
        self._interfaces = interfaces

    def __call__(self, action):
        assert action == "network-get-interfaces"
        return _FakeGet({"result": self._interfaces})


class _FakeQemu:
    def __init__(self, interfaces):
        self.agent = _FakeAgent(interfaces)

    @property
    def status(self):
        raise AssertionError("status fallback should not be reached in these tests")


class _FakeNode:
    def __init__(self, interfaces):
        self._interfaces = interfaces

    def qemu(self, vmid):
        return _FakeQemu(self._interfaces)


class _FakeProxmox:
    def __init__(self, interfaces):
        self._interfaces = interfaces

    def nodes(self, node):
        return _FakeNode(self._interfaces)


def _iface(ip):
    return {
        "name": "eth0",
        "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": ip}],
    }


def test_a_candidate_with_a_shell_metacharacter_is_rejected():
    api_main = _load_api_main()
    malicious = "172.16.120.5;curl evil"
    proxmox = _FakeProxmox([_iface(malicious)])

    result = api_main.get_vm_ip(proxmox, vmid=101)

    assert result != malicious
    assert result is None


def test_a_legitimate_address_is_still_returned():
    api_main = _load_api_main()
    legitimate = "172.16.120.10"
    proxmox = _FakeProxmox([_iface(legitimate)])

    result = api_main.get_vm_ip(proxmox, vmid=101)

    assert result == legitimate


def test_a_legitimate_address_survives_alongside_a_malicious_one():
    api_main = _load_api_main()
    malicious = "172.16.120.5;curl evil"
    legitimate = "172.16.120.10"
    proxmox = _FakeProxmox([_iface(malicious), _iface(legitimate)])

    result = api_main.get_vm_ip(proxmox, vmid=101)

    assert result == legitimate
