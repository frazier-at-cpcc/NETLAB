import pytest

from api.rdp import InvalidRdpTarget, RdpTarget, guacamole_rdp_parameters


def test_guacamole_parameters_are_server_side_connection_data():
    target = RdpTarget("10.10.10.42", "student", "secret")

    assert guacamole_rdp_parameters(target) == {
        "hostname": "10.10.10.42",
        "port": "3389",
        "username": "student",
        "password": "secret",
        "domain": "",
        "security": "nla",
        "ignore-cert": "true",
        "enable-drive": "false",
        "enable-printing": "false",
        "enable-audio": "false",
    }


@pytest.mark.parametrize("host", ["8.8.8.8", "example.com"])
def test_public_or_named_targets_are_rejected(host):
    with pytest.raises(InvalidRdpTarget):
        RdpTarget(host, "student", "secret")


def test_invalid_port_and_security_are_rejected():
    with pytest.raises(InvalidRdpTarget):
        RdpTarget("10.10.10.42", "student", "secret", port=70000)
    with pytest.raises(InvalidRdpTarget):
        RdpTarget("10.10.10.42", "student", "secret", security="rdp")
