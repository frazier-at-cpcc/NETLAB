"""Server-side RDP connection data for the Guacamole gateway.

The browser must never receive this structure. It is the private contract
between lab-api and guacd/Guacamole when the connection store is added.
"""

from dataclasses import dataclass
import ipaddress


class InvalidRdpTarget(ValueError):
    """Raised when a session target is not a private VM address."""


@dataclass(frozen=True)
class RdpTarget:
    host: str
    username: str
    password: str
    port: int = 3389
    domain: str = ""
    security: str = "nla"

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise InvalidRdpTarget("RDP host must be an IP address") from exc
        if not address.is_private:
            raise InvalidRdpTarget("RDP host must be private")
        if not 1 <= self.port <= 65535:
            raise InvalidRdpTarget("RDP port is out of range")
        if not self.username or not self.password:
            raise InvalidRdpTarget("RDP credentials are required server-side")
        if self.security not in {"nla", "tls", "any"}:
            raise InvalidRdpTarget("unsupported RDP security mode")


def guacamole_rdp_parameters(target: RdpTarget) -> dict[str, str]:
    """Return private Guacamole RDP parameters for an internal connection."""

    return {
        "hostname": target.host,
        "port": str(target.port),
        "username": target.username,
        "password": target.password,
        "domain": target.domain,
        "security": target.security,
        "ignore-cert": "true",
        "enable-drive": "false",
        "enable-printing": "false",
        "enable-audio": "false",
    }
