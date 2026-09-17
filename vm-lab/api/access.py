"""Desktop access records: mint, single-use redeem, and revoke.

The browser holds one opaque reference. Everything that could open an RDP
session to a student's VM stays in vm_session_access and leaves lab-api
only over a service-token-authenticated call from the gateway.

Redemption is one statement. The UPDATE that reads a token is the same
UPDATE that clears it, so two concurrent redemptions of one reference
cannot both return a connection. Splitting the read from the clear would
open exactly that window.

Nothing here logs a token, a credential reference, or a password.
"""

import hashlib
import os
import secrets

try:
    from rdp import InvalidRdpTarget, RdpTarget, guacamole_rdp_parameters
except ImportError:
    from api.rdp import InvalidRdpTarget, RdpTarget, guacamole_rdp_parameters

DESKTOP_MODE = "desktop"
TERMINAL_MODE = "terminal"

ENV_CREDENTIAL_SCHEME = "env:"


class CredentialUnavailable(Exception):
    """Raised when a credential reference cannot be resolved server-side."""


class AccessNotRedeemable(Exception):
    """Raised when no live access record matches a presented reference."""


def mint_desktop_token() -> str:
    """Return a fresh browser reference.

    token_urlsafe(32) is 256 bits. The reference is the only thing standing
    between a guessed value and a student's desktop, so it is not derived
    from the session id, which is eight characters long.
    """
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Return the stored form of a reference. The reference is never stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# One statement. The WHERE clause rejects a revoked row and an expired row,
# and setting token_hash to NULL consumes the reference in the same write
# that returns the target. RETURNING is what makes the read and the consume
# indivisible.
REDEEM_DESKTOP_TOKEN_SQL = """
UPDATE vm_session_access
SET token_hash = NULL,
    last_accessed = CURRENT_TIMESTAMP
WHERE mode = 'desktop'
  AND token_hash = $1
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
RETURNING session_id, rdp_host, rdp_port, rdp_username, rdp_security,
          credential_ref
"""

ASSIGN_DESKTOP_TOKEN_SQL = """
UPDATE vm_session_access
SET token_hash = $2,
    expires_at = CURRENT_TIMESTAMP + ($3 || ' seconds')::interval
WHERE session_id = $1
  AND mode = 'desktop'
  AND revoked_at IS NULL
RETURNING session_id
"""

REVOKE_SESSION_ACCESS_SQL = """
UPDATE vm_session_access
SET revoked_at = CURRENT_TIMESTAMP,
    token_hash = NULL
WHERE session_id = $1
  AND revoked_at IS NULL
"""


def resolve_credential(reference: str) -> str:
    """Resolve a credential reference to a password, server-side only.

    Only one scheme is supported, and it names an environment variable
    rather than carrying a value. A reference that resolves to nothing is
    refused rather than defaulted, because a blank password would be
    offered to guacd as though it were real.
    """
    if not reference or not reference.startswith(ENV_CREDENTIAL_SCHEME):
        raise CredentialUnavailable("unsupported credential reference scheme")
    name = reference[len(ENV_CREDENTIAL_SCHEME):]
    value = os.getenv(name, "")
    if not value:
        raise CredentialUnavailable("credential reference resolves to nothing")
    return value


def connection_parameters(row) -> dict[str, str]:
    """Build the private guacd parameters for a redeemed access record.

    RdpTarget re-validates the target on the way out. A stored row that has
    drifted to a public address, an impossible port, or a missing credential
    is refused here rather than handed to guacd.
    """
    target = RdpTarget(
        host=row["rdp_host"],
        username=row["rdp_username"],
        password=resolve_credential(row["credential_ref"]),
        port=row["rdp_port"] or 3389,
        security=row["rdp_security"] or "any",
    )
    return guacamole_rdp_parameters(target)


__all__ = [
    "ASSIGN_DESKTOP_TOKEN_SQL",
    "AccessNotRedeemable",
    "CredentialUnavailable",
    "DESKTOP_MODE",
    "InvalidRdpTarget",
    "REDEEM_DESKTOP_TOKEN_SQL",
    "REVOKE_SESSION_ACCESS_SQL",
    "TERMINAL_MODE",
    "connection_parameters",
    "hash_token",
    "mint_desktop_token",
    "resolve_credential",
]
