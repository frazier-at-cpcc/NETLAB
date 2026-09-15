import hashlib
import logging
import os
import secrets
import shlex

logger = logging.getLogger(__name__)

DEFAULT_PASSBACK_URL = "https://labapi.labsconnect.org/api/grade"

ASSIGN_GRADE_TOKEN_SQL = (
    "UPDATE vm_sessions SET grade_token_hash = $2 WHERE session_id = $1"
)
SELECT_GRADE_TOKEN_HASH_SQL = (
    "SELECT grade_token_hash FROM vm_sessions WHERE session_id = $1"
)


class GradeTokenAlreadyAssigned(Exception):
    """Raised when a session already has a grade_token_hash."""


def mint_grade_token() -> str:
    return secrets.token_urlsafe(32)


def hash_grade_token(token: str) -> str:
    if not token:
        raise ValueError("grade token is empty")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def get_passback_url() -> str:
    return os.getenv("PASSBACK_URL", DEFAULT_PASSBACK_URL)


def redact_secret(text: str, secret: str) -> str:
    if not text or not secret:
        return text or ""
    return text.replace(secret, "[redacted]")


def nested_ssh_command(nested_user: str, nested_host: str, inner_command: str) -> str:
    """Build an `ssh ... 'bash -lc <inner_command>'` string, quoting every
    nesting layer with shlex.quote instead of by hand.

    This string is interpreted by TWO real shells before it reaches
    `inner_command`: the outer virtual machine's login shell (invoked by
    its sshd to run the string this function returns), and then the nested
    guest's login shell (invoked by ITS sshd to run the embedded
    `bash -lc ...` call once the outer shell has stripped its layer of
    quoting). shlex.quote wraps each layer in single quotes -- which are
    inert to everything except another single quote -- so neither hop can
    expand `$( )`, backticks, or `$VAR`, or break on an embedded quote.

    Quoting any caller-supplied value that goes INTO `inner_command` is the
    caller's responsibility; this function only protects the layers around
    `inner_command` itself, since `inner_command` is meant to still read as
    a shell command (e.g. containing its own `--flag value` structure) once
    it reaches the nested guest.
    """
    remote = f"bash -lc {shlex.quote(inner_command)}"
    return (
        "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"{nested_user}@{nested_host} {shlex.quote(remote)}"
    )


def nested_xapi_config_command(
    nested_user: str, nested_host: str, key: str, value: str
) -> str:
    inner = (
        f"LAB_XAPI_PROVISION=1 lab xapi-config {key} "
        f"--provision {shlex.quote(value)}"
    )
    return nested_ssh_command(nested_user, nested_host, inner)


def nested_xapi_email_command(nested_user: str, nested_host: str, email: str) -> str:
    """Configure the guest's xAPI actor email.

    Unlike token, passback, and session-id, email is NOT provisioner-locked:
    the Learning Record Store actor is the student's own mailbox, so this
    must never gain `--provision` or set `LAB_XAPI_PROVISION`. `email`
    originates from the inbound LTI launch (`lis_person_contact_email_primary`),
    so it crosses a trust boundary the token/passback/session-id values
    never do; it still must be quoted, just without provisioner authority.
    """
    inner = f"lab xapi-config email {shlex.quote(email)}"
    return nested_ssh_command(nested_user, nested_host, inner)


async def assign_grade_token(db, session_id: str) -> str:
    existing = await db.fetchval(SELECT_GRADE_TOKEN_HASH_SQL, session_id)
    if existing:
        raise GradeTokenAlreadyAssigned(session_id)
    token = mint_grade_token()
    digest = hash_grade_token(token)
    await db.execute(ASSIGN_GRADE_TOKEN_SQL, session_id, digest)
    logger.info("Assigned grade token for session %s", session_id)
    return token


async def inject_guest_xapi_config(
    run_ssh,
    *,
    vm_ip: str,
    ssh_user: str,
    ssh_password: str,
    nested_user: str,
    nested_host: str,
    token: str,
    passback: str,
    session_id: str,
) -> None:
    specs = (
        ("token", token),
        ("passback", passback),
        ("session-id", session_id),
    )
    for key, value in specs:
        cmd = nested_xapi_config_command(nested_user, nested_host, key, value)
        success, output = await run_ssh(
            vm_ip, ssh_user, ssh_password, cmd, timeout=60
        )
        safe_output = redact_secret(output or "", token)
        if success:
            logger.info(
                "xAPI %s configuration successful for session %s",
                key,
                session_id,
            )
        else:
            logger.warning(
                "xAPI %s configuration failed for session %s (continuing): %s",
                key,
                session_id,
                safe_output[:200],
            )
