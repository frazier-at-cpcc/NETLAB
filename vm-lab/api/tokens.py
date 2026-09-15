import hashlib
import logging
import os
import secrets

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


def nested_xapi_config_command(
    nested_user: str, nested_host: str, key: str, value: str
) -> str:
    return (
        "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"{nested_user}@{nested_host} "
        "'bash -lc \"LAB_XAPI_PROVISION=1 lab xapi-config "
        f"{key} --provision '\\''{value}'\\''\"'"
    )


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
