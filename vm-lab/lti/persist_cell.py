import json
import logging
from types import SimpleNamespace

logger = logging.getLogger(__name__)


def grade_cell_body(session_id, ctx) -> dict | None:
    if not ctx.lab_slug or not ctx.sourcedid or not ctx.outcome_service_url:
        return None
    return {
        "course_session_id": session_id,
        "lab_slug": ctx.lab_slug,
        "resource_link_id": ctx.resource_link_id,
        "outcome_service_url": ctx.outcome_service_url,
        "sourcedid": ctx.sourcedid,
        "consumer_key": ctx.consumer_key,
    }


async def persist_grade_cell(session_id, ctx, *, post) -> None:
    body = grade_cell_body(session_id, ctx)
    if body is None:
        logger.warning(
            "Skipping grade cell persist; missing fields for resource_link_id=%s",
            ctx.resource_link_id,
        )
        return
    await post(body)


# --- Pending cell fields ---------------------------------------------------
#
# The grade cell cannot be written at launch time when no virtual machine
# session exists yet, because grade_cells.course_session_id is a foreign key
# onto vm_sessions.session_id. The fields therefore have to survive from the
# launch until the student clicks Start Lab and /api/provision creates the
# session.
#
# They used to survive in the signed `lti_session` cookie alone. That cookie
# is set inside an LMS iframe, so it is a third-party cookie, and a browser
# that blocks third-party cookies drops it. Everything else the provision
# call needs (session_key, user_id, and the rest) is embedded in the page and
# posted in the request body, so provisioning still succeeded while the cell
# silently did not persist: `lab grade` then reported "no gradebook column"
# for a lab whose gradebook column was real.
#
# The fields cannot follow the others into the page, because `sourcedid` is a
# write-back credential for the student's own gradebook cell and must never
# reach the browser. Redis carries them instead, keyed by the session key the
# page already holds, so the credential stays server-side and no cookie is
# load-bearing.

PENDING_CELL_PREFIX = "pending_cell:"
PENDING_CELL_TTL_SECONDS = 4 * 3600

_PENDING_FIELDS = (
    "lab_slug",
    "sourcedid",
    "outcome_service_url",
    "resource_link_id",
    "consumer_key",
)


def pending_cell_key(session_key: str) -> str | None:
    if not session_key:
        return None
    return f"{PENDING_CELL_PREFIX}{session_key}"


def cell_fields_from_ctx(ctx) -> dict[str, str]:
    """Flatten the launch context down to the fields a grade cell needs."""
    return {name: (getattr(ctx, name, "") or "") for name in _PENDING_FIELDS}


def ctx_from_cell_fields(fields):
    """Rebuild a cell context from stored fields.

    Empty strings become None so that `grade_cell_body` rejects an
    incomplete set the same way it rejects a launch that carried none.
    """
    fields = fields or {}
    return SimpleNamespace(
        lab_slug=fields.get("lab_slug") or None,
        sourcedid=fields.get("sourcedid") or None,
        outcome_service_url=fields.get("outcome_service_url") or None,
        resource_link_id=fields.get("resource_link_id") or "",
        consumer_key=fields.get("consumer_key") or "",
    )


def store_pending_cell(redis_client, session_key: str, ctx) -> bool:
    """Stash the launch's cell fields for the provision call that follows.

    Returns True when something was stored. A launch that carried no
    outcome information stores nothing, because there is no gradebook cell
    to write back to and a later provision must not resurrect a stale one.
    """
    key = pending_cell_key(session_key)
    if key is None or ctx is None:
        return False
    fields = cell_fields_from_ctx(ctx)
    if not fields["sourcedid"] or not fields["outcome_service_url"]:
        return False
    try:
        redis_client.setex(key, PENDING_CELL_TTL_SECONDS, json.dumps(fields))
    except Exception as exc:
        # Never fail a launch because the stash failed; the cookie path
        # remains as a fallback and the next launch retries.
        logger.warning(
            "Could not stash pending grade cell for resource_link_id=%s: %s",
            fields.get("resource_link_id"),
            type(exc).__name__,
        )
        return False
    return True


def load_pending_cell(redis_client, session_key: str):
    """Return the stashed cell context, or None when there is none."""
    key = pending_cell_key(session_key)
    if key is None:
        return None
    try:
        raw = redis_client.get(key)
    except Exception as exc:
        logger.warning("Could not read pending grade cell: %s", type(exc).__name__)
        return None
    if not raw:
        return None
    try:
        fields = json.loads(raw)
    except (ValueError, TypeError):
        logger.warning("Discarding malformed pending grade cell entry")
        return None
    if not isinstance(fields, dict):
        logger.warning("Discarding malformed pending grade cell entry")
        return None
    return ctx_from_cell_fields(fields)
