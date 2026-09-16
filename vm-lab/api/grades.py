import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel

try:
    from tokens import hash_grade_token
except ImportError:
    from api.tokens import hash_grade_token

logger = logging.getLogger(__name__)

SELECT_SESSION_SQL = """
SELECT session_id FROM vm_sessions
 WHERE grade_token_hash = $1
   AND status IN ('starting', 'running')
"""

SELECT_CELL_SQL = """
SELECT id FROM grade_cells
 WHERE course_session_id = $1 AND lab_slug = $2
"""

INSERT_EVENT_SQL = """
INSERT INTO grade_events (
    cell_id, idempotency_key, slug, score_raw, score_max, occurred_at, payload
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id
"""

SELECT_EVENT_BY_KEY_SQL = """
SELECT id FROM grade_events WHERE idempotency_key = $1
"""

SUPERSEDE_DELIVERIES_SQL = """
UPDATE grade_deliveries SET state = 'SUPERSEDED'
 WHERE cell_id = $1 AND state IN ('PENDING', 'RETRYING')
"""

INSERT_DELIVERY_SQL = """
INSERT INTO grade_deliveries (event_id, cell_id, state)
VALUES ($1, $2, 'PENDING')
"""

LIST_DELIVERED_EVENTS_SQL = """
SELECT
    s.user_email,
    c.lab_slug,
    e.score_raw,
    e.score_max,
    d.delivered_at,
    s.session_id
FROM grade_events e
JOIN grade_deliveries d ON d.event_id = e.id
JOIN grade_cells c ON c.id = d.cell_id
JOIN vm_sessions s ON s.session_id = c.course_session_id
WHERE d.state = 'DELIVERED'
  AND ($1::timestamptz IS NULL OR d.delivered_at >= $1)
ORDER BY d.delivered_at ASC, e.id ASC
"""

# Joins each of the session's grade cells to its newest grade_events row,
# and that event's newest grade_deliveries row, so a regrade (a new event
# for the same cell) replaces rather than appends. A SUPERSEDED delivery
# is excluded outright: it is a replaced attempt, not a grade the student
# holds. Selects only what a student may see -- never a sourcedid, a
# grade token, an idempotency key, or an internal delivery state name;
# state is translated to student-facing words in Python, not in SQL.
SESSION_GRADE_SUMMARY_SQL = """
SELECT
    c.lab_slug,
    e.score_raw,
    e.score_max,
    e.occurred_at,
    d.state
FROM grade_cells c
JOIN LATERAL (
    SELECT id, score_raw, score_max, occurred_at
    FROM grade_events
    WHERE cell_id = c.id
    ORDER BY occurred_at DESC, id DESC
    LIMIT 1
) e ON true
JOIN LATERAL (
    SELECT state
    FROM grade_deliveries
    WHERE event_id = e.id
    ORDER BY id DESC
    LIMIT 1
) d ON true
WHERE c.course_session_id = $1
  AND d.state != 'SUPERSEDED'
ORDER BY c.lab_slug ASC
"""

# The student-facing words for each delivery state. SUPERSEDED never
# reaches this map: SESSION_GRADE_SUMMARY_SQL excludes it at the source.
DELIVERY_STATE_WORDS = {
    "PENDING": "sending",
    "IN_FLIGHT": "sending",
    "RETRYING": "sending",
    "DELIVERED": "delivered",
    "DEAD_LETTER": "failed",
}


class InvalidGradeScore(ValueError):
    """Raised when score.max is not positive."""


class InvalidGradeSince(ValueError):
    """Raised when the since query parameter is not ISO-8601."""


class TaskBody(BaseModel):
    label: str
    passed: bool


class ScoreBody(BaseModel):
    raw: Decimal
    max: Decimal
    scaled: Decimal


class GradeRequest(BaseModel):
    slug: str
    occurred_at: datetime
    score: ScoreBody
    passed: bool
    tasks: list[TaskBody] = []


@dataclass(frozen=True)
class GradeAcceptResult:
    status: Literal["accepted", "duplicate", "no_session", "no_handle"]
    event_id: int | None


def extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


def map_grade_http(result: GradeAcceptResult) -> tuple[int, dict | None]:
    if result.status == "no_session":
        return 401, None
    if result.status == "no_handle":
        return 404, {"error": "no_handle"}
    if result.status in ("accepted", "duplicate"):
        return 202, {"status": result.status, "event_id": result.event_id}
    raise ValueError(f"unknown grade status: {result.status}")


def _is_unique_violation(exc: BaseException) -> bool:
    if getattr(exc, "sqlstate", None) == "23505":
        return True
    return type(exc).__name__ == "UniqueViolationError"


async def accept_grade(
    db,
    *,
    token: str,
    idempotency_key: str,
    request: GradeRequest,
) -> GradeAcceptResult:
    if request.score.max <= 0:
        raise InvalidGradeScore("score.max must be greater than 0")

    digest = hash_grade_token(token)
    async with db.acquire() as conn:
        session_id = await conn.fetchval(SELECT_SESSION_SQL, digest)
        if session_id is None:
            logger.info("Grade post rejected: no session")
            return GradeAcceptResult(status="no_session", event_id=None)

        cell_id = await conn.fetchval(SELECT_CELL_SQL, session_id, request.slug)
        if cell_id is None:
            logger.info(
                "Grade post rejected: no handle for session %s slug %s",
                session_id,
                request.slug,
            )
            return GradeAcceptResult(status="no_handle", event_id=None)

        payload = json.dumps(request.model_dump(mode="json"))
        try:
            async with conn.transaction():
                event_id = await conn.fetchval(
                    INSERT_EVENT_SQL,
                    cell_id,
                    idempotency_key,
                    request.slug,
                    request.score.raw,
                    request.score.max,
                    request.occurred_at,
                    payload,
                )
                await conn.execute(SUPERSEDE_DELIVERIES_SQL, cell_id)
                await conn.execute(INSERT_DELIVERY_SQL, event_id, cell_id)
        except Exception as exc:
            if not _is_unique_violation(exc):
                raise
            event_id = await conn.fetchval(SELECT_EVENT_BY_KEY_SQL, idempotency_key)
            logger.info(
                "Duplicate grade event %s for session %s slug %s",
                event_id,
                session_id,
                request.slug,
            )
            return GradeAcceptResult(status="duplicate", event_id=event_id)

        logger.info(
            "Accepted grade event %s for session %s slug %s",
            event_id,
            session_id,
            request.slug,
        )
        return GradeAcceptResult(status="accepted", event_id=event_id)


def parse_since(value: str | None) -> datetime | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise InvalidGradeSince("since must be ISO-8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _serialize_delivered_event(row) -> dict:
    delivered_at = row["delivered_at"]
    if hasattr(delivered_at, "isoformat"):
        delivered_at = delivered_at.isoformat()
    raw = row["score_raw"]
    maximum = row["score_max"]
    return {
        "user_email": row["user_email"],
        "lab_slug": row["lab_slug"],
        "score_raw": format(raw, "f") if isinstance(raw, Decimal) else str(raw),
        "score_max": format(maximum, "f") if isinstance(maximum, Decimal) else str(maximum),
        "delivered_at": delivered_at,
        "session_id": row["session_id"],
    }


def _grade_percent(raw, maximum) -> float:
    """Raw over max as a percentage. A zero maximum is guarded rather than
    raising, since a malformed score.max must never break the panel."""
    if not maximum:
        return 0.0
    return round(float(raw) / float(maximum) * 100, 1)


def _serialize_grade_summary_row(row) -> dict:
    occurred_at = row["occurred_at"]
    if hasattr(occurred_at, "isoformat"):
        occurred_at = occurred_at.isoformat()
    raw = row["score_raw"]
    maximum = row["score_max"]
    # No lab-title catalog exists in this database; lab_slug is the only
    # descriptor a grade cell carries, so title mirrors slug until a
    # catalog is introduced.
    return {
        "slug": row["lab_slug"],
        "title": row["lab_slug"],
        "score_raw": format(raw, "f") if isinstance(raw, Decimal) else str(raw),
        "score_max": format(maximum, "f") if isinstance(maximum, Decimal) else str(maximum),
        "percent": _grade_percent(raw, maximum),
        "state": DELIVERY_STATE_WORDS[row["state"]],
        "occurred_at": occurred_at,
    }


async def session_grade_summary(db, *, session_id: str) -> list[dict]:
    """The newest grade per cell for one session, in student-facing terms.

    session_id must come from the caller's own signed session cookie; this
    function trusts whatever session_id it is given, so the caller is the
    only place that identity is allowed to be decided.
    """
    async with db.acquire() as conn:
        rows = await conn.fetch(SESSION_GRADE_SUMMARY_SQL, session_id)
    summary = [_serialize_grade_summary_row(row) for row in rows]
    logger.info(
        "Listed %s grade summary rows for session %s", len(summary), session_id
    )
    return summary


async def list_delivered_grade_events(db, *, since: datetime | None = None) -> list[dict]:
    async with db.acquire() as conn:
        rows = await conn.fetch(LIST_DELIVERED_EVENTS_SQL, since)
    events = [_serialize_delivered_event(row) for row in rows]
    logger.info(
        "Listed %s delivered grade events since %s",
        len(events),
        since.isoformat() if since is not None else "beginning",
    )
    return events
