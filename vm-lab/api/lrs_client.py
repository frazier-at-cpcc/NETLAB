"""Read-only access to the Learning Record Store for grade backfill.

This module only reads. Nothing here posts a statement back to the store.

The write credential for this store lives on student machines, so a
student can post a fabricated statement under their own address and set
that statement's `timestamp` to any value they like. They cannot control
`stored`, which the store assigns on receipt. `graded_lesson_statements`
filters on `stored`, never on `timestamp`, and the comparison against the
cutoff is strict so a statement stored at the exact boundary instant is
still dropped. Weakening either of those turns the filter from a security
control into a formality.

This runs as a background task against data written by many clients over
months. A single malformed statement must be dropped, not allowed to
raise and stop the rest of the batch.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

LESSON_TYPE = "http://adlnet.gov/expapi/activities/lesson"
ACTIVITY_PREFIX = "https://training.redhat.com/labs/"

_STATEMENT_ERRORS = (AttributeError, TypeError, ValueError)


class LrsQueryError(Exception):
    """Raised by fetch_statements when the store answers a statements
    query with a non-200 status.

    Deliberately left uncaught here: letting it propagate up through
    attempt_backfill's existing generic exception handling means an HTTP
    failure is treated exactly like a network exception, which that
    handler already treats as transient -- the cell is left unmarked so
    the next launch retries, rather than being permanently consumed. A
    revoked, rotated, or wrong read credential is frequently the root
    cause of both. See api/backfill.py's module docstring.
    """

    def __init__(self, status_code):
        super().__init__(f"LRS statements query failed with HTTP {status_code}")
        self.status_code = status_code


def parse_stored(value: str) -> datetime:
    """Parse an xAPI `stored` value.

    The store emits nine fractional digits, which `datetime.fromisoformat`
    rejects on the interpreter versions this project targets, so the
    fraction is truncated to six digits before parsing. A value with no
    fractional part at all, and one with a trailing `Z` rather than an
    explicit offset, both still parse. A value with no offset at all is
    treated as UTC, matching what the store actually emits.
    """
    text = (value or "").strip().replace("Z", "+00:00")
    if "." in text:
        head, _, tail = text.partition(".")
        digits = ""
        rest = ""
        for i, ch in enumerate(tail):
            if ch.isdigit():
                digits += ch
            else:
                rest = tail[i:]
                break
        text = f"{head}.{digits[:6]}{rest}"
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _is_number(value) -> bool:
    """True for an int or float, excluding bool (a bool is an int in
    Python, and a score is never legitimately True/False)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def graded_lesson_statements(payload: dict, slug: str, before: datetime) -> list[dict]:
    """Return statements that are a scored lesson for this slug, stored before the bound.

    A statement is eligible only if all of the following hold:

    - its object id matches the lab activity for `slug`
    - its object definition type is a lesson, not an assessment or another
      activity type
    - it carries a `result.score.scaled` value, AND numeric `result.score.raw`
      and `result.score.max` values
    - its `stored` timestamp parses and falls strictly before `before`

    xAPI 1.0.3 only requires `scaled`; `raw` and `max` are optional on the
    wire. But the caller delivers `raw`/`max` verbatim as the grade, so a
    statement that has `scaled` without a real `raw`/`max` cannot produce
    a real score and must be dropped here rather than admitted and given
    a made-up default downstream -- that default is exactly what once
    wrote a zero into a live gradebook for a student who scored full
    marks. Every eligibility rule for this statement type lives in this
    one function.

    Any statement that fails to parse, or whose shape does not match what
    the store actually emits, is dropped rather than raised. Each
    statement is evaluated independently, so one malformed record never
    stops the rest of the batch from being read.
    """
    wanted = f"{ACTIVITY_PREFIX}{slug}"
    statements = (payload or {}).get("statements") or []
    kept = []
    for statement in statements:
        try:
            obj = statement.get("object") or {}
            if obj.get("id") != wanted:
                continue
            if (obj.get("definition") or {}).get("type") != LESSON_TYPE:
                continue
            score = (statement.get("result") or {}).get("score") or {}
            if score.get("scaled") is None:
                continue
            if not _is_number(score.get("raw")) or not _is_number(score.get("max")):
                continue
            stored = parse_stored(statement.get("stored", ""))
        except _STATEMENT_ERRORS:
            continue
        if stored >= before:
            continue
        kept.append(statement)
    return kept


async def fetch_statements(
    http, *, base_url, auth, agent_mbox, activity, limit=50, until=None
) -> dict:
    """GET one page of statements for one agent and one activity.

    `auth` is the pre-encoded HTTP Basic credential for this store. It is
    used only to build the Authorization header for this one request. It
    is never logged, never included in a raised exception, and never
    written anywhere else, because this credential lives for the whole
    store and must not leak into logs or error output.

    `until`, when given, is passed as xAPI's `until` query parameter,
    filtering on `stored` at the store itself. This enforces the
    freshness bound from spec section 4 server-side, keeps eligible
    statements on the first page, and reduces transfer. `until` is
    inclusive on the wire, so the caller's own strict (exclusive)
    comparison in `graded_lesson_statements` remains the authority; this
    is an optimisation and a defence in depth, not a replacement for it.

    A non-200 response raises `LrsQueryError` rather than being treated
    as an empty result. An empty `{"statements": []}` and "the query
    failed" must never look identical to the caller: attempt_backfill
    treats an empty result as license to permanently mark a cell as
    attempted, so silently swallowing a 401/500/503 here would burn a
    whole cohort's one attempt each on a bad credential. The status code
    is logged at WARNING; the credential is not.
    """
    agent = '{"objectType":"Agent","mbox":"%s"}' % agent_mbox
    params = {"agent": agent, "activity": activity, "limit": limit}
    if until is not None:
        params["until"] = until.isoformat()
    response = await http.get(
        f"{base_url.rstrip('/')}/statements",
        params=params,
        headers={
            "Authorization": f"Basic {auth}",
            "X-Experience-API-Version": "1.0.3",
        },
    )
    if response.status_code != 200:
        logger.warning("LRS statements query failed status=%s", response.status_code)
        raise LrsQueryError(response.status_code)
    return response.json()
