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

from datetime import datetime, timezone

LESSON_TYPE = "http://adlnet.gov/expapi/activities/lesson"
ACTIVITY_PREFIX = "https://training.redhat.com/labs/"

_STATEMENT_ERRORS = (AttributeError, TypeError, ValueError)


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


def graded_lesson_statements(payload: dict, slug: str, before: datetime) -> list[dict]:
    """Return statements that are a scored lesson for this slug, stored before the bound.

    A statement is eligible only if all of the following hold:

    - its object id matches the lab activity for `slug`
    - its object definition type is a lesson, not an assessment or another
      activity type
    - it carries a numeric `result.score.scaled` value
    - its `stored` timestamp parses and falls strictly before `before`

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
            stored = parse_stored(statement.get("stored", ""))
        except _STATEMENT_ERRORS:
            continue
        if stored >= before:
            continue
        kept.append(statement)
    return kept


async def fetch_statements(http, *, base_url, auth, agent_mbox, activity, limit=50) -> dict:
    """GET one page of statements for one agent and one activity.

    `auth` is the pre-encoded HTTP Basic credential for this store. It is
    used only to build the Authorization header for this one request. It
    is never logged, never included in a raised exception, and never
    written anywhere else, because this credential lives for the whole
    store and must not leak into logs or error output.

    A non-200 response is treated as no statements rather than raised,
    since the caller runs in a background task where one page it cannot
    fetch should not stop a backfill that spans many students.
    """
    agent = '{"objectType":"Agent","mbox":"%s"}' % agent_mbox
    response = await http.get(
        f"{base_url.rstrip('/')}/statements",
        params={"agent": agent, "activity": activity, "limit": limit},
        headers={
            "Authorization": f"Basic {auth}",
            "X-Experience-API-Version": "1.0.3",
        },
    )
    if response.status_code != 200:
        return {"statements": []}
    return response.json()
