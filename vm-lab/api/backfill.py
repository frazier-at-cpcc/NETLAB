"""Grade backfill from the Learning Record Store.

Email is reintroduced as a lookup key here, and only here, and only for
statements the store accepted before a configured cutover. See the spec.

`attempt_backfill` is the orchestrator: one claimed attempt per cell,
never more. `config` is a small mapping (duck-typed, `.get()` is all that
is required) carrying:

  enabled   bool   -- feature flag; a false value short-circuits before
                       any query.
  domains   list[str] -- the equivalence list passed to `candidate_mboxes`.
  cutoff    datetime | str -- the freshness bound from spec section 4. A
                       string is parsed with the store's own `parse_stored`,
                       so an ISO instant from configuration and a `stored`
                       value from the store are interpreted identically.
  base_url  str   -- passed straight through to `fetch_statements`.
  auth      str   -- the pre-encoded HTTP Basic credential for the read-only
                       store account. Passed straight through to
                       `fetch_statements` and never logged.

On an unexpected failure while reaching or reading the store -- a network
error, or anything else raised before a terminal outcome is reached -- the
whole attempt is rolled back and the cell is left unmarked, not
`backfill_attempted_at`-stamped. A transient outage must not permanently
foreclose recovering a student's history; the next launch of the same
resource link tries again. See the task report for the trade-off this
accepts: a persistently failing cell is retried on every later launch
rather than silently and permanently giving up on it.
"""

import json
import logging
from datetime import datetime, timezone
from decimal import Decimal

try:
    from lrs_client import ACTIVITY_PREFIX, fetch_statements, graded_lesson_statements, parse_stored
except ImportError:
    from api.lrs_client import ACTIVITY_PREFIX, fetch_statements, graded_lesson_statements, parse_stored

logger = logging.getLogger(__name__)

CLAIM_CELL_SQL = """
SELECT c.id, c.course_session_id, c.lab_slug, s.user_email
FROM grade_cells c
JOIN vm_sessions s ON s.session_id = c.course_session_id
WHERE c.id = $1 AND c.backfill_attempted_at IS NULL
FOR UPDATE OF c SKIP LOCKED
"""

SELECT_GRADE_EVENT_SQL = """
SELECT id FROM grade_events WHERE cell_id = $1 LIMIT 1
"""

INSERT_BACKFILL_EVENT_SQL = """
INSERT INTO grade_events (
    cell_id, idempotency_key, slug, score_raw, score_max, occurred_at, payload, provenance
) VALUES ($1, $2, $3, $4, $5, $6, $7, 'lrs_backfill')
RETURNING id
"""

INSERT_BACKFILL_DELIVERY_SQL = """
INSERT INTO grade_deliveries (event_id, cell_id, state)
VALUES ($1, $2, 'PENDING')
"""

MARK_ATTEMPTED_SQL = """
UPDATE grade_cells SET backfill_attempted_at = $2 WHERE id = $1
"""


def candidate_mboxes(email: str, domains: list[str]) -> list[str]:
    """Return the launch address plus the same local part at each configured domain.

    Substitution is by whole domain. A local part is never matched on its own,
    because a different institution shares this store and a collision would move
    a grade between colleges.
    """
    address = (email or "").strip()
    if address.count("@") != 1:
        return []
    local, _, domain = address.partition("@")
    if not local or not domain:
        return []
    ordered = [address]
    if domain in domains:
        for candidate_domain in domains:
            candidate = f"{local}@{candidate_domain}"
            if candidate not in ordered:
                ordered.append(candidate)
    return [f"mailto:{a}" for a in ordered]


def best_statement(statements: list[dict]) -> dict | None:
    """Return the statement with the highest scaled score, or None."""
    best = None
    best_score = None
    for statement in statements or []:
        scaled = ((statement.get("result") or {}).get("score") or {}).get("scaled")
        if scaled is None:
            continue
        if best_score is None or scaled > best_score:
            best, best_score = statement, scaled
    return best


def _log_outcome(cell_id, slug, outcome) -> None:
    logger.info("backfill cell=%s slug=%s outcome=%s", cell_id, slug, outcome)


async def attempt_backfill(db, http, cell_id, *, config) -> str:
    """Orchestrate one backfill attempt for a grade cell.

    Returns one of: disabled, already_attempted, has_grades, no_email,
    no_history, delivered. See the module docstring for the `config`
    contract and for what happens on an unexpected failure.
    """
    if not config.get("enabled", False):
        return "disabled"

    async with db.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(CLAIM_CELL_SQL, cell_id)
            if row is None:
                return "already_attempted"

            claimed_id = row["id"]
            slug = row["lab_slug"]
            user_email = row["user_email"]

            existing = await conn.fetchrow(SELECT_GRADE_EVENT_SQL, claimed_id)
            if existing is not None:
                await conn.execute(MARK_ATTEMPTED_SQL, claimed_id, datetime.now(timezone.utc))
                _log_outcome(claimed_id, slug, "has_grades")
                return "has_grades"

            candidates = candidate_mboxes(user_email, config.get("domains", []))
            if not candidates:
                await conn.execute(MARK_ATTEMPTED_SQL, claimed_id, datetime.now(timezone.utc))
                _log_outcome(claimed_id, slug, "no_email")
                return "no_email"

            cutoff = config.get("cutoff")
            if isinstance(cutoff, str):
                cutoff = parse_stored(cutoff)

            activity = f"{ACTIVITY_PREFIX}{slug}"

            # From here through the insert, any exception -- a network
            # error reaching the store, a malformed response, a database
            # error on write -- is deliberately NOT converted into a
            # marked attempt. Letting it propagate rolls back this
            # transaction (the cell's FOR UPDATE lock releases with it),
            # so `backfill_attempted_at` stays NULL and the next launch of
            # this resource link gets a fresh attempt. See the module
            # docstring for why a transient failure must not consume the
            # one attempt this cell will ever get.
            try:
                all_statements = []
                for mbox in candidates:
                    payload = await fetch_statements(
                        http,
                        base_url=config.get("base_url", ""),
                        auth=config.get("auth", ""),
                        agent_mbox=mbox,
                        activity=activity,
                    )
                    all_statements.extend(graded_lesson_statements(payload, slug, cutoff))

                best = best_statement(all_statements)
                if best is None:
                    await conn.execute(MARK_ATTEMPTED_SQL, claimed_id, datetime.now(timezone.utc))
                    _log_outcome(claimed_id, slug, "no_history")
                    return "no_history"

                statement_id = best.get("id", "")
                result = best.get("result") or {}
                score = result.get("score") or {}
                score_raw = Decimal(str(score.get("raw", 0)))
                score_max = Decimal(str(score.get("max", 1)))
                stored_str = best.get("stored", "")
                occurred_at = parse_stored(stored_str) if stored_str else datetime.now(timezone.utc)

                idempotency_key = f"backfill:{claimed_id}:{statement_id}"
                payload_json = json.dumps(best)

                event_id = await conn.fetchval(
                    INSERT_BACKFILL_EVENT_SQL,
                    claimed_id,
                    idempotency_key,
                    slug,
                    score_raw,
                    score_max,
                    occurred_at,
                    payload_json,
                )
                await conn.execute(INSERT_BACKFILL_DELIVERY_SQL, event_id, claimed_id)
                await conn.execute(MARK_ATTEMPTED_SQL, claimed_id, datetime.now(timezone.utc))
                _log_outcome(claimed_id, slug, "delivered")
                return "delivered"
            except Exception:
                logger.warning(
                    "backfill cell=%s slug=%s outcome=error, leaving attempt open for retry",
                    claimed_id,
                    slug,
                )
                raise
