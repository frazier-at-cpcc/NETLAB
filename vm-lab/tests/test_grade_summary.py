"""Proves session_grade_summary's join and student-facing mapping.

Joins grade_cells to its newest grade_events row and that event's newest
grade_deliveries row, filtered to one course_session_id. A SUPERSEDED
delivery is never returned. A regrade creates a new event for the same
cell, and only the newest event survives the join, so an improved score
replaces rather than appends.

Follows the stub-pool pattern in test_pox_delivery.py and
test_grade_events.py: the stub asserts the required joins and filters are
present in the real SQL text, then computes the result from its own
in-memory rows rather than a live database.
"""

import asyncio
from datetime import datetime, timezone
from decimal import Decimal

SESSION_ID = "sess-1"
OTHER_SESSION_ID = "sess-2"
SOURCEDID = "secret-sourcedid-value"
IDEMPOTENCY_KEY = "secret-idempotency-key"
OCCURRED_AT = datetime(2026, 9, 14, 18, 0, 0, tzinfo=timezone.utc)
LATER_OCCURRED_AT = datetime(2026, 9, 15, 9, 0, 0, tzinfo=timezone.utc)


class _AsyncCM:
    def __init__(self, value):
        self._value = value

    async def __aenter__(self):
        return self._value

    async def __aexit__(self, exc_type, exc, tb):
        return False


class GradeSummaryStubPool:
    """In-memory stand-in for asyncpg. Records SQL and grade summary rows."""

    def __init__(self):
        self.calls = []
        self.cells = []
        self.events = []
        self.deliveries = []
        self.acquired = 0
        self._next_cell_id = 1

    def acquire(self):
        self.acquired += 1
        return _AsyncCM(self)

    def add_cell(self, session_id, lab_slug, *, cell_id=None, sourcedid=SOURCEDID):
        cell_id = self._next_cell_id if cell_id is None else cell_id
        self._next_cell_id = max(self._next_cell_id, cell_id + 1)
        self.cells.append(
            {
                "id": cell_id,
                "course_session_id": session_id,
                "lab_slug": lab_slug,
                "sourcedid": sourcedid,
            }
        )
        return cell_id

    def add_event(
        self,
        cell_id,
        *,
        event_id,
        score_raw=Decimal("8"),
        score_max=Decimal("10"),
        occurred_at=OCCURRED_AT,
        idempotency_key=IDEMPOTENCY_KEY,
    ):
        self.events.append(
            {
                "id": event_id,
                "cell_id": cell_id,
                "score_raw": score_raw,
                "score_max": score_max,
                "occurred_at": occurred_at,
                "idempotency_key": idempotency_key,
            }
        )

    def add_delivery(self, event_id, *, delivery_id, state):
        self.deliveries.append({"id": delivery_id, "event_id": event_id, "state": state})

    async def fetch(self, sql, *args):
        self.calls.append(("fetch", sql, args))
        return self._dispatch(sql, args)

    def _dispatch(self, sql, args):
        sql_n = " ".join(sql.split())
        if "FROM grade_cells" not in sql_n:
            raise AssertionError(f"unhandled SQL: {sql_n}")
        if "grade_events" not in sql_n:
            raise AssertionError("summary SQL must join grade_events")
        if "grade_deliveries" not in sql_n:
            raise AssertionError("summary SQL must join grade_deliveries")
        if "SUPERSEDED" not in sql_n:
            raise AssertionError("summary SQL must exclude SUPERSEDED")
        if "sourcedid" in sql_n.lower():
            raise AssertionError("summary SQL must never select sourcedid")
        if "idempotency_key" in sql_n.lower():
            raise AssertionError("summary SQL must never select the idempotency key")

        session_id = args[0]
        out = []
        for cell in self.cells:
            if cell["course_session_id"] != session_id:
                continue
            cell_events = [e for e in self.events if e["cell_id"] == cell["id"]]
            if not cell_events:
                continue
            newest_event = max(cell_events, key=lambda e: (e["occurred_at"], e["id"]))
            event_deliveries = [
                d for d in self.deliveries if d["event_id"] == newest_event["id"]
            ]
            if not event_deliveries:
                continue
            newest_delivery = max(event_deliveries, key=lambda d: d["id"])
            if newest_delivery["state"] == "SUPERSEDED":
                continue
            out.append(
                {
                    "lab_slug": cell["lab_slug"],
                    "score_raw": newest_event["score_raw"],
                    "score_max": newest_event["score_max"],
                    "occurred_at": newest_event["occurred_at"],
                    "state": newest_delivery["state"],
                }
            )
        out.sort(key=lambda r: r["lab_slug"])
        return out


def _sql(call):
    return " ".join(call[1].split())


def _summary(db, session_id=SESSION_ID):
    from api.grades import session_grade_summary

    return asyncio.run(session_grade_summary(db, session_id=session_id))


def test_session_with_no_cells_returns_empty_list():
    db = GradeSummaryStubPool()

    rows = _summary(db)

    assert rows == []
    assert db.acquired >= 1
    assert db.calls[0][2] == (SESSION_ID,)


def test_delivered_event_returns_one_row_with_delivered_state():
    db = GradeSummaryStubPool()
    cell_id = db.add_cell(SESSION_ID, "cli-review")
    db.add_event(cell_id, event_id=1)
    db.add_delivery(1, delivery_id=1, state="DELIVERED")

    rows = _summary(db)

    assert len(rows) == 1
    row = rows[0]
    assert row["slug"] == "cli-review"
    assert row["state"] == "delivered"
    assert set(row) == {
        "slug",
        "title",
        "score_raw",
        "score_max",
        "percent",
        "state",
        "occurred_at",
    }


def test_pending_delivery_returns_sending_state():
    db = GradeSummaryStubPool()
    cell_id = db.add_cell(SESSION_ID, "cli-review")
    db.add_event(cell_id, event_id=1)
    db.add_delivery(1, delivery_id=1, state="PENDING")

    rows = _summary(db)

    assert rows[0]["state"] == "sending"


def test_retrying_delivery_returns_sending_state():
    db = GradeSummaryStubPool()
    cell_id = db.add_cell(SESSION_ID, "cli-review")
    db.add_event(cell_id, event_id=1)
    db.add_delivery(1, delivery_id=1, state="RETRYING")

    rows = _summary(db)

    assert rows[0]["state"] == "sending"


def test_dead_letter_delivery_returns_failed_state():
    db = GradeSummaryStubPool()
    cell_id = db.add_cell(SESSION_ID, "cli-review")
    db.add_event(cell_id, event_id=1)
    db.add_delivery(1, delivery_id=1, state="DEAD_LETTER")

    rows = _summary(db)

    assert rows[0]["state"] == "failed"


def test_superseded_delivery_is_not_returned_at_all():
    db = GradeSummaryStubPool()
    cell_id = db.add_cell(SESSION_ID, "cli-review")
    db.add_event(cell_id, event_id=1)
    db.add_delivery(1, delivery_id=1, state="SUPERSEDED")

    rows = _summary(db)

    assert rows == []


def test_regrade_returns_only_the_newest_event():
    """A cell with two events (a regrade) must surface only the newer
    score, or a student who improved a lab would see both attempts."""
    db = GradeSummaryStubPool()
    cell_id = db.add_cell(SESSION_ID, "cli-review")
    db.add_event(
        cell_id,
        event_id=1,
        score_raw=Decimal("6"),
        score_max=Decimal("10"),
        occurred_at=OCCURRED_AT,
    )
    db.add_delivery(1, delivery_id=1, state="DELIVERED")
    db.add_event(
        cell_id,
        event_id=2,
        score_raw=Decimal("9"),
        score_max=Decimal("10"),
        occurred_at=LATER_OCCURRED_AT,
    )
    db.add_delivery(2, delivery_id=2, state="DELIVERED")

    rows = _summary(db)

    assert len(rows) == 1
    assert rows[0]["score_raw"] == "9"
    assert rows[0]["occurred_at"] == LATER_OCCURRED_AT.isoformat()


def test_only_rows_for_the_requested_session_are_returned():
    db = GradeSummaryStubPool()
    mine = db.add_cell(SESSION_ID, "cli-review")
    db.add_event(mine, event_id=1)
    db.add_delivery(1, delivery_id=1, state="DELIVERED")
    theirs = db.add_cell(OTHER_SESSION_ID, "help-review", cell_id=2)
    db.add_event(theirs, event_id=2)
    db.add_delivery(2, delivery_id=2, state="DELIVERED")

    rows = _summary(db, session_id=SESSION_ID)

    assert [r["slug"] for r in rows] == ["cli-review"]


def test_percent_is_computed_from_raw_over_max():
    db = GradeSummaryStubPool()
    cell_id = db.add_cell(SESSION_ID, "cli-review")
    db.add_event(cell_id, event_id=1, score_raw=Decimal("8"), score_max=Decimal("10"))
    db.add_delivery(1, delivery_id=1, state="DELIVERED")

    rows = _summary(db)

    assert rows[0]["percent"] == 80.0


def test_zero_score_max_does_not_raise_and_yields_zero_percent():
    db = GradeSummaryStubPool()
    cell_id = db.add_cell(SESSION_ID, "cli-review")
    db.add_event(cell_id, event_id=1, score_raw=Decimal("0"), score_max=Decimal("0"))
    db.add_delivery(1, delivery_id=1, state="DELIVERED")

    rows = _summary(db)

    assert rows[0]["percent"] == 0.0


def test_no_sensitive_field_reaches_the_returned_rows():
    db = GradeSummaryStubPool()
    cell_id = db.add_cell(SESSION_ID, "cli-review")
    db.add_event(cell_id, event_id=1)
    db.add_delivery(1, delivery_id=1, state="DELIVERED")

    rows = _summary(db)

    row = rows[0]
    assert "sourcedid" not in row
    assert "consumer_key" not in row
    assert "outcome_service_url" not in row
    assert "idempotency_key" not in row
    assert "token" not in row
    text = str(row)
    assert SOURCEDID not in text
    assert IDEMPOTENCY_KEY not in text
    assert "sourcedid" not in text.lower()
    assert "token" not in text.lower()
