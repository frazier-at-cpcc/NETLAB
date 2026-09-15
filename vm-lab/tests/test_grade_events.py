import asyncio
import logging
from datetime import datetime, timezone
from decimal import Decimal

import pytest

TOKEN = "grade-token-plaintext-secret"
SOURCEDID = "secret-sourcedid-value"
SESSION_ID = "sess-1"
EMAIL = "jane@email.cpcc.edu"
SINCE = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)
DELIVERED_AT = datetime(2026, 9, 14, 18, 0, 0, tzinfo=timezone.utc)


class _AsyncCM:
    def __init__(self, value):
        self._value = value

    async def __aenter__(self):
        return self._value

    async def __aexit__(self, exc_type, exc, tb):
        return False


class GradeEventsStubPool:
    """In-memory stand-in for asyncpg. Records SQL for delivered-event listing."""

    def __init__(self):
        self.calls = []
        self.rows = []
        self.acquired = 0

    def acquire(self):
        self.acquired += 1
        return _AsyncCM(self)

    def add_row(
        self,
        *,
        user_email=EMAIL,
        lab_slug="cli-review",
        score_raw=Decimal("8"),
        score_max=Decimal("10"),
        delivered_at=DELIVERED_AT,
        session_id=SESSION_ID,
        state="DELIVERED",
        sourcedid=SOURCEDID,
        grade_token_hash="deadbeef",
    ):
        self.rows.append(
            {
                "user_email": user_email,
                "lab_slug": lab_slug,
                "score_raw": score_raw,
                "score_max": score_max,
                "delivered_at": delivered_at,
                "session_id": session_id,
                "state": state,
                "sourcedid": sourcedid,
                "grade_token_hash": grade_token_hash,
            }
        )

    async def fetch(self, sql, *args):
        self.calls.append(("fetch", sql, args))
        return self._dispatch(sql, args)

    def _dispatch(self, sql, args):
        sql_n = " ".join(sql.split())
        if "FROM grade_events" not in sql_n:
            raise AssertionError(f"unhandled SQL: {sql_n}")
        if "grade_deliveries" not in sql_n:
            raise AssertionError("listing SQL must join grade_deliveries")
        if "grade_cells" not in sql_n:
            raise AssertionError("listing SQL must join grade_cells")
        if "vm_sessions" not in sql_n:
            raise AssertionError("listing SQL must join vm_sessions")
        if "DELIVERED" not in sql_n:
            raise AssertionError("listing SQL must filter DELIVERED")

        since = args[0] if args else None
        out = []
        for row in self.rows:
            if row["state"] != "DELIVERED":
                continue
            if since is not None and (
                row["delivered_at"] is None or row["delivered_at"] < since
            ):
                continue
            out.append(
                {
                    "user_email": row["user_email"],
                    "lab_slug": row["lab_slug"],
                    "score_raw": row["score_raw"],
                    "score_max": row["score_max"],
                    "delivered_at": row["delivered_at"],
                    "session_id": row["session_id"],
                }
            )
        return out


def _sql(call):
    return " ".join(call[1].split())


def _list(db, since=None):
    from api.grades import list_delivered_grade_events

    return asyncio.run(list_delivered_grade_events(db, since=since))


def test_list_delivered_events_returns_safe_fields_only():
    db = GradeEventsStubPool()
    db.add_row()
    db.add_row(
        lab_slug="help-review",
        score_raw=Decimal("10"),
        score_max=Decimal("10"),
        state="PENDING",
    )

    events = _list(db)

    assert len(events) == 1
    event = events[0]
    assert event["user_email"] == EMAIL
    assert event["lab_slug"] == "cli-review"
    assert event["score_raw"] == "8"
    assert event["score_max"] == "10"
    assert event["delivered_at"] == DELIVERED_AT.isoformat()
    assert event["session_id"] == SESSION_ID
    assert set(event) == {
        "user_email",
        "lab_slug",
        "score_raw",
        "score_max",
        "delivered_at",
        "session_id",
    }
    assert "sourcedid" not in event
    assert "token" not in str(event).lower()
    assert SOURCEDID not in str(event)
    assert TOKEN not in str(event)

    sql = _sql(db.calls[0])
    assert "SELECT" in sql
    assert "user_email" in sql
    assert "lab_slug" in sql
    assert "score_raw" in sql
    assert "score_max" in sql
    assert "delivered_at" in sql
    assert "session_id" in sql
    assert "grade_events" in sql
    assert "grade_deliveries" in sql
    assert "grade_cells" in sql
    assert "vm_sessions" in sql
    assert "DELIVERED" in sql
    assert "sourcedid" not in sql.lower()
    assert "grade_token" not in sql.lower()
    assert "token" not in sql.lower()
    assert db.acquired >= 1
    assert db.calls[0][2] == (None,)


def test_list_delivered_events_since_filters_delivered_at():
    db = GradeEventsStubPool()
    db.add_row(
        lab_slug="cli-review",
        delivered_at=datetime(2026, 9, 13, 12, 0, 0, tzinfo=timezone.utc),
    )
    db.add_row(
        lab_slug="help-review",
        delivered_at=datetime(2026, 9, 14, 18, 0, 0, tzinfo=timezone.utc),
        score_raw=Decimal("9"),
        score_max=Decimal("10"),
    )

    events = _list(db, since=SINCE)

    assert [e["lab_slug"] for e in events] == ["help-review"]
    assert db.calls[0][2] == (SINCE,)
    sql = _sql(db.calls[0])
    assert "delivered_at" in sql
    assert "$1" in sql


def test_parse_since_accepts_iso8601_and_rejects_invalid():
    from api.grades import InvalidGradeSince, parse_since

    assert parse_since(None) is None
    assert parse_since("") is None
    parsed = parse_since("2026-09-14T12:00:00Z")
    assert parsed == SINCE
    with pytest.raises(InvalidGradeSince):
        parse_since("not-a-date")


def test_list_delivered_events_does_not_log_token_or_sourcedid(caplog):
    db = GradeEventsStubPool()
    db.add_row()

    with caplog.at_level(logging.INFO):
        events = _list(db)

    assert len(events) == 1
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert TOKEN not in text
    assert SOURCEDID not in text
    assert "sourcedid" not in text.lower()
    assert "token" not in text.lower()
    assert SESSION_ID in text or "1" in text
