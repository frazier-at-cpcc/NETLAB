import asyncio
import logging
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from api.tokens import hash_grade_token

TOKEN = "grade-token-plaintext-secret"
SOURCEDID = "secret-sourcedid-value"
SESSION_ID = "sess-1"
CELL_ID = 7
IDEMPOTENCY_KEY = "idem-key-1"


class UniqueViolationError(Exception):
    sqlstate = "23505"


class _AsyncCM:
    def __init__(self, value):
        self._value = value

    async def __aenter__(self):
        return self._value

    async def __aexit__(self, exc_type, exc, tb):
        return False


class GradeStubPool:
    """In-memory stand-in for asyncpg. Records SQL and grade rows."""

    def __init__(self):
        self.calls = []
        self.sessions = {}
        self.cells = {}
        self.events = []
        self.events_by_key = {}
        self.deliveries = []
        self.acquired = 0
        self.transactions = 0
        self._next_event_id = 1
        self._next_delivery_id = 1

    def acquire(self):
        self.acquired += 1
        return _AsyncCM(self)

    def transaction(self):
        self.transactions += 1
        return _AsyncCM(self)

    def add_session(self, session_id, token, status="running"):
        self.sessions[hash_grade_token(token)] = {
            "session_id": session_id,
            "status": status,
        }

    def add_cell(self, session_id, slug, cell_id=CELL_ID, sourcedid=SOURCEDID):
        self.cells[(session_id, slug)] = {
            "id": cell_id,
            "sourcedid": sourcedid,
        }
        return cell_id

    async def fetchval(self, sql, *args):
        self.calls.append(("fetchval", sql, args))
        return self._dispatch(sql, args, returning=True)

    async def execute(self, sql, *args):
        self.calls.append(("execute", sql, args))
        self._dispatch(sql, args, returning=False)
        return "OK"

    def _dispatch(self, sql, args, returning):
        sql_n = " ".join(sql.split())
        if "FROM vm_sessions" in sql_n and "grade_token_hash" in sql_n:
            row = self.sessions.get(args[0])
            if row is None:
                return None
            if row["status"] not in ("starting", "running"):
                return None
            return row["session_id"]
        if "FROM grade_cells" in sql_n:
            cell = self.cells.get((args[0], args[1]))
            return None if cell is None else cell["id"]
        if "INSERT INTO grade_events" in sql_n:
            key = args[1]
            if key in self.events_by_key:
                raise UniqueViolationError()
            event = {
                "id": self._next_event_id,
                "cell_id": args[0],
                "idempotency_key": args[1],
                "slug": args[2],
                "score_raw": args[3],
                "score_max": args[4],
                "occurred_at": args[5],
                "payload": args[6],
            }
            self._next_event_id += 1
            self.events.append(event)
            self.events_by_key[key] = event
            return event["id"]
        if "FROM grade_events" in sql_n and "idempotency_key" in sql_n:
            event = self.events_by_key.get(args[0])
            return None if event is None else event["id"]
        if "UPDATE grade_deliveries" in sql_n and "SUPERSEDED" in sql_n:
            cell_id = args[0]
            for delivery in self.deliveries:
                if delivery["cell_id"] == cell_id and delivery["state"] in (
                    "PENDING",
                    "RETRYING",
                ):
                    delivery["state"] = "SUPERSEDED"
            return "UPDATE"
        if "INSERT INTO grade_deliveries" in sql_n:
            delivery = {
                "id": self._next_delivery_id,
                "event_id": args[0],
                "cell_id": args[1],
                "state": "PENDING",
            }
            self._next_delivery_id += 1
            self.deliveries.append(delivery)
            return delivery["id"]
        raise AssertionError(f"unhandled SQL: {sql_n}")


def _sql(call):
    return " ".join(call[1].split())


def _request(**overrides):
    from api.grades import GradeRequest, ScoreBody, TaskBody

    data = dict(
        slug="cli-review",
        occurred_at=datetime(2026, 9, 14, 22, 0, 0, tzinfo=timezone.utc),
        score=ScoreBody(
            raw=Decimal("8"),
            max=Decimal("10"),
            scaled=Decimal("0.8"),
        ),
        passed=False,
        tasks=[TaskBody(label="Verify Music directory exists", passed=True)],
    )
    data.update(overrides)
    return GradeRequest(**data)


def _seeded_db():
    db = GradeStubPool()
    db.add_session(SESSION_ID, TOKEN, status="running")
    db.add_cell(SESSION_ID, "cli-review")
    return db


def _accept(db, token=TOKEN, idempotency_key=IDEMPOTENCY_KEY, request=None):
    from api.grades import accept_grade

    if request is None:
        request = _request()
    return asyncio.run(
        accept_grade(
            db,
            token=token,
            idempotency_key=idempotency_key,
            request=request,
        )
    )


def test_unknown_token_returns_no_session():
    db = GradeStubPool()

    result = _accept(db, token="unknown-token")

    assert result.status == "no_session"
    assert result.event_id is None
    assert db.events == []
    assert db.deliveries == []
    assert "SELECT session_id FROM vm_sessions" in _sql(db.calls[0])
    assert "grade_token_hash" in _sql(db.calls[0])
    assert "status IN ('starting', 'running')" in _sql(db.calls[0])
    assert db.calls[0][2][0] == hash_grade_token("unknown-token")
    assert "unknown-token" not in db.calls[0][2]


def test_known_token_slug_without_cell_returns_no_handle():
    db = _seeded_db()
    request = _request(slug="cli-desktop")

    result = _accept(db, request=request)

    assert result.status == "no_handle"
    assert result.event_id is None
    assert db.events == []
    assert db.deliveries == []
    cell_lookups = [c for c in db.calls if "FROM grade_cells" in _sql(c)]
    assert len(cell_lookups) == 1
    assert cell_lookups[0][2] == (SESSION_ID, "cli-desktop")


def test_first_post_accepted_inserts_event_and_pending_delivery():
    db = _seeded_db()

    result = _accept(db)

    assert result.status == "accepted"
    assert result.event_id == 1
    assert len(db.events) == 1
    assert len(db.deliveries) == 1
    event = db.events[0]
    assert event["cell_id"] == CELL_ID
    assert event["idempotency_key"] == IDEMPOTENCY_KEY
    assert event["slug"] == "cli-review"
    assert event["score_raw"] == Decimal("8")
    assert event["score_max"] == Decimal("10")
    assert db.deliveries[0]["event_id"] == 1
    assert db.deliveries[0]["cell_id"] == CELL_ID
    assert db.deliveries[0]["state"] == "PENDING"
    sqls = [_sql(c) for c in db.calls]
    assert any("INSERT INTO grade_events" in s for s in sqls)
    assert any("INSERT INTO grade_deliveries" in s for s in sqls)
    assert any(
        "UPDATE grade_deliveries" in s
        and "SUPERSEDED" in s
        and "PENDING" in s
        and "RETRYING" in s
        for s in sqls
    )
    session_lookup = db.calls[0]
    assert session_lookup[2][0] == hash_grade_token(TOKEN)
    assert TOKEN not in session_lookup[2]
    event_inserts = [c for c in db.calls if "INSERT INTO grade_events" in _sql(c)]
    assert len(event_inserts) == 1
    payload_arg = event_inserts[0][2][6]
    assert isinstance(payload_arg, str)
    assert db.acquired >= 1
    assert db.transactions >= 1


def test_same_idempotency_key_returns_duplicate_one_event():
    db = _seeded_db()
    first = _accept(db)
    second = _accept(db)

    assert first.status == "accepted"
    assert second.status == "duplicate"
    assert second.event_id == first.event_id
    assert len(db.events) == 1
    assert len(db.deliveries) == 1
    assert db.deliveries[0]["state"] == "PENDING"


def test_new_idempotency_key_supersedes_pending_delivery():
    db = _seeded_db()
    from api.grades import ScoreBody

    first = _accept(db, idempotency_key="key-a")
    second = _accept(
        db,
        idempotency_key="key-b",
        request=_request(
            score=ScoreBody(
                raw=Decimal("10"),
                max=Decimal("10"),
                scaled=Decimal("1.0"),
            ),
            passed=True,
        ),
    )

    assert first.status == "accepted"
    assert second.status == "accepted"
    assert second.event_id != first.event_id
    assert len(db.events) == 2
    assert db.events[1]["score_raw"] == Decimal("10")
    assert len(db.deliveries) == 2
    assert db.deliveries[0]["state"] == "SUPERSEDED"
    assert db.deliveries[0]["event_id"] == first.event_id
    assert db.deliveries[1]["state"] == "PENDING"
    assert db.deliveries[1]["event_id"] == second.event_id
    supersede = [
        c
        for c in db.calls
        if "UPDATE grade_deliveries" in _sql(c) and "SUPERSEDED" in _sql(c)
    ]
    assert supersede[-1][2] == (CELL_ID,)


def test_score_max_non_positive_rejects_before_insert():
    from api.grades import InvalidGradeScore, ScoreBody

    db = _seeded_db()
    request = _request(
        score=ScoreBody(
            raw=Decimal("0"),
            max=Decimal("0"),
            scaled=Decimal("0"),
        )
    )

    with pytest.raises(InvalidGradeScore):
        _accept(db, request=request)

    assert db.events == []
    assert db.deliveries == []
    assert not any("INSERT INTO grade_events" in _sql(c) for c in db.calls)


def test_missing_bearer_maps_to_401():
    from api.grades import extract_bearer_token, map_grade_http, GradeAcceptResult

    assert extract_bearer_token(None) is None
    assert extract_bearer_token("") is None
    assert extract_bearer_token("Basic abc") is None
    assert extract_bearer_token("Bearer ") is None
    assert extract_bearer_token(f"Bearer {TOKEN}") == TOKEN

    status, body = map_grade_http(GradeAcceptResult(status="no_session", event_id=None))
    assert status == 401
    assert body is None


def test_http_status_mapping():
    from api.grades import GradeAcceptResult, map_grade_http

    status, body = map_grade_http(GradeAcceptResult(status="no_handle", event_id=None))
    assert status == 404
    assert body == {"error": "no_handle"}

    status, body = map_grade_http(GradeAcceptResult(status="accepted", event_id=3))
    assert status == 202
    assert body["status"] == "accepted"
    assert body["event_id"] == 3

    status, body = map_grade_http(GradeAcceptResult(status="duplicate", event_id=3))
    assert status == 202
    assert body["status"] == "duplicate"


def test_accept_logs_session_and_slug_not_token_or_sourcedid(caplog):
    db = _seeded_db()

    with caplog.at_level(logging.INFO):
        result = _accept(db)

    assert result.status == "accepted"
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert SESSION_ID in text
    assert "cli-review" in text
    assert TOKEN not in text
    assert SOURCEDID not in text
    assert "sourcedid" not in text.lower()
