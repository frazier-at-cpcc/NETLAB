import asyncio
import copy
import json
import logging
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest

from api.backfill import attempt_backfill, candidate_mboxes, best_statement
from api.lrs_client import LrsQueryError

DOMAINS = ["email.cpcc.edu", "lab.cpcc.edu", "email.edu.cpcc", "cpcc.email.edu", "cpcc.edu"]

CELL_ID = 42
SLUG = "rhel-storage-basics"
COURSE_SESSION_ID = "course-session-1"
USER_EMAIL = "augarte0@email.cpcc.edu"
USER_MBOX = f"mailto:{USER_EMAIL}"
SECOND_MBOX = "mailto:augarte0@lab.cpcc.edu"
BASE_URL = "https://lrs.example/xapi"
AUTH = "super-secret-lrs-read-credential"
CUTOFF = datetime(2026, 9, 1, tzinfo=timezone.utc)


class _AsyncCM:
    def __init__(self, value):
        self._value = value

    async def __aenter__(self):
        return self._value

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _statement(statement_id, *, scaled, raw, max_, stored, slug=SLUG, actor_mbox=None):
    return {
        "id": statement_id,
        "object": {
            "id": f"https://training.redhat.com/labs/{slug}",
            "definition": {"type": "http://adlnet.gov/expapi/activities/lesson"},
        },
        "result": {"score": {"scaled": scaled, "raw": raw, "max": max_}},
        "stored": stored,
        "actor": {"mbox": actor_mbox or USER_MBOX},
    }


class FakeLrsHttp:
    """Fake xAPI store client for fetch_statements. Keyed by exact mbox.

    `status_code` simulates the store's own HTTP answer, so a non-200
    passes through the real fetch_statements (never mocked out here) and
    exercises its actual failure-signalling behaviour (ITEM 2).
    """

    def __init__(self, statements_by_mbox=None, error=None, status_code=200):
        self.statements_by_mbox = statements_by_mbox or {}
        self.error = error
        self.status_code = status_code
        self.calls = []

    async def get(self, url, *, params=None, headers=None):
        self.calls.append({"url": url, "params": params, "headers": headers})
        if self.error is not None:
            raise self.error
        agent_json = (params or {}).get("agent", "{}")
        mbox = json.loads(agent_json).get("mbox")
        statements = self.statements_by_mbox.get(mbox, [])
        return SimpleNamespace(
            status_code=self.status_code, json=lambda: {"statements": list(statements)}
        )


class RaceConditionHttp(FakeLrsHttp):
    """Inserts a competing grade event into `db` during the first store
    call, simulating a token grade committing while attempt_backfill's
    slow LRS query is still in flight (ITEM 7c)."""

    def __init__(self, db, cell_id, statements_by_mbox=None, error=None, status_code=200):
        super().__init__(statements_by_mbox=statements_by_mbox, error=error, status_code=status_code)
        self._db = db
        self._cell_id = cell_id
        self._injected = False

    async def get(self, url, *, params=None, headers=None):
        if not self._injected:
            self._injected = True
            self._db.add_grade_event(self._cell_id, provenance="token")
        return await super().get(url, params=params, headers=headers)


class _TransactionCM:
    """ITEM 8: gives BackfillStubPool a real rollback.

    Snapshots cells, grade_events, deliveries and the event-id counter on
    enter; if the `async with` block exits with an exception, restores
    all four so the failed transaction leaves no trace, matching what a
    real `conn.transaction()` does. Without this, removing the
    `async with conn.transaction():` wrapper from attempt_backfill left
    every test passing, because the stub had nothing to roll back.
    """

    def __init__(self, pool):
        self._pool = pool
        self._snapshot = None

    async def __aenter__(self):
        self._snapshot = (
            copy.deepcopy(self._pool.cells),
            copy.deepcopy(self._pool.grade_events),
            copy.deepcopy(self._pool.deliveries),
            self._pool._next_event_id,
        )
        return self._pool

    async def __aexit__(self, exc_type, exc, tb):
        if exc_type is not None:
            cells, grade_events, deliveries, next_event_id = self._snapshot
            self._pool.cells = cells
            self._pool.grade_events = grade_events
            self._pool.deliveries = deliveries
            self._pool._next_event_id = next_event_id
        return False


class BackfillStubPool:
    """In-memory stand-in for asyncpg, in the shape DeliveryStubPool uses."""

    def __init__(self):
        self.calls = []
        self.cells = {}
        self.grade_events = []
        self.deliveries = []
        self._next_event_id = 1
        self.acquired = 0
        self.transactions = 0
        # ITEM 8 test hook: raise between the grade_events insert and the
        # grade_deliveries insert, to prove the transaction wrapper matters.
        self.fail_before_delivery_insert = False

    def add_cell(
        self,
        cell_id=CELL_ID,
        course_session_id=COURSE_SESSION_ID,
        lab_slug=SLUG,
        user_email=USER_EMAIL,
        backfill_attempted_at=None,
    ):
        self.cells[cell_id] = dict(
            id=cell_id,
            course_session_id=course_session_id,
            lab_slug=lab_slug,
            user_email=user_email,
            backfill_attempted_at=backfill_attempted_at,
        )
        return self.cells[cell_id]

    def add_grade_event(self, cell_id, **overrides):
        row = dict(id=self._next_event_id, cell_id=cell_id, idempotency_key=f"existing:{cell_id}")
        row.update(overrides)
        self._next_event_id += 1
        self.grade_events.append(row)
        return row

    def acquire(self):
        self.acquired += 1
        return _AsyncCM(self)

    def transaction(self):
        self.transactions += 1
        return _TransactionCM(self)

    async def fetchrow(self, sql, *args):
        self.calls.append(("fetchrow", sql, args))
        sql_n = " ".join(sql.split())
        if "FOR UPDATE" in sql_n and "SKIP LOCKED" in sql_n:
            row = self.cells.get(args[0])
            if row is None or row["backfill_attempted_at"] is not None:
                return None
            return dict(row)
        if "SELECT" in sql_n and "grade_events" in sql_n and "cell_id" in sql_n:
            for event in self.grade_events:
                if event["cell_id"] == args[0]:
                    return event
            return None
        raise AssertionError(f"unhandled fetchrow SQL: {sql_n}")

    async def fetchval(self, sql, *args):
        self.calls.append(("fetchval", sql, args))
        sql_n = " ".join(sql.split())
        if "INSERT INTO grade_events" in sql_n:
            event_id = self._next_event_id
            self._next_event_id += 1
            row = dict(
                id=event_id,
                cell_id=args[0],
                idempotency_key=args[1],
                slug=args[2],
                score_raw=args[3],
                score_max=args[4],
                occurred_at=args[5],
                payload=args[6],
                provenance="lrs_backfill" if "'lrs_backfill'" in sql_n else None,
            )
            self.grade_events.append(row)
            return event_id
        raise AssertionError(f"unhandled fetchval SQL: {sql_n}")

    async def execute(self, sql, *args):
        self.calls.append(("execute", sql, args))
        sql_n = " ".join(sql.split())
        if "INSERT INTO grade_deliveries" in sql_n:
            if self.fail_before_delivery_insert:
                raise RuntimeError("simulated failure between event insert and delivery insert")
            self.deliveries.append(dict(event_id=args[0], cell_id=args[1], state="PENDING"))
            return "INSERT 0 1"
        if "UPDATE grade_cells" in sql_n and "backfill_attempted_at" in sql_n:
            self.cells[args[0]]["backfill_attempted_at"] = args[1]
            return "UPDATE 1"
        raise AssertionError(f"unhandled execute SQL: {sql_n}")


def _sql(call):
    return " ".join(call[1].split())


def _config(**overrides):
    cfg = dict(enabled=True, domains=DOMAINS, cutoff=CUTOFF, base_url=BASE_URL, auth=AUTH)
    cfg.update(overrides)
    return cfg


def _attempt(db, http, cell_id=CELL_ID, config=None):
    return asyncio.run(attempt_backfill(db, http, cell_id, config=config or _config()))

def test_candidates_cover_every_configured_domain():
    got = candidate_mboxes("augarte0@email.cpcc.edu", DOMAINS)
    assert "mailto:augarte0@email.cpcc.edu" in got
    assert "mailto:augarte0@lab.cpcc.edu" in got
    assert "mailto:augarte0@email.edu.cpcc" in got
    assert len(got) == len(set(got))

def test_an_unlisted_domain_is_never_substituted():
    got = candidate_mboxes("student@lancers.lenoircc.edu", DOMAINS)
    assert got == ["mailto:student@lancers.lenoircc.edu"]

def test_an_empty_or_malformed_address_yields_nothing():
    assert candidate_mboxes("", DOMAINS) == []
    assert candidate_mboxes("notanemail", DOMAINS) == []

def test_best_statement_picks_the_highest_scaled_score():
    low = {"id": "a", "result": {"score": {"scaled": 0.4}}}
    high = {"id": "b", "result": {"score": {"scaled": 0.9}}}
    assert best_statement([low, high])["id"] == "b"

def test_best_statement_of_nothing_is_none():
    assert best_statement([]) is None


def test_disabled_configuration_returns_disabled_and_queries_nothing():
    db = BackfillStubPool()
    db.add_cell()
    http = FakeLrsHttp()

    result = _attempt(db, http, config=_config(enabled=False))

    assert result == "disabled"
    assert db.calls == []
    assert db.acquired == 0
    assert http.calls == []


def test_already_attempted_cell_returns_already_attempted_without_a_query():
    db = BackfillStubPool()
    db.add_cell(backfill_attempted_at=datetime(2026, 9, 10, tzinfo=timezone.utc))
    http = FakeLrsHttp()

    result = _attempt(db, http)

    assert result == "already_attempted"
    assert http.calls == []
    assert not any(call[0] == "execute" for call in db.calls)


def test_cell_with_existing_grade_event_returns_has_grades_and_marks_the_attempt():
    db = BackfillStubPool()
    db.add_cell()
    db.add_grade_event(CELL_ID)
    http = FakeLrsHttp()

    result = _attempt(db, http)

    assert result == "has_grades"
    assert http.calls == []
    assert db.cells[CELL_ID]["backfill_attempted_at"] is not None
    assert db.deliveries == []


def test_session_with_no_matchable_email_returns_no_email_and_marks_the_attempt():
    db = BackfillStubPool()
    db.add_cell(user_email="")
    http = FakeLrsHttp()

    result = _attempt(db, http)

    assert result == "no_email"
    assert http.calls == []
    assert db.cells[CELL_ID]["backfill_attempted_at"] is not None


def test_store_returning_nothing_returns_no_history_and_marks_the_attempt():
    db = BackfillStubPool()
    db.add_cell()
    http = FakeLrsHttp(statements_by_mbox={})

    result = _attempt(db, http)

    assert result == "no_history"
    assert db.cells[CELL_ID]["backfill_attempted_at"] is not None
    assert db.grade_events == []
    assert db.deliveries == []
    # every configured candidate was queried, not just the exact address
    assert len(http.calls) == len(candidate_mboxes(USER_EMAIL, DOMAINS))
    for call in http.calls:
        assert call["params"]["activity"] == f"https://training.redhat.com/labs/{SLUG}"
        assert "Authorization" not in (call["params"] or {})


def test_two_statements_under_two_domains_pool_and_deliver_the_higher_one():
    db = BackfillStubPool()
    db.add_cell()
    low = _statement("stmt-low", scaled=0.4, raw=4, max_=10, stored="2026-08-01T00:00:00Z")
    high = _statement(
        "stmt-high", scaled=0.9, raw=9, max_=10, stored="2026-08-15T00:00:00Z", actor_mbox=SECOND_MBOX
    )
    http = FakeLrsHttp(statements_by_mbox={USER_MBOX: [low], SECOND_MBOX: [high]})

    before = datetime.now(timezone.utc)
    result = _attempt(db, http)
    after = datetime.now(timezone.utc)

    assert result == "delivered"
    assert len(db.grade_events) == 1
    event = db.grade_events[0]
    assert event["provenance"] == "lrs_backfill"
    assert event["score_raw"] == Decimal("9")
    assert event["score_max"] == Decimal("10")
    assert event["idempotency_key"] == f"backfill:{CELL_ID}:stmt-high"
    assert json.loads(event["payload"])["id"] == "stmt-high"

    insert_event_calls = [c for c in db.calls if c[0] == "fetchval" and "INSERT INTO grade_events" in _sql(c)]
    assert len(insert_event_calls) == 1
    assert "'lrs_backfill'" in _sql(insert_event_calls[0])

    assert len(db.deliveries) == 1
    assert db.deliveries[0]["event_id"] == event["id"]
    assert db.deliveries[0]["cell_id"] == CELL_ID
    assert db.deliveries[0]["state"] == "PENDING"

    marked_at = db.cells[CELL_ID]["backfill_attempted_at"]
    assert before <= marked_at <= after


def test_idempotency_key_is_deterministic_for_the_same_cell_and_statement():
    statement = _statement("stmt-fixed", scaled=0.7, raw=7, max_=10, stored="2026-08-20T00:00:00Z")

    db1 = BackfillStubPool()
    db1.add_cell()
    _attempt(db1, FakeLrsHttp(statements_by_mbox={USER_MBOX: [statement]}))

    db2 = BackfillStubPool()
    db2.add_cell()
    _attempt(db2, FakeLrsHttp(statements_by_mbox={USER_MBOX: [statement]}))

    key1 = db1.grade_events[0]["idempotency_key"]
    key2 = db2.grade_events[0]["idempotency_key"]
    assert key1 == key2 == f"backfill:{CELL_ID}:stmt-fixed"


def test_statement_stored_after_the_cutoff_is_no_history_not_delivered():
    db = BackfillStubPool()
    db.add_cell()
    # Otherwise a perfect, matching statement -- excluded only because the
    # store accepted it after the configured cutover. This is the security
    # control from spec section 4: a client-controlled timestamp cannot
    # forge its way past a store-assigned `stored` value.
    forged_or_late = _statement("stmt-late", scaled=1.0, raw=10, max_=10, stored="2026-09-10T00:00:00Z")
    http = FakeLrsHttp(statements_by_mbox={USER_MBOX: [forged_or_late]})

    result = _attempt(db, http, config=_config(cutoff=CUTOFF))

    assert result == "no_history"
    assert db.grade_events == []
    assert db.deliveries == []


def test_credential_and_address_never_appear_in_logs(caplog):
    db = BackfillStubPool()
    db.add_cell()
    statement = _statement("stmt-log", scaled=0.5, raw=5, max_=10, stored="2026-08-20T00:00:00Z")
    http = FakeLrsHttp(statements_by_mbox={USER_MBOX: [statement]})

    with caplog.at_level(logging.INFO):
        result = _attempt(db, http)

    assert result == "delivered"
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert AUTH not in text
    assert USER_EMAIL not in text
    assert str(CELL_ID) in text
    assert SLUG in text


def test_transient_store_error_leaves_the_attempt_open_for_a_later_launch(caplog):
    db = BackfillStubPool()
    db.add_cell()
    http = FakeLrsHttp(error=httpx.ConnectError("connection refused"))

    with caplog.at_level(logging.WARNING):
        with pytest.raises(httpx.ConnectError):
            _attempt(db, http)

    # The cell was claimed but not consumed: no mark, no partial write.
    assert db.cells[CELL_ID]["backfill_attempted_at"] is None
    assert db.grade_events == []
    assert db.deliveries == []
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert AUTH not in text
    assert USER_EMAIL not in text

    # A later launch (a fresh call, same still-unmarked cell) can retry and succeed.
    statement = _statement("stmt-retry", scaled=0.6, raw=6, max_=10, stored="2026-08-20T00:00:00Z")
    http_retry = FakeLrsHttp(statements_by_mbox={USER_MBOX: [statement]})

    result = _attempt(db, http_retry)

    assert result == "delivered"
    assert db.cells[CELL_ID]["backfill_attempted_at"] is not None


# --- ITEM 2: a non-200 must be treated like a network error, not like ---
# --- "no history" -------------------------------------------------------


def test_a_non_200_from_the_store_leaves_the_attempt_open_for_a_later_launch(caplog):
    """Before the fix, fetch_statements swallowed any non-200 into
    {"statements": []}, so a revoked or rotated read credential produced
    a clean log full of `no_history` for an entire cohort and
    permanently consumed every cell's one attempt. This proves a 401
    is now treated exactly like the network-error case above: the cell
    stays unmarked and the exception propagates loudly."""
    db = BackfillStubPool()
    db.add_cell()
    http = FakeLrsHttp(status_code=401)

    with caplog.at_level(logging.WARNING):
        with pytest.raises(LrsQueryError):
            _attempt(db, http)

    assert db.cells[CELL_ID]["backfill_attempted_at"] is None
    assert db.grade_events == []
    assert db.deliveries == []
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert AUTH not in text
    assert "401" in text


# --- ITEM 1 / ITEM 5: end-to-end -- a malformed score never reaches -----
# --- the gradebook, and never crashes the worker either ------------------


def test_a_scaled_only_statement_is_never_delivered_as_a_zero_grade():
    """The dangerous case named in the review: a legitimate xAPI 1.0.3
    statement carrying only the required `scaled` field. Before the
    fix, Decimal(str(score.get("raw", 0))) would have delivered a
    literal zero for a student who may have scored full marks."""
    db = BackfillStubPool()
    db.add_cell()
    scaled_only = {
        "id": "stmt-scaled-only",
        "object": {
            "id": f"https://training.redhat.com/labs/{SLUG}",
            "definition": {"type": "http://adlnet.gov/expapi/activities/lesson"},
        },
        "result": {"score": {"scaled": 1.0}},
        "stored": "2026-08-20T00:00:00Z",
        "actor": {"mbox": USER_MBOX},
    }
    http = FakeLrsHttp(statements_by_mbox={USER_MBOX: [scaled_only]})

    result = _attempt(db, http)

    assert result == "no_history"
    assert db.grade_events == []
    assert db.deliveries == []


def test_a_null_max_drops_the_statement_instead_of_raising_decimal_invalid_operation():
    """The exact malformed shape from the review:
    {"scaled": 1.0, "raw": 5, "max": None}. Before the fix this reached
    Decimal(str(None)), raised decimal.InvalidOperation inside the
    generic exception handler, and retried identically on every future
    launch forever. It must instead be dropped like any other malformed
    record and resolve to no_history."""
    db = BackfillStubPool()
    db.add_cell()
    null_max = {
        "id": "stmt-null-max",
        "object": {
            "id": f"https://training.redhat.com/labs/{SLUG}",
            "definition": {"type": "http://adlnet.gov/expapi/activities/lesson"},
        },
        "result": {"score": {"scaled": 1.0, "raw": 5, "max": None}},
        "stored": "2026-08-20T00:00:00Z",
        "actor": {"mbox": USER_MBOX},
    }
    http = FakeLrsHttp(statements_by_mbox={USER_MBOX: [null_max]})

    result = _attempt(db, http)

    assert result == "no_history"
    assert db.grade_events == []
    assert db.deliveries == []


# --- ITEM 4: the institution boundary is enforced in code, not just -----
# --- trusted to the store's `agent` filter -------------------------------


def test_a_statement_whose_actor_does_not_match_the_queried_mbox_is_dropped():
    """Simulates a store, endpoint, or proxy that stops honouring the
    `agent` query filter: the response to a query for USER_MBOX comes
    back carrying a statement that actually belongs to a student at a
    different institution sharing this store. Without checking the
    actor, this would be pooled and delivered as the winning score --
    handing one college's student the other's grade."""
    db = BackfillStubPool()
    db.add_cell()
    wrong_actor = _statement(
        "stmt-wrong-actor",
        scaled=1.0,
        raw=10,
        max_=10,
        stored="2026-08-20T00:00:00Z",
        actor_mbox="mailto:other-student@lancers.lenoircc.edu",
    )
    http = FakeLrsHttp(statements_by_mbox={USER_MBOX: [wrong_actor]})

    result = _attempt(db, http)

    assert result == "no_history"
    assert db.grade_events == []
    assert db.deliveries == []


def test_pooling_ignores_a_higher_score_belonging_to_a_different_actor():
    """A mismatched-actor statement scores higher than the legitimate
    one under the same candidate mbox. The legitimate, lower score must
    still win, because the higher one is not this student's."""
    db = BackfillStubPool()
    db.add_cell()
    legitimate = _statement(
        "stmt-mine", scaled=0.5, raw=5, max_=10, stored="2026-08-20T00:00:00Z"
    )
    someone_elses = _statement(
        "stmt-not-mine",
        scaled=1.0,
        raw=10,
        max_=10,
        stored="2026-08-21T00:00:00Z",
        actor_mbox="mailto:other-student@lancers.lenoircc.edu",
    )
    http = FakeLrsHttp(statements_by_mbox={USER_MBOX: [legitimate, someone_elses]})

    result = _attempt(db, http)

    assert result == "delivered"
    assert len(db.grade_events) == 1
    assert db.grade_events[0]["idempotency_key"] == f"backfill:{CELL_ID}:stmt-mine"


# --- ITEM 6: the store-side `until` bound is passed on every query ------


def test_until_param_matches_the_configured_cutoff_on_every_candidate_query():
    db = BackfillStubPool()
    db.add_cell()
    http = FakeLrsHttp(statements_by_mbox={})

    _attempt(db, http)

    assert http.calls  # every configured candidate was queried
    for call in http.calls:
        assert call["params"]["until"] == CUTOFF.isoformat()


# --- ITEM 7a: domain matching in candidate_mboxes is case-insensitive ---


def test_domain_matching_in_candidate_mboxes_is_case_insensitive():
    got = candidate_mboxes("Student@EMAIL.CPCC.EDU", DOMAINS)
    # The launch address itself is always kept, in its original casing.
    assert "mailto:Student@EMAIL.CPCC.EDU" in got
    # Substitution still happens across every OTHER configured domain, in
    # the domain's own configured casing, even though the input domain
    # was uppercase and did not literally match any entry in DOMAINS.
    # Before the fix, an uppercase domain matched nothing and this
    # candidate set was just the one address above.
    assert "mailto:Student@lab.cpcc.edu" in got
    assert "mailto:Student@email.edu.cpcc" in got
    assert "mailto:Student@cpcc.email.edu" in got
    assert "mailto:Student@cpcc.edu" in got


# --- ITEM 7c: the existing-grade-event guard is re-run right before -----
# --- the insert, closing the race with a slow store query ----------------


def test_a_token_grade_committed_during_the_store_query_wins_the_race():
    """A token grade can commit between the first has_grades check (run
    before any store query) and the insert. Spec section 3's guard --
    a student already graded through the token channel is never
    overwritten by history -- must hold even when the race lands in
    that window, not just at the start of the attempt."""
    db = BackfillStubPool()
    db.add_cell()
    statement = _statement("stmt-race", scaled=0.9, raw=9, max_=10, stored="2026-08-20T00:00:00Z")
    http = RaceConditionHttp(db, CELL_ID, statements_by_mbox={USER_MBOX: [statement]})

    result = _attempt(db, http)

    assert result == "has_grades"
    assert len(db.grade_events) == 1
    assert db.grade_events[0]["provenance"] == "token"
    assert db.deliveries == []
    assert db.cells[CELL_ID]["backfill_attempted_at"] is not None


# --- ITEM 8: the stub's transaction() must actually roll back -----------


def test_a_failure_between_the_two_inserts_leaves_nothing_persisted():
    """Proves the atomicity the design depends on: a failure between the
    grade_events insert and the grade_deliveries insert must leave no
    committed event, no delivery, and no attempted-mark behind. Without
    a real rollback in the stub, the grade_events insert -- which
    mutates db.grade_events immediately, with no buffering -- would
    survive the exception and this test would catch a design defect
    that removing `async with conn.transaction():` from production code
    would otherwise pass unnoticed."""
    db = BackfillStubPool()
    db.add_cell()
    db.fail_before_delivery_insert = True
    statement = _statement("stmt-atomic", scaled=0.8, raw=8, max_=10, stored="2026-08-20T00:00:00Z")
    http = FakeLrsHttp(statements_by_mbox={USER_MBOX: [statement]})

    with pytest.raises(RuntimeError):
        _attempt(db, http)

    assert db.grade_events == []
    assert db.deliveries == []
    assert db.cells[CELL_ID]["backfill_attempted_at"] is None
