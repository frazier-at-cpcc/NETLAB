import asyncio
import logging
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace

SOURCEDID = "secret-sourcedid-value"
OUTCOME_URL = "https://lms.example/d2l/le/lti/Outcome"
CONSUMER_KEY = "cpcc-brightspace"
CONSUMER_SECRET = "brightspace-secret"
SECRETS = {CONSUMER_KEY: CONSUMER_SECRET}
NOW = datetime(2026, 9, 14, 22, 0, 0, tzinfo=timezone.utc)
DELIVERY_ID = 1
CELL_ID = 7
SUCCESS_ENVELOPE = (
    '<imsx_POXEnvelopeResponse xmlns="http://www.imsglobal.org/services/'
    'ltiv1p1/xsd/imsoms_v1p0"><imsx_POXHeader><imsx_POXResponseHeaderInfo>'
    "<imsx_statusInfo><imsx_codeMajor>success</imsx_codeMajor>"
    "</imsx_statusInfo></imsx_POXResponseHeaderInfo></imsx_POXHeader>"
    "</imsx_POXEnvelopeResponse>"
)


class _AsyncCM:
    def __init__(self, value):
        self._value = value

    async def __aenter__(self):
        return self._value

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FrozenRNG:
    def __init__(self, value=1.5):
        self.value = value
        self.calls = []

    def uniform(self, low, high):
        self.calls.append((low, high))
        return self.value


class FakeHttp:
    def __init__(self, status_code=200, text=SUCCESS_ENVELOPE):
        self.status_code = status_code
        self.text = text
        self.calls = []

    async def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return SimpleNamespace(status_code=self.status_code, text=self.text)


class DeliveryStubPool:
    """In-memory stand-in for asyncpg. Records SQL and due rows."""

    def __init__(self):
        self.calls = []
        self.deliveries = []
        self.due = []
        self.acquired = 0
        self.transactions = 0

    def acquire(self):
        self.acquired += 1
        return _AsyncCM(self)

    def transaction(self):
        self.transactions += 1
        return _AsyncCM(self)

    def add_due(self, **overrides):
        row = dict(
            id=DELIVERY_ID,
            event_id=1,
            cell_id=CELL_ID,
            attempts=0,
            state="PENDING",
            score_raw=Decimal("8"),
            score_max=Decimal("10"),
            sourcedid=SOURCEDID,
            outcome_service_url=OUTCOME_URL,
            consumer_key=CONSUMER_KEY,
            next_attempt_at=NOW,
            last_error=None,
            delivered_at=None,
        )
        row.update(overrides)
        self.deliveries.append(row)
        self.due.append(row)
        return row

    def _by_id(self, delivery_id):
        for row in self.deliveries:
            if row["id"] == delivery_id:
                return row
        raise AssertionError(f"unknown delivery id {delivery_id}")

    async def fetchrow(self, sql, *args):
        self.calls.append(("fetchrow", sql, args))
        sql_n = " ".join(sql.split())
        if "FOR UPDATE" in sql_n and "SKIP LOCKED" in sql_n:
            if not self.due:
                return None
            return self.due.pop(0)
        raise AssertionError(f"unhandled fetchrow SQL: {sql_n}")

    async def execute(self, sql, *args):
        self.calls.append(("execute", sql, args))
        sql_n = " ".join(sql.split())
        if "UPDATE grade_deliveries" not in sql_n:
            raise AssertionError(f"unhandled execute SQL: {sql_n}")
        delivery = self._by_id(args[0])
        delivery["attempts"] = args[1]
        if "DELIVERED" in sql_n:
            delivery["state"] = "DELIVERED"
            delivery["delivered_at"] = args[2]
            delivery["last_error"] = None
        elif "RETRYING" in sql_n:
            delivery["state"] = "RETRYING"
            delivery["next_attempt_at"] = args[2]
            delivery["last_error"] = args[3]
        elif "DEAD_LETTER" in sql_n:
            delivery["state"] = "DEAD_LETTER"
            delivery["last_error"] = args[2]
        else:
            raise AssertionError(f"unhandled update SQL: {sql_n}")
        return "UPDATE 1"


def _sql(call):
    return " ".join(call[1].split())


def _deliver(db, http, secrets=SECRETS, now=NOW, rng=None):
    from api.pox_delivery import deliver_due

    kwargs = {}
    if rng is not None:
        kwargs["rng"] = rng
    return asyncio.run(deliver_due(db, http, secrets, now, **kwargs))


def test_build_replace_result_contains_sourcedid_and_scaled_score():
    from api.pox_delivery import build_replace_result, scale_score

    score = scale_score(Decimal("8"), Decimal("10"))
    xml = build_replace_result(SOURCEDID, score)

    assert SOURCEDID in xml
    assert "0.8" in xml
    assert "replaceResultRequest" in xml
    assert "http://www.imsglobal.org/services/ltiv1p1/xsd/imsoms_v1p0" in xml
    assert score == Decimal("0.8000")


def test_http_200_marks_delivered():
    db = DeliveryStubPool()
    db.add_due()
    http = FakeHttp(200)

    _deliver(db, http)

    assert db.deliveries[0]["state"] == "DELIVERED"
    assert db.deliveries[0]["delivered_at"] == NOW
    assert db.deliveries[0]["attempts"] == 1
    assert len(http.calls) == 1
    assert http.calls[0]["url"] == OUTCOME_URL
    body = http.calls[0].get("content") or http.calls[0].get("data") or ""
    assert SOURCEDID in body
    assert "0.8" in body
    headers = http.calls[0]["headers"]
    assert "oauth_signature" in headers.get("Authorization", "")
    assert headers.get("Content-Type") == "application/xml"
    sqls = [_sql(c) for c in db.calls]
    assert any("FOR UPDATE" in s and "SKIP LOCKED" in s for s in sqls)
    assert any("DELIVERED" in s for s in sqls)
    assert db.acquired >= 1
    assert db.transactions >= 1


def test_http_500_marks_retrying_with_backoff_and_jitter():
    db = DeliveryStubPool()
    db.add_due()
    http = FakeHttp(500)
    rng = FrozenRNG(1.5)

    _deliver(db, http, rng=rng)

    delivery = db.deliveries[0]
    assert delivery["state"] == "RETRYING"
    assert delivery["attempts"] == 1
    assert rng.calls == [(0, 5)]
    assert delivery["next_attempt_at"] == NOW + timedelta(seconds=61.5)
    assert delivery["next_attempt_at"] > NOW
    assert delivery["last_error"]
    assert SOURCEDID not in str(delivery["last_error"])
    sqls = [_sql(c) for c in db.calls]
    assert any("RETRYING" in s for s in sqls)


def test_http_400_marks_dead_letter():
    db = DeliveryStubPool()
    db.add_due()
    http = FakeHttp(400)

    _deliver(db, http)

    delivery = db.deliveries[0]
    assert delivery["state"] == "DEAD_LETTER"
    assert delivery["attempts"] == 1
    assert delivery["last_error"]
    assert SOURCEDID not in str(delivery["last_error"])
    sqls = [_sql(c) for c in db.calls]
    assert any("DEAD_LETTER" in s for s in sqls)
    assert len(http.calls) == 1


def test_claim_miss_is_noop():
    db = DeliveryStubPool()
    http = FakeHttp(200)

    _deliver(db, http)

    assert http.calls == []
    assert db.deliveries == []
    claim_calls = [
        c for c in db.calls if "FOR UPDATE" in _sql(c) and "SKIP LOCKED" in _sql(c)
    ]
    assert len(claim_calls) == 1
    assert claim_calls[0][0] == "fetchrow"
    assert claim_calls[0][2] == (NOW,)
    assert not any(c[0] == "execute" for c in db.calls)


def test_missing_secret_marks_dead_letter_without_http():
    db = DeliveryStubPool()
    db.add_due()
    http = FakeHttp(200)

    _deliver(db, http, secrets={})

    delivery = db.deliveries[0]
    assert delivery["state"] == "DEAD_LETTER"
    assert http.calls == []
    assert SOURCEDID not in str(delivery["last_error"])


def test_deliver_logs_ids_not_sourcedid_or_oauth_header(caplog):
    db = DeliveryStubPool()
    db.add_due()
    http = FakeHttp(200)

    with caplog.at_level(logging.INFO):
        _deliver(db, http)

    text = "\n".join(r.getMessage() for r in caplog.records)
    assert str(DELIVERY_ID) in text
    assert SOURCEDID not in text
    assert "sourcedid" not in text.lower()
    auth = http.calls[0]["headers"].get("Authorization", "")
    assert auth
    assert auth not in text
    assert "oauth_signature" not in text
    assert CONSUMER_SECRET not in text


def test_request_carries_a_header_and_a_text_string():
    from api.pox_delivery import build_replace_result

    body = build_replace_result("abc123", Decimal("0.8000"))

    assert "imsx_POXHeader" in body
    assert "<imsx_version>V1.0</imsx_version>" in body
    assert "<textString>0.8000</textString>" in body
    assert "<text>" not in body


def test_pox_status_reads_the_code_major():
    from api.pox_delivery import pox_status

    ok = (
        '<imsx_POXEnvelopeResponse xmlns="http://www.imsglobal.org/services/'
        'ltiv1p1/xsd/imsoms_v1p0"><imsx_POXHeader><imsx_POXResponseHeaderInfo>'
        "<imsx_statusInfo><imsx_codeMajor>success</imsx_codeMajor>"
        "</imsx_statusInfo></imsx_POXResponseHeaderInfo></imsx_POXHeader>"
        "</imsx_POXEnvelopeResponse>"
    )

    assert pox_status(ok) == "success"
    assert pox_status(ok.replace("success", "failure")) == "failure"
    assert pox_status("") == "malformed"
