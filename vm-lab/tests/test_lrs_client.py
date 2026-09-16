"""Tests for the read-only Learning Record Store client.

The store is fed by student machines that hold the write credential, so
`stored` is the only timestamp a statement cannot forge. `timestamp` is
client-supplied and must never substitute for it. These tests exist to
prove the boundary stays exclusive and that malformed records are
dropped rather than raised.
"""

import asyncio
import logging
from datetime import datetime, timezone

import pytest

from api.lrs_client import LrsQueryError, fetch_statements, graded_lesson_statements, parse_stored

CUTOFF = datetime(2026, 9, 15, tzinfo=timezone.utc)


def _stmt(
    slug="cli-review",
    scaled=1.0,
    stored="2026-09-14T02:25:07.229000000Z",
    otype="http://adlnet.gov/expapi/activities/lesson",
    score=True,
):
    s = {
        "id": "11111111-1111-1111-1111-111111111111",
        "stored": stored,
        "actor": {"mbox": "mailto:a@email.cpcc.edu"},
        "verb": {"id": "http://adlnet.gov/expapi/verbs/passed"},
        "object": {
            "id": f"https://training.redhat.com/labs/{slug}",
            "definition": {"type": otype},
        },
    }
    if score:
        s["result"] = {"score": {"scaled": scaled, "raw": 5, "min": 0, "max": 5}}
    return s


# --- parse_stored -----------------------------------------------------


def test_parse_stored_accepts_nine_fractional_digits():
    assert parse_stored("2026-09-14T02:25:07.229000000Z") == datetime(
        2026, 9, 14, 2, 25, 7, 229000, tzinfo=timezone.utc
    )


def test_parse_stored_accepts_no_fractional_part():
    assert parse_stored("2026-09-14T02:25:07Z") == datetime(
        2026, 9, 14, 2, 25, 7, tzinfo=timezone.utc
    )


def test_parse_stored_accepts_an_explicit_offset_instead_of_z():
    assert parse_stored("2026-09-14T02:25:07.229000000+00:00") == datetime(
        2026, 9, 14, 2, 25, 7, 229000, tzinfo=timezone.utc
    )


def test_parse_stored_rejects_garbage():
    with pytest.raises(ValueError):
        parse_stored("not-a-date")


# --- graded_lesson_statements ------------------------------------------


def test_keeps_a_graded_lesson_before_the_cutoff():
    out = graded_lesson_statements({"statements": [_stmt()]}, "cli-review", CUTOFF)
    assert len(out) == 1


def test_drops_a_statement_stored_after_the_cutoff():
    late = _stmt(stored="2026-09-16T00:00:00.000000000Z")
    assert graded_lesson_statements({"statements": [late]}, "cli-review", CUTOFF) == []


def test_drops_a_statement_stored_exactly_at_the_cutoff():
    # The bound is "before": a statement stored at the exact instant of the
    # cutoff must not be admitted. A later-posted forged statement could
    # otherwise land on this boundary and slip through.
    at_cutoff = _stmt(stored="2026-09-15T00:00:00.000000000Z")
    assert graded_lesson_statements({"statements": [at_cutoff]}, "cli-review", CUTOFF) == []


def test_drops_a_different_slug():
    assert (
        graded_lesson_statements(
            {"statements": [_stmt(slug="help-review")]}, "cli-review", CUTOFF
        )
        == []
    )


def test_drops_a_non_lesson_activity():
    other = _stmt(otype="http://adlnet.gov/expapi/activities/assessment")
    assert graded_lesson_statements({"statements": [other]}, "cli-review", CUTOFF) == []


def test_drops_a_statement_with_no_score():
    assert (
        graded_lesson_statements({"statements": [_stmt(score=False)]}, "cli-review", CUTOFF)
        == []
    )


def test_drops_a_score_missing_the_scaled_key():
    s = _stmt()
    s["result"] = {"score": {"raw": 5, "min": 0, "max": 5}}
    assert graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF) == []


# --- ITEM 1 / ITEM 5: scaled alone is not a deliverable score ----------
#
# xAPI 1.0.3 only requires `scaled`. A statement carrying just `{"scaled":
# 1.0}` used to be admitted here and then read at the delivery site with
# `score.get("raw", 0)` / `score.get("max", 1)`, writing a literal zero
# into a real gradebook for a student who may have scored full marks.
# The fix moves the requirement here: every eligibility rule lives in one
# function, and a statement that cannot produce a real score is dropped
# like any other malformed record.


def test_drops_a_score_missing_raw_even_with_scaled_present():
    s = _stmt()
    s["result"]["score"].pop("raw")
    assert graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF) == []


def test_drops_a_score_missing_max_even_with_scaled_present():
    s = _stmt()
    s["result"]["score"].pop("max")
    assert graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF) == []


def test_drops_a_score_with_a_null_max():
    """The exact malformed shape from the review: scaled and raw present,
    max explicitly null. Before the fix this reached
    Decimal(str(None)) downstream and raised decimal.InvalidOperation
    from inside attempt_backfill's generic exception handler, which
    retries identically on every future launch forever. Dropping it here
    means it never reaches that code at all."""
    s = _stmt()
    s["result"]["score"]["max"] = None
    assert graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF) == []


def test_drops_a_score_with_a_null_raw():
    s = _stmt()
    s["result"]["score"]["raw"] = None
    assert graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF) == []


def test_drops_a_score_with_a_non_numeric_raw():
    s = _stmt()
    s["result"]["score"]["raw"] = "five"
    assert graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF) == []


def test_drops_a_score_with_a_non_numeric_max():
    s = _stmt()
    s["result"]["score"]["max"] = "ten"
    assert graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF) == []


def test_drops_a_scaled_only_statement_with_no_raw_or_max_at_all():
    s = _stmt()
    s["result"] = {"score": {"scaled": 1.0}}
    assert graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF) == []


def test_keeps_a_normal_score_carrying_scaled_raw_and_max():
    # Sanity check the tightened predicate doesn't over-reject the
    # ordinary case that _stmt() already builds.
    assert len(graded_lesson_statements({"statements": [_stmt()]}, "cli-review", CUTOFF)) == 1


def test_keeps_an_incomplete_verb_that_still_carries_a_score():
    s = _stmt(scaled=0.4)
    s["verb"]["id"] = "http://adlnet.gov/expapi/verbs/incomplete"
    assert len(graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF)) == 1


def test_a_malformed_stored_value_drops_the_statement_rather_than_raising():
    assert (
        graded_lesson_statements(
            {"statements": [_stmt(stored="not-a-date")]}, "cli-review", CUTOFF
        )
        == []
    )


def test_a_non_dict_statement_drops_rather_than_raising():
    garbage = ["not-a-statement", None, 42, "cli-review"]
    assert graded_lesson_statements({"statements": garbage}, "cli-review", CUTOFF) == []


def test_a_statement_missing_the_object_entirely_is_dropped():
    s = _stmt()
    del s["object"]
    assert graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF) == []


def test_a_non_dict_score_drops_rather_than_raising():
    s = _stmt()
    s["result"] = {"score": "not-a-mapping"}
    assert graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF) == []


def test_empty_and_missing_payloads_return_no_statements():
    assert graded_lesson_statements({}, "cli-review", CUTOFF) == []
    assert graded_lesson_statements(None, "cli-review", CUTOFF) == []
    assert graded_lesson_statements({"statements": None}, "cli-review", CUTOFF) == []


def test_a_mixed_batch_keeps_only_the_eligible_statement():
    batch = [
        _stmt(),
        _stmt(slug="help-review"),
        _stmt(otype="http://adlnet.gov/expapi/activities/assessment"),
        _stmt(score=False),
        _stmt(stored="2026-09-16T00:00:00.000000000Z"),
        _stmt(stored="not-a-date"),
        "garbage",
    ]
    out = graded_lesson_statements({"statements": batch}, "cli-review", CUTOFF)
    assert len(out) == 1
    assert out[0]["stored"] == "2026-09-14T02:25:07.229000000Z"


# --- security boundary: stored decides, timestamp never does ----------
#
# `stored` is assigned by the record store itself when a statement is
# received. `timestamp` is supplied by the poster. The write credential
# for this store lives on student machines, so a student can set
# `timestamp` to whatever value would help a forged statement slip past
# the cutoff, but cannot touch `stored`. Every test above omits
# `timestamp` entirely, which would let a silent `stored`-or-`timestamp`
# fallback pass unnoticed. These three populate both fields and make them
# disagree, so that if `timestamp` were ever consulted, one of them would
# go red.


def test_a_backdated_timestamp_does_not_rescue_a_late_forgery():
    """The forgery shape: posted after the cutoff, backdated by the client.

    `stored` is real and after the cutoff; `timestamp` is forged and well
    before it. The statement must be dropped. A fallback or preference
    that reaches for `timestamp` here would keep it instead.
    """
    s = _stmt(stored="2026-09-16T00:00:00.000000000Z")
    s["timestamp"] = "2020-01-01T00:00:00.000000000Z"
    assert graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF) == []


def test_a_future_timestamp_does_not_hide_legitimate_old_work():
    """The inverse mistake: real old work behind a skewed client clock.

    `stored` is real and before the cutoff; `timestamp` is client-supplied
    and after it. The statement must be kept. A mistake that prefers
    `timestamp` outright would drop it instead.
    """
    s = _stmt(stored="2026-09-14T02:25:07.229000000Z")
    s["timestamp"] = "2030-01-01T00:00:00.000000000Z"
    assert len(graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF)) == 1


def test_an_unparseable_timestamp_is_never_even_inspected():
    """Proves the code does not read `timestamp` at all, not even to validate it.

    `stored` is valid and before the cutoff, so the statement must be kept
    no matter what garbage `timestamp` carries. If the code ever touched
    `timestamp`, a value this broken would raise or force a drop.
    """
    s = _stmt(stored="2026-09-14T02:25:07.229000000Z")
    s["timestamp"] = "not-a-date-at-all"
    assert len(graded_lesson_statements({"statements": [s]}, "cli-review", CUTOFF)) == 1


# --- fetch_statements ----------------------------------------------------


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class FakeHttp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self.payload = payload if payload is not None else {"statements": []}
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return FakeResponse(self.status_code, self.payload)


def test_fetch_statements_builds_the_request_and_returns_the_payload():
    http = FakeHttp(payload={"statements": [{"id": "x"}]})
    result = asyncio.run(
        fetch_statements(
            http,
            base_url="https://lrs.example/xapi",
            auth="dGVzdDpzZWNyZXQ=",
            agent_mbox="mailto:a@email.cpcc.edu",
            activity="https://training.redhat.com/labs/cli-review",
        )
    )
    assert result == {"statements": [{"id": "x"}]}
    assert len(http.calls) == 1
    call = http.calls[0]
    assert call["url"] == "https://lrs.example/xapi/statements"
    assert call["params"]["activity"] == "https://training.redhat.com/labs/cli-review"
    assert call["params"]["limit"] == 50
    assert "mailto:a@email.cpcc.edu" in call["params"]["agent"]
    assert call["headers"]["Authorization"] == "Basic dGVzdDpzZWNyZXQ="
    assert call["headers"]["X-Experience-API-Version"] == "1.0.3"


def test_fetch_statements_strips_a_trailing_slash_on_base_url():
    http = FakeHttp()
    asyncio.run(
        fetch_statements(
            http,
            base_url="https://lrs.example/xapi/",
            auth="x",
            agent_mbox="mailto:a@email.cpcc.edu",
            activity="https://training.redhat.com/labs/cli-review",
        )
    )
    assert http.calls[0]["url"] == "https://lrs.example/xapi/statements"


def test_fetch_statements_respects_a_limit_override():
    http = FakeHttp()
    asyncio.run(
        fetch_statements(
            http,
            base_url="https://lrs.example",
            auth="x",
            agent_mbox="mailto:a@email.cpcc.edu",
            activity="https://training.redhat.com/labs/cli-review",
            limit=10,
        )
    )
    assert http.calls[0]["params"]["limit"] == 10


def test_fetch_statements_raises_on_a_non_200_instead_of_returning_an_empty_envelope(caplog):
    """ITEM 2: an empty envelope is indistinguishable from a real 'this
    student has no history' answer. attempt_backfill treats an empty
    result as license to stamp backfill_attempted_at forever, so
    swallowing a 401/500/503 into {"statements": []} would permanently
    burn a cohort's one attempt each on a revoked or rotated credential.
    Raising instead lets attempt_backfill's existing network-error
    handling -- which already leaves a cell unmarked for retry -- catch
    an HTTP failure the same way, since it is frequently the same root
    cause. The status code is logged at WARNING; the credential never is.
    """
    http = FakeHttp(status_code=401, payload={"error": "unauthorized"})

    with caplog.at_level(logging.WARNING):
        with pytest.raises(LrsQueryError) as excinfo:
            asyncio.run(
                fetch_statements(
                    http,
                    base_url="https://lrs.example",
                    auth="super-secret-basic-token",
                    agent_mbox="mailto:a@email.cpcc.edu",
                    activity="https://training.redhat.com/labs/cli-review",
                )
            )

    assert excinfo.value.status_code == 401
    assert "401" in caplog.text
    assert "super-secret-basic-token" not in caplog.text


def test_fetch_statements_passes_until_matching_the_cutoff_when_given():
    """ITEM 6: passing xAPI's `until` parameter filters on `stored`
    server-side, enforcing the freshness bound at the store itself,
    keeping eligible statements on the first page, and reducing
    transfer. The local strict comparison in graded_lesson_statements
    stays the authority because `until` is inclusive."""
    http = FakeHttp()
    cutoff = datetime(2026, 9, 1, tzinfo=timezone.utc)
    asyncio.run(
        fetch_statements(
            http,
            base_url="https://lrs.example",
            auth="x",
            agent_mbox="mailto:a@email.cpcc.edu",
            activity="https://training.redhat.com/labs/cli-review",
            until=cutoff,
        )
    )
    assert http.calls[0]["params"]["until"] == cutoff.isoformat()


def test_fetch_statements_omits_until_when_not_given():
    http = FakeHttp()
    asyncio.run(
        fetch_statements(
            http,
            base_url="https://lrs.example",
            auth="x",
            agent_mbox="mailto:a@email.cpcc.edu",
            activity="https://training.redhat.com/labs/cli-review",
        )
    )
    assert "until" not in http.calls[0]["params"]


def test_fetch_statements_never_logs_the_credential(caplog):
    caplog.set_level(logging.DEBUG)
    secret = "super-secret-basic-token"
    http = FakeHttp()
    asyncio.run(
        fetch_statements(
            http,
            base_url="https://lrs.example",
            auth=secret,
            agent_mbox="mailto:a@email.cpcc.edu",
            activity="https://training.redhat.com/labs/cli-review",
        )
    )
    assert secret not in caplog.text
