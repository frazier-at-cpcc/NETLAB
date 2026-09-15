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

from api.lrs_client import fetch_statements, graded_lesson_statements, parse_stored

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


def test_fetch_statements_returns_an_empty_envelope_on_a_non_200():
    http = FakeHttp(status_code=503, payload={"error": "unavailable"})
    result = asyncio.run(
        fetch_statements(
            http,
            base_url="https://lrs.example",
            auth="x",
            agent_mbox="mailto:a@email.cpcc.edu",
            activity="https://training.redhat.com/labs/cli-review",
        )
    )
    assert result == {"statements": []}


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
