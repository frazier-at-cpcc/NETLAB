"""The grade cell must survive a launch whose third-party cookie is dropped.

The production failure these cover: a student launched a lab link cold, with
no virtual machine session running. The launch stored the cell fields in the
`lti_session` cookie and returned the ready page. The browser, inside the LMS
iframe, dropped that third-party cookie. The student clicked Start Lab, the
page posted session_key and user_id from its own body so provisioning
succeeded, and the cell persist silently skipped because the rebuilt context
was empty. `lab grade` then reported "no gradebook column" for a lab that had
one, and no grade could ever reach the gradebook.
"""

import json
from types import SimpleNamespace

import pytest

from lti.persist_cell import (
    PENDING_CELL_TTL_SECONDS,
    cell_fields_from_ctx,
    ctx_from_cell_fields,
    grade_cell_body,
    load_pending_cell,
    pending_cell_key,
    store_pending_cell,
)


class FakeRedis:
    def __init__(self, raising=False):
        self.store = {}
        self.ttls = {}
        self.raising = raising

    def setex(self, key, ttl, value):
        if self.raising:
            raise RuntimeError("redis down")
        self.store[key] = value
        self.ttls[key] = ttl

    def get(self, key):
        if self.raising:
            raise RuntimeError("redis down")
        return self.store.get(key)


def _ctx(**over):
    base = dict(
        lab_slug="perms-review",
        sourcedid="SECRET-SOURCEDID",
        outcome_service_url="https://lms.example.edu/outcome",
        resource_link_id="806a69c3",
        consumer_key="ltibroker",
    )
    base.update(over)
    return SimpleNamespace(**base)


def test_round_trip_produces_a_persistable_body():
    redis = FakeRedis()
    assert store_pending_cell(redis, "skey", _ctx()) is True

    ctx = load_pending_cell(redis, "skey")
    body = grade_cell_body("vm-session-1", ctx)

    assert body == {
        "course_session_id": "vm-session-1",
        "lab_slug": "perms-review",
        "resource_link_id": "806a69c3",
        "outcome_service_url": "https://lms.example.edu/outcome",
        "sourcedid": "SECRET-SOURCEDID",
        "consumer_key": "ltibroker",
    }


def test_stash_survives_a_launch_that_set_no_cookie():
    """The regression itself: nothing but the stash carries the fields."""
    redis = FakeRedis()
    store_pending_cell(redis, "skey", _ctx())

    # A provision request arriving with no usable cookie at all.
    ctx = load_pending_cell(redis, "skey")

    assert ctx is not None
    assert grade_cell_body("vm-1", ctx) is not None


def test_ttl_is_applied_so_a_stash_cannot_outlive_the_launch_window():
    redis = FakeRedis()
    store_pending_cell(redis, "skey", _ctx())
    assert redis.ttls[pending_cell_key("skey")] == PENDING_CELL_TTL_SECONDS


@pytest.mark.parametrize("missing", ["sourcedid", "outcome_service_url"])
def test_launch_without_outcome_information_stores_nothing(missing):
    """A link with no gradebook column must not leave a stale stash behind."""
    redis = FakeRedis()
    assert store_pending_cell(redis, "skey", _ctx(**{missing: ""})) is False
    assert redis.store == {}
    assert load_pending_cell(redis, "skey") is None


def test_no_session_key_stores_nothing():
    redis = FakeRedis()
    assert store_pending_cell(redis, "", _ctx()) is False
    assert pending_cell_key("") is None
    assert load_pending_cell(redis, "") is None


def test_redis_failure_never_breaks_the_launch():
    redis = FakeRedis(raising=True)
    assert store_pending_cell(redis, "skey", _ctx()) is False
    assert load_pending_cell(redis, "skey") is None


@pytest.mark.parametrize("raw", ["not json", "[]", "null", '"text"'])
def test_malformed_stash_is_discarded_not_raised(raw):
    redis = FakeRedis()
    redis.store[pending_cell_key("skey")] = raw
    assert load_pending_cell(redis, "skey") is None


def test_incomplete_stash_is_rejected_by_the_body_builder():
    redis = FakeRedis()
    redis.store[pending_cell_key("skey")] = json.dumps({"lab_slug": "x"})
    ctx = load_pending_cell(redis, "skey")
    assert grade_cell_body("vm-1", ctx) is None


def test_stash_carries_no_field_beyond_the_cell():
    """The stash is not a general session store; it holds the cell only."""
    fields = cell_fields_from_ctx(
        SimpleNamespace(
            lab_slug="s", sourcedid="d", outcome_service_url="u",
            resource_link_id="r", consumer_key="c",
            user_email="student@example.edu", password="nope",
        )
    )
    assert set(fields) == {
        "lab_slug", "sourcedid", "outcome_service_url",
        "resource_link_id", "consumer_key",
    }


def test_missing_attributes_degrade_to_empty_not_attribute_error():
    fields = cell_fields_from_ctx(SimpleNamespace())
    assert fields["sourcedid"] == ""
    assert ctx_from_cell_fields(fields).sourcedid is None
