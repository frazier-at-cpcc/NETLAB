"""LabsConnect's side of the downstream launch contract.

The broker produces the parameters in contracts/downstream_launch_v1.json;
this file proves this service can read them. The bug this exists to prevent
was not a regression in either codebase: the broker sent resource_link_id,
this service read custom_lab_slug, both were internally consistent and well
tested, and no test spanned the gap. Every graded lab in NOS 120 and NOS 220
silently stopped returning scores when those courses moved behind the
broker, and the only symptom was `lab grade` telling students "no gradebook
column" about something only an instructor could fix.

The contract file is a copy of the broker's, which owns it. Keeping two
copies in two repositories is a real weakness: they can drift. What this
buys is that neither side can change its own half without a test failing,
which is what was missing.
"""

import json
import pathlib

import pytest

CONTRACT = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "contracts" / "downstream_launch_v1.json").read_text()
)
SAMPLE = CONTRACT["sample"]


def _parse(form=None):
    from lti.launch_context import parse_lti11_form

    return parse_lti11_form(dict(form if form is not None else SAMPLE))


# --- the launch resolves --------------------------------------------------


def test_the_contract_sample_parses_at_all():
    ctx = _parse()
    assert ctx.user_id == SAMPLE["user_id"]
    assert ctx.course_id == SAMPLE["context_id"]


def test_the_lab_is_identified():
    """The whole failure in one assertion. Without the slug no grade cell is
    written, and nothing downstream reports why."""
    assert _parse().lab_slug == "scripts-review"


def test_a_grade_cell_can_be_built_from_the_launch():
    """Every field a cell needs has to survive the parse, or the cell is
    skipped and `lab grade` finds no column."""
    from lti.persist_cell import cell_fields_from_ctx

    fields = cell_fields_from_ctx(_parse())
    for name in ("lab_slug", "sourcedid", "outcome_service_url", "resource_link_id"):
        assert fields.get(name), f"a cell cannot be written without {name}"


def test_the_course_session_key_is_stable_for_a_student_in_a_course():
    """Cells are keyed on this, so a student must resolve to the same value
    on every launch of every lab in the course."""
    one = _parse()
    other = _parse({**SAMPLE, "custom_lab_slug": "logs-review",
                    "resource_link_id": "a-different-link"})
    assert one.course_session_key == other.course_session_key


def test_the_key_is_built_from_the_guid_the_broker_sends():
    ctx = _parse()
    assert ctx.course_session_key == "ltibroker:u-1:abc123"


# --- every parameter the contract requires is one we actually read --------


def test_this_service_reads_every_required_parameter():
    """A parameter the broker promises and this service ignores is a
    promise nobody is keeping. Each required field must change something
    observable in the parsed context."""
    read = {
        "lti_message_type": None,  # consumed by the route, not the context
        "lti_version": None,
        "resource_link_id": "resource_link_id",
        "context_id": "course_id",
        "user_id": "user_id",
        "roles": "roles",
        "custom_lab_slug": "lab_slug",
    }
    ctx = _parse()
    for param in CONTRACT["required"]:
        assert param in read, f"the contract requires {param} and this test does not account for it"
        attr = read[param]
        if attr:
            assert getattr(ctx, attr), f"{param} should populate ctx.{attr}"


def test_dropping_the_slug_is_caught_here():
    """The exact production payload, minus the one parameter. This is what
    ran for a term."""
    without = {k: v for k, v in SAMPLE.items() if k != "custom_lab_slug"}
    ctx = _parse(without)
    assert ctx.lab_slug is None

    from lti.persist_cell import cell_fields_from_ctx

    assert not cell_fields_from_ctx(ctx).get("lab_slug")


def test_a_complete_launch_yields_a_postable_cell_body():
    """grade_cell_body is the gate on the write itself. cell_fields_from_ctx,
    asserted above, is the Redis stash on the way to it: a different
    function, and covering only that left this one unguarded."""
    from lti.persist_cell import grade_cell_body

    body = grade_cell_body("ltibroker:u-1:abc123", _parse())
    assert body is not None
    for name in ("course_session_id", "lab_slug", "outcome_service_url", "sourcedid"):
        assert body.get(name), f"a cell cannot be posted without {name}"


def test_an_incomplete_launch_yields_no_cell_body():
    """Posting a cell with a null slug writes a row that can never be
    matched by `lab grade`, or fails the NOT NULL and errors the launch."""
    from lti.persist_cell import grade_cell_body

    without = {k: v for k, v in SAMPLE.items() if k != "custom_lab_slug"}
    assert grade_cell_body("ltibroker:u-1:abc123", _parse(without)) is None

    ungraded = {k: v for k, v in SAMPLE.items() if k != "lis_result_sourcedid"}
    assert grade_cell_body("ltibroker:u-1:abc123", _parse(ungraded)) is None


def test_the_graded_parameters_are_read_when_present():
    ctx = _parse()
    assert ctx.sourcedid == SAMPLE["lis_result_sourcedid"]
    assert ctx.outcome_service_url == SAMPLE["lis_outcome_service_url"]


def test_the_contract_version_is_the_one_this_file_was_written_against():
    """A new version means the producer changed the promise; this side should
    fail until someone has read the change."""
    assert CONTRACT["version"] == 1
