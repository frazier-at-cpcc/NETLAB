import asyncio
import logging

from api.session_keys import course_session_key
from lti.launch_context import parse_lti11_form


class StubPool:
    """In-memory stand-in for asyncpg. Records SQL and upserts by (session, slug)."""

    def __init__(self):
        self.calls = []
        self.rows = {}
        self._next_id = 1

    async def fetchrow(self, sql, *args):
        self.calls.append((sql, args))
        key = (args[0], args[1])
        if key in self.rows:
            row = self.rows[key]
            row["resource_link_id"] = args[2]
            row["outcome_service_url"] = args[3]
            row["sourcedid"] = args[4]
            row["consumer_key"] = args[5]
            row["updated_at"] = "updated"
            return dict(row)
        row = {
            "id": self._next_id,
            "course_session_id": args[0],
            "lab_slug": args[1],
            "resource_link_id": args[2],
            "outcome_service_url": args[3],
            "sourcedid": args[4],
            "consumer_key": args[5],
            "updated_at": "created",
        }
        self._next_id += 1
        self.rows[key] = row
        return dict(row)


def _sql(call):
    return " ".join(call[0].split())


def _upsert(**overrides):
    from api.cells import upsert_grade_cell

    kwargs = dict(
        course_session_id="sess-1",
        lab_slug="cli-review",
        resource_link_id="rl-cli",
        outcome_service_url="https://lms.example/outcome",
        sourcedid="cell-1",
        consumer_key="cpcc-brightspace",
    )
    kwargs.update(overrides)
    return upsert_grade_cell, kwargs


def test_first_upsert_inserts():
    db = StubPool()
    upsert_grade_cell, kwargs = _upsert()

    cell_id = asyncio.run(upsert_grade_cell(db, **kwargs))

    assert cell_id == 1
    assert len(db.calls) == 1
    sql = _sql(db.calls[0])
    assert "INSERT INTO grade_cells" in sql
    assert db.calls[0][1] == (
        "sess-1",
        "cli-review",
        "rl-cli",
        "https://lms.example/outcome",
        "cell-1",
        "cpcc-brightspace",
    )
    stored = db.rows[("sess-1", "cli-review")]
    assert stored["sourcedid"] == "cell-1"
    assert stored["updated_at"] == "created"


def test_second_upsert_updates_pox_fields():
    db = StubPool()
    upsert_grade_cell, first = _upsert()
    asyncio.run(upsert_grade_cell(db, **first))

    cell_id = asyncio.run(
        upsert_grade_cell(
            db,
            course_session_id="sess-1",
            lab_slug="cli-review",
            resource_link_id="rl-cli-2",
            outcome_service_url="https://lms.example/outcome-v2",
            sourcedid="cell-2",
            consumer_key="cpcc-brightspace",
        )
    )

    assert cell_id == 1
    assert len(db.rows) == 1
    assert len(db.calls) == 2
    sql = _sql(db.calls[1])
    assert "ON CONFLICT (course_session_id, lab_slug)" in sql
    assert "resource_link_id = EXCLUDED.resource_link_id" in sql
    assert "outcome_service_url = EXCLUDED.outcome_service_url" in sql
    assert "sourcedid = EXCLUDED.sourcedid" in sql
    assert "updated_at = CURRENT_TIMESTAMP" in sql
    stored = db.rows[("sess-1", "cli-review")]
    assert stored["sourcedid"] == "cell-2"
    assert stored["outcome_service_url"] == "https://lms.example/outcome-v2"
    assert stored["resource_link_id"] == "rl-cli-2"
    assert stored["updated_at"] == "updated"
    assert db.calls[1][1] == (
        "sess-1",
        "cli-review",
        "rl-cli-2",
        "https://lms.example/outcome-v2",
        "cell-2",
        "cpcc-brightspace",
    )


def test_upsert_skipped_when_slug_or_sourcedid_none():
    db = StubPool()
    upsert_grade_cell, kwargs = _upsert()

    skipped_slug = asyncio.run(upsert_grade_cell(db, **{**kwargs, "lab_slug": None}))
    skipped_sourcedid = asyncio.run(upsert_grade_cell(db, **{**kwargs, "sourcedid": None}))

    assert skipped_slug is None
    assert skipped_sourcedid is None
    assert db.calls == []
    assert db.rows == {}


def test_two_slugs_same_course_session_store_two_cells():
    form_cli = {
        "oauth_consumer_key": "cpcc-brightspace",
        "user_id": "u1",
        "context_id": "354303",
        "tool_consumer_instance_guid": "brightspace.cpcc.edu",
        "resource_link_id": "rl-cli",
        "custom_lab_slug": "cli-review",
        "lis_outcome_service_url": "https://brightspace.cpcc.edu/d2l/le/lti/Outcome",
        "lis_result_sourcedid": "cell-cli",
        "roles": "Learner",
    }
    form_pipes = {
        **form_cli,
        "resource_link_id": "rl-pipes",
        "custom_lab_slug": "pipes",
        "lis_result_sourcedid": "cell-pipes",
    }
    ctx_cli = parse_lti11_form(form_cli)
    ctx_pipes = parse_lti11_form(form_pipes)

    assert ctx_cli.course_session_key == ctx_pipes.course_session_key
    assert ctx_cli.course_session_key == course_session_key(
        "brightspace.cpcc.edu", "u1", "354303"
    )
    assert ctx_cli.lab_slug != ctx_pipes.lab_slug

    from api.cells import upsert_grade_cell
    from lti.persist_cell import persist_grade_cell

    db = StubPool()
    posted = []

    async def post(body):
        posted.append(body)
        return await upsert_grade_cell(db, **body)

    async def run():
        session_id = "sess-course"
        await persist_grade_cell(session_id, ctx_cli, post=post)
        await persist_grade_cell(session_id, ctx_pipes, post=post)

    asyncio.run(run())

    assert len(posted) == 2
    assert {p["lab_slug"] for p in posted} == {"cli-review", "pipes"}
    assert {p["course_session_id"] for p in posted} == {"sess-course"}
    assert len(db.rows) == 2
    assert db.rows[("sess-course", "cli-review")]["sourcedid"] == "cell-cli"
    assert db.rows[("sess-course", "pipes")]["sourcedid"] == "cell-pipes"


def test_persist_skips_when_fields_missing_and_logs_resource_link_only(caplog):
    from lti.persist_cell import persist_grade_cell

    ctx = parse_lti11_form({
        "oauth_consumer_key": "cpcc-brightspace",
        "user_id": "u1",
        "context_id": "354303",
        "tool_consumer_instance_guid": "brightspace.cpcc.edu",
        "resource_link_id": "rl-x",
        "roles": "Learner",
    })
    posted = []

    async def post(body):
        posted.append(body)

    with caplog.at_level(logging.WARNING):
        asyncio.run(persist_grade_cell("sess-1", ctx, post=post))

    assert posted == []
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "rl-x" in text
    assert "cell-" not in text
    assert "sourcedid" not in text.lower()


def test_persist_missing_outcome_does_not_log_sourcedid(caplog):
    from lti.persist_cell import persist_grade_cell

    ctx = parse_lti11_form({
        "oauth_consumer_key": "cpcc-brightspace",
        "user_id": "u1",
        "context_id": "354303",
        "tool_consumer_instance_guid": "brightspace.cpcc.edu",
        "resource_link_id": "rl-cli",
        "custom_lab_slug": "cli-review",
        "lis_result_sourcedid": "secret-sourcedid-value",
        "roles": "Learner",
    })
    posted = []

    async def post(body):
        posted.append(body)

    with caplog.at_level(logging.WARNING):
        asyncio.run(persist_grade_cell("sess-1", ctx, post=post))

    assert posted == []
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "rl-cli" in text
    assert "secret-sourcedid-value" not in text
    assert "sourcedid" not in text.lower()
