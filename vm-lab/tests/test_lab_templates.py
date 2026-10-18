"""Templates keyed on the lab slug prefix.

006 keyed the template on course_id, derived from the Brightspace course
shell. Every new SECTION is a new key, matches no row, and falls back to the
deployment default: it boots, it runs, and it is the wrong image, with
nothing reporting an error. A slug names the course family and outlives every
shell, so csc228-lab-02 maps the same way in every section and every term.

The rule this file holds is the resolution order: slug prefix, then course,
then deployment default, with each step falling through rather than failing.
"""

import sys
import types

import pytest

CSC228_TEMPLATE = 2280
PILOT_TEMPLATE = 501
PILOT_SNAPSHOT = "base-with-rdp"
MAPPED_COURSE = "brightspace-org-unit-991155"


def _load_api_main():
    for name, attrs in (("asyncpg", {}), ("proxmoxer", {"ProxmoxAPI": object})):
        if name not in sys.modules:
            try:
                __import__(name)
            except ImportError:
                stub = types.ModuleType(name)
                for attr, value in attrs.items():
                    setattr(stub, attr, value)
                sys.modules[name] = stub
    import api.main as lab_api_main
    return lab_api_main


class _Db:
    """Answers the lab-template query from `rows`, the course query from `course`."""

    def __init__(self, rows=None, course=None, lab_raises=False):
        self._rows = rows or []
        self._course = course
        self._lab_raises = lab_raises

    async def fetchrow(self, sql, arg):
        if "lab_templates" in sql:
            if self._lab_raises:
                raise RuntimeError("relation lab_templates does not exist")
            # Longest matching prefix, mirroring the ORDER BY in the query.
            matches = [r for r in self._rows if arg.startswith(r["slug_prefix"])]
            matches.sort(key=lambda r: len(r["slug_prefix"]), reverse=True)
            return matches[0] if matches else None
        return self._course


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _row(prefix, template_id, cores=None, memory_mb=None, snapshot=""):
    return {"slug_prefix": prefix, "template_id": template_id,
            "snapshot_name": snapshot, "cores": cores, "memory_mb": memory_mb}


@pytest.mark.anyio
async def test_a_slug_maps_the_course_family_whatever_the_shell_is():
    """The point of the change. Two different sections, two different course
    ids, the same slug, the same image."""
    api_main = _load_api_main()
    db = _Db(rows=[_row("csc228-", CSC228_TEMPLATE, 8, 24576)])

    for course in ("fall-shell-aaaa", "spring-shell-bbbb", None):
        choice = await api_main.resolve_lab_template(db, "csc228-lab-02", course)
        assert choice.template_id == CSC228_TEMPLATE
        assert choice.cores == 8
        assert choice.memory_mb == 24576


@pytest.mark.anyio
async def test_the_slug_wins_over_the_course_mapping():
    """A shell-specific row cannot quietly override the course family's image
    for a lab that names it."""
    api_main = _load_api_main()
    db = _Db(rows=[_row("csc228-", CSC228_TEMPLATE, 8, 24576)],
             course={"template_id": PILOT_TEMPLATE, "snapshot_name": PILOT_SNAPSHOT})
    choice = await api_main.resolve_lab_template(db, "csc228-lab-02", MAPPED_COURSE)
    assert choice.template_id == CSC228_TEMPLATE


@pytest.mark.anyio
async def test_a_slug_that_matches_nothing_falls_through_to_the_course():
    """Every NOS lab slug matches no prefix, and those courses must keep
    resolving exactly as they do today."""
    api_main = _load_api_main()
    db = _Db(rows=[_row("csc228-", CSC228_TEMPLATE)],
             course={"template_id": PILOT_TEMPLATE, "snapshot_name": PILOT_SNAPSHOT})
    choice = await api_main.resolve_lab_template(db, "perms-review", MAPPED_COURSE)
    assert choice.template_id == PILOT_TEMPLATE
    assert choice.snapshot_name == PILOT_SNAPSHOT


@pytest.mark.anyio
async def test_no_slug_at_all_falls_through_to_the_course():
    """A launch carrying no custom_resource still has to provision."""
    api_main = _load_api_main()
    db = _Db(rows=[_row("csc228-", CSC228_TEMPLATE)],
             course={"template_id": PILOT_TEMPLATE, "snapshot_name": PILOT_SNAPSHOT})
    choice = await api_main.resolve_lab_template(db, None, MAPPED_COURSE)
    assert choice.template_id == PILOT_TEMPLATE


@pytest.mark.anyio
async def test_a_database_without_the_table_falls_through_rather_than_failing():
    """Additive, like 006 and 007. A deployment still on 007 must launch."""
    api_main = _load_api_main()
    db = _Db(lab_raises=True,
             course={"template_id": PILOT_TEMPLATE, "snapshot_name": PILOT_SNAPSHOT})
    choice = await api_main.resolve_lab_template(db, "csc228-lab-02", MAPPED_COURSE)
    assert choice.template_id == PILOT_TEMPLATE


@pytest.mark.anyio
async def test_the_longest_matching_prefix_wins():
    """A narrower rule overrides a broader one without deleting it, so one
    lab can pilot a new image while the rest of the course does not."""
    api_main = _load_api_main()
    db = _Db(rows=[_row("csc228-", CSC228_TEMPLATE), _row("csc228-lab-08", 2290)])
    assert (await api_main.resolve_lab_template(db, "csc228-lab-08", None)).template_id == 2290
    assert (await api_main.resolve_lab_template(db, "csc228-lab-02", None)).template_id == CSC228_TEMPLATE


def test_the_provision_request_carries_the_slug():
    """The resolver cannot key on something the request never sends."""
    api_main = _load_api_main()
    assert "lab_slug" in api_main.ProvisionRequest.model_fields


def test_the_query_itself_orders_longest_prefix_first():
    """The fake above sorts in Python, so it validates the fake rather than
    the query. The precedence actually comes from the ORDER BY, which only a
    real database would exercise, so assert on the statement text instead of
    claiming coverage the suite does not have."""
    api_main = _load_api_main()
    sql = " ".join(api_main.LAB_TEMPLATE_SQL.split())
    assert "ORDER BY length(slug_prefix) DESC" in sql
    assert "LIMIT 1" in sql
    assert "LIKE slug_prefix || '%'" in sql


def test_the_migration_refuses_an_empty_prefix():
    """An empty prefix matches every slug in every course, which would point
    NOS launches at the CSC 228 image."""
    import pathlib
    sql = pathlib.Path("migrations/008_lab_templates.sql").read_text()
    assert "length(slug_prefix) > 0" in sql
