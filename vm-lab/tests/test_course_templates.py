"""Proves a course can name its own Proxmox template.

Today the template is a property of the deployment: PROXMOX_TEMPLATE_ID is one
environment variable and clone_vm uses it for every course. That is why the
browser RDP desktop can only be offered to every course at once or to none.

The rule this file holds is that the change is additive. A course with no
mapping must clone exactly what it clones today, from the same template and
the same snapshot, because every course in production is unmapped on the day
this ships.
"""

import sys
import types

import pytest

COURSE_WITH_TEMPLATE = "brightspace-org-unit-991155"
UNMAPPED_COURSE = "brightspace-org-unit-000000"
PILOT_TEMPLATE = 501
PILOT_SNAPSHOT = "base-with-rdp"


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


class _FakeDb:
    def __init__(self, row=None):
        self._row = row
        self.args = None

    async def fetchrow(self, _query, *args):
        self.args = args
        return self._row


@pytest.fixture
def anyio_backend():
    return "asyncio"


# --- resolution -------------------------------------------------------


@pytest.mark.anyio
async def test_an_unmapped_course_clones_exactly_what_it_clones_today():
    api_main = _load_api_main()

    choice = await api_main.resolve_course_template(_FakeDb(), UNMAPPED_COURSE)

    assert choice.template_id == api_main.PROXMOX_TEMPLATE_ID
    assert choice.snapshot_name == api_main.PROXMOX_TEMPLATE_SNAPSHOT


@pytest.mark.anyio
async def test_a_mapped_course_clones_its_own_template_and_snapshot():
    api_main = _load_api_main()
    db = _FakeDb({"template_id": PILOT_TEMPLATE, "snapshot_name": PILOT_SNAPSHOT})

    choice = await api_main.resolve_course_template(db, COURSE_WITH_TEMPLATE)

    assert choice.template_id == PILOT_TEMPLATE
    assert choice.snapshot_name == PILOT_SNAPSHOT


@pytest.mark.anyio
async def test_a_mapping_without_a_snapshot_keeps_the_deployment_default():
    """Most mappings will only want to change the template. Requiring a
    snapshot name on every row would make the common case verbose and the
    typo silent."""
    api_main = _load_api_main()
    db = _FakeDb({"template_id": PILOT_TEMPLATE, "snapshot_name": None})

    choice = await api_main.resolve_course_template(db, COURSE_WITH_TEMPLATE)

    assert choice.template_id == PILOT_TEMPLATE
    assert choice.snapshot_name == api_main.PROXMOX_TEMPLATE_SNAPSHOT


@pytest.mark.anyio
async def test_resolution_is_keyed_on_the_course_and_nothing_else():
    api_main = _load_api_main()
    db = _FakeDb()

    await api_main.resolve_course_template(db, COURSE_WITH_TEMPLATE)

    assert db.args == (COURSE_WITH_TEMPLATE,)


@pytest.mark.anyio
async def test_a_missing_course_id_falls_back_rather_than_querying():
    """A launch with no course context must still provision. It gets the
    deployment default, which is what it gets today."""
    api_main = _load_api_main()
    db = _FakeDb({"template_id": PILOT_TEMPLATE, "snapshot_name": PILOT_SNAPSHOT})

    choice = await api_main.resolve_course_template(db, None)

    assert choice.template_id == api_main.PROXMOX_TEMPLATE_ID
    assert db.args is None


@pytest.mark.anyio
async def test_an_unreadable_mapping_table_does_not_fail_the_launch():
    """The table is additive. If it is missing or unreadable, a student still
    gets the lab they get today."""
    api_main = _load_api_main()

    class _BrokenDb:
        async def fetchrow(self, *_args):
            raise RuntimeError("relation does not exist")

    choice = await api_main.resolve_course_template(_BrokenDb(), COURSE_WITH_TEMPLATE)

    assert choice.template_id == api_main.PROXMOX_TEMPLATE_ID


# --- the clone honours the resolution ---------------------------------


def test_clone_uses_the_resolved_template_and_snapshot():
    api_main = _load_api_main()
    calls = {}

    class _FakeClone:
        def post(self, **kwargs):
            calls.update(kwargs)
            return "UPID:fake"

    class _FakeQemu:
        def __init__(self, vmid):
            # qemu() is called twice: once for the template being cloned and
            # once for the new VM being configured. Recording every call keeps
            # the second from masking the first.
            calls.setdefault("qemu_ids", []).append(vmid)
            self.clone = _FakeClone()
            self.config = type("C", (), {"put": lambda *a, **k: None})()

    class _FakeNode:
        def qemu(self, vmid):
            return _FakeQemu(vmid)

    class _FakeProxmox:
        def __init__(self):
            self.cluster = type(
                "C", (), {"resources": type("R", (), {"get": lambda *a, **k: []})()}
            )()
            self.nodes = lambda _name: _FakeNode()

    choice = api_main.TemplateChoice(
        template_id=PILOT_TEMPLATE, snapshot_name=PILOT_SNAPSHOT
    )
    api_main.clone_vm(
        _FakeProxmox(), "a1b2c3d4", "vm-a1b2c3d4", choice, wait=lambda *a, **k: True
    )

    assert calls["qemu_ids"][0] == PILOT_TEMPLATE
    assert calls["snapname"] == PILOT_SNAPSHOT


# --- the migration ----------------------------------------------------


def test_the_mapping_is_one_row_per_course():
    from pathlib import Path

    sql = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "006_course_templates.sql"
    ).read_text()

    assert "course_templates" in sql
    assert "course_id" in sql
    assert "PRIMARY KEY" in sql
    assert "template_id INTEGER NOT NULL" in sql
