"""Student VMs and terminal containers whose session is gone.

Nothing reaped these. destroy_vm posted a stop, slept five seconds, and
issued a delete that Proxmox refused while the guest was still shutting
down; the error was logged and swallowed, so the VM stayed on the node while
the session row read destroyed. Seven had accumulated against a pool of
about twelve.

The rule here is the direction of doubt. Deleting a VM a student is sitting
in is far worse than leaving a dead one on the node, so anything this cannot
resolve counts as still owned.
"""

import inspect
import pathlib
import sys
import types

import pytest


def _load():
    for name, attrs in (("asyncpg", {}), ("proxmoxer", {"ProxmoxAPI": object})):
        if name not in sys.modules:
            try:
                __import__(name)
            except ImportError:
                stub = types.ModuleType(name)
                for attr, value in attrs.items():
                    setattr(stub, attr, value)
                sys.modules[name] = stub
    import api.main as m
    return m


@pytest.fixture
def anyio_backend():
    return "asyncio"


class _Db:
    def __init__(self, rows=None, raises=False):
        self._rows = rows or []
        self._raises = raises

    async def fetch(self, sql, arg=None):
        if self._raises:
            raise RuntimeError("database unavailable")
        return [r for r in self._rows if r["session_id"] in (arg or [])]


def _row(session_id, status):
    return {"session_id": session_id, "status": status}


# --- the direction of doubt --------------------------------------------


@pytest.mark.anyio
async def test_a_live_session_is_never_an_orphan():
    m = _load()
    db = _Db([_row("aaa", "running"), _row("bbb", "starting"),
              _row("ccc", "provisioning")])
    assert await m._orphan_session_ids(db, ["aaa", "bbb", "ccc"]) == set()


@pytest.mark.anyio
async def test_a_database_failure_leaves_everything_owned():
    """A failed query must never authorise a delete."""
    m = _load()
    assert await m._orphan_session_ids(_Db(raises=True), ["aaa"]) == set()


@pytest.mark.anyio
async def test_nothing_asked_means_nothing_orphaned():
    m = _load()
    assert await m._orphan_session_ids(_Db(), []) == set()


# --- what counts as an orphan -----------------------------------------


@pytest.mark.anyio
async def test_a_session_with_no_row_is_an_orphan():
    """The row was deleted while the VM survived, which is how most arise."""
    m = _load()
    assert await m._orphan_session_ids(_Db([]), ["gone"]) == {"gone"}


@pytest.mark.anyio
async def test_a_destroyed_or_errored_session_no_longer_owns_its_vm():
    m = _load()
    db = _Db([_row("dead", "destroyed"), _row("bad", "error")])
    assert await m._orphan_session_ids(db, ["dead", "bad"]) == {"dead", "bad"}


@pytest.mark.anyio
async def test_live_and_dead_are_separated_in_one_pass():
    m = _load()
    db = _Db([_row("live", "running"), _row("dead", "destroyed")])
    assert await m._orphan_session_ids(db, ["live", "dead", "absent"]) == {
        "dead", "absent"
    }


# --- it reports before it acts -----------------------------------------


def test_the_sweep_changes_nothing_until_it_is_switched_on():
    """It deletes VMs and containers, so the matching is audited against a
    real node before it is trusted to act."""
    m = _load()
    assert m.ORPHAN_REAP_ENABLED is False
    src = inspect.getsource(m.sweep_orphans)
    assert 'verb = "Reaping" if ORPHAN_REAP_ENABLED else "Would reap"' in src
    assert src.count("if ORPHAN_REAP_ENABLED:") == 2


def test_it_is_forwarded_so_it_can_be_switched_on():
    m = _load()
    assert 'os.getenv("ORPHAN_REAP_ENABLED"' in inspect.getsource(m)
    assert "ORPHAN_REAP_ENABLED=" in pathlib.Path("docker-compose.yml").read_text()


def test_a_template_is_never_a_candidate():
    """2280 and 2289 are templates, and deleting one would take the course
    down rather than free a slot."""
    src = inspect.getsource(_load().sweep_orphans)
    assert 'not guest.get("template")' in src


def test_only_student_vms_are_considered():
    """The node also runs the NAS, the appliances and the templates."""
    src = inspect.getsource(_load().sweep_orphans)
    assert 'name.startswith("student-")' in src


def test_the_vm_delete_goes_through_the_single_teardown_helper():
    """destroy_vm is where the wait-for-stop fix lives; a second delete path
    would reintroduce the leak it fixes."""
    src = inspect.getsource(_load().sweep_orphans)
    assert "destroy_vm, proxmox_api, vmid" in src
    assert ".delete()" not in src


def test_the_sweep_runs_on_the_existing_reaper_schedule():
    assert "sweep_orphans" in inspect.getsource(_load().cleanup_loop)


def test_a_listing_failure_does_not_stop_the_sweep():
    src = inspect.getsource(_load().sweep_orphans)
    assert src.count("except Exception as exc:") >= 2
