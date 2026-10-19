"""A student can grade any lab they have opened, from any session.

A grade cell belonged to one VM session: grades.py joined
course_session_id straight against vm_sessions.session_id. In NOS 220 a
student runs fifteen labs inside one workstation VM, so only the single lab
whose link they clicked could pass back. Everything else reported "no
gradebook column", which reads as a broken lab and names no cause.

course_key is added alongside rather than replacing course_session_id.
Rewriting that column would have merged 332 of 640 cells, because students
relaunch the same lab repeatedly and each launch mints a new sourcedid, and
all 690 grade events hang off the cells that would have vanished.
"""

import inspect
import pathlib
import sys
import types


def _load(module):
    for name, attrs in (("asyncpg", {}), ("proxmoxer", {"ProxmoxAPI": object})):
        if name not in sys.modules:
            try:
                __import__(name)
            except ImportError:
                stub = types.ModuleType(name)
                for attr, value in attrs.items():
                    setattr(stub, attr, value)
                sys.modules[name] = stub
    import importlib
    return importlib.import_module(module)


# --- the lookup ---------------------------------------------------------


def test_a_lab_is_found_by_course_not_by_vm_session():
    sql = " ".join(_load("api.grades").SELECT_CELL_SQL.split())
    assert "course_key = (" in sql
    assert "SELECT course_session_key FROM vm_sessions WHERE session_id = $1" in sql


def test_the_old_session_scoped_match_still_works():
    """Cells written before this existed have no course_key. Dropping the
    fallback would strand every one of them."""
    sql = " ".join(_load("api.grades").SELECT_CELL_SQL.split())
    assert "OR course_session_id = $1" in sql


def test_a_relaunch_supersedes_rather_than_duplicates():
    """A student relaunching the same lab mints a new sourcedid. The newest
    cell is the one Brightspace expects a score against."""
    sql = " ".join(_load("api.grades").SELECT_CELL_SQL.split())
    assert "ORDER BY created_at DESC" in sql
    assert "LIMIT 1" in sql


# --- the key is written -------------------------------------------------


def test_the_cell_records_the_course_key():
    src = _load("api.cells").UPSERT_GRADE_CELL_SQL
    assert "course_key" in src


def test_a_relaunch_refreshes_the_key_rather_than_leaving_it_stale():
    assert "course_key = EXCLUDED.course_key" in _load("api.cells").UPSERT_GRADE_CELL_SQL


def test_the_launch_sends_it():
    src = pathlib.Path("lti/persist_cell.py").read_text()
    assert '"course_key": getattr(ctx, "course_session_key", None)' in src


def test_the_deferred_path_carries_it_too():
    """The Redis stash exists because the cookie does not survive the
    Brightspace iframe. Without the key in the stash, the path that matters
    most would write a cell nothing can find by course."""
    src = pathlib.Path("lti/persist_cell.py").read_text()
    fields = src.split("_PENDING_FIELDS = (")[1].split(")")[0]
    assert '"course_session_key"' in fields
    assert "course_session_key=fields.get" in src


# --- nothing was destroyed ----------------------------------------------


def test_the_session_scoped_column_is_untouched():
    """640 cells and 690 grade events depend on it."""
    sql = pathlib.Path("migrations/019_cells_keyed_by_course.sql").read_text()
    assert "ADD COLUMN IF NOT EXISTS course_key" in sql
    assert "DROP COLUMN" not in sql
    assert "DELETE" not in sql.upper().replace("DELETED", "")


def test_the_backfill_only_fills_what_is_empty():
    sql = pathlib.Path("migrations/019_cells_keyed_by_course.sql").read_text()
    assert "c.course_key IS NULL" in sql
