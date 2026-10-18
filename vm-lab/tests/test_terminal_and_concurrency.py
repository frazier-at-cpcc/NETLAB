"""Terminal continuity, recording, and one lab per student per class.

Three properties a course family states on its lab_templates row, plus the
constraint that keeps a student to one live VM.
"""

import inspect
import pathlib
import sys
import types

import pytest


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


# --- terminal continuity ----------------------------------------------


def test_a_persistent_terminal_runs_the_shell_inside_tmux():
    """ttyd spawns its command once per client connection, so without tmux a
    closed tab kills the ssh session and everything running in it. A
    three-hour lab cannot lose its work to a dropped network."""
    src = inspect.getsource(_load_api_main().spawn_ttyd_container)
    assert "tmux new-session -A -s lab" in src


def test_the_tmux_session_attaches_rather_than_replacing():
    """-A attaches to `lab` when it exists. Without it a reconnect would
    start a second shell beside the first and the student would see an empty
    prompt while their job ran invisibly."""
    src = inspect.getsource(_load_api_main().spawn_ttyd_container)
    assert "new-session -A" in src
    assert "kill-session" not in src


def test_persistence_is_opt_in_so_the_nested_courses_are_untouched():
    """The NOS courses reach the student workstation through a second ssh
    hop, which is a different shape."""
    sig = inspect.signature(_load_api_main().spawn_ttyd_container)
    assert sig.parameters["persist"].default is False


# --- recording ---------------------------------------------------------


def test_recording_can_be_turned_off_for_a_family():
    src = inspect.getsource(_load_api_main().spawn_ttyd_container)
    assert "if record:" in src


def test_recording_stays_on_by_default():
    """Every existing course records today and must keep doing so."""
    sig = inspect.signature(_load_api_main().spawn_ttyd_container)
    assert sig.parameters["record"].default is True


def test_a_database_without_the_recording_column_still_records():
    """A deployment still on 008 has no terminal_recording column, and the
    absence must read as "records", not as "does not"."""
    src = inspect.getsource(_load_api_main().resolve_lab_template)
    assert "True if recording is None else bool(recording)" in src


# --- one lab per class -------------------------------------------------


def test_provisioning_returns_the_existing_session_rather_than_a_second_vm():
    """Each VM holds a slot out of roughly twelve, and two terminals onto two
    VMs is a student doing the lab twice and submitting the wrong one."""
    src = inspect.getsource(_load_api_main().provision_vm)
    assert "status IN ('provisioning', 'starting', 'running')" in src
    assert '"reused": True' in src


def test_the_database_enforces_it_too():
    """The application check and the insert cannot be atomic across two
    requests, so a double click needs the index to lose the race."""
    sql = pathlib.Path("migrations/010_one_lab_per_class.sql").read_text()
    assert "CREATE UNIQUE INDEX" in sql
    assert "ON vm_sessions (course_session_key)" in sql
    assert "status IN ('provisioning', 'starting', 'running')" in sql


def test_a_finished_session_does_not_block_a_new_one():
    """Destroyed and errored sessions are excluded, so a student can start
    again once the previous one ends."""
    sql = pathlib.Path("migrations/010_one_lab_per_class.sql").read_text()
    assert "destroyed" not in sql.split("WHERE", 1)[1]


# --- session length ----------------------------------------------------


def test_the_family_sets_its_own_session_length():
    """A four-hour lab against the four-hour default loses the VM to the
    first break a student takes."""
    src = inspect.getsource(_load_api_main().provision_vm)
    assert "template_choice.session_hours" in src


def test_the_ceiling_still_applies():
    src = inspect.getsource(_load_api_main().provision_vm)
    assert "MAX_SESSION_HOURS" in src


def test_csc228_asks_for_the_full_eight_hours():
    sql = pathlib.Path("migrations/009_lab_terminal_behaviour.sql").read_text()
    assert "session_hours = 8" in sql
    assert "terminal_persist = TRUE" in sql
    assert "terminal_recording = FALSE" in sql
