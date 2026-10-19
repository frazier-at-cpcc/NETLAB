"""Sessions that never finished coming up.

Only 'running' sessions were ever reaped, so a failed clone sat in
'provisioning' forever. The one-live-lab-per-class index made that a lockout
rather than a leak: it covers exactly the states a stuck session sits in, so
the student cannot start another lab until someone intervenes. Before the
index they could launch again and get a second VM.
"""

import inspect
import pathlib
import sys
import types


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


def test_the_reaper_covers_exactly_the_states_the_index_locks():
    """If these two sets ever diverge, a session can be locked out by the
    index while the reaper cannot see it."""
    api_main = _load_api_main()
    reaper_sql = " ".join(api_main.STUCK_SESSION_SQL.split())
    index_sql = pathlib.Path("migrations/010_one_lab_per_class.sql").read_text()
    assert "status IN ('provisioning', 'starting')" in reaper_sql
    for state in ("provisioning", "starting"):
        assert state in index_sql


def test_a_running_session_is_never_reaped_as_stuck():
    """Expiry and idleness own running sessions. This reaper must not."""
    api_main = _load_api_main()
    assert "'running'" not in api_main.STUCK_SESSION_SQL


def test_the_window_is_generous_enough_to_survive_a_slow_boot():
    """Reaping a session that is merely slow destroys a VM while a student
    watches it come up."""
    api_main = _load_api_main()
    assert api_main.STUCK_SESSION_MINUTES >= 15


def test_the_window_is_configurable():
    api_main = _load_api_main()
    src = inspect.getsource(api_main)
    assert 'os.getenv("STUCK_SESSION_MINUTES"' in src


def test_the_age_is_measured_from_creation():
    api_main = _load_api_main()
    sql = " ".join(api_main.STUCK_SESSION_SQL.split())
    assert "created_at <" in sql


def test_a_session_that_never_got_a_vm_is_still_released():
    """A clone that failed early leaves vm_id NULL. Teardown tolerates that,
    and the row must still be marked so the index releases the student."""
    api_main = _load_api_main()
    teardown = inspect.getsource(api_main.destroy_session_internal)
    assert "if vm_id and proxmox_api:" in teardown


def test_one_bad_row_does_not_strand_the_rest():
    """A single session that will not tear down must not keep every other
    student locked out."""
    src = inspect.getsource(_load_api_main().reap_stuck_sessions)
    assert "except Exception" in src.split("for row in stuck:")[1]


def test_the_reason_distinguishes_a_timeout_from_an_ending():
    src = inspect.getsource(_load_api_main().reap_stuck_sessions)
    assert 'reason="provisioning_timeout"' in src


def test_the_reaper_runs_on_the_same_schedule_as_the_others():
    src = inspect.getsource(_load_api_main().cleanup_loop)
    assert "reap_stuck_sessions" in src


def test_a_failure_to_list_candidates_does_not_kill_the_loop():
    """cleanup_loop catches, but a raise here would skip idle reclaim for
    that pass."""
    src = inspect.getsource(_load_api_main().reap_stuck_sessions)
    head = src.split("for row in stuck:")[0]
    assert "except Exception" in head and "return" in head


# --- destroying the VM itself ------------------------------------------
#
# Found by running a real teardown: Proxmox refused the delete with "VM 1003
# is running - destroy failed", the error was logged and swallowed, and the
# VM stayed on the node. The session row said destroyed while the disk and
# the pool slot were still held. Seven orphaned student VMs had accumulated
# against a pool of about twelve.


def test_the_destroy_waits_for_the_vm_to_actually_stop():
    """A fixed five-second sleep is a race a 24 GB guest loses."""
    src = inspect.getsource(_load_api_main().destroy_vm)
    assert "time.sleep(5)" not in src
    assert "VM_STOP_TIMEOUT_SECONDS" in src
    assert "if current.get('status') != 'running':" in src


def test_a_vm_that_will_not_stop_is_reported_rather_than_deleted():
    """Issuing the delete anyway fails and gets swallowed, which is how the
    leak stayed invisible."""
    src = inspect.getsource(_load_api_main().destroy_vm)
    assert "NOT deleting" in src
    assert "still holding a pool slot" in src


def test_the_stop_budget_is_configurable_and_forwarded():
    api_main = _load_api_main()
    assert 'os.getenv("VM_STOP_TIMEOUT_SECONDS"' in inspect.getsource(api_main)
    assert "VM_STOP_TIMEOUT_SECONDS=" in pathlib.Path("docker-compose.yml").read_text()


def test_recording_is_not_finalized_for_a_family_that_does_not_record():
    """It logged a duration and a null size for a file never written."""
    api_main = _load_api_main()
    src = inspect.getsource(api_main.destroy_session_internal)
    assert "_session_was_recorded(db, session_id)" in src


def test_an_unanswerable_recording_question_assumes_it_recorded():
    """Dropping a real recording is worse than finalizing a missing one."""
    src = inspect.getsource(_load_api_main()._session_was_recorded)
    assert "return True" in src
    assert "coalesce(t.terminal_recording, TRUE)" in src
