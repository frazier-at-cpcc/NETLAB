"""Attaching and releasing a student's persistent home.

Two failures here cost a student their work, so the rules are about
identity and about teardown.

The home key must be stable for the life of a course. The broker forwards
the upstream subject unchanged as user_id, so the subject half is stable
across sections and terms; the issuer half is a deployment constant rather
than anything carried on a launch, because every per-launch candidate can be
rotated and rotating it orphans every directory on the NAS while the work is
still sitting there.

Teardown must revoke the key it granted, read back from the row. The export
otherwise keeps serving an address that is about to be recycled onto another
student's VM.
"""

import inspect
import pathlib
import sys
import types


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


# --- identity ----------------------------------------------------------


def test_the_issuer_is_a_deployment_constant_not_a_launch_value():
    """An OAuth consumer key can be rotated. Keying homes on one would
    change every key and orphan every directory."""
    m = _load()
    src = inspect.getsource(m)
    assert 'HOME_KEY_ISSUER = os.getenv("HOME_KEY_ISSUER", "ltibroker")' in src


def test_the_subject_is_the_forwarded_upstream_subject():
    """The broker sends user_id = actor.upstream_sub, so user_id IS the
    Brightspace subject and is stable across sections and terms."""
    m = _load()
    src = inspect.getsource(m.provision_vm) + inspect.getsource(m)
    assert "csc228_home.home_key(HOME_KEY_ISSUER, request.user_id)" in src


def test_a_student_with_no_subject_gets_no_home():
    """home_key refuses an empty subject rather than hashing one. Hashing it
    would put every such student in one shared directory."""
    m = _load()
    src = inspect.getsource(m)
    attach = src.split("template_choice.persistent_home and CSC228_NAS_VMID")[1]
    assert "if request.user_id:" in attach
    assert "cannot derive a home key" in attach


# --- scope -------------------------------------------------------------


def test_only_a_family_that_asks_for_a_home_attempts_one():
    """The attach runs a script only the CSC 228 image carries, so a NOS
    session must never try it."""
    m = _load()
    assert "if template_choice.persistent_home and CSC228_NAS_VMID:" in inspect.getsource(m)


def test_no_nas_configured_disables_homes_everywhere():
    m = _load()
    assert m.CSC228_NAS_VMID == 0 or m.CSC228_NAS_VMID > 0
    assert 'os.getenv("CSC228_NAS_VMID", "0")' in inspect.getsource(m)


def test_a_failed_attach_leaves_the_session_without_a_home():
    """A lab with no home beats no lab. The launch page then tells the
    student to download their work."""
    m = _load()
    src = inspect.getsource(m)
    assert "has no persistent home, continuing " in src


def test_the_caller_does_not_assert_a_cause_it_cannot_see():
    """Only attach_home sees the script's output, so it owns the severity
    and the diagnosis. This line adds the session id and nothing else."""
    m = _load()
    src = inspect.getsource(m)
    attach = src.split("template_choice.persistent_home and CSC228_NAS_VMID")[1]
    assert "names the cause" in attach
    assert "local home" not in attach


def test_the_attach_result_is_what_sets_home_attached():
    """home_attached drives what the student is told, so it must come from
    the attach actually succeeding, not from the family being configured."""
    m = _load()
    src = inspect.getsource(m)
    assert "SET home_key = $2, home_attached = $3 " in src
    assert "session_id, key, attached," in src


def test_the_home_attaches_before_the_terminal_exists():
    """The student's first shell must already see the directory."""
    m = _load()
    src = inspect.getsource(m)
    attach_at = src.index("csc228_home.provision_home(")
    ssh_at = src.index('logger.info(f"Waiting for SSH on {vm_ip}...")')
    assert attach_at < ssh_at


# --- teardown ----------------------------------------------------------


def test_the_grant_is_released_on_the_single_teardown_path():
    """A clean end, expiry, idle reclaim, and the stuck reaper all route
    through destroy_session_internal."""
    m = _load()
    assert "await release_session_home(db, session_id)" in inspect.getsource(
        m.destroy_session_internal
    )


def test_the_key_is_read_back_rather_than_recomputed():
    """Recomputing at teardown would revoke a different student's directory
    if the derivation ever changed."""
    m = _load()
    src = inspect.getsource(m.release_session_home)
    assert "SELECT vm_ip, home_key FROM vm_sessions" in src
    assert "home_key(" not in src


def test_a_session_that_never_had_a_home_is_left_alone():
    m = _load()
    src = inspect.getsource(m.release_session_home)
    assert 'not row["home_key"]' in src


def test_the_grant_is_released_before_the_vm_is_destroyed():
    """The mount lives on the VM. Destroying it first leaves the export
    serving an address nobody holds."""
    m = _load()
    src = inspect.getsource(m.destroy_session_internal)
    assert src.index("release_session_home") < src.index("destroy_vm(")


def test_a_failed_revoke_is_logged_loudly():
    """revoke_home never raises, so without this the export would keep
    serving an address about to be recycled onto another student's VM, and
    nothing would say so."""
    m = _load()
    src = inspect.getsource(m.release_session_home)
    assert "logger.error" in src
    assert "was NOT revoked" in src


def test_the_migration_keeps_homes_off_for_every_other_course():
    sql = pathlib.Path("migrations/013_persistent_home.sql").read_text()
    assert "persistent_home BOOLEAN NOT NULL DEFAULT FALSE" in sql
    assert "WHERE slug_prefix = 'csc228-'" in sql
    assert "home_key VARCHAR(32)" in sql
