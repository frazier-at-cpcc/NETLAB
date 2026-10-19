"""Who the terminal connects as.

SSH_USER and NESTED_SSH_ENABLED were deployment-wide, defaulting to kiosk
and true, which is right for the Red Hat Academy images: land on the outer
VM as kiosk, then jump to student@workstation inside it.

CSC 228 has neither a kiosk user nor a nested workstation. On the
deployment defaults a launch fails twice over: provisioning waits for an
SSH login as kiosk and marks the session errored on timeout, and if it got
past that the terminal would run `ssh kiosk@vm ssh student@workstation`
against hosts that do not exist, so the tmux session persistence depends on
would never be created.
"""

import inspect
import pathlib
import re
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


# --- the family decides ------------------------------------------------


def test_the_template_carries_the_terminal_identity():
    m = _load()
    choice = m.TemplateChoice(template_id=1, snapshot_name="")
    assert choice.ssh_user is None
    assert choice.nested_ssh is None


def test_no_row_means_todays_behaviour():
    """Every NOS course has no lab_templates row, so both values are None
    and the deployment defaults apply unchanged."""
    m = _load()
    src = inspect.getsource(m.spawn_ttyd_container)
    assert "user = ssh_user or SSH_USER" in src
    assert "use_nested = NESTED_SSH_ENABLED if nested is None else nested" in src


def test_a_family_can_turn_the_nested_hop_off():
    """False must be honoured, not treated as absent. `nested or DEFAULT`
    would read False as unset and keep the hop on."""
    m = _load()
    src = inspect.getsource(m.spawn_ttyd_container)
    assert "if nested is None else nested" in src
    assert "nested or NESTED_SSH_ENABLED" not in src


def test_provisioning_honours_it_too():
    """The terminal is reached only if provisioning succeeds, and
    provisioning waits for an SSH login as this user before starting nested
    VMs. Fixing only the terminal would still fail every CSC 228 launch
    with an SSH login timeout."""
    m = _load()
    src = inspect.getsource(m)
    assert "terminal_user = template_choice.ssh_user or SSH_USER" in src
    assert "if use_nested_hop:" in src
    assert "wait_for_ssh_login(vm_ip, terminal_user, SSH_PASSWORD" in src


def test_both_decision_points_are_covered():
    """Exactly the module-level constant definition should remain as a bare
    use; every decision must go through the per-family value."""
    m = _load()
    src = inspect.getsource(m)
    bare = re.findall(r"^\s*if NESTED_SSH_ENABLED:", src, re.M)
    assert bare == [], f"a decision still reads the global directly: {bare}"


def test_the_ssh_commands_never_use_the_global_user():
    m = _load()
    src = inspect.getsource(m.spawn_ttyd_container)
    assert "{SSH_USER}@{vm_ip}" not in src
    assert "{user}@{vm_ip}" in src


def test_the_call_site_passes_the_family_values():
    m = _load()
    src = inspect.getsource(m)
    assert "ssh_user=template_choice.ssh_user," in src
    assert "nested=template_choice.nested_ssh," in src


# --- configuration reaching the container ------------------------------


def test_every_variable_the_api_reads_is_forwarded_by_compose():
    """A variable the code reads but compose does not pass through cannot be
    set at all: it silently keeps its default however the .env is written.
    That is how CSC228_NAS_VMID would have been unsettable."""
    api = pathlib.Path("api/main.py").read_text()
    compose = pathlib.Path("docker-compose.yml").read_text()
    read = set(re.findall(r'os\.getenv\(\s*["\']([A-Z0-9_]+)', api))
    missing = sorted(name for name in read if name not in compose)
    assert missing == [], f"not forwarded by docker-compose.yml: {missing}"


def test_homes_are_off_unless_a_nas_is_named():
    compose = pathlib.Path("docker-compose.yml").read_text()
    assert "CSC228_NAS_VMID=${CSC228_NAS_VMID:-0}" in compose


def test_the_home_key_issuer_carries_its_warning_where_it_is_set():
    """The hazard belongs next to the setting, not only in the code."""
    for path in ("docker-compose.yml", ".env.example"):
        text = pathlib.Path(path).read_text()
        assert "HOME_KEY_ISSUER" in text
        assert "orphan" in text.lower() or "rekey" in text.lower()


def test_the_migration_only_changes_csc228():
    sql = pathlib.Path("migrations/014_per_course_terminal_identity.sql").read_text()
    assert "WHERE slug_prefix = 'csc228-'" in sql
    assert "nested_ssh = FALSE" in sql
    assert "ssh_user = 'student'" in sql


# --- how the terminal authenticates ------------------------------------
#
# SSH_PASSWORD is deployment-wide and carries the Red Hat Academy default.
# The CSC 228 image does not use it, so the terminal failed to log in for
# every CSC 228 student: the lab provisioned, the home attached, and the
# student got a terminal that answered "Permission denied".


def test_a_family_can_authenticate_with_the_key_instead():
    m = _load()
    src = inspect.getsource(m.spawn_ttyd_container)
    assert 'use_key = ssh_auth == "key"' in src
    assert "ssh -i {TTYD_KEY_PATH}" in src


def test_the_password_remains_the_default_for_every_other_course():
    """NOS 120 and NOS 220 store NULL and must keep using sshpass."""
    m = _load()
    src = inspect.getsource(m.spawn_ttyd_container)
    assert "sshpass -e ssh" in src
    sig = inspect.signature(m.spawn_ttyd_container)
    assert sig.parameters["ssh_auth"].default is None


def test_key_auth_refuses_to_fall_back_to_another_identity():
    """IdentitiesOnly stops ssh trying an agent or default key, which would
    make a misconfigured image look like it worked on one machine."""
    m = _load()
    assert "IdentitiesOnly=yes" in inspect.getsource(m.spawn_ttyd_container)


def test_both_ssh_branches_use_the_chosen_credential():
    """The nested branch and the direct branch share one prefix, so neither
    can quietly keep using the password."""
    m = _load()
    src = inspect.getsource(m.spawn_ttyd_container)
    assert src.count("{prefix} {user}@{vm_ip}") == 2
    assert "sshpass -e ssh -t -o StrictHostKeyChecking" not in src


def test_the_call_site_passes_the_auth_mode():
    m = _load()
    assert "ssh_auth=template_choice.ssh_auth," in inspect.getsource(m)


def test_the_migration_only_switches_csc228_to_the_key():
    sql = pathlib.Path("migrations/016_terminal_auth.sql").read_text()
    assert "ssh_auth = 'key'" in sql
    assert "WHERE slug_prefix = 'csc228-'" in sql
    assert "IN ('password', 'key')" in sql


# --- session length ----------------------------------------------------


def test_the_request_does_not_default_over_the_family():
    """A concrete default on the request is always truthy, so it won over
    the family's session_hours and every CSC 228 lab expired after 4 hours
    instead of 8. Found by running a real provision, not by a test."""
    m = _load()
    assert m.ProvisionRequest.model_fields["session_hours"].default is None


def test_an_explicit_request_still_wins():
    """A caller that genuinely asks for a length must still get it."""
    m = _load()
    src = inspect.getsource(m.provision_vm)
    assert "request.session_hours or template_choice.session_hours" in src


# --- honest logging -----------------------------------------------------


def test_the_spawn_log_reports_what_it_actually_did():
    """It claimed "with recording" unconditionally, including for CSC 228
    where recording is off."""
    m = _load()
    src = inspect.getsource(m.spawn_ttyd_container)
    assert "with recording" not in src
    assert 'recording=%s, auth=%s' in src
