import asyncio
import json
import logging
import os
import stat
import subprocess
import sys

import pytest

from api.tokens import (
    LAB_XAPI_WRAPPER,
    GradeTokenAlreadyAssigned,
    assign_grade_token,
    get_passback_url,
    hash_grade_token,
    inject_guest_xapi_config,
    mint_grade_token,
    nested_xapi_config_command,
    nested_xapi_email_command,
)


class TokenStubPool:
    """In-memory stand-in for asyncpg. Stores hash by session_id."""

    def __init__(self, existing_hash=None):
        self.calls = []
        self.existing_hash = existing_hash

    async def fetchval(self, sql, *args):
        self.calls.append(("fetchval", sql, args))
        return self.existing_hash

    async def execute(self, sql, *args):
        self.calls.append(("execute", sql, args))
        self.existing_hash = args[1]
        return "UPDATE 1"


def _sql(call):
    return " ".join(call[1].split())


def test_mint_grade_token_is_urlsafe_and_unique():
    a = mint_grade_token()
    b = mint_grade_token()
    assert a != b
    assert len(a) >= 32
    assert "/" not in a


def test_hash_grade_token_is_sha256_hex():
    import hashlib
    digest = hash_grade_token("unit-test-token")
    assert digest == hashlib.sha256(b"unit-test-token").hexdigest()
    assert digest != "unit-test-token"


def test_provision_stores_hash_not_plaintext():
    db = TokenStubPool()

    token = asyncio.run(assign_grade_token(db, "sess-1"))

    assert token
    assert token != db.existing_hash
    assert db.existing_hash == hash_grade_token(token)
    execute_calls = [c for c in db.calls if c[0] == "execute"]
    assert len(execute_calls) == 1
    sql = _sql(execute_calls[0])
    assert "UPDATE vm_sessions" in sql
    assert "grade_token_hash" in sql
    assert execute_calls[0][2] == ("sess-1", db.existing_hash)
    assert token not in execute_calls[0][2]


def test_second_assign_grade_token_does_not_rotate():
    db = TokenStubPool()
    first = asyncio.run(assign_grade_token(db, "sess-1"))
    stored = db.existing_hash

    with pytest.raises(GradeTokenAlreadyAssigned):
        asyncio.run(assign_grade_token(db, "sess-1"))

    assert db.existing_hash == stored == hash_grade_token(first)
    execute_calls = [c for c in db.calls if c[0] == "execute"]
    assert len(execute_calls) == 1


def test_assign_logs_session_id_not_token(caplog):
    db = TokenStubPool()

    with caplog.at_level(logging.INFO):
        token = asyncio.run(assign_grade_token(db, "sess-abc"))

    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "sess-abc" in text
    assert token not in text


def test_nested_xapi_config_command_quotes_token_and_claims_provision():
    token = "abc_TOKEN-1"
    cmd = nested_xapi_config_command("student", "workstation", "token", token)
    assert "LAB_XAPI_PROVISION=1 " + LAB_XAPI_WRAPPER + " xapi-config token --provision" in cmd
    assert f"--provision {token}" in cmd
    assert cmd.startswith(
        "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null student@workstation "
    )


def test_passback_url_default(monkeypatch):
    monkeypatch.delenv("PASSBACK_URL", raising=False)
    assert get_passback_url() == "https://labapi.labsconnect.org/api/grade"


def test_inject_failure_warns_without_token_or_destroy(caplog):
    token = "super-secret-token-value"
    commands = []

    async def run_ssh(ip, user, password, command, timeout=60):
        commands.append(command)
        return False, f"ssh failed running {command}"

    with caplog.at_level(logging.WARNING):
        asyncio.run(
            inject_guest_xapi_config(
                run_ssh,
                vm_ip="10.0.0.1",
                ssh_user="kiosk",
                ssh_password="redhat",
                nested_user="student",
                nested_host="workstation",
                token=token,
                passback="https://labapi.labsconnect.org/api/grade",
                session_id="sess-zz",
            )
        )

    assert len(commands) == 3
    assert LAB_XAPI_WRAPPER + " xapi-config token" in commands[0]
    assert LAB_XAPI_WRAPPER + " xapi-config passback" in commands[1]
    assert LAB_XAPI_WRAPPER + " xapi-config session-id" in commands[2]
    assert "sess-zz" in commands[2]
    assert "--provision" in commands[0]
    assert "--provision" in commands[1]
    assert "--provision" in commands[2]
    assert "LAB_XAPI_PROVISION=1" in commands[0]
    assert "LAB_XAPI_PROVISION=1" in commands[1]
    assert "LAB_XAPI_PROVISION=1" in commands[2]
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "sess-zz" in text
    assert token not in text
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_run_ssh_timeout_does_not_log_token_or_password(caplog, monkeypatch):
    import subprocess
    from api.ssh import run_ssh_command

    sentinel = "SENTINEL-GRADE-TOKEN"
    password = "super-secret-ssh-password"
    command = f"lab xapi-config token {sentinel}"
    leaked = subprocess.TimeoutExpired(
        cmd=["sshpass", "-p", password, "ssh", "kiosk@10.0.0.1", command],
        timeout=1,
    )
    assert sentinel in str(leaked)
    assert password in str(leaked)

    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 1))

    monkeypatch.setattr("api.ssh.subprocess.run", boom)

    with caplog.at_level(logging.ERROR):
        success, output = asyncio.run(
            run_ssh_command("10.0.0.1", "kiosk", password, command, timeout=1)
        )

    assert success is False
    text = "\n".join(r.getMessage() for r in caplog.records)
    combined = f"{text}\n{output}"
    assert sentinel not in combined
    assert password not in combined
    assert command not in combined
    assert "SSH command failed" in text


def test_injection_claims_provisioner_authority():
    from api.tokens import nested_xapi_config_command

    cmd = nested_xapi_config_command("student", "workstation", "token", "s3cr3t")

    assert "LAB_XAPI_PROVISION=1" in cmd
    assert "--provision" in cmd
    assert "--provision s3cr3t" in cmd


# --- Execution-based quoting verification ---------------------------------
#
# nested_xapi_config_command's string is interpreted by TWO real shells
# before it reaches `lab`, not one: the outer virtual machine's login shell
# (invoked by its sshd to run the string this test's `sh -c` call stands in
# for), and then the nested guest's login shell (invoked by ITS sshd to run
# the embedded `ssh ... 'bash -lc ...'` call, once the outer shell has
# stripped its layer of quoting). A prior version of this command wrapped
# the value in single quotes that lived INSIDE a double-quoted `bash -lc
# "..."` argument -- double quotes do not neutralize `$( )`, backticks, or
# `$VAR`, so the nested guest's shell expanded them before `bash -lc` ever
# ran, and a value containing a single quote broke the command outright.
# Pattern-matching substrings cannot catch that; only actually executing the
# string through both shell layers can. The `ssh` shim below stands in for
# hop two by taking its last argv element (the remote command string ssh
# would have sent verbatim) and running it through a fresh `sh -c`, exactly
# as a real sshd invokes the remote user's login shell.

_SSH_SHIM = f"""#!{sys.executable}
import subprocess
import sys

subprocess.run(["sh", "-c", sys.argv[-1]])
"""

def _lab_shim(which):
    """A stand-in for one of the two binaries named `lab` on a real guest.

    `which` is "wrapper" for the lab-xapi wrapper at its install path and
    "redhat_lab" for Red Hat's own /usr/local/bin/lab, which is what plain
    `lab` resolves to in a non-interactive shell. Recording which one ran
    is the whole point: the production failure was not a quoting bug but a
    resolution bug, and only the identity of the answering binary reveals it.
    """
    return f"""#!{sys.executable}
import json
import os
import sys

with open(os.environ["LAB_SHIM_OUTPUT"], "w") as f:
    json.dump(
        {{
            "which": {which!r},
            "argv": sys.argv[1:],
            "provision_env": os.environ.get("LAB_XAPI_PROVISION"),
        }},
        f,
    )
"""


def _write_shim(path, content):
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _run_command_for_real(cmd, tmp_path):
    """Execute a generated command string through two real shell re-parses
    (the outer VM hop, then the nested guest hop) with `ssh` and `lab`
    replaced by shims, and return what the `lab` shim actually received.
    """
    home = tmp_path / "home"
    bin_dir = tmp_path / "bin"
    wrapper_dir = home / ".local" / "share" / "lab-xapi"
    wrapper_dir.mkdir(parents=True)
    bin_dir.mkdir()

    _write_shim(bin_dir / "ssh", _SSH_SHIM)

    # Red Hat's own `lab`, reachable as bare `lab` on PATH. A guest always
    # has this one; the wrapper is only ever reachable by its install path
    # or through an interactive-shell alias that a `bash -lc` hop will not
    # expand. If the generated command calls bare `lab`, THIS answers, which
    # is exactly what happened in production.
    _write_shim(bin_dir / "lab", _lab_shim("redhat_lab"))
    _write_shim(wrapper_dir / "lab-xapi", _lab_shim("wrapper"))

    output_file = tmp_path / "lab_received.json"
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["HOME"] = str(home)
    env["LAB_SHIM_OUTPUT"] = str(output_file)
    env.pop("LAB_XAPI_PROVISION", None)

    result = subprocess.run(
        ["sh", "-c", cmd],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )

    if not output_file.exists():
        raise AssertionError(
            "lab shim never ran (command likely broke mid-parse):\n"
            f"generated cmd: {cmd}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return json.loads(output_file.read_text())


ADVERSARIAL_VALUES = [
    pytest.param("s3cr3t-token-value", id="plain_token"),
    pytest.param("$(id)", id="command_substitution"),
    pytest.param("`id`", id="backtick_substitution"),
    pytest.param("$HOME", id="variable_expansion"),
    pytest.param("it's a token", id="embedded_single_quote"),
    pytest.param("hello * world", id="space_and_glob"),
]


@pytest.mark.parametrize("value", ADVERSARIAL_VALUES)
def test_nested_xapi_config_command_survives_real_shell_layers(value, tmp_path):
    cmd = nested_xapi_config_command("student", "workstation", "token", value)

    received = _run_command_for_real(cmd, tmp_path)

    assert received["which"] == "wrapper", (
        "bare `lab` resolved to Red Hat's binary instead of the lab-xapi "
        "wrapper; the guest would be left with no token"
    )
    assert received["argv"] == ["xapi-config", "token", "--provision", value]
    assert received["provision_env"] == "1"


# --- Email path: same defect, deliberately NOT provisioner-locked --------
#
# `main.py` built the xAPI email-configuration command by hand with the
# identical broken nesting (value single-quoted inside a double-quoted
# `bash -lc "..."` argument). It is worse than the token/passback/session-id
# case: `request.user_email` comes from the inbound LTI launch
# (`lis_person_contact_email_primary`), so it crosses a trust boundary the
# provisioner-generated values never do. Unlike those values, email must
# NOT gain `--provision` or `LAB_XAPI_PROVISION=1` -- the design deliberately
# leaves email overridable by the student, since the LRS actor is their own
# mailbox. Both this command and the token/passback/session-id command now
# go through the same shared `nested_ssh_command` layer-quoting builder;
# only the inner command each one builds differs.


@pytest.mark.parametrize("value", ADVERSARIAL_VALUES)
def test_nested_xapi_email_command_survives_real_shell_layers(value, tmp_path):
    cmd = nested_xapi_email_command("student", "workstation", value)

    received = _run_command_for_real(cmd, tmp_path)

    assert received["which"] == "wrapper"
    assert received["argv"] == ["xapi-config", "email", value]
    assert received["provision_env"] is None


def test_nested_xapi_email_command_never_gains_provisioner_authority():
    cmd = nested_xapi_email_command("student", "workstation", "student@example.edu")

    assert "--provision" not in cmd
    assert "LAB_XAPI_PROVISION" not in cmd
    assert LAB_XAPI_WRAPPER + " xapi-config email student@example.edu" in cmd


def test_inject_success_logs_session_id_not_token(caplog):
    token = "super-secret-token-value"
    commands = []

    async def run_ssh(ip, user, password, command, timeout=60):
        commands.append(command)
        return True, f"configured {command}"

    with caplog.at_level(logging.INFO):
        asyncio.run(
            inject_guest_xapi_config(
                run_ssh,
                vm_ip="10.0.0.1",
                ssh_user="kiosk",
                ssh_password="redhat",
                nested_user="student",
                nested_host="workstation",
                token=token,
                passback="https://labapi.labsconnect.org/api/grade",
                session_id="sess-zz",
            )
        )

    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "sess-zz" in text
    assert token not in text
    assert "WARNING" not in [r.levelname for r in caplog.records]
    assert any(
        LAB_XAPI_WRAPPER + " xapi-config session-id" in cmd and "sess-zz" in cmd
        for cmd in commands
    )
    assert token not in "".join(commands[2:])
