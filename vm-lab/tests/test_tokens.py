import asyncio
import logging

import pytest

from api.tokens import (
    GradeTokenAlreadyAssigned,
    assign_grade_token,
    get_passback_url,
    hash_grade_token,
    inject_guest_xapi_config,
    mint_grade_token,
    nested_xapi_config_command,
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


def test_nested_xapi_config_command_quotes_token_and_omits_provision():
    token = "abc_TOKEN-1"
    cmd = nested_xapi_config_command("student", "workstation", "token", token)
    assert "lab xapi-config token" in cmd
    assert "--provision" not in cmd
    assert f"'\\''{token}'\\''" in cmd
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
    assert "lab xapi-config token" in commands[0]
    assert "lab xapi-config passback" in commands[1]
    assert "lab xapi-config session-id" in commands[2]
    assert "sess-zz" in commands[2]
    assert "--provision" not in commands[0]
    assert "--provision" not in commands[1]
    assert "--provision" not in commands[2]
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
    assert any("lab xapi-config session-id" in cmd and "sess-zz" in cmd for cmd in commands)
    assert token not in "".join(commands[2:])
