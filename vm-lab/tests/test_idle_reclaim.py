"""Reclaiming abandoned lab VMs.

The property that matters most is the direction of failure. Destroying a
working lab costs a student three hours of work; holding an abandoned one
costs 24 GB for a while. Every probe that cannot answer must therefore read
as active, and most of this file is about that.
"""

import pathlib
import sys
import types
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from api import idle_reclaim

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


NODE = "rh-labhost"
VMID = 2301
VM_IP = "172.18.8.57"
NOW = datetime(2026, 10, 18, 15, 0, tzinfo=timezone.utc)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@dataclass
class FakeExec:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""


def exec_returning(result=None, raises=False):
    async def _exec(proxmox, node, vmid, argv):
        if raises:
            raise RuntimeError("guest agent not responding")
        return result
    return _exec


def http_returning(payload=None, raises=False):
    async def _get(url, timeout):
        if raises:
            raise RuntimeError("connection refused")
        return payload
    return _get


class FakeProxmox:
    """Minimal proxmox stub exposing nodes(n).qemu(v).status.current.get()."""

    def __init__(self, cpu=0.0, raises=False):
        self._cpu = cpu
        self._raises = raises

    def nodes(self, node):
        return self

    def qemu(self, vmid):
        return self

    @property
    def status(self):
        return self

    @property
    def current(self):
        return self

    def get(self):
        if self._raises:
            raise RuntimeError("proxmox unreachable")
        return {"cpu": self._cpu}


# --- the fail-safe direction -------------------------------------------


def test_an_unreadable_cpu_counts_as_busy():
    """Proxmox being unreachable must never cost a student their VM."""
    assert idle_reclaim.vm_busy(FakeProxmox(raises=True), NODE, VMID) is True


@pytest.mark.anyio
async def test_an_unreadable_terminal_counts_as_attached():
    """A broken guest agent is not evidence that nobody is working."""
    assert await idle_reclaim.terminal_attached(
        None, NODE, VMID, exec_returning(raises=True)
    ) is True


@pytest.mark.anyio
async def test_an_unexpected_tmux_failure_counts_as_attached():
    """Only tmux's own "no session" answers mean no client. Anything else is
    unknown, and unknown holds the VM."""
    assert await idle_reclaim.terminal_attached(
        None, NODE, VMID, exec_returning(FakeExec(exit_code=1, stderr="protocol error"))
    ) is True


@pytest.mark.anyio
async def test_a_closed_jupyter_port_counts_as_active():
    """Jupyter is enabled at boot, so a closed 8888 is a fault rather than
    idleness, and a fault must not reclaim the session."""
    assert await idle_reclaim.jupyter_recently_active(
        VM_IP, http_returning(raises=True), now=NOW
    ) is True


@pytest.mark.anyio
async def test_an_unparseable_last_activity_counts_as_active():
    assert await idle_reclaim.jupyter_recently_active(
        VM_IP, http_returning({"last_activity": "not a date"}), now=NOW
    ) is True


@pytest.mark.anyio
async def test_a_session_with_no_address_is_never_idle():
    """Without an address Jupyter cannot be probed at all.

    Every other signal here says idle, and the notebook payload would too if
    it were reached, so only the missing-address guard can hold this VM.
    """
    stale = (NOW - timedelta(hours=3)).isoformat().replace("+00:00", "Z")
    assert await idle_reclaim.session_is_idle(
        FakeProxmox(cpu=0.0), NODE, VMID, None,
        exec_returning(FakeExec(exit_code=1, stderr="no server running")),
        http_returning({"last_activity": stale}), now=NOW,
    ) is False


def exec_only_on_student_socket(stdout):
    """Answers only when the probe names the student's tmux socket.

    guest-exec runs as root, so a bare `tmux list-clients` inspects root's
    socket at /tmp/tmux-0/default rather than the student's. tmux answers
    that probe with "no server running", which the rule reads as nobody
    attached, so the terminal axis would report idle while the student is
    working. This stub reproduces that: drop the -S argument and the probe
    gets the root-socket answer.
    """
    async def _exec(proxmox, node, vmid, argv):
        # Literal on purpose. Reading the constant back from the module would
        # make this stub move with a mutation of it and assert nothing.
        if "-S" in argv and "/tmp/tmux-1001/default" in argv:
            return FakeExec(stdout=stdout)
        return FakeExec(
            exit_code=1,
            stderr="no server running on /tmp/tmux-0/default",
        )
    return _exec


# --- the root-socket defect --------------------------------------------


@pytest.mark.anyio
async def test_the_probe_names_the_students_socket_not_roots():
    """The defect this guards: as root, the bare probe finds no server and
    the rule concludes nobody is attached. A student reading output at an
    idle prompt would then be reclaimed out from under themselves."""
    assert await idle_reclaim.terminal_attached(
        None, NODE, VMID,
        exec_only_on_student_socket("/dev/pts/0: lab [80x24]"),
    ) is True


@pytest.mark.anyio
async def test_a_session_is_not_idle_when_only_the_student_socket_answers():
    """End to end: every other signal says idle, so only a correctly
    targeted tmux probe can hold this VM."""
    stale = (NOW - timedelta(hours=3)).isoformat().replace("+00:00", "Z")
    assert await idle_reclaim.session_is_idle(
        FakeProxmox(cpu=0.0), NODE, VMID, VM_IP,
        exec_only_on_student_socket("/dev/pts/0: lab [80x24]"),
        http_returning({"last_activity": stale}), now=NOW,
    ) is False


@pytest.mark.anyio
async def test_a_failure_to_reach_the_student_socket_counts_as_attached():
    """tmux reports a missing socket as a connect error, which is only
    "nobody attached" when it names the student's socket."""
    assert await idle_reclaim.terminal_attached(
        None, NODE, VMID,
        exec_returning(FakeExec(
            exit_code=1,
            stderr="error connecting to /tmp/tmux-1001/default (No such file or directory)",
        )),
    ) is False


def test_the_probe_targets_the_session_the_terminal_actually_creates():
    """spawn_ttyd_container creates `lab`. A probe naming any other session
    gets "can't find session", which reads as nobody attached, and every
    student would look idle."""
    import inspect
    api_main = _load_api_main()
    spawn = inspect.getsource(api_main.spawn_ttyd_container)
    assert f"new-session -A -s {idle_reclaim.TMUX_SESSION}" in spawn


def test_the_socket_belongs_to_the_student_not_root():
    """guest-exec runs as root. Root's socket is /tmp/tmux-0/default and
    holds no student session."""
    assert idle_reclaim.TMUX_SOCKET == "/tmp/tmux-1001/default"


# --- the signals themselves --------------------------------------------


@pytest.mark.anyio
async def test_tmux_reporting_a_client_means_attached():
    assert await idle_reclaim.terminal_attached(
        None, NODE, VMID,
        exec_returning(FakeExec(stdout="/dev/pts/0: lab [80x24]")),
    ) is True


@pytest.mark.anyio
async def test_no_tmux_server_means_nothing_is_attached():
    for stderr in ("no server running on /tmp/tmux-0/default",
                   "can't find session: lab"):
        assert await idle_reclaim.terminal_attached(
            None, NODE, VMID, exec_returning(FakeExec(exit_code=1, stderr=stderr))
        ) is False


@pytest.mark.anyio
async def test_empty_tmux_output_means_nothing_is_attached():
    assert await idle_reclaim.terminal_attached(
        None, NODE, VMID, exec_returning(FakeExec(stdout="   \n"))
    ) is False


def test_a_loaded_vm_is_busy():
    assert idle_reclaim.vm_busy(FakeProxmox(cpu=0.42), NODE, VMID) is True


def test_an_unloaded_vm_is_not_busy():
    assert idle_reclaim.vm_busy(FakeProxmox(cpu=0.001), NODE, VMID) is False


@pytest.mark.anyio
async def test_a_recently_touched_notebook_is_active():
    recent = (NOW - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    assert await idle_reclaim.jupyter_recently_active(
        VM_IP, http_returning({"last_activity": recent}), now=NOW
    ) is True


@pytest.mark.anyio
async def test_a_long_untouched_notebook_is_not_active():
    stale = (NOW - timedelta(hours=3)).isoformat().replace("+00:00", "Z")
    assert await idle_reclaim.jupyter_recently_active(
        VM_IP, http_returning({"last_activity": stale}), now=NOW
    ) is False


# --- the combined rule -------------------------------------------------


@pytest.mark.anyio
async def test_every_signal_must_agree_before_a_session_is_idle():
    stale = (NOW - timedelta(hours=3)).isoformat().replace("+00:00", "Z")
    assert await idle_reclaim.session_is_idle(
        FakeProxmox(cpu=0.0), NODE, VMID, VM_IP,
        exec_returning(FakeExec(exit_code=1, stderr="no server running")),
        http_returning({"last_activity": stale}), now=NOW,
    ) is True


@pytest.mark.anyio
async def test_a_long_run_with_the_tab_closed_is_not_idle():
    """The case tmux exists to protect. No terminal attached, notebook
    untouched, but the VM is working: a quantisation run."""
    stale = (NOW - timedelta(hours=3)).isoformat().replace("+00:00", "Z")
    assert await idle_reclaim.session_is_idle(
        FakeProxmox(cpu=0.95), NODE, VMID, VM_IP,
        exec_returning(FakeExec(exit_code=1, stderr="no server running")),
        http_returning({"last_activity": stale}), now=NOW,
    ) is False


@pytest.mark.anyio
async def test_a_student_reading_output_at_an_idle_prompt_is_not_idle():
    """Attached terminal, no CPU. Reclaiming this would close the lab in
    front of someone looking at it."""
    stale = (NOW - timedelta(hours=3)).isoformat().replace("+00:00", "Z")
    assert await idle_reclaim.session_is_idle(
        FakeProxmox(cpu=0.0), NODE, VMID, VM_IP,
        exec_returning(FakeExec(stdout="/dev/pts/0: lab [80x24]")),
        http_returning({"last_activity": stale}), now=NOW,
    ) is False


@pytest.mark.anyio
async def test_a_student_working_in_a_notebook_is_not_idle():
    """No terminal, no CPU between cells, but the notebook is in use."""
    recent = (NOW - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    assert await idle_reclaim.session_is_idle(
        FakeProxmox(cpu=0.0), NODE, VMID, VM_IP,
        exec_returning(FakeExec(exit_code=1, stderr="no server running")),
        http_returning({"last_activity": recent}), now=NOW,
    ) is False


# --- scope and bookkeeping ---------------------------------------------


def test_only_families_that_opt_in_are_considered():
    """Every NOS course must be untouched by this."""
    api_main = _load_api_main()
    sql = " ".join(api_main.IDLE_CANDIDATE_SQL.split())
    assert "t.idle_reclaim_minutes IS NOT NULL" in sql
    assert "s.status = 'running'" in sql


def test_returning_activity_resets_the_clock():
    """The window measures continuous idleness, not time since launch."""
    import inspect
    api_main = _load_api_main()
    src = inspect.getsource(api_main.reclaim_idle_sessions)
    assert "SET idle_since = NULL" in src


def test_the_reason_is_recorded_so_a_student_can_be_told():
    import inspect
    api_main = _load_api_main()
    assert 'reason="idle_reclaimed"' in inspect.getsource(api_main.reclaim_idle_sessions)
    assert "destroyed_reason" in inspect.getsource(api_main.destroy_session_internal)


def test_the_migration_keeps_reclaim_off_by_default():
    sql = pathlib.Path("migrations/011_idle_reclaim.sql").read_text()
    assert "ADD COLUMN IF NOT EXISTS idle_reclaim_minutes INTEGER" in sql
    assert "DEFAULT" not in sql.split("idle_reclaim_minutes INTEGER")[1].split(";")[0]
    assert "idle_reclaim_minutes = 45" in sql
