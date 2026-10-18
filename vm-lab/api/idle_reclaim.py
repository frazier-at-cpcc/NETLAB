"""Reclaiming abandoned lab VMs.

A CSC 228 session runs for eight hours because the labs run three to four
and a student who takes a break must not lose the VM. Nothing reclaimed a
session early, so a student who finished in two hours held 24 GB for the
remaining six.

tmux made that worse rather than better. Closing the tab is now the correct
thing to do, because the shell survives it, so abandonment became both
invisible and durable.

The rule is deliberately conservative, because destroying a working lab is
far worse than holding an idle one. A session is idle only when all three
signals agree, and any signal that cannot be read counts as active. A failed
probe must never destroy a student's work.

  1. No terminal attached. tmux reports its own clients, so this is the
     student's browser actually being connected.
  2. No recent JupyterLab activity. A student reading a notebook has no
     terminal attached and no CPU load, and is not idle.
  3. VM CPU below a floor. This is what catches the long run with the tab
     closed, which is exactly what tmux exists to protect.

Proxmox reports CPU without touching the guest, which matters because a
guest cannot be trusted to report its own idleness.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Below this fraction of a core the VM is doing nothing a student would miss.
CPU_IDLE_FRACTION = 0.05
# A notebook touched this recently means someone is working in it.
JUPYTER_IDLE_MINUTES = 15
JUPYTER_PORT = 8888
PROBE_TIMEOUT_SECONDS = 10

# guest-exec runs as root, and tmux addresses a server by socket rather than
# by owner. A bare `tmux list-clients` as root therefore inspects ROOT's
# socket at /tmp/tmux-0/default, finds nothing, and reports no client while
# the student is attached to their own server. That reads as idle in the
# dangerous direction, so the student's socket is always named explicitly.
# One constant to change if the image's student uid is ever not 1001.
TMUX_SOCKET = "/tmp/tmux-1001/default"
TMUX_SESSION = "lab"


async def terminal_attached(proxmox, node: str, vmid: int, guest_exec) -> bool:
    """True when a browser is connected to the tmux session.

    Returns True on any failure. An unreadable terminal is treated as
    attached, so a broken probe holds the VM rather than reclaiming it.
    """
    try:
        result = await guest_exec(
            proxmox, node, vmid,
            ["/usr/bin/tmux", "-S", TMUX_SOCKET, "list-clients", "-t", TMUX_SESSION],
        )
    except Exception as exc:
        logger.warning(
            "VM %s: could not read tmux clients, treating as attached: %s",
            vmid, type(exc).__name__,
        )
        return True

    # tmux exits non-zero when the session does not exist, which means no
    # client is attached to it. Any other failure is unknown, so hold.
    if result.exit_code != 0:
        stderr = (result.stderr or "").lower()
        # tmux says one of these when the student's server is genuinely not
        # there, which is the only non-zero exit that means "nobody attached".
        if (
            "no server running" in stderr
            or "error connecting to" in stderr
            or "can't find session" in stderr
        ):
            return False
        logger.warning(
            "VM %s: tmux exited %s, treating as attached", vmid, result.exit_code
        )
        return True

    return bool((result.stdout or "").strip())


async def jupyter_recently_active(
    vm_ip: str, http_get, now: Optional[datetime] = None
) -> bool:
    """True when JupyterLab reports activity inside the idle window.

    Returns True on any failure, including a closed port. Jupyter is enabled
    at boot, so a closed 8888 is a fault rather than evidence of idleness,
    and a fault must not cost the student their VM.
    """
    now = now or datetime.now(timezone.utc)
    url = f"http://{vm_ip}:{JUPYTER_PORT}/api/status"
    try:
        payload = await http_get(url, PROBE_TIMEOUT_SECONDS)
        last = payload["last_activity"]
    except Exception as exc:
        logger.warning(
            "VM at %s: could not read Jupyter status, treating as active: %s",
            vm_ip, type(exc).__name__,
        )
        return True

    try:
        stamp = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        logger.warning("VM at %s: unparseable last_activity %r", vm_ip, last)
        return True

    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)

    return (now - stamp).total_seconds() < JUPYTER_IDLE_MINUTES * 60


def vm_busy(proxmox, node: str, vmid: int) -> bool:
    """True when the VM is using more than the idle floor of a core.

    Returns True on any failure, so an unreadable VM is held.
    """
    try:
        status = proxmox.nodes(node).qemu(vmid).status.current.get()
        cpu = float(status.get("cpu", 1.0))
    except Exception as exc:
        logger.warning(
            "VM %s: could not read CPU, treating as busy: %s", vmid, type(exc).__name__
        )
        return True
    return cpu >= CPU_IDLE_FRACTION


async def session_is_idle(
    proxmox, node: str, vmid: int, vm_ip: Optional[str], guest_exec, http_get,
    now: Optional[datetime] = None,
) -> bool:
    """True only when every signal agrees the session is abandoned.

    Checks the cheapest decisive signal first. Any single active signal is
    enough to hold the VM.
    """
    if vm_busy(proxmox, node, vmid):
        return False
    if await terminal_attached(proxmox, node, vmid, guest_exec):
        return False
    # Without an address Jupyter cannot be probed, and an unprobeable signal
    # counts as active.
    if not vm_ip:
        return False
    if await jupyter_recently_active(vm_ip, http_get, now=now):
        return False
    return True
