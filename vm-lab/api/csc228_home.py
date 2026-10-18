"""Per-session persistent homes for CSC 228, over the Proxmox guest agent.

Students have sudo on their VMs and Docker access grants root regardless, so
a plain NFS export every student VM can reach lets root on any one of them
mount it and read every other student's home. That is a FERPA exposure, not
an untidiness. The NAS therefore exports one student's directory to one VM's
address at a time, and this module is the control path for that grant.

Everything runs through the guest agent, on the NAS VM and on the student VM
alike, so the NAS needs no management network and lab-api needs no route to
it. The NAS address is read from the guest agent on every session rather than
configured, because a DHCP reservation is a convention and not a guarantee.

The pairing this module has to keep is grant and revoke. A grant that is
never revoked is the same exposure with extra steps, so revoke runs from
``destroy_session_internal``, which is the one path both a clean end and a
reaped timeout travel. The NAS also expires grants older than nine hours by
itself, and that is defense in depth rather than the mechanism: it leaves a
window in which a recycled address inherits another student's access.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

NAS_EXPORT_PATH = "/srv/csc228-homes"
GRANT_SCRIPT = "/usr/local/sbin/csc228-nas-grant"
REVOKE_SCRIPT = "/usr/local/sbin/csc228-nas-revoke"
ATTACH_SCRIPT = "/usr/local/sbin/csc228-attach-home"

# The lab network every student VM and the NAS share. The NAS is identified
# by holding an address here, not by what its interface happens to be named.
LAB_SUBNET_PREFIX = "172.18.8."

# The guest agent runs a command asynchronously and reports completion by
# polling. Attaching a mount is quick; the ceiling is for an agent that
# answers but never finishes, which must not hold a provisioning task open.
EXEC_TIMEOUT_SECONDS = 60
POLL_INTERVAL_SECONDS = 1.0


def home_key(issuer: str, subject: str) -> str:
    """Derive the per-student directory name.

    Keyed on the LTI subject and never on name or email, because a provider's
    claim policy may withhold both while the subject always survives. The
    issuer is included so that two deployments cannot collide on one key.
    """
    if not issuer or not subject:
        raise ValueError("home key requires both an issuer and a subject")
    material = f"{issuer}|{subject}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


async def guest_exec(proxmox, node: str, vmid: int, argv: list[str]) -> ExecResult:
    """Run one command inside a VM through the Proxmox guest agent.

    Returns the result rather than raising on a non-zero exit, because every
    caller here distinguishes between outcomes the scripts report by code.
    A transport failure raises, since that is not an outcome the scripts
    describe.
    """
    started = proxmox.nodes(node).qemu(vmid).agent.exec.post(command=argv)
    pid = started.get("pid") if isinstance(started, dict) else None
    if pid is None:
        raise RuntimeError(f"guest agent on VM {vmid} returned no pid")

    waited = 0.0
    while waited < EXEC_TIMEOUT_SECONDS:
        status = proxmox.nodes(node).qemu(vmid).agent("exec-status").get(pid=pid)
        if status.get("exited"):
            return ExecResult(
                exit_code=int(status.get("exitcode", 0) or 0),
                stdout=(status.get("out-data") or "").strip(),
                stderr=(status.get("err-data") or "").strip(),
            )
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        waited += POLL_INTERVAL_SECONDS

    raise TimeoutError(f"guest exec on VM {vmid} did not finish in {EXEC_TIMEOUT_SECONDS}s")


def nas_address(proxmox, node: str, nas_vmid: int, prefix: str = LAB_SUBNET_PREFIX) -> str:
    """Read the NAS VM's address on the lab network from its guest agent.

    Selected by subnet rather than by interface name. An interface name is a
    property of the guest's kernel and udev rules, so a rebuilt or differently
    virtualised NAS can answer on enp0s18 or ens19 while being the same host
    on the same network. The address being in the lab subnet is what actually
    makes it the one a student VM can mount from.

    Read every session rather than configured, so that a NAS which reboots
    onto a different lease does not silently strand every later mount.
    """
    info = proxmox.nodes(node).qemu(nas_vmid).agent("network-get-interfaces").get()
    for iface in info.get("result", []):
        for addr in iface.get("ip-addresses", []):
            if addr.get("ip-address-type") != "ipv4":
                continue
            ip = addr.get("ip-address") or ""
            if ip.startswith(prefix):
                return ip
    raise RuntimeError(
        f"NAS VM {nas_vmid} reported no IPv4 address in {prefix}0/24"
    )


async def grant_home(proxmox, node: str, nas_vmid: int, vm_ip: str, key: str) -> bool:
    """Export one student's directory to one VM address.

    Returns False when the NAS refuses, which is a session that must run on a
    local home rather than one that must fail. Raising here would turn a
    storage problem into a launch failure.
    """
    result = await guest_exec(proxmox, node, nas_vmid, [GRANT_SCRIPT, vm_ip, key])
    if result.ok and result.stdout.startswith("GRANTED"):
        logger.info("NAS granted %s… to %s", key[:8], vm_ip)
        return True
    # Exit 2 is DENIED and 3 is ERROR, but a script aborting under set -e
    # exits 1 with no prefix at all. Anything that is not an exit-0 GRANTED
    # is a refusal, so the unrecognised case cannot read as success.
    reason = {2: "denied", 3: "error"}.get(result.exit_code, "failed")
    logger.warning(
        "NAS %s granting %s… to %s (exit %s): %s",
        reason, key[:8], vm_ip, result.exit_code, (result.stdout or result.stderr)[:200],
    )
    return False


async def attach_home(proxmox, node: str, vmid: int, nas_ip: str, key: str) -> bool:
    """Mount the granted directory on the student VM.

    ATTACHED means the session persists. LOCAL-HOME means it works and does
    not persist, which the student has to be told, because silently losing a
    session's work is worse than a session that never started.
    """
    result = await guest_exec(
        proxmox, node, vmid, [ATTACH_SCRIPT, nas_ip, NAS_EXPORT_PATH, key]
    )
    if result.ok and result.stdout.startswith("ATTACHED"):
        logger.info("VM %s attached persistent home %s…", vmid, key[:8])
        return True
    logger.warning(
        "VM %s is running on a local home and will not persist: %s",
        vmid, (result.stdout or result.stderr)[:200],
    )
    return False


async def revoke_home(proxmox, node: str, nas_vmid: int, vm_ip: str) -> bool:
    """Withdraw a VM address's access to the export.

    Never raises. This runs inside teardown, and a revoke that fails must not
    prevent the VM from being destroyed; a destroyed VM with a stale grant is
    recoverable, a surviving VM is a leaked 24 GB of a twelve-slot pool.
    """
    try:
        result = await guest_exec(proxmox, node, nas_vmid, [REVOKE_SCRIPT, vm_ip])
    except Exception as exc:
        logger.error("NAS revoke for %s failed to run: %s", vm_ip, type(exc).__name__)
        return False
    # REVOKED is returned even when no grant existed, so a second teardown
    # of the same session is not an error.
    if result.ok and result.stdout.startswith("REVOKED"):
        logger.info("NAS revoked access for %s", vm_ip)
        return True
    logger.error(
        "NAS revoke for %s returned %s: %s",
        vm_ip, result.exit_code, (result.stdout or result.stderr)[:200],
    )
    return False


async def provision_home(
    proxmox, node: str, nas_vmid: int, vmid: int, vm_ip: str, key: str
) -> bool:
    """Grant, then attach, in that order. Returns whether the home persists.

    The order is load-bearing and not a convention. The NAS grant is what
    creates the student's directory on first use, with its ownership and its
    quota, and then exports exactly that directory to exactly this VM.
    csc228-attach-home only mounts; it cannot create, because the session VM
    cannot see the export root. Attaching first therefore fails for every
    student's first ever launch and succeeds for everyone else, which is the
    kind of fault that reaches production looking like a flake.

    Never raises. A session without a persistent home is a session the
    student must be told about, not a launch that fails.
    """
    try:
        nas_ip = nas_address(proxmox, node, nas_vmid)
    except Exception as exc:
        logger.error(
            "VM %s has no persistent home: NAS address unavailable (%s)",
            vmid, type(exc).__name__,
        )
        return False

    if not await grant_home(proxmox, node, nas_vmid, vm_ip, key):
        return False
    return await attach_home(proxmox, node, vmid, nas_ip, key)
