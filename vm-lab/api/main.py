"""
VM Orchestration API

Manages the lifecycle of student VMs:
- Provisioning new VMs from QCOW2 templates
- Spawning ttyd containers for web terminal access
- Session management and cleanup
- Session recording for audit/review
"""

import os
import time
import secrets
import string
import subprocess
import logging
import asyncio
import json
import re
from typing import Optional, List
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel
import asyncpg
import docker
import libvirt

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

DOMAIN = os.getenv("DOMAIN", "lab.yourdomain.com")
BASE_QCOW = os.getenv("BASE_QCOW", "/var/lib/libvirt/images/rhel-academy-base.qcow2")
VM_RAM_MB = int(os.getenv("VM_RAM_MB", "16384"))
VM_VCPUS = int(os.getenv("VM_VCPUS", "4"))
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://lab:lab@localhost:5432/lab")
SSH_PRIVATE_KEY_PATH = os.getenv("SSH_PRIVATE_KEY_PATH", "/app/keys/id_ed25519")

# Session recordings directory
RECORDINGS_DIR = os.getenv("RECORDINGS_DIR", "/var/lib/vm-lab/recordings")

# VM network configuration
VM_NETWORK_NAME = "lab-net"
VM_BRIDGE = "virbr1"

# Session defaults
DEFAULT_SESSION_HOURS = 4
MAX_SESSION_HOURS = 8

# Docker network for ttyd containers
DOCKER_NETWORK = "vm-lab_lab-network"


# ============================================================================
# Pydantic Models
# ============================================================================

class ProvisionRequest(BaseModel):
    session_key: Optional[str] = None
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    course_id: Optional[str] = None
    course_title: Optional[str] = None
    assignment_id: Optional[str] = None
    assignment_title: Optional[str] = None
    session_hours: Optional[int] = DEFAULT_SESSION_HOURS


class Session(BaseModel):
    session_id: str
    url: str
    vm_ip: str
    status: str
    user_name: Optional[str] = None
    course_title: Optional[str] = None
    assignment_title: Optional[str] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class SessionList(BaseModel):
    sessions: List[Session]
    total: int


class Recording(BaseModel):
    id: int
    session_id: str
    user_name: Optional[str] = None
    user_email: Optional[str] = None
    course_title: Optional[str] = None
    assignment_title: Optional[str] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    file_size_bytes: Optional[int] = None
    status: str


class RecordingList(BaseModel):
    recordings: List[Recording]
    total: int


# ============================================================================
# Application Setup
# ============================================================================

# Global connections
docker_client: Optional[docker.DockerClient] = None
libvirt_conn: Optional[libvirt.virConnect] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - setup and teardown."""
    global docker_client, libvirt_conn

    # Create recordings directory
    os.makedirs(RECORDINGS_DIR, exist_ok=True)
    logger.info(f"Recordings directory: {RECORDINGS_DIR}")

    # Setup database pool
    app.state.db = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=2,
        max_size=10
    )
    logger.info("Database pool created")

    # Setup Docker client
    docker_client = docker.from_env()
    logger.info("Docker client connected")

    # Setup libvirt connection
    try:
        libvirt_conn = libvirt.open("qemu:///system")
        logger.info("Libvirt connected")
    except libvirt.libvirtError as e:
        logger.error(f"Failed to connect to libvirt: {e}")
        libvirt_conn = None

    # Start cleanup background task
    cleanup_task = asyncio.create_task(cleanup_loop(app.state.db))

    yield

    # Cleanup
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

    await app.state.db.close()
    if libvirt_conn:
        libvirt_conn.close()
    logger.info("Connections closed")


app = FastAPI(
    title="Red Hat Academy Lab - VM Orchestration API",
    description="Manages VM lifecycle for student lab environments",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Helper Functions
# ============================================================================

def generate_session_id(length: int = 8) -> str:
    """Generate a random alphanumeric session ID."""
    chars = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))


def sanitize_filename(name: str) -> str:
    """Sanitize a string for use in filenames."""
    if not name:
        return "unknown"
    # Replace spaces and special chars with underscores
    sanitized = re.sub(r'[^\w\-.]', '_', name)
    # Remove consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized)
    return sanitized[:50]  # Limit length


def get_recording_path(session_id: str, user_email: str, user_name: str, started_at: datetime) -> tuple:
    """
    Generate organized recording file paths.
    Structure: /recordings/YYYY/MM/DD/email_name_sessionid_timestamp.{log,timing}
    """
    date_path = started_at.strftime("%Y/%m/%d")
    timestamp = started_at.strftime("%H%M%S")

    safe_email = sanitize_filename(user_email.split('@')[0] if user_email else "unknown")
    safe_name = sanitize_filename(user_name)

    base_name = f"{safe_email}_{safe_name}_{session_id}_{timestamp}"

    dir_path = os.path.join(RECORDINGS_DIR, date_path)
    os.makedirs(dir_path, exist_ok=True)

    recording_path = os.path.join(dir_path, f"{base_name}.log")
    timing_path = os.path.join(dir_path, f"{base_name}.timing")

    return recording_path, timing_path


async def get_db():
    """Get database connection from pool."""
    return app.state.db


async def allocate_ip(db: asyncpg.Pool, session_id: str) -> Optional[str]:
    """Allocate an IP address from the pool."""
    result = await db.fetchval(
        "SELECT allocate_ip($1)",
        session_id
    )
    return result


async def release_ip(db: asyncpg.Pool, session_id: str):
    """Release an IP address back to the pool."""
    await db.execute("SELECT release_ip($1)", session_id)


async def log_event(db: asyncpg.Pool, session_id: str, event_type: str, event_data: dict = None):
    """Log a session event."""
    await db.execute(
        """
        INSERT INTO vm_session_events (session_id, event_type, event_data)
        VALUES ($1, $2, $3)
        """,
        session_id, event_type, json.dumps(event_data) if event_data else None
    )


async def create_recording_entry(
    db: asyncpg.Pool,
    session_id: str,
    user_id: str,
    user_email: str,
    user_name: str,
    course_id: str,
    course_title: str,
    assignment_id: str,
    assignment_title: str,
    recording_path: str,
    timing_path: str
) -> int:
    """Create a recording entry in the database."""
    recording_id = await db.fetchval(
        """
        INSERT INTO session_recordings (
            session_id, user_id, user_email, user_name,
            course_id, course_title, assignment_id, assignment_title,
            recording_path, timing_path, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'recording')
        RETURNING id
        """,
        session_id, user_id, user_email, user_name,
        course_id, course_title, assignment_id, assignment_title,
        recording_path, timing_path
    )
    return recording_id


async def finalize_recording(db: asyncpg.Pool, session_id: str):
    """Finalize a recording when session ends."""
    # Get recording info
    recording = await db.fetchrow(
        "SELECT id, recording_path, timing_path, started_at FROM session_recordings WHERE session_id = $1 AND status = 'recording'",
        session_id
    )

    if not recording:
        return

    # Calculate duration and file size
    ended_at = datetime.utcnow()
    duration_seconds = None
    file_size_bytes = None

    if recording['started_at']:
        duration_seconds = int((ended_at - recording['started_at']).total_seconds())

    if recording['recording_path'] and os.path.exists(recording['recording_path']):
        file_size_bytes = os.path.getsize(recording['recording_path'])

    # Update recording
    await db.execute(
        """
        UPDATE session_recordings
        SET ended_at = $2, duration_seconds = $3, file_size_bytes = $4, status = 'completed'
        WHERE id = $1
        """,
        recording['id'], ended_at, duration_seconds, file_size_bytes
    )

    logger.info(f"Finalized recording for session {session_id}: {duration_seconds}s, {file_size_bytes} bytes")


def create_vm_xml(
    vm_name: str,
    overlay_path: str,
    ram_mb: int,
    vcpus: int,
    mac_address: str
) -> str:
    """Generate libvirt XML for VM definition."""
    return f"""
<domain type='kvm'>
  <name>{vm_name}</name>
  <uuid></uuid>
  <memory unit='MiB'>{ram_mb}</memory>
  <currentMemory unit='MiB'>{ram_mb}</currentMemory>
  <vcpu placement='static'>{vcpus}</vcpu>

  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>

  <features>
    <acpi/>
    <apic/>
  </features>

  <cpu mode='host-passthrough' check='none'/>

  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
  </clock>

  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>

  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>

    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='writeback' discard='unmap'/>
      <source file='{overlay_path}'/>
      <target dev='vda' bus='virtio'/>
    </disk>

    <interface type='network'>
      <mac address='{mac_address}'/>
      <source network='{VM_NETWORK_NAME}'/>
      <model type='virtio'/>
    </interface>

    <serial type='pty'>
      <target port='0'/>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>

    <channel type='unix'>
      <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>

    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'>
      <listen type='address' address='127.0.0.1'/>
    </graphics>

    <video>
      <model type='virtio' heads='1' primary='yes'/>
    </video>

    <memballoon model='virtio'/>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
  </devices>
</domain>
"""


def generate_mac_address() -> str:
    """Generate a random MAC address with local admin prefix."""
    mac = [0x52, 0x54, 0x00,
           secrets.randbelow(256),
           secrets.randbelow(256),
           secrets.randbelow(256)]
    return ':'.join(f'{b:02x}' for b in mac)


async def wait_for_vm_ip(vm_name: str, timeout: int = 120) -> Optional[str]:
    """Wait for VM to get an IP address via DHCP."""
    if not libvirt_conn:
        return None

    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            dom = libvirt_conn.lookupByName(vm_name)
            # Get interfaces from guest agent or ARP
            ifaces = dom.interfaceAddresses(libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)
            for iface_name, iface_data in ifaces.items():
                for addr in iface_data.get('addrs', []):
                    if addr['type'] == 0:  # IPv4
                        return addr['addr']
        except libvirt.libvirtError:
            pass
        await asyncio.sleep(2)

    return None


async def wait_for_ssh(ip: str, timeout: int = 120) -> bool:
    """Wait for SSH to become available on the VM."""
    import socket

    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 22))
            sock.close()
            if result == 0:
                # Give SSH a moment to fully initialize
                await asyncio.sleep(2)
                return True
        except socket.error:
            pass
        await asyncio.sleep(2)

    return False


def spawn_ttyd_container(
    session_id: str,
    vm_ip: str,
    domain: str,
    recording_path: str,
    timing_path: str
) -> Optional[str]:
    """
    Spawn a ttyd container for web terminal access with session recording.

    Uses the `script` command to record all terminal I/O with timing information.
    """
    if not docker_client:
        return None

    container_name = f"ttyd-{session_id}"

    try:
        # Check if container already exists
        try:
            existing = docker_client.containers.get(container_name)
            existing.remove(force=True)
        except docker.errors.NotFound:
            pass

        # Create recording directory inside container mount
        recording_dir = os.path.dirname(recording_path)
        os.makedirs(recording_dir, exist_ok=True)

        # Command that wraps SSH with script for recording
        # script -q -f -t<timing_file> <output_file> -c "<command>"
        # -q = quiet, -f = flush after each write, -t = timing file
        ssh_command = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /keys/id_ed25519 student@{vm_ip}"
        script_command = f"script -q -f -t/recordings/{os.path.relpath(timing_path, RECORDINGS_DIR)} /recordings/{os.path.relpath(recording_path, RECORDINGS_DIR)} -c '{ssh_command}'"

        # Spawn ttyd container with recording
        container = docker_client.containers.run(
            "tsl0922/ttyd:latest",
            command=f"ttyd --writable --port 7681 /bin/sh -c \"{script_command}\"",
            name=container_name,
            detach=True,
            network=DOCKER_NETWORK,
            volumes={
                os.path.dirname(SSH_PRIVATE_KEY_PATH): {
                    'bind': '/keys',
                    'mode': 'ro'
                },
                RECORDINGS_DIR: {
                    'bind': '/recordings',
                    'mode': 'rw'
                }
            },
            labels={
                "traefik.enable": "true",
                f"traefik.http.routers.ttyd-{session_id}.rule": f"Host(`lab-{session_id}.{domain}`)",
                f"traefik.http.routers.ttyd-{session_id}.entrypoints": "websecure",
                f"traefik.http.routers.ttyd-{session_id}.tls": "true",
                f"traefik.http.services.ttyd-{session_id}.loadbalancer.server.port": "7681",
                "lab.session_id": session_id,
                "lab.vm_ip": vm_ip,
                "lab.recording_path": recording_path,
            },
            restart_policy={"Name": "unless-stopped"}
        )

        logger.info(f"Spawned ttyd container with recording: {container_name}")
        return container.id

    except docker.errors.APIError as e:
        logger.error(f"Failed to spawn ttyd container: {e}")
        return None


def destroy_ttyd_container(session_id: str):
    """Remove ttyd container."""
    if not docker_client:
        return

    container_name = f"ttyd-{session_id}"
    try:
        container = docker_client.containers.get(container_name)
        container.stop(timeout=5)
        container.remove()
        logger.info(f"Removed ttyd container: {container_name}")
    except docker.errors.NotFound:
        pass
    except docker.errors.APIError as e:
        logger.error(f"Failed to remove ttyd container: {e}")


def destroy_vm(vm_name: str, overlay_path: str):
    """Destroy VM and remove overlay disk."""
    if libvirt_conn:
        try:
            dom = libvirt_conn.lookupByName(vm_name)
            if dom.isActive():
                dom.destroy()
            dom.undefine()
            logger.info(f"Destroyed VM: {vm_name}")
        except libvirt.libvirtError as e:
            logger.error(f"Failed to destroy VM {vm_name}: {e}")

    # Remove overlay file
    if overlay_path and os.path.exists(overlay_path):
        try:
            os.remove(overlay_path)
            logger.info(f"Removed overlay: {overlay_path}")
        except OSError as e:
            logger.error(f"Failed to remove overlay {overlay_path}: {e}")


# ============================================================================
# Background Tasks
# ============================================================================

async def cleanup_loop(db: asyncpg.Pool):
    """Background task to cleanup expired sessions."""
    while True:
        try:
            await asyncio.sleep(300)  # Check every 5 minutes
            await cleanup_expired_sessions(db)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Cleanup loop error: {e}")


async def cleanup_expired_sessions(db: asyncpg.Pool):
    """Find and destroy expired sessions."""
    expired = await db.fetch(
        """
        SELECT session_id, vm_name, overlay_path
        FROM vm_sessions
        WHERE status = 'running' AND expires_at < CURRENT_TIMESTAMP
        """
    )

    for row in expired:
        logger.info(f"Cleaning up expired session: {row['session_id']}")
        await destroy_session_internal(
            db,
            row['session_id'],
            row['vm_name'],
            row['overlay_path']
        )


async def destroy_session_internal(
    db: asyncpg.Pool,
    session_id: str,
    vm_name: str,
    overlay_path: str
):
    """Internal function to destroy a session."""
    # Finalize recording before destroying container
    await finalize_recording(db, session_id)

    # Remove ttyd container
    destroy_ttyd_container(session_id)

    # Destroy VM
    destroy_vm(vm_name, overlay_path)

    # Release IP
    await release_ip(db, session_id)

    # Update database
    await db.execute(
        """
        UPDATE vm_sessions
        SET status = 'destroyed', destroyed_at = CURRENT_TIMESTAMP
        WHERE session_id = $1
        """,
        session_id
    )

    # Log event
    await log_event(db, session_id, 'destroyed')


# ============================================================================
# API Endpoints - Sessions
# ============================================================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    db_healthy = False
    libvirt_healthy = False
    docker_healthy = False

    try:
        db = await get_db()
        await db.fetchval("SELECT 1")
        db_healthy = True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")

    if libvirt_conn:
        try:
            libvirt_conn.getHostname()
            libvirt_healthy = True
        except libvirt.libvirtError:
            pass

    if docker_client:
        try:
            docker_client.ping()
            docker_healthy = True
        except docker.errors.APIError:
            pass

    status = "healthy" if all([db_healthy, libvirt_healthy, docker_healthy]) else "degraded"

    return {
        "status": status,
        "database": "connected" if db_healthy else "disconnected",
        "libvirt": "connected" if libvirt_healthy else "disconnected",
        "docker": "connected" if docker_healthy else "disconnected",
        "recordings_dir": RECORDINGS_DIR
    }


@app.get("/api/session/by-key/{session_key:path}", response_model=Session)
async def get_session_by_key(session_key: str):
    """Find existing session by composite key."""
    db = await get_db()

    row = await db.fetchrow(
        """
        SELECT session_id, url, vm_ip, status, user_name, course_title,
               assignment_title, created_at, expires_at
        FROM vm_sessions
        WHERE session_key = $1 AND status = 'running'
        """,
        session_key
    )

    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    # Update last accessed time
    await db.execute(
        "UPDATE vm_sessions SET last_accessed = CURRENT_TIMESTAMP WHERE session_key = $1",
        session_key
    )

    return Session(**dict(row))


@app.post("/api/provision", response_model=Session)
async def provision_vm(request: ProvisionRequest, background_tasks: BackgroundTasks):
    """Provision a new VM for a student."""
    db = await get_db()

    if not libvirt_conn:
        raise HTTPException(status_code=503, detail="Libvirt not available")

    # Verify base image exists
    if not os.path.exists(BASE_QCOW):
        raise HTTPException(
            status_code=503,
            detail=f"Base QCOW2 image not found: {BASE_QCOW}"
        )

    # Generate session ID
    session_id = generate_session_id()
    vm_name = f"student-{session_id}"

    # Calculate expiry
    session_hours = min(request.session_hours or DEFAULT_SESSION_HOURS, MAX_SESSION_HOURS)
    expires_at = datetime.utcnow() + timedelta(hours=session_hours)

    # Allocate IP address
    vm_ip = await allocate_ip(db, session_id)
    if not vm_ip:
        raise HTTPException(status_code=503, detail="No IP addresses available")

    logger.info(f"Provisioning VM {vm_name} with IP {vm_ip}")

    # Generate recording paths
    started_at = datetime.utcnow()
    recording_path, timing_path = get_recording_path(
        session_id,
        request.user_email or "",
        request.user_name or "",
        started_at
    )

    # Create overlay QCOW2
    overlay_path = f"/var/lib/libvirt/images/{vm_name}.qcow2"
    try:
        subprocess.run([
            "qemu-img", "create", "-f", "qcow2",
            "-b", BASE_QCOW,
            "-F", "qcow2",
            overlay_path
        ], check=True, capture_output=True)
        logger.info(f"Created overlay: {overlay_path}")
    except subprocess.CalledProcessError as e:
        await release_ip(db, session_id)
        logger.error(f"Failed to create overlay: {e.stderr.decode()}")
        raise HTTPException(status_code=500, detail="Failed to create VM disk")

    # Generate MAC address
    mac_address = generate_mac_address()

    # Create VM
    vm_xml = create_vm_xml(vm_name, overlay_path, VM_RAM_MB, VM_VCPUS, mac_address)

    try:
        dom = libvirt_conn.defineXML(vm_xml)
        dom.create()
        vm_uuid = dom.UUIDString()
        logger.info(f"Started VM: {vm_name} (UUID: {vm_uuid})")
    except libvirt.libvirtError as e:
        await release_ip(db, session_id)
        os.remove(overlay_path)
        logger.error(f"Failed to start VM: {e}")
        raise HTTPException(status_code=500, detail="Failed to start VM")

    # Create initial database record
    url = f"https://lab-{session_id}.{DOMAIN}"

    await db.execute(
        """
        INSERT INTO vm_sessions (
            session_id, session_key, user_id, user_email, user_name,
            course_id, course_title, assignment_id, assignment_title,
            vm_ip, vm_name, vm_uuid, overlay_path, url, status, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'starting', $15)
        """,
        session_id, request.session_key, request.user_id, request.user_email,
        request.user_name, request.course_id, request.course_title,
        request.assignment_id, request.assignment_title, vm_ip, vm_name,
        vm_uuid, overlay_path, url, expires_at
    )

    await log_event(db, session_id, 'provisioned', {
        'user_id': request.user_id,
        'course_id': request.course_id
    })

    # Wait for VM to be ready and spawn ttyd (in background for faster response)
    async def finalize_provisioning():
        try:
            # Wait for SSH
            logger.info(f"Waiting for SSH on {vm_ip}...")
            ssh_ready = await wait_for_ssh(vm_ip, timeout=120)

            if not ssh_ready:
                logger.error(f"SSH not available on {vm_ip} after timeout")
                await db.execute(
                    "UPDATE vm_sessions SET status = 'error', status_message = 'SSH timeout' WHERE session_id = $1",
                    session_id
                )
                return

            # Create recording entry in database
            await create_recording_entry(
                db, session_id,
                request.user_id, request.user_email, request.user_name,
                request.course_id, request.course_title,
                request.assignment_id, request.assignment_title,
                recording_path, timing_path
            )

            # Spawn ttyd container with recording
            container_id = spawn_ttyd_container(
                session_id, vm_ip, DOMAIN,
                recording_path, timing_path
            )

            if container_id:
                await db.execute(
                    """
                    UPDATE vm_sessions
                    SET status = 'running', started_at = CURRENT_TIMESTAMP,
                        container_id = $2, container_name = $3
                    WHERE session_id = $1
                    """,
                    session_id, container_id, f"ttyd-{session_id}"
                )
                await log_event(db, session_id, 'running', {'recording_path': recording_path})
                logger.info(f"Session {session_id} is now running with recording")
            else:
                await db.execute(
                    "UPDATE vm_sessions SET status = 'error', status_message = 'Container spawn failed' WHERE session_id = $1",
                    session_id
                )

        except Exception as e:
            logger.error(f"Error finalizing provisioning: {e}")
            await db.execute(
                "UPDATE vm_sessions SET status = 'error', status_message = $2 WHERE session_id = $1",
                session_id, str(e)
            )

    background_tasks.add_task(finalize_provisioning)

    return Session(
        session_id=session_id,
        url=url,
        vm_ip=vm_ip,
        status="starting",
        user_name=request.user_name,
        course_title=request.course_title,
        assignment_title=request.assignment_title,
        created_at=datetime.utcnow(),
        expires_at=expires_at
    )


@app.delete("/api/{session_id}")
async def destroy_session(session_id: str):
    """Destroy a VM session."""
    db = await get_db()

    row = await db.fetchrow(
        "SELECT vm_name, overlay_path FROM vm_sessions WHERE session_id = $1",
        session_id
    )

    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    await destroy_session_internal(db, session_id, row['vm_name'], row['overlay_path'])

    return {"status": "destroyed", "session_id": session_id}


@app.get("/api/sessions", response_model=SessionList)
async def list_sessions(
    status: Optional[str] = None,
    course_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """List all sessions with optional filtering."""
    db = await get_db()

    # Build query
    conditions = []
    params = []
    param_count = 0

    if status:
        param_count += 1
        conditions.append(f"status = ${param_count}")
        params.append(status)

    if course_id:
        param_count += 1
        conditions.append(f"course_id = ${param_count}")
        params.append(course_id)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # Get total count
    count_query = f"SELECT COUNT(*) FROM vm_sessions WHERE {where_clause}"
    total = await db.fetchval(count_query, *params)

    # Get sessions
    param_count += 1
    limit_param = param_count
    param_count += 1
    offset_param = param_count

    query = f"""
        SELECT session_id, url, vm_ip, status, user_name, course_title,
               assignment_title, created_at, expires_at
        FROM vm_sessions
        WHERE {where_clause}
        ORDER BY created_at DESC
        LIMIT ${limit_param} OFFSET ${offset_param}
    """

    rows = await db.fetch(query, *params, limit, offset)

    sessions = [Session(**dict(row)) for row in rows]

    return SessionList(sessions=sessions, total=total)


@app.post("/api/{session_id}/extend")
async def extend_session(session_id: str, hours: int = 2):
    """Extend a session's expiry time."""
    db = await get_db()

    hours = min(hours, MAX_SESSION_HOURS)

    result = await db.execute(
        """
        UPDATE vm_sessions
        SET expires_at = CURRENT_TIMESTAMP + INTERVAL '1 hour' * $2
        WHERE session_id = $1 AND status = 'running'
        """,
        session_id, hours
    )

    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Session not found or not running")

    await log_event(db, session_id, 'extended', {'hours': hours})

    return {"status": "extended", "hours": hours}


# ============================================================================
# API Endpoints - Recordings
# ============================================================================

@app.get("/api/recordings", response_model=RecordingList)
async def list_recordings(
    user_email: Optional[str] = None,
    user_name: Optional[str] = None,
    course_id: Optional[str] = None,
    date_from: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    limit: int = 100,
    offset: int = 0
):
    """
    List session recordings with filtering options.

    Filter by:
    - user_email: Student email address
    - user_name: Student name (partial match)
    - course_id: Course identifier
    - date_from/date_to: Date range
    """
    db = await get_db()

    conditions = []
    params = []
    param_count = 0

    if user_email:
        param_count += 1
        conditions.append(f"user_email ILIKE ${param_count}")
        params.append(f"%{user_email}%")

    if user_name:
        param_count += 1
        conditions.append(f"user_name ILIKE ${param_count}")
        params.append(f"%{user_name}%")

    if course_id:
        param_count += 1
        conditions.append(f"course_id = ${param_count}")
        params.append(course_id)

    if date_from:
        param_count += 1
        conditions.append(f"started_at >= ${param_count}::date")
        params.append(date_from)

    if date_to:
        param_count += 1
        conditions.append(f"started_at < (${param_count}::date + interval '1 day')")
        params.append(date_to)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # Get total count
    count_query = f"SELECT COUNT(*) FROM session_recordings WHERE {where_clause}"
    total = await db.fetchval(count_query, *params)

    # Get recordings
    param_count += 1
    limit_param = param_count
    param_count += 1
    offset_param = param_count

    query = f"""
        SELECT id, session_id, user_name, user_email, course_title, assignment_title,
               started_at, ended_at, duration_seconds, file_size_bytes, status
        FROM session_recordings
        WHERE {where_clause}
        ORDER BY started_at DESC
        LIMIT ${limit_param} OFFSET ${offset_param}
    """

    rows = await db.fetch(query, *params, limit, offset)

    recordings = [Recording(**dict(row)) for row in rows]

    return RecordingList(recordings=recordings, total=total)


@app.get("/api/recordings/{recording_id}")
async def get_recording(recording_id: int):
    """Get details of a specific recording."""
    db = await get_db()

    row = await db.fetchrow(
        """
        SELECT r.*, s.vm_ip, s.url
        FROM session_recordings r
        LEFT JOIN vm_sessions s ON r.session_id = s.session_id
        WHERE r.id = $1
        """,
        recording_id
    )

    if not row:
        raise HTTPException(status_code=404, detail="Recording not found")

    return dict(row)


@app.get("/api/recordings/{recording_id}/download")
async def download_recording(recording_id: int):
    """Download the raw recording file (typescript log)."""
    db = await get_db()

    row = await db.fetchrow(
        "SELECT recording_path, user_email, started_at FROM session_recordings WHERE id = $1",
        recording_id
    )

    if not row or not row['recording_path']:
        raise HTTPException(status_code=404, detail="Recording not found")

    if not os.path.exists(row['recording_path']):
        raise HTTPException(status_code=404, detail="Recording file not found on disk")

    # Generate download filename
    date_str = row['started_at'].strftime("%Y%m%d_%H%M%S") if row['started_at'] else "unknown"
    email_part = sanitize_filename(row['user_email'].split('@')[0] if row['user_email'] else "unknown")
    filename = f"recording_{email_part}_{date_str}.log"

    return FileResponse(
        row['recording_path'],
        media_type="text/plain",
        filename=filename
    )


@app.get("/api/recordings/{recording_id}/timing")
async def download_timing(recording_id: int):
    """Download the timing file for playback with scriptreplay."""
    db = await get_db()

    row = await db.fetchrow(
        "SELECT timing_path, user_email, started_at FROM session_recordings WHERE id = $1",
        recording_id
    )

    if not row or not row['timing_path']:
        raise HTTPException(status_code=404, detail="Timing file not found")

    if not os.path.exists(row['timing_path']):
        raise HTTPException(status_code=404, detail="Timing file not found on disk")

    date_str = row['started_at'].strftime("%Y%m%d_%H%M%S") if row['started_at'] else "unknown"
    email_part = sanitize_filename(row['user_email'].split('@')[0] if row['user_email'] else "unknown")
    filename = f"recording_{email_part}_{date_str}.timing"

    return FileResponse(
        row['timing_path'],
        media_type="text/plain",
        filename=filename
    )


@app.get("/api/recordings/{recording_id}/view")
async def view_recording(recording_id: int):
    """
    View recording contents as plain text.
    Useful for quick inspection without downloading.
    """
    db = await get_db()

    row = await db.fetchrow(
        "SELECT recording_path FROM session_recordings WHERE id = $1",
        recording_id
    )

    if not row or not row['recording_path']:
        raise HTTPException(status_code=404, detail="Recording not found")

    if not os.path.exists(row['recording_path']):
        raise HTTPException(status_code=404, detail="Recording file not found on disk")

    # Read file (limit to 1MB for safety)
    try:
        with open(row['recording_path'], 'r', errors='replace') as f:
            content = f.read(1024 * 1024)  # Max 1MB

        # Strip ANSI escape codes for cleaner text output
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_content = ansi_escape.sub('', content)

        return PlainTextResponse(clean_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read recording: {e}")


@app.get("/api/recordings/by-session/{session_id}")
async def get_recording_by_session(session_id: str):
    """Get recording for a specific session."""
    db = await get_db()

    row = await db.fetchrow(
        """
        SELECT id, session_id, user_name, user_email, course_title, assignment_title,
               started_at, ended_at, duration_seconds, file_size_bytes, status,
               recording_path, timing_path
        FROM session_recordings
        WHERE session_id = $1
        ORDER BY started_at DESC
        LIMIT 1
        """,
        session_id
    )

    if not row:
        raise HTTPException(status_code=404, detail="Recording not found for this session")

    return dict(row)


# ============================================================================
# API Endpoints - Statistics
# ============================================================================

@app.get("/api/stats")
async def get_stats():
    """Get overall system statistics."""
    db = await get_db()

    stats = await db.fetchrow("""
        SELECT
            COUNT(*) FILTER (WHERE status = 'running') as running,
            COUNT(*) FILTER (WHERE status = 'starting') as starting,
            COUNT(*) FILTER (WHERE status = 'error') as errors,
            COUNT(*) FILTER (WHERE status = 'destroyed') as destroyed,
            COUNT(DISTINCT course_id) FILTER (WHERE status = 'running') as active_courses,
            COUNT(DISTINCT user_id) FILTER (WHERE status = 'running') as active_users
        FROM vm_sessions
    """)

    recording_stats = await db.fetchrow("""
        SELECT
            COUNT(*) as total_recordings,
            COUNT(*) FILTER (WHERE status = 'completed') as completed_recordings,
            COALESCE(SUM(file_size_bytes), 0) as total_recording_bytes
        FROM session_recordings
    """)

    # Get available IPs
    available_ips = await db.fetchval(
        "SELECT COUNT(*) FROM ip_allocations WHERE session_id IS NULL OR released_at IS NOT NULL"
    )

    return {
        "running_vms": stats['running'],
        "starting_vms": stats['starting'],
        "error_vms": stats['errors'],
        "total_destroyed": stats['destroyed'],
        "active_courses": stats['active_courses'],
        "active_users": stats['active_users'],
        "available_ips": available_ips,
        "vm_ram_mb": VM_RAM_MB,
        "vm_vcpus": VM_VCPUS,
        "total_recordings": recording_stats['total_recordings'],
        "completed_recordings": recording_stats['completed_recordings'],
        "total_recording_size_mb": round(recording_stats['total_recording_bytes'] / (1024 * 1024), 2)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
