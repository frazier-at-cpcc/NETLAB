"""
VM Orchestration API - Proxmox Edition

Manages the lifecycle of student VMs via Proxmox VE:
- Cloning VMs from templates
- Spawning ttyd containers for web terminal access
- Session management and cleanup
- Session recording for audit/review
"""

import os
import time
import secrets
import string
import logging
import asyncio
import base64
import json
import re
import ipaddress
from typing import Optional, List
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType

import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, Response, JSONResponse
from pydantic import BaseModel
import asyncpg
import docker
from proxmoxer import ProxmoxAPI

try:
    from backfill import attempt_backfill
    from cells import upsert_grade_cell
    from grades import (
        GradeRequest,
        InvalidGradeScore,
        InvalidGradeSince,
        accept_grade,
        extract_bearer_token,
        list_delivered_grade_events,
        map_grade_http,
        parse_since,
    )
    from lrs_client import parse_stored
    from pox_delivery import pox_delivery_loop
    from service_auth import SERVICE_TOKEN_HEADER, ServiceTokenError, check_service_token, service_token
    from ssh import run_ssh_command
    from tokens import (
        assign_grade_token,
        get_passback_url,
        inject_guest_xapi_config,
        nested_xapi_email_command,
    )
except ImportError:
    from api.backfill import attempt_backfill
    from api.cells import upsert_grade_cell
    from api.grades import (
        GradeRequest,
        InvalidGradeScore,
        InvalidGradeSince,
        accept_grade,
        extract_bearer_token,
        list_delivered_grade_events,
        map_grade_http,
        parse_since,
    )
    from api.lrs_client import parse_stored
    from api.pox_delivery import pox_delivery_loop
    from api.service_auth import SERVICE_TOKEN_HEADER, ServiceTokenError, check_service_token, service_token
    from api.ssh import run_ssh_command
    from api.tokens import (
        assign_grade_token,
        get_passback_url,
        inject_guest_xapi_config,
        nested_xapi_email_command,
    )

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

DOMAIN = os.getenv("DOMAIN", "labsconnect.org")

# Proxmox configuration
PROXMOX_HOST = os.getenv("PROXMOX_HOST", "host1.pm.itdivision.org")
PROXMOX_PORT = int(os.getenv("PROXMOX_PORT", "8006"))
PROXMOX_USER = os.getenv("PROXMOX_USER", "root@pam")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD", "")
PROXMOX_TOKEN_NAME = os.getenv("PROXMOX_TOKEN_NAME", "")  # Optional: use token instead of password
PROXMOX_TOKEN_VALUE = os.getenv("PROXMOX_TOKEN_VALUE", "")
PROXMOX_VERIFY_SSL = os.getenv("PROXMOX_VERIFY_SSL", "false").lower() == "true"
PROXMOX_NODE = os.getenv("PROXMOX_NODE", "host1")  # Proxmox node name
PROXMOX_STORAGE = os.getenv("PROXMOX_STORAGE", "not-vsan")
PROXMOX_TEMPLATE_ID = int(os.getenv("PROXMOX_TEMPLATE_ID", "500"))
PROXMOX_BRIDGE = os.getenv("PROXMOX_BRIDGE", "vmbr0")
PROXMOX_VLAN_TAG = os.getenv("PROXMOX_VLAN_TAG", "")  # Optional VLAN tag for net0; empty = use bridge native/untagged
PROXMOX_MTU = os.getenv("PROXMOX_MTU", "")  # Optional MTU for net0; empty = Proxmox default (1500)

# VM resource configuration
VM_RAM_MB = int(os.getenv("VM_RAM_MB", "16384"))
VM_VCPUS = int(os.getenv("VM_VCPUS", "4"))

# VM ID range for student VMs (to avoid conflicts)
VM_ID_START = int(os.getenv("VM_ID_START", "1000"))
VM_ID_END = int(os.getenv("VM_ID_END", "9999"))

# Database
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://lab:lab@localhost:5432/lab")

# SSH configuration for ttyd
SSH_PRIVATE_KEY_PATH = os.getenv("SSH_PRIVATE_KEY_PATH", "/app/keys/id_ed25519")
SSH_USER = os.getenv("SSH_USER", "kiosk")
SSH_PASSWORD = os.getenv("SSH_PASSWORD", "redhat")  # Default RHA password

# Nested environment SSH - auto-connect to student workstation
NESTED_SSH_ENABLED = os.getenv("NESTED_SSH_ENABLED", "true").lower() == "true"
NESTED_SSH_USER = os.getenv("NESTED_SSH_USER", "student")
NESTED_SSH_HOST = os.getenv("NESTED_SSH_HOST", "workstation")
NESTED_SSH_PASSWORD = os.getenv("NESTED_SSH_PASSWORD", "student")  # Default RHA student password

# Management network prefix - VMs with multiple NICs should use this network
MGMT_NETWORK_PREFIX = os.getenv("MGMT_NETWORK_PREFIX", "172.16.120.")

# Session recordings directory
RECORDINGS_DIR = os.getenv("RECORDINGS_DIR", "/var/lib/vm-lab/recordings")

# Session defaults
DEFAULT_SESSION_HOURS = 4
MAX_SESSION_HOURS = 8

# Docker network for ttyd containers
DOCKER_NETWORK = "vm-lab_lab-network"

# Traefik dynamic config directory for session routes
TRAEFIK_DYNAMIC_DIR = os.getenv("TRAEFIK_DYNAMIC_DIR", "/app/traefik-dynamic")


# ============================================================================
# LRS grade backfill configuration
#
# Disabled by default. Every gap in configuration fails the feature off,
# never open, and is logged once at startup so an operator can see why
# without ever seeing the value of anything sensitive. See
# docs/superpowers/specs/2026-09-15-lrs-grade-backfill.md sections 3 and 9.
# ============================================================================

_LRS_BACKFILL_TRUTHY = {"1", "true", "yes"}

_LRS_BACKFILL_DEFAULT_DOMAINS = (
    "email.cpcc.edu,lab.cpcc.edu,email.edu.cpcc,cpcc.email.edu,cpcc.edu"
)


def _encode_lrs_read_auth(raw: str) -> str:
    """Return the base64 HTTP Basic credential attempt_backfill hands to
    fetch_statements, which sends it verbatim as
    'Authorization: Basic {auth}'.

    An operator may paste in either form: a raw `key:secret` pair copied
    straight off the store's credential page, or the credential already
    base64-encoded. A colon never appears in valid base64 output, so a
    value containing ':' is treated as raw and encoded here; a value with
    no colon is assumed to already be base64 and passed through
    unchanged. The raw value is never logged.

    Callers must strip surrounding whitespace before calling this. A
    trailing newline on a raw pair would otherwise become part of the
    base64 input, silently encoding a different credential; a trailing
    newline on an already-encoded value would otherwise survive
    unchanged into the Authorization header.
    """
    if ":" in raw:
        return base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return raw


def load_backfill_config():
    """Read the LRS grade backfill configuration from the environment.

    Returns a frozen mapping carrying exactly the five keys
    api/backfill.py's attempt_backfill reads via config.get(): enabled,
    domains, cutoff, base_url, auth. A missing or unparseable
    LRS_READ_AUTH or LRS_BACKFILL_CUTOFF forces enabled to False
    regardless of LRS_BACKFILL_ENABLED, and is logged once here, naming
    only which variable is missing or invalid, never its value.
    """
    enabled_flag = os.getenv("LRS_BACKFILL_ENABLED", "false").strip().lower() in _LRS_BACKFILL_TRUTHY

    # Every raw string pulled from the environment is stripped before it is
    # inspected or used, matching lrs_client.parse_stored's own internal
    # strip. A trailing newline is routine, not contrived: `echo x > file`,
    # a Kubernetes secretKeyRef mount, and several .env tools all append
    # one. Left unstripped, it survives into an already-encoded credential
    # as literal header bytes, or gets folded into a raw credential's own
    # base64 encoding, in both cases producing a wrong value that is still
    # non-empty and still looks configured, so the feature stays "enabled"
    # and fails every store query with no visible cause.
    base_url = os.getenv("LRS_READ_URL", "https://lrs.labsconnect.org/xapi").strip()

    raw_auth = os.getenv("LRS_READ_AUTH", "").strip()
    if not raw_auth:
        logger.warning("LRS backfill disabled: LRS_READ_AUTH is not set")
        auth = ""
    else:
        auth = _encode_lrs_read_auth(raw_auth)

    raw_cutoff = os.getenv("LRS_BACKFILL_CUTOFF", "")
    cutoff = None
    if not raw_cutoff:
        logger.warning("LRS backfill disabled: LRS_BACKFILL_CUTOFF is not set")
    else:
        try:
            parsed_cutoff = parse_stored(raw_cutoff)
        except (ValueError, TypeError):
            logger.warning("LRS backfill disabled: LRS_BACKFILL_CUTOFF is not a valid ISO instant")
            parsed_cutoff = None
        if parsed_cutoff is not None:
            # A cutoff in the future admits every statement anyone can
            # forge today, which erases the one security control this
            # feature has (spec section 4: `stored` cannot be forged, but
            # a cutoff that is never exceeded stops mattering). Every
            # other invalid-cutoff case above already fails off rather
            # than warns and proceeds; refusing here too keeps a single
            # failure discipline instead of a second, weaker one an
            # operator could miss in an alert flood.
            if parsed_cutoff > datetime.now(timezone.utc):
                logger.warning(
                    "LRS backfill disabled: LRS_BACKFILL_CUTOFF %s is in the future",
                    parsed_cutoff.isoformat(),
                )
            else:
                cutoff = parsed_cutoff

    domains_raw = os.getenv("LRS_BACKFILL_DOMAINS", "").strip()
    if not domains_raw:
        # os.getenv(name, default) only applies `default` when the
        # variable is unset entirely. LRS_BACKFILL_DOMAINS="" is set, just
        # empty, so without this an operator who explicitly clears the
        # variable gets [] instead of the documented default list,
        # silently losing all cross-domain pooling.
        domains_raw = _LRS_BACKFILL_DEFAULT_DOMAINS
    domains = [d.strip() for d in domains_raw.split(",") if d.strip()]

    enabled = enabled_flag and bool(auth) and cutoff is not None

    # The cutoff is not sensitive, unlike the credential. Logging it here,
    # alongside the enabled state, at every startup regardless of outcome,
    # is what lets an operator confirm afterward which bound was actually
    # in force -- the gap named in the review.
    logger.info(
        "LRS backfill config: enabled=%s cutoff=%s",
        enabled,
        cutoff.isoformat() if cutoff is not None else None,
    )

    return MappingProxyType(
        {
            "enabled": enabled,
            "domains": domains,
            "cutoff": cutoff,
            "base_url": base_url,
            "auth": auth,
        }
    )


BACKFILL_CONFIG = load_backfill_config()


# ============================================================================
# Pydantic Models
# ============================================================================

class ProvisionRequest(BaseModel):
    session_key: Optional[str] = None
    course_session_key: Optional[str] = None
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    course_id: Optional[str] = None
    course_title: Optional[str] = None
    assignment_id: Optional[str] = None
    assignment_title: Optional[str] = None
    session_hours: Optional[int] = DEFAULT_SESSION_HOURS


class GradeCellRequest(BaseModel):
    course_session_id: str
    lab_slug: Optional[str] = None
    resource_link_id: Optional[str] = None
    outcome_service_url: Optional[str] = None
    sourcedid: Optional[str] = None
    consumer_key: Optional[str] = None


class Session(BaseModel):
    session_id: str
    url: str
    vm_ip: Optional[str] = None
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


class ProvisioningStep(BaseModel):
    """Represents a step in the provisioning process."""
    id: str
    label: str
    status: str  # 'pending', 'in_progress', 'completed', 'error'
    message: Optional[str] = None


class SessionStatus(BaseModel):
    """Detailed session status for polling during provisioning."""
    session_id: str
    status: str
    ready: bool
    url: Optional[str] = None
    vm_ip: Optional[str] = None
    error_message: Optional[str] = None
    steps: List[ProvisioningStep]
    progress_percent: int
    estimated_seconds_remaining: Optional[int] = None


# ============================================================================
# Application Setup
# ============================================================================

# Global connections
docker_client: Optional[docker.DockerClient] = None
proxmox_api: Optional[ProxmoxAPI] = None


def get_proxmox_connection() -> ProxmoxAPI:
    """Create a new Proxmox API connection."""
    if PROXMOX_TOKEN_NAME and PROXMOX_TOKEN_VALUE:
        # Use API token authentication
        return ProxmoxAPI(
            PROXMOX_HOST,
            port=PROXMOX_PORT,
            user=PROXMOX_USER,
            token_name=PROXMOX_TOKEN_NAME,
            token_value=PROXMOX_TOKEN_VALUE,
            verify_ssl=PROXMOX_VERIFY_SSL,
            timeout=120  # 2 minute timeout for large VM operations
        )
    else:
        # Use password authentication
        return ProxmoxAPI(
            PROXMOX_HOST,
            port=PROXMOX_PORT,
            user=PROXMOX_USER,
            password=PROXMOX_PASSWORD,
            verify_ssl=PROXMOX_VERIFY_SSL,
            timeout=120  # 2 minute timeout for large VM operations
        )


async def connect_proxmox_with_retry():
    global proxmox_api
    delay = 10
    while True:
        try:
            conn = get_proxmox_connection()
            version = conn.version.get()
            proxmox_api = conn
            logger.info(f"Proxmox connected: {PROXMOX_HOST} (version {version.get('version', 'unknown')})")
            return
        except Exception as e:
            logger.warning(f"Proxmox not reachable, retrying in {delay}s: {e}")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 120)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - setup and teardown."""
    global docker_client, proxmox_api

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

    # Connect to Proxmox in background; retries with backoff if pve isn't up yet
    asyncio.create_task(connect_proxmox_with_retry())

    # Start cleanup background task
    cleanup_task = asyncio.create_task(cleanup_loop(app.state.db))
    pox_task = asyncio.create_task(pox_delivery_loop(app.state.db))

    yield

    # Cleanup
    cleanup_task.cancel()
    pox_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    try:
        await pox_task
    except asyncio.CancelledError:
        pass

    await app.state.db.close()
    logger.info("Connections closed")


app = FastAPI(
    title="LabsConnect - VM Orchestration API",
    description="Manages VM lifecycle for virtual lab environments via Proxmox VE",
    version="2.0.0",
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
    sanitized = re.sub(r'[^\w\-.]', '_', name)
    sanitized = re.sub(r'_+', '_', sanitized)
    return sanitized[:50]


def get_recording_path(session_id: str, user_email: str, user_name: str, started_at: datetime) -> tuple:
    """Generate organized recording file paths."""
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
    recording = await db.fetchrow(
        "SELECT id, recording_path, timing_path, started_at FROM session_recordings WHERE session_id = $1 AND status = 'recording'",
        session_id
    )

    if not recording:
        return

    from datetime import timezone
    ended_at = datetime.now(timezone.utc)
    duration_seconds = None
    file_size_bytes = None

    if recording['started_at']:
        # Ensure both datetimes are timezone-aware for comparison
        started = recording['started_at']
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        duration_seconds = int((ended_at - started).total_seconds())

    if recording['recording_path'] and os.path.exists(recording['recording_path']):
        file_size_bytes = os.path.getsize(recording['recording_path'])

    await db.execute(
        """
        UPDATE session_recordings
        SET ended_at = $2, duration_seconds = $3, file_size_bytes = $4, status = 'completed'
        WHERE id = $1
        """,
        recording['id'], ended_at, duration_seconds, file_size_bytes
    )

    logger.info(f"Finalized recording for session {session_id}: {duration_seconds}s, {file_size_bytes} bytes")


# ============================================================================
# Proxmox VM Management
# ============================================================================

def allocate_vm_id(proxmox: ProxmoxAPI) -> int:
    """Allocate a unique VM ID in the allowed range."""
    # Get list of existing VMs
    existing_ids = set()
    for vm in proxmox.cluster.resources.get(type='vm'):
        existing_ids.add(vm['vmid'])

    # Find first available ID in range
    for vmid in range(VM_ID_START, VM_ID_END):
        if vmid not in existing_ids:
            return vmid

    raise Exception("No available VM IDs in range")


def wait_for_task(proxmox: ProxmoxAPI, node: str, upid: str, timeout: int = 300) -> bool:
    """Wait for a Proxmox task to complete."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        task_status = proxmox.nodes(node).tasks(upid).status.get()
        if task_status.get('status') == 'stopped':
            if task_status.get('exitstatus') == 'OK':
                return True
            else:
                raise Exception(f"Task failed: {task_status.get('exitstatus')}")
        time.sleep(2)
    raise Exception("Task timeout")


def clone_vm(proxmox: ProxmoxAPI, session_id: str, vm_name: str) -> int:
    """Clone a VM from the template."""
    vmid = allocate_vm_id(proxmox)

    logger.info(f"Cloning template {PROXMOX_TEMPLATE_ID} to VM {vmid} ({vm_name})")

    # Clone the template - returns a task ID (UPID)
    # Using linked clone (full=0) from snapshot for faster provisioning
    # Linked clones share the base snapshot's disk as a read-only base
    upid = proxmox.nodes(PROXMOX_NODE).qemu(PROXMOX_TEMPLATE_ID).clone.post(
        newid=vmid,
        name=vm_name,
        target=PROXMOX_NODE,
        snapname='base-with-reporting',  # Clone from the base snapshot with reporting enabled
        full=0  # Linked clone (faster, uses snapshot as base)
    )

    # Wait for clone task to complete
    logger.info(f"Waiting for clone task {upid} to complete...")
    wait_for_task(proxmox, PROXMOX_NODE, upid, timeout=120)  # Linked clones are fast
    logger.info(f"Clone completed for VM {vmid}")

    # Configure the cloned VM. Build net0 from optional VLAN tag and MTU so that
    # environments where the template's net0 needs a tag (VLAN-aware bridge) or a
    # non-default MTU don't lose those parameters when this rewrite happens.
    net0 = f"virtio,bridge={PROXMOX_BRIDGE}"
    if PROXMOX_VLAN_TAG:
        net0 += f",tag={PROXMOX_VLAN_TAG}"
    if PROXMOX_MTU:
        net0 += f",mtu={PROXMOX_MTU}"

    proxmox.nodes(PROXMOX_NODE).qemu(vmid).config.put(
        memory=VM_RAM_MB,
        cores=VM_VCPUS,
        net0=net0,
        description=f"Student lab VM - Session: {session_id}"
    )

    return vmid


def start_vm(proxmox: ProxmoxAPI, vmid: int):
    """Start a VM."""
    logger.info(f"Starting VM {vmid}")
    proxmox.nodes(PROXMOX_NODE).qemu(vmid).status.start.post()


def stop_vm(proxmox: ProxmoxAPI, vmid: int):
    """Stop a VM."""
    logger.info(f"Stopping VM {vmid}")
    try:
        proxmox.nodes(PROXMOX_NODE).qemu(vmid).status.stop.post()
    except Exception as e:
        logger.warning(f"Failed to stop VM {vmid}: {e}")


def destroy_vm(proxmox: ProxmoxAPI, vmid: int):
    """Destroy a VM."""
    logger.info(f"Destroying VM {vmid}")
    try:
        # Stop first if running
        status = proxmox.nodes(PROXMOX_NODE).qemu(vmid).status.current.get()
        if status.get('status') == 'running':
            proxmox.nodes(PROXMOX_NODE).qemu(vmid).status.stop.post()
            time.sleep(5)

        # Delete the VM
        proxmox.nodes(PROXMOX_NODE).qemu(vmid).delete()
        logger.info(f"VM {vmid} destroyed")
    except Exception as e:
        logger.error(f"Failed to destroy VM {vmid}: {e}")


def _validated_ipv4(candidate: Optional[str]) -> Optional[str]:
    """Return candidate if it is a syntactically valid IPv4 address, else None.

    vm_ip is later interpolated into a command string that reaches
    `script -c`, which hands its argument to /bin/sh -c inside the ttyd
    container. The Proxmox guest agent reports it from inside a VM the
    student controls as root, so every candidate must be validated here,
    at the source, rather than quoted at each call site.
    """
    if not candidate:
        return None
    try:
        ipaddress.IPv4Address(candidate)
    except ValueError:
        return None
    return candidate


def get_vm_ip(proxmox: ProxmoxAPI, vmid: int) -> Optional[str]:
    """Get VM IP address from Proxmox guest agent or network info."""
    try:
        # Try guest agent first
        agent_info = proxmox.nodes(PROXMOX_NODE).qemu(vmid).agent('network-get-interfaces').get()
        all_ips = []
        for iface in agent_info.get('result', []):
            if iface.get('name') == 'lo':
                continue
            for addr in iface.get('ip-addresses', []):
                if addr.get('ip-address-type') == 'ipv4':
                    ip = _validated_ipv4(addr.get('ip-address'))
                    if ip is None and addr.get('ip-address'):
                        logger.warning(
                            f"VM {vmid} guest agent reported a network interface "
                            "address that is not valid IPv4; ignoring it"
                        )
                    if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                        all_ips.append(ip)

        logger.debug(f"VM {vmid} found IPs: {all_ips}, looking for prefix: {MGMT_NETWORK_PREFIX}")

        # Prefer management network IP if configured
        if MGMT_NETWORK_PREFIX:
            for ip in all_ips:
                if ip.startswith(MGMT_NETWORK_PREFIX):
                    logger.debug(f"VM {vmid} using management IP: {ip}")
                    return ip
            # If we have IPs but none on management network, don't return yet - wait for DHCP
            if all_ips:
                logger.debug(f"VM {vmid} has IPs {all_ips} but none on management network {MGMT_NETWORK_PREFIX}, waiting...")
                return None

        # Fall back to first available IP (only if no MGMT_NETWORK_PREFIX configured)
        if all_ips:
            return all_ips[0]
    except Exception as e:
        logger.debug(f"Guest agent not available for VM {vmid}: {e}")

    # Try getting from VM config/status (if DHCP lease is visible)
    try:
        # Check if there's network info in the status
        status = proxmox.nodes(PROXMOX_NODE).qemu(vmid).status.current.get()
        # Some setups expose IP in status
        if 'ip' in status:
            validated = _validated_ipv4(status['ip'])
            if validated:
                return validated
    except Exception:
        pass

    return None


async def wait_for_vm_ip(proxmox: ProxmoxAPI, vmid: int, timeout: int = 300) -> Optional[str]:
    """Wait for VM to get an IP address."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        ip = get_vm_ip(proxmox, vmid)
        if ip:
            logger.info(f"VM {vmid} got IP: {ip}")
            return ip
        await asyncio.sleep(5)

    logger.warning(f"VM {vmid} did not get IP after {timeout}s")
    return None


async def wait_for_ssh(ip: str, timeout: int = 300) -> bool:
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
                await asyncio.sleep(2)
                return True
        except socket.error:
            pass
        await asyncio.sleep(5)

    return False


async def wait_for_ssh_login(ip: str, user: str, password: str, timeout: int = 180) -> bool:
    """Wait for SSH login to be fully ready (system booted, not just port open)."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        # Try a simple command to verify we can actually log in
        success, output = await run_ssh_command(ip, user, password, "echo ready", timeout=10)
        if success and "ready" in output:
            logger.info(f"SSH login ready on {ip}")
            return True
        if "System is booting up" in output or "pam_nologin" in output:
            logger.info(f"System still booting on {ip}, waiting...")
        await asyncio.sleep(5)
    return False


async def check_nested_host_ssh(ip: str, user: str, password: str, nested_host: str) -> bool:
    """Check if a nested host is reachable via SSH from the outer VM."""
    success, output = await run_ssh_command(
        ip, user, password,
        f"nc -z -w2 {nested_host} 22 && echo OK || echo FAIL",
        timeout=15
    )
    if not success:
        logger.debug(f"check_nested_host_ssh failed for {nested_host}: {output}")
    elif "OK" not in output:
        logger.debug(f"check_nested_host_ssh: {nested_host} not reachable yet: {output}")
    return success and "OK" in output


# ============================================================================
# Docker/Traefik Management
# ============================================================================

def write_traefik_route(session_id: str, container_name: str, domain: str):
    """Write a Traefik route config file for a ttyd session."""
    route_file = os.path.join(TRAEFIK_DYNAMIC_DIR, f"session-{session_id}.yml")
    config = f"""# Auto-generated route for session {session_id}
http:
  routers:
    ttyd-{session_id}:
      rule: "Host(`lab-{session_id}.{domain}`)"
      entryPoints:
        - web
      service: ttyd-{session_id}
  services:
    ttyd-{session_id}:
      loadBalancer:
        servers:
          - url: "http://{container_name}:7681"
"""
    try:
        with open(route_file, 'w') as f:
            f.write(config)
        logger.info(f"Wrote Traefik route config: {route_file}")
    except Exception as e:
        logger.error(f"Failed to write Traefik route config: {e}")


def delete_traefik_route(session_id: str):
    """Delete the Traefik route config file for a session."""
    route_file = os.path.join(TRAEFIK_DYNAMIC_DIR, f"session-{session_id}.yml")
    try:
        if os.path.exists(route_file):
            os.remove(route_file)
            logger.info(f"Deleted Traefik route config: {route_file}")
    except Exception as e:
        logger.error(f"Failed to delete Traefik route config: {e}")


def spawn_ttyd_container(
    session_id: str,
    vm_ip: str,
    domain: str,
    recording_path: str,
    timing_path: str
) -> Optional[str]:
    """Spawn a ttyd container for web terminal access with session recording."""
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

        # Create recording directory
        recording_dir = os.path.dirname(recording_path)
        os.makedirs(recording_dir, exist_ok=True)

        # Command that wraps SSH with script for recording
        # Use sshpass for password authentication (RHA images use password auth by default)
        # Passwords are passed via environment variables to avoid shell quoting issues
        recording_rel_path = os.path.relpath(recording_path, RECORDINGS_DIR)
        timing_rel_path = os.path.relpath(timing_path, RECORDINGS_DIR)

        if NESTED_SSH_ENABLED:
            # Chain SSH: first connect to outer VM, then directly to nested workstation
            # Nested VMs are already started and workstation is verified reachable by the provisioning process
            # Use SSHPASS env var (-e flag) for outer connection (kiosk uses password)
            # Inner connection to student@workstation uses SSH keys (no password needed)
            inner_connect = f"ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {NESTED_SSH_USER}@{NESTED_SSH_HOST}"
            ssh_command = f"sshpass -e ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {SSH_USER}@{vm_ip} {inner_connect}"
            logger.info(f"Nested SSH enabled: connecting to {NESTED_SSH_USER}@{NESTED_SSH_HOST} via {SSH_USER}@{vm_ip}")
            env_vars = {
                "SSHPASS": SSH_PASSWORD,
            }
        else:
            # Direct SSH to the VM only
            ssh_command = f"sshpass -e ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {SSH_USER}@{vm_ip}"
            env_vars = {
                "SSHPASS": SSH_PASSWORD,
            }

        # Build the ttyd command with script recording wrapper
        ttyd_command = [
            "ttyd", "--writable", "--port", "7681",
            "script", "-q", "-f",
            f"-t/recordings/{timing_rel_path}",
            f"/recordings/{recording_rel_path}",
            "-c", ssh_command
        ]

        # Spawn ttyd container with recording
        # Use custom image with SSH client installed
        container = docker_client.containers.run(
            "vm-lab-ttyd:latest",
            command=ttyd_command,
            name=container_name,
            detach=True,
            network=DOCKER_NETWORK,
            environment=env_vars,
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
                "lab.session_id": session_id,
                "lab.vm_ip": vm_ip,
                "lab.recording_path": recording_path,
            },
            restart_policy={"Name": "unless-stopped"}
        )

        # Write Traefik route config file
        write_traefik_route(session_id, container_name, domain)

        logger.info(f"Spawned ttyd container with recording: {container_name}")
        return container.id

    except docker.errors.APIError as e:
        logger.error(f"Failed to spawn ttyd container: {e}")
        return None


def destroy_ttyd_container(session_id: str):
    """Remove ttyd container and its Traefik route."""
    delete_traefik_route(session_id)

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
        SELECT session_id, vm_id
        FROM vm_sessions
        WHERE status = 'running' AND expires_at < CURRENT_TIMESTAMP
        """
    )

    for row in expired:
        logger.info(f"Cleaning up expired session: {row['session_id']}")
        await destroy_session_internal(db, row['session_id'], row['vm_id'])


async def destroy_session_internal(db: asyncpg.Pool, session_id: str, vm_id: int):
    """Internal function to destroy a session."""
    # Finalize recording before destroying container
    await finalize_recording(db, session_id)

    # Remove ttyd container
    destroy_ttyd_container(session_id)

    # Destroy VM in Proxmox
    if vm_id and proxmox_api:
        try:
            destroy_vm(proxmox_api, vm_id)
        except Exception as e:
            logger.error(f"Failed to destroy VM {vm_id}: {e}")

    # Update database
    await db.execute(
        """
        UPDATE vm_sessions
        SET status = 'destroyed', destroyed_at = CURRENT_TIMESTAMP
        WHERE session_id = $1
        """,
        session_id
    )

    await log_event(db, session_id, 'destroyed')


# ============================================================================
# API Endpoints - Sessions
# ============================================================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    db_healthy = False
    proxmox_healthy = False
    docker_healthy = False

    try:
        db = await get_db()
        await db.fetchval("SELECT 1")
        db_healthy = True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")

    if proxmox_api:
        try:
            proxmox_api.version.get()
            proxmox_healthy = True
        except Exception:
            pass

    if docker_client:
        try:
            docker_client.ping()
            docker_healthy = True
        except docker.errors.APIError:
            pass

    status = "healthy" if all([db_healthy, proxmox_healthy, docker_healthy]) else "degraded"

    return {
        "status": status,
        "database": "connected" if db_healthy else "disconnected",
        "proxmox": "connected" if proxmox_healthy else "disconnected",
        "docker": "connected" if docker_healthy else "disconnected",
        "proxmox_host": PROXMOX_HOST,
        "proxmox_node": PROXMOX_NODE,
        "recordings_dir": RECORDINGS_DIR
    }


@app.get("/api/session/by-key/{session_key:path}", response_model=Session)
async def get_session_by_key(session_key: str):
    """Find existing session by course_session_key, then session_key."""
    db = await get_db()

    row = await db.fetchrow(
        """
        SELECT session_id, url, vm_ip, status, user_name, course_title,
               assignment_title, created_at, expires_at
        FROM vm_sessions
        WHERE course_session_key = $1
          AND status IN ('provisioning', 'starting', 'running')
        """,
        session_key
    )
    if not row:
        row = await db.fetchrow(
            """
            SELECT session_id, url, vm_ip, status, user_name, course_title,
                   assignment_title, created_at, expires_at
            FROM vm_sessions
            WHERE session_key = $1
              AND status IN ('provisioning', 'starting', 'running')
            """,
            session_key
        )

    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    await db.execute(
        "UPDATE vm_sessions SET last_accessed = CURRENT_TIMESTAMP WHERE session_id = $1",
        row["session_id"]
    )

    return Session(**dict(row))


async def require_service_token(
    x_labsconnect_service_token: Optional[str] = Header(
        default=None, alias=SERVICE_TOKEN_HEADER
    ),
) -> None:
    try:
        check_service_token(
            configured=service_token(), presented=x_labsconnect_service_token
        )
    except ServiceTokenError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


async def _run_lrs_backfill(cell_id: int) -> None:
    """Background-task entry point for the LRS grade backfill.

    Scheduled from POST /api/cells only after a successful upsert, and
    only when the backfill feature is fully configured. It is never
    awaited inline: that request path is latency-sensitive, with a
    student waiting on a virtual machine, and a slow or unreachable
    Learning Record Store must not delay it. This function runs after the
    response has already been sent, so any exception here -- a network
    error, a database error, anything -- is caught and logged rather than
    left to propagate; it cannot affect a response the caller has already
    received.
    """
    db = await get_db()
    http = httpx.AsyncClient(timeout=10.0)
    try:
        await attempt_backfill(db, http, cell_id, config=BACKFILL_CONFIG)
    except Exception:
        # No exc_info and no exception text here, matching
        # attempt_backfill's own discipline: an underlying httpx error can
        # carry the request URL, and this request's query string carries
        # the student's candidate mailboxes. Only the cell id is logged.
        logger.warning(
            "LRS backfill background task failed for cell_id=%s; the cell "
            "remains unmarked and is retried on the student's next launch",
            cell_id,
        )
    finally:
        await http.aclose()


@app.post("/api/cells", dependencies=[Depends(require_service_token)])
async def upsert_cell(body: GradeCellRequest, background_tasks: BackgroundTasks):
    """Persist or update a POX grade cell for a course session."""
    if not body.lab_slug or not body.sourcedid:
        return Response(status_code=204)

    db = await get_db()
    cell_id = await upsert_grade_cell(
        db,
        course_session_id=body.course_session_id,
        lab_slug=body.lab_slug,
        resource_link_id=body.resource_link_id or "",
        outcome_service_url=body.outcome_service_url or "",
        sourcedid=body.sourcedid,
        consumer_key=body.consumer_key or "",
    )
    if cell_id is None:
        return Response(status_code=204)

    if BACKFILL_CONFIG.get("enabled", False):
        background_tasks.add_task(_run_lrs_backfill, cell_id)

    return {"id": cell_id}


@app.post("/api/grade")
async def post_grade(
    body: GradeRequest,
    authorization: Optional[str] = Header(default=None),
    x_labsconnect_idempotency_key: Optional[str] = Header(
        default=None, alias="X-LabsConnect-Idempotency-Key"
    ),
):
    """Accept a token-keyed grade post. Does not deliver POX."""
    token = extract_bearer_token(authorization)
    if token is None:
        return Response(status_code=401)
    if not x_labsconnect_idempotency_key:
        return JSONResponse(
            status_code=400, content={"error": "missing_idempotency_key"}
        )
    db = await get_db()
    try:
        result = await accept_grade(
            db,
            token=token,
            idempotency_key=x_labsconnect_idempotency_key,
            request=body,
        )
    except InvalidGradeScore as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    status_code, payload = map_grade_http(result)
    if payload is None:
        return Response(status_code=status_code)
    return JSONResponse(status_code=status_code, content=payload)


@app.get("/api/grade-events", dependencies=[Depends(require_service_token)])
async def get_grade_events(since: Optional[str] = Query(None)):
    """List delivered grade events for LRS reconcile. Omits tokens and sourcedids."""
    try:
        parsed_since = parse_since(since)
    except InvalidGradeSince:
        return JSONResponse(status_code=400, content={"error": "invalid_since"})
    db = await get_db()
    events = await list_delivered_grade_events(db, since=parsed_since)
    return {"events": events}


@app.get("/api/session/{session_id}", response_model=Session)
async def get_session_by_id(session_id: str):
    """Get session details by session ID."""
    db = await get_db()

    row = await db.fetchrow(
        """
        SELECT session_id, url, vm_ip, status, user_name, course_title,
               assignment_title, created_at, expires_at
        FROM vm_sessions
        WHERE session_id = $1
        """,
        session_id
    )

    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    return Session(**dict(row))


@app.get("/api/session/{session_id}/status", response_model=SessionStatus)
async def get_session_status(session_id: str):
    """Get detailed session status with provisioning steps."""
    db = await get_db()

    row = await db.fetchrow(
        """
        SELECT session_id, url, vm_ip, status, status_message,
               user_name, course_title, assignment_title,
               created_at, expires_at, started_at
        FROM vm_sessions
        WHERE session_id = $1
        """,
        session_id
    )

    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    status = row['status']
    vm_ip = row['vm_ip']
    status_message = row['status_message']

    # Define provisioning steps based on status and status_message
    if status == 'error':
        steps = [
            ProvisioningStep(id="create_vm", label="Creating virtual machine", status="completed"),
            ProvisioningStep(id="boot_vm", label="Booting system", status="error", message=status_message or "An error occurred"),
            ProvisioningStep(id="network", label="Configuring network", status="pending"),
            ProvisioningStep(id="ssh", label="Starting SSH service", status="pending"),
            ProvisioningStep(id="nested_vms", label="Starting lab environment", status="pending"),
            ProvisioningStep(id="lms_connect", label="Connecting to LMS", status="pending"),
            ProvisioningStep(id="terminal", label="Launching web terminal", status="pending"),
        ]
        progress = 20
        ready = False
        estimated_remaining = None
    elif status == 'starting':
        if status_message == 'nested_starting':
            # Running rht-vmctl start all
            steps = [
                ProvisioningStep(id="create_vm", label="Creating virtual machine", status="completed"),
                ProvisioningStep(id="boot_vm", label="Booting system", status="completed"),
                ProvisioningStep(id="network", label="Configuring network", status="completed"),
                ProvisioningStep(id="ssh", label="Starting SSH service", status="completed"),
                ProvisioningStep(id="nested_vms", label="Starting lab environment", status="in_progress", message="Starting nested VMs..."),
                ProvisioningStep(id="lms_connect", label="Connecting to LMS", status="pending"),
                ProvisioningStep(id="terminal", label="Launching web terminal", status="pending"),
            ]
            progress = 60
            estimated_remaining = 180
        elif status_message == 'nested_waiting':
            # Waiting for workstation to be reachable
            steps = [
                ProvisioningStep(id="create_vm", label="Creating virtual machine", status="completed"),
                ProvisioningStep(id="boot_vm", label="Booting system", status="completed"),
                ProvisioningStep(id="network", label="Configuring network", status="completed"),
                ProvisioningStep(id="ssh", label="Starting SSH service", status="completed"),
                ProvisioningStep(id="nested_vms", label="Starting lab environment", status="in_progress", message="Waiting for workstation..."),
                ProvisioningStep(id="lms_connect", label="Connecting to LMS", status="pending"),
                ProvisioningStep(id="terminal", label="Launching web terminal", status="pending"),
            ]
            progress = 75
            estimated_remaining = 90
        elif status_message == 'lms_connecting':
            # Connecting lab to LMS
            steps = [
                ProvisioningStep(id="create_vm", label="Creating virtual machine", status="completed"),
                ProvisioningStep(id="boot_vm", label="Booting system", status="completed"),
                ProvisioningStep(id="network", label="Configuring network", status="completed"),
                ProvisioningStep(id="ssh", label="Starting SSH service", status="completed"),
                ProvisioningStep(id="nested_vms", label="Starting lab environment", status="completed"),
                ProvisioningStep(id="lms_connect", label="Connecting to LMS", status="in_progress", message="Configuring LMS integration..."),
                ProvisioningStep(id="terminal", label="Launching web terminal", status="pending"),
            ]
            progress = 90
            estimated_remaining = 30
        elif vm_ip:
            steps = [
                ProvisioningStep(id="create_vm", label="Creating virtual machine", status="completed"),
                ProvisioningStep(id="boot_vm", label="Booting system", status="completed"),
                ProvisioningStep(id="network", label="Configuring network", status="completed"),
                ProvisioningStep(id="ssh", label="Starting SSH service", status="in_progress", message="Waiting for SSH..."),
                ProvisioningStep(id="nested_vms", label="Starting lab environment", status="pending"),
                ProvisioningStep(id="lms_connect", label="Connecting to LMS", status="pending"),
                ProvisioningStep(id="terminal", label="Launching web terminal", status="pending"),
            ]
            progress = 40
            estimated_remaining = 180
        else:
            steps = [
                ProvisioningStep(id="create_vm", label="Creating virtual machine", status="completed"),
                ProvisioningStep(id="boot_vm", label="Booting system", status="in_progress", message="VM is booting..."),
                ProvisioningStep(id="network", label="Configuring network", status="pending"),
                ProvisioningStep(id="ssh", label="Starting SSH service", status="pending"),
                ProvisioningStep(id="nested_vms", label="Starting lab environment", status="pending"),
                ProvisioningStep(id="lms_connect", label="Connecting to LMS", status="pending"),
                ProvisioningStep(id="terminal", label="Launching web terminal", status="pending"),
            ]
            progress = 30
            estimated_remaining = 180
        ready = False
    elif status == 'running':
        steps = [
            ProvisioningStep(id="create_vm", label="Creating virtual machine", status="completed"),
            ProvisioningStep(id="boot_vm", label="Booting system", status="completed"),
            ProvisioningStep(id="network", label="Configuring network", status="completed"),
            ProvisioningStep(id="ssh", label="Starting SSH service", status="completed"),
            ProvisioningStep(id="nested_vms", label="Starting lab environment", status="completed"),
            ProvisioningStep(id="lms_connect", label="Connecting to LMS", status="completed"),
            ProvisioningStep(id="terminal", label="Launching web terminal", status="completed"),
        ]
        progress = 100
        ready = True
        estimated_remaining = 0
    else:
        steps = [
            ProvisioningStep(id="create_vm", label="Creating virtual machine", status="pending"),
            ProvisioningStep(id="boot_vm", label="Booting system", status="pending"),
            ProvisioningStep(id="network", label="Configuring network", status="pending"),
            ProvisioningStep(id="ssh", label="Starting SSH service", status="pending"),
            ProvisioningStep(id="nested_vms", label="Starting lab environment", status="pending"),
            ProvisioningStep(id="lms_connect", label="Connecting to LMS", status="pending"),
            ProvisioningStep(id="terminal", label="Launching web terminal", status="pending"),
        ]
        progress = 0
        ready = False
        estimated_remaining = None

    return SessionStatus(
        session_id=session_id,
        status=status,
        ready=ready,
        url=row['url'] if ready else None,
        vm_ip=vm_ip,
        error_message=status_message if status == 'error' else None,
        steps=steps,
        progress_percent=progress,
        estimated_seconds_remaining=estimated_remaining
    )


@app.post("/api/provision", response_model=Session)
async def provision_vm(request: ProvisionRequest, background_tasks: BackgroundTasks):
    """Provision a new VM for a student via Proxmox."""
    db = await get_db()

    global proxmox_api
    if not proxmox_api:
        try:
            conn = get_proxmox_connection()
            conn.version.get()
            proxmox_api = conn
        except Exception:
            raise HTTPException(status_code=503, detail="Proxmox not available")

    # Generate session ID
    session_id = generate_session_id()
    vm_name = f"student-{session_id}"

    # Calculate expiry
    session_hours = min(request.session_hours or DEFAULT_SESSION_HOURS, MAX_SESSION_HOURS)
    expires_at = datetime.utcnow() + timedelta(hours=session_hours)

    # Generate recording paths
    started_at = datetime.utcnow()
    recording_path, timing_path = get_recording_path(
        session_id,
        request.user_email or "",
        request.user_name or "",
        started_at
    )

    # URL for the session
    url = f"https://lab-{session_id}.{DOMAIN}"

    # Clone VM from template
    try:
        vmid = clone_vm(proxmox_api, session_id, vm_name)
    except Exception as e:
        logger.error(f"Failed to clone VM: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create VM: {e}")

    course_session_key = request.course_session_key or request.session_key

    # Create initial database record
    await db.execute(
        """
        INSERT INTO vm_sessions (
            session_id, session_key, course_session_key, user_id, user_email, user_name,
            course_id, course_title, assignment_id, assignment_title,
            vm_ip, vm_name, vm_id, url, status, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, $11, $12, $13, 'starting', $14)
        """,
        session_id, request.session_key, course_session_key, request.user_id, request.user_email,
        request.user_name, request.course_id, request.course_title,
        request.assignment_id, request.assignment_title, vm_name, vmid, url, expires_at
    )

    grade_token = await assign_grade_token(db, session_id)

    logger.info(f"Provisioned VM {vm_name} (ID: {vmid}) on Proxmox")

    await log_event(db, session_id, 'provisioned', {
        'user_id': request.user_id,
        'course_id': request.course_id,
        'vm_id': vmid
    })

    # Start VM and wait for readiness in background
    async def finalize_provisioning():
        try:
            # Start the VM
            start_vm(proxmox_api, vmid)

            # Wait for VM to get IP
            logger.info(f"Waiting for VM {vmid} to get IP...")
            vm_ip = await wait_for_vm_ip(proxmox_api, vmid, timeout=300)

            if not vm_ip:
                logger.error(f"VM {vmid} did not get IP after timeout")
                await db.execute(
                    "UPDATE vm_sessions SET status = 'error', status_message = 'IP timeout' WHERE session_id = $1",
                    session_id
                )
                return

            logger.info(f"VM {vmid} got IP: {vm_ip}")

            # Update session with actual IP
            await db.execute(
                "UPDATE vm_sessions SET vm_ip = $2 WHERE session_id = $1",
                session_id, vm_ip
            )

            # Wait for SSH port to be open
            logger.info(f"Waiting for SSH on {vm_ip}...")
            ssh_ready = await wait_for_ssh(vm_ip, timeout=300)

            if not ssh_ready:
                logger.error(f"SSH not available on {vm_ip} after timeout")
                await db.execute(
                    "UPDATE vm_sessions SET status = 'error', status_message = 'SSH timeout' WHERE session_id = $1",
                    session_id
                )
                return

            # If nested SSH is enabled, start nested VMs and wait for workstation
            if NESTED_SSH_ENABLED:
                # Wait for system to be fully booted (not just SSH port open)
                logger.info(f"Waiting for system to be fully booted on {vm_ip}...")
                login_ready = await wait_for_ssh_login(vm_ip, SSH_USER, SSH_PASSWORD, timeout=180)
                if not login_ready:
                    logger.error(f"SSH login not ready on {vm_ip} after timeout")
                    await db.execute(
                        "UPDATE vm_sessions SET status = 'error', status_message = 'SSH login timeout' WHERE session_id = $1",
                        session_id
                    )
                    return

                # Update status to show we're starting nested VMs
                await db.execute(
                    "UPDATE vm_sessions SET status_message = 'nested_starting' WHERE session_id = $1",
                    session_id
                )
                logger.info(f"Starting nested VMs on {vm_ip}...")

                # Run rht-vmctl start all (retry a few times if it fails)
                for attempt in range(3):
                    success, output = await run_ssh_command(
                        vm_ip, SSH_USER, SSH_PASSWORD,
                        "rht-vmctl start all",
                        timeout=120
                    )
                    if success:
                        logger.info(f"rht-vmctl start all succeeded on attempt {attempt + 1}")
                        break
                    logger.warning(f"rht-vmctl start all attempt {attempt + 1} failed: {output}")
                    if attempt < 2:
                        await asyncio.sleep(10)
                else:
                    logger.warning(f"rht-vmctl start all failed after 3 attempts, continuing anyway")

                # Update status to show we're waiting for workstation
                await db.execute(
                    "UPDATE vm_sessions SET status_message = 'nested_waiting' WHERE session_id = $1",
                    session_id
                )
                logger.info(f"Waiting for {NESTED_SSH_HOST} to become available...")

                # Wait for workstation to be reachable (up to 5 minutes)
                workstation_ready = False
                for attempt in range(60):  # 60 attempts * 5 seconds = 5 minutes
                    if await check_nested_host_ssh(vm_ip, SSH_USER, SSH_PASSWORD, NESTED_SSH_HOST):
                        workstation_ready = True
                        logger.info(f"{NESTED_SSH_HOST} is now reachable")
                        break
                    await asyncio.sleep(5)

                if not workstation_ready:
                    logger.error(f"{NESTED_SSH_HOST} not reachable after timeout")
                    await db.execute(
                        "UPDATE vm_sessions SET status = 'error', status_message = 'Workstation timeout' WHERE session_id = $1",
                        session_id
                    )
                    return

                # Connect lab environment to LMS
                await db.execute(
                    "UPDATE vm_sessions SET status_message = 'lms_connecting' WHERE session_id = $1",
                    session_id
                )
                logger.info(f"Connecting lab environment to LMS...")

                # Run the LMS connection command on the workstation via the outer VM
                lms_connect_cmd = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {NESTED_SSH_USER}@{NESTED_SSH_HOST} 'curl -sL nos120.labsconnect.org | bash'"
                success, output = await run_ssh_command(
                    vm_ip, SSH_USER, SSH_PASSWORD,
                    lms_connect_cmd,
                    timeout=120
                )
                if success:
                    logger.info(f"LMS connection successful: {output[:200]}")
                else:
                    logger.warning(f"LMS connection command returned non-zero (continuing): {output[:200]}")

                # Configure xAPI with user email
                if request.user_email:
                    logger.info(f"Configuring xAPI with user email: {request.user_email}")
                    # Use bash -lc to ensure login shell environment with lab subcommands available
                    xapi_config_cmd = nested_xapi_email_command(
                        NESTED_SSH_USER, NESTED_SSH_HOST, request.user_email
                    )
                    success, output = await run_ssh_command(
                        vm_ip, SSH_USER, SSH_PASSWORD,
                        xapi_config_cmd,
                        timeout=60
                    )
                    if success:
                        logger.info(f"xAPI email configuration successful: {output[:200]}")
                    else:
                        logger.warning(f"xAPI email configuration failed (continuing): {output[:200]}")
                else:
                    logger.warning("No user email provided, skipping xAPI configuration")

                await inject_guest_xapi_config(
                    run_ssh_command,
                    vm_ip=vm_ip,
                    ssh_user=SSH_USER,
                    ssh_password=SSH_PASSWORD,
                    nested_user=NESTED_SSH_USER,
                    nested_host=NESTED_SSH_HOST,
                    token=grade_token,
                    passback=get_passback_url(),
                    session_id=session_id,
                )

            # Create recording entry
            await create_recording_entry(
                db, session_id,
                request.user_id, request.user_email, request.user_name,
                request.course_id, request.course_title,
                request.assignment_id, request.assignment_title,
                recording_path, timing_path
            )

            # Spawn ttyd container
            container_id = spawn_ttyd_container(
                session_id, vm_ip, DOMAIN,
                recording_path, timing_path
            )

            if container_id:
                await db.execute(
                    """
                    UPDATE vm_sessions
                    SET status = 'running', started_at = CURRENT_TIMESTAMP,
                        container_id = $2, container_name = $3, status_message = NULL
                    WHERE session_id = $1
                    """,
                    session_id, container_id, f"ttyd-{session_id}"
                )
                await log_event(db, session_id, 'running', {'recording_path': recording_path})
                logger.info(f"Session {session_id} is now running")
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
        vm_ip=None,
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
        "SELECT vm_id FROM vm_sessions WHERE session_id = $1",
        session_id
    )

    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    await destroy_session_internal(db, session_id, row['vm_id'])

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

    count_query = f"SELECT COUNT(*) FROM vm_sessions WHERE {where_clause}"
    total = await db.fetchval(count_query, *params)

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
    """List session recordings with filtering options."""
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

    count_query = f"SELECT COUNT(*) FROM session_recordings WHERE {where_clause}"
    total = await db.fetchval(count_query, *params)

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
    """Download the raw recording file."""
    db = await get_db()

    row = await db.fetchrow(
        "SELECT recording_path, user_email, started_at FROM session_recordings WHERE id = $1",
        recording_id
    )

    if not row or not row['recording_path']:
        raise HTTPException(status_code=404, detail="Recording not found")

    if not os.path.exists(row['recording_path']):
        raise HTTPException(status_code=404, detail="Recording file not found on disk")

    date_str = row['started_at'].strftime("%Y%m%d_%H%M%S") if row['started_at'] else "unknown"
    email_part = sanitize_filename(row['user_email'].split('@')[0] if row['user_email'] else "unknown")
    filename = f"recording_{email_part}_{date_str}.log"

    return FileResponse(
        row['recording_path'],
        media_type="text/plain",
        filename=filename
    )


@app.get("/api/recordings/{recording_id}/view")
async def view_recording(recording_id: int):
    """View recording contents as plain text."""
    db = await get_db()

    row = await db.fetchrow(
        "SELECT recording_path FROM session_recordings WHERE id = $1",
        recording_id
    )

    if not row or not row['recording_path']:
        raise HTTPException(status_code=404, detail="Recording not found")

    if not os.path.exists(row['recording_path']):
        raise HTTPException(status_code=404, detail="Recording file not found on disk")

    try:
        with open(row['recording_path'], 'r', errors='replace') as f:
            content = f.read(1024 * 1024)

        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_content = ansi_escape.sub('', content)

        return PlainTextResponse(clean_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read recording: {e}")


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

    unique_students = await db.fetchval(
        "SELECT COUNT(DISTINCT user_email) FROM session_recordings WHERE user_email IS NOT NULL"
    )

    total_sessions = await db.fetchval("SELECT COUNT(*) FROM vm_sessions")

    return {
        "running_vms": stats['running'],
        "starting_vms": stats['starting'],
        "error_vms": stats['errors'],
        "total_destroyed": stats['destroyed'],
        "active_courses": stats['active_courses'],
        "active_users": stats['active_users'],
        "vm_ram_mb": VM_RAM_MB,
        "vm_vcpus": VM_VCPUS,
        "total_recordings": recording_stats['total_recordings'],
        "completed_recordings": recording_stats['completed_recordings'],
        "total_recording_size_mb": round(recording_stats['total_recording_bytes'] / (1024 * 1024), 2),
        "total_sessions": total_sessions,
        "active_sessions": stats['running'],
        "unique_students": unique_students or 0,
        "proxmox_host": PROXMOX_HOST,
        "proxmox_node": PROXMOX_NODE
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
