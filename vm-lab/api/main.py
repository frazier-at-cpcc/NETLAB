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
import socket
from dataclasses import dataclass
from typing import Optional, List
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType

import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, Response, JSONResponse
from pydantic import BaseModel, Field, computed_field
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
        session_grade_summary,
    )
    import access
    import csc228_home
    import idle_reclaim
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
        session_grade_summary,
    )
    from api import access
    from api import csc228_home
    from api import idle_reclaim
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
PROXMOX_TEMPLATE_SNAPSHOT = os.getenv(
    "PROXMOX_TEMPLATE_SNAPSHOT", "base-with-reporting"
)
# Linked clones are storage-dependent when the source is not a Proxmox
# template. On LVM-thin, full=0 against a snapshot silently yields a full
# clone. On a ZFS pool the same call is refused outright with "Linked clone
# feature is not supported for a snapshot of ...". Deployments whose image
# lives on ZFS set this; the default keeps what every existing deployment
# already sends.
PROXMOX_FULL_CLONE = os.getenv("PROXMOX_FULL_CLONE", "").strip().lower() in {
    "1", "true", "yes", "on",
}
def _int_setting(raw: str | None, default: int) -> int:
    """Read an integer setting that docker-compose may supply as empty.

    Compose substitutes an empty string, not None, for a variable the operator
    has not set, so a bare int(os.getenv(name, "0")) raises ValueError on "".
    This runs at import, so that failure crash-loops the whole service instead
    of failing one request. The same trap is recorded against LTI11_CONSUMERS.
    """
    try:
        return int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        return default


# Seconds to wait for the clone task. Zero means choose by clone mode.
PROXMOX_CLONE_TIMEOUT = _int_setting(os.getenv("PROXMOX_CLONE_TIMEOUT"), 0)
LINKED_CLONE_TIMEOUT = 120
FULL_CLONE_TIMEOUT = 1800


def clone_timeout_seconds(*, full_clone: bool) -> int:
    """How long to wait for a clone task.

    A linked clone writes almost nothing and finishes in seconds. A full clone
    copies the entire disk, and 128 GiB takes far longer than the 120 seconds
    that was chosen when linked was the only mode. Overrunning the wait does
    not cancel the clone: Proxmox finishes it and lab-api has already raised,
    so the virtual machine survives with nothing owning it.
    """
    if PROXMOX_CLONE_TIMEOUT:
        return PROXMOX_CLONE_TIMEOUT
    return FULL_CLONE_TIMEOUT if full_clone else LINKED_CLONE_TIMEOUT
PROXMOX_BRIDGE = os.getenv("PROXMOX_BRIDGE", "vmbr0")
PROXMOX_VLAN_TAG = os.getenv("PROXMOX_VLAN_TAG", "")  # Optional VLAN tag for net0; empty = use bridge native/untagged
PROXMOX_MTU = os.getenv("PROXMOX_MTU", "")  # Optional MTU for net0; empty = Proxmox default (1500)

# Browser RDP desktop access. Off by default. Phase 9 of the browser RDP plan
# governs the rollout; nothing reads this beyond the reported access mode
# until the gateway broker and provisioning hooks land.
BROWSER_RDP_ENABLED = os.getenv("BROWSER_RDP_ENABLED", "").strip().lower() in {
    "1", "true", "yes", "on",
}
RDP_PORT = int(os.getenv("RDP_PORT", "3389"))
RDP_USERNAME = os.getenv("RDP_USERNAME", "student")
# RHEL GNOME Remote Desktop negotiates TLS. Windows images will want "nla".
RDP_SECURITY = os.getenv("RDP_SECURITY", "any")
# The password is never stored on the access record. The record carries this
# reference, and only lab-api resolves it.
LAB_RDP_CREDENTIAL_REF = "env:LAB_RDP_PASSWORD"

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
# The same key as seen from inside the ttyd container, which mounts the key
# directory at /keys.
TTYD_KEY_PATH = os.getenv("TTYD_KEY_PATH", "/keys/id_ed25519")
# The key directory's path ON THE DOCKER HOST.
#
# This has to be configured separately and cannot be derived from
# SSH_PRIVATE_KEY_PATH. That path is where this process sees the key, inside
# its own container, and a bind source is resolved by the daemon on the host.
# Passing the container path mounted an unrelated empty host directory, so
# the terminal got no key and every key login failed with "Identity file not
# accessible" while the file sat correctly in place one container away.
TTYD_KEY_HOST_DIR = os.getenv("TTYD_KEY_HOST_DIR", "")
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
# How long a session may sit in provisioning or starting before it is
# treated as dead. A clone and boot takes a few minutes, so this is
# deliberately generous: reaping a session that is merely slow would destroy
# a VM while a student watches it come up.
STUCK_SESSION_MINUTES = int(os.getenv("STUCK_SESSION_MINUTES", "30"))

# The NAS VM that serves persistent homes. 0 disables them everywhere, which
# is the state until one is configured.
CSC228_NAS_VMID = int(os.getenv("CSC228_NAS_VMID", "0"))
# The issuer half of the home key.
#
# Deliberately a deployment constant rather than anything carried on a
# launch. The broker forwards the upstream subject unchanged as user_id, so
# the subject half is already stable across sections and terms, but every
# per-launch issuer candidate is a hazard: an OAuth consumer key can be
# rotated, and rotating it would change every key and orphan every
# student's directory while the NAS still held their work. This value exists
# only so two deployments sharing one NAS cannot collide, and it must never
# be changed on a running course.
HOME_KEY_ISSUER = os.getenv("HOME_KEY_ISSUER", "ltibroker")

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
    lab_slug: Optional[str] = None
    # None, not DEFAULT_SESSION_HOURS. A concrete default here is always
    # truthy, so it silently won over the course family's session_hours and
    # every CSC 228 lab expired after 4 hours instead of 8.
    session_hours: Optional[int] = None


class DesktopRedeemRequest(BaseModel):
    token: str


class GradeCellRequest(BaseModel):
    course_session_id: str
    lab_slug: Optional[str] = None
    resource_link_id: Optional[str] = None
    outcome_service_url: Optional[str] = None
    sourcedid: Optional[str] = None
    consumer_key: Optional[str] = None


# Reason codes for an unavailable desktop mode. The browser shows the student
# a message chosen from these; none of them names a host, a port, or an image.
DESKTOP_DISABLED = "disabled"
DESKTOP_PENDING = "pending"
DESKTOP_NOT_PROVISIONED = "not_provisioned"


class TerminalAccess(BaseModel):
    url: Optional[str] = None


class DesktopAccess(BaseModel):
    """Availability only. This structure is relayed to the browser by an
    unauthenticated proxy, so it carries no token and no target detail."""

    available: bool = False
    reason: Optional[str] = None


class SessionAccess(BaseModel):
    terminal: TerminalAccess
    desktop: DesktopAccess


def build_access(
    url: Optional[str], ready: bool, desktop_record: bool = False
) -> SessionAccess:
    """Derive the access map from the values a response already reports.

    Deriving rather than assigning is what keeps `url` and
    access.terminal.url from drifting apart as later phases fill in the
    desktop mode.
    """
    if not BROWSER_RDP_ENABLED:
        desktop = DesktopAccess(reason=DESKTOP_DISABLED)
    elif not ready:
        desktop = DesktopAccess(reason=DESKTOP_PENDING)
    elif desktop_record:
        desktop = DesktopAccess(available=True)
    else:
        desktop = DesktopAccess(reason=DESKTOP_NOT_PROVISIONED)
    return SessionAccess(terminal=TerminalAccess(url=url), desktop=desktop)


class Session(BaseModel):
    session_id: str
    url: str
    vm_ip: Optional[str] = None
    status: str
    # Carried so a recreate can take the lab from the row rather than from
    # the cookie session, which is not sent inside the Brightspace iframe.
    lab_slug: Optional[str] = None
    user_name: Optional[str] = None
    course_title: Optional[str] = None
    assignment_title: Optional[str] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    @computed_field
    @property
    def access(self) -> SessionAccess:
        return build_access(self.url, self.status == "running")


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
    error_message: Optional[str] = None
    steps: List[ProvisioningStep]
    progress_percent: int
    estimated_seconds_remaining: Optional[int] = None
    # Whether this session's files survive it ending. False until
    # provision_home is wired, and false per-session when an attach fails,
    # so the page never promises persistence a student does not have.
    persistent_home: bool = False
    # None when the course does not use notebooks, so the page stays silent
    # for every course that never had them.
    notebooks_available: Optional[bool] = None
    # Input to the access map, never part of the payload. The browser learns
    # that a desktop exists, not what the record holds.
    desktop_record: bool = Field(default=False, exclude=True)

    @computed_field
    @property
    def access(self) -> SessionAccess:
        return build_access(self.url, self.ready, self.desktop_record)


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

    write_core_traefik_routes(DOMAIN)

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


@dataclass(frozen=True)
class TemplateChoice:
    """What a launch clones, and at what size. Resolved once, then carried,
    so the decision is made in one place and logged with the session.

    cores and memory_mb are None when the course states no shape, which keeps
    the deployment defaults VM_VCPUS and VM_RAM_MB. clone_vm resolves them;
    nothing else reads them."""

    template_id: int
    snapshot_name: str
    cores: Optional[int] = None
    memory_mb: Optional[int] = None
    session_hours: Optional[int] = None
    terminal_persist: bool = False
    terminal_recording: bool = True
    persistent_home: bool = False
    # None means use the deployment default, so a course with no row keeps
    # today's behaviour exactly.
    ssh_user: Optional[str] = None
    nested_ssh: Optional[bool] = None
    # "key" or "password". None is the deployment password.
    ssh_auth: Optional[str] = None
    # VM-side channels this family publishes. Empty is the terminal only.
    channels: tuple = ()


COURSE_TEMPLATE_SQL = """
SELECT template_id, snapshot_name, cores, memory_mb
FROM course_templates
WHERE course_id = $1
"""


def _optional_column(row, name: str):
    """Read a column that migration 007 may not have added yet.

    006 made the course mapping additive: a deployment without the table
    falls back to the deployment default rather than failing. The shape
    columns keep that promise. A row from a database still on 006 has no
    cores or memory_mb, and asking for them by subscript raises rather than
    degrading, so the absence is treated as "course states no shape".
    """
    try:
        value = row[name]
    except (KeyError, IndexError, TypeError):
        return None
    return value


async def resolve_course_template(db, course_id: Optional[str]) -> TemplateChoice:
    """Return the template a course clones from.

    Additive by construction. A course with no mapping, a launch carrying no
    course, and a deployment where the table does not yet exist all resolve to
    the deployment default, which is what every course clones today.
    """
    default = TemplateChoice(PROXMOX_TEMPLATE_ID, PROXMOX_TEMPLATE_SNAPSHOT)
    if not course_id:
        return default

    try:
        row = await db.fetchrow(COURSE_TEMPLATE_SQL, course_id)
    except Exception as exc:
        logger.warning(
            "Course template lookup failed for %s, using the deployment "
            "default: %s",
            course_id,
            type(exc).__name__,
        )
        return default

    if not row:
        return default

    stored = row["snapshot_name"]
    # NULL defers to the deployment default. An empty string is a deliberate
    # choice of no snapshot, which a template carrying none requires.
    return TemplateChoice(
        template_id=row["template_id"],
        snapshot_name=PROXMOX_TEMPLATE_SNAPSHOT if stored is None else stored,
        cores=_optional_column(row, "cores"),
        memory_mb=_optional_column(row, "memory_mb"),
    )


LAB_TEMPLATE_SQL = """
SELECT slug_prefix, template_id, snapshot_name, cores, memory_mb,
       session_hours, terminal_persist, terminal_recording, persistent_home,
       ssh_user, nested_ssh, channels, ssh_auth
FROM lab_templates
WHERE $1 LIKE slug_prefix || '%'
ORDER BY length(slug_prefix) DESC
LIMIT 1
"""


async def resolve_lab_template(
    db, lab_slug: Optional[str], course_id: Optional[str]
) -> TemplateChoice:
    """Return the template a launch clones, preferring the lab slug.

    Order is slug prefix, then course, then deployment default. The slug wins
    because it names the course family and outlives every shell: csc228-lab-02
    is the same slug in every section and every term, while course_id changes
    with each new Brightspace shell and silently stops matching.

    The longest matching prefix wins, so a narrower rule can override a
    broader one without deleting it.

    Falls through to resolve_course_template on any failure, including a
    database still on 007 where the table does not exist, so a course that
    relies on the shell mapping keeps working.
    """
    if lab_slug:
        try:
            row = await db.fetchrow(LAB_TEMPLATE_SQL, lab_slug)
        except Exception as exc:
            logger.warning(
                "Lab template lookup failed for %s, falling back to the course "
                "mapping: %s",
                lab_slug,
                type(exc).__name__,
            )
            row = None
        if row:
            stored = row["snapshot_name"]
            logger.info(
                "Lab slug %s matched prefix %s, cloning template %s",
                lab_slug, row["slug_prefix"], row["template_id"],
            )
            persist = _optional_column(row, "terminal_persist")
            recording = _optional_column(row, "terminal_recording")
            return TemplateChoice(
                template_id=row["template_id"],
                snapshot_name=PROXMOX_TEMPLATE_SNAPSHOT if stored is None else stored,
                cores=_optional_column(row, "cores"),
                memory_mb=_optional_column(row, "memory_mb"),
                session_hours=_optional_column(row, "session_hours"),
                terminal_persist=bool(persist),
                # A database still on 008 has no column; recording stays on,
                # which is what every course does today.
                terminal_recording=True if recording is None else bool(recording),
                persistent_home=bool(_optional_column(row, "persistent_home")),
                ssh_user=_optional_column(row, "ssh_user"),
                nested_ssh=_optional_column(row, "nested_ssh"),
                channels=_parse_channels(_optional_column(row, "channels")),
                ssh_auth=_optional_column(row, "ssh_auth"),
            )

    return await resolve_course_template(db, course_id)


def clone_vm(
    proxmox: ProxmoxAPI,
    session_id: str,
    vm_name: str,
    choice: "TemplateChoice" = None,
    wait=None,
) -> int:
    """Clone a VM from the template the course resolved to."""
    if choice is None:
        choice = TemplateChoice(PROXMOX_TEMPLATE_ID, PROXMOX_TEMPLATE_SNAPSHOT)
    if wait is None:
        wait = wait_for_task
    vmid = allocate_vm_id(proxmox)

    logger.info(
        f"Cloning template {choice.template_id} "
        f"snapshot {choice.snapshot_name or 'none'} to VM {vmid} ({vm_name})"
    )

    # Clone the template - returns a task ID (UPID)
    # Using linked clone (full=0) from snapshot for faster provisioning
    # Linked clones share the base snapshot's disk as a read-only base
    clone_args = {
        "newid": vmid,
        "name": vm_name,
        "target": PROXMOX_NODE,
        "full": 1 if PROXMOX_FULL_CLONE else 0,
    }
    # Every RHCSA foundation template on the pve cluster carries no snapshot.
    # Sending snapname regardless asks Proxmox for one that does not exist and
    # the clone fails, so the parameter is omitted when no snapshot is named.
    if choice.snapshot_name:
        clone_args["snapname"] = choice.snapshot_name

    upid = proxmox.nodes(PROXMOX_NODE).qemu(choice.template_id).clone.post(
        **clone_args
    )

    # Wait for clone task to complete
    logger.info(f"Waiting for clone task {upid} to complete...")
    wait(proxmox, PROXMOX_NODE, upid,
         timeout=clone_timeout_seconds(full_clone=PROXMOX_FULL_CLONE))
    logger.info(f"Clone completed for VM {vmid}")

    # Configure the cloned VM. Build net0 from optional VLAN tag and MTU so that
    # environments where the template's net0 needs a tag (VLAN-aware bridge) or a
    # non-default MTU don't lose those parameters when this rewrite happens.
    net0 = f"virtio,bridge={PROXMOX_BRIDGE}"
    if PROXMOX_VLAN_TAG:
        net0 += f",tag={PROXMOX_VLAN_TAG}"
    if PROXMOX_MTU:
        net0 += f",mtu={PROXMOX_MTU}"

    # Shape comes from the course when it states one, otherwise from the
    # deployment. sockets is pinned to 1 and cores carries the whole vCPU
    # count, because Proxmox multiplies sockets by cores: cores=8 against a
    # template built with 2 sockets yields 16 vCPUs, not 8. Pinning here
    # makes the requested number the delivered number whatever the template
    # was built with.
    cores = choice.cores if choice.cores else VM_VCPUS
    memory_mb = choice.memory_mb if choice.memory_mb else VM_RAM_MB
    logger.info(
        f"Configuring VM {vmid}: {cores} vCPU (1 socket), {memory_mb} MB, net0={net0}"
    )

    proxmox.nodes(PROXMOX_NODE).qemu(vmid).config.put(
        memory=memory_mb,
        sockets=1,
        cores=cores,
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


# How long to wait for a VM to actually stop before giving up on deleting it.
VM_STOP_TIMEOUT_SECONDS = int(os.getenv("VM_STOP_TIMEOUT_SECONDS", "60"))
# Whether the orphan sweep may actually delete what it finds.
#
# Off by default, and deliberately so: it reports and changes nothing until
# someone turns it on. The sweep deletes student VMs and terminal
# containers, and a bug in the matching would destroy a lab somebody is
# sitting in. Reporting first makes the matching auditable against a real
# node before it is given the power to act.
ORPHAN_REAP_ENABLED = os.getenv("ORPHAN_REAP_ENABLED", "").lower() in ("1", "true", "yes")
VM_STOP_POLL_SECONDS = 2


def destroy_vm(proxmox: ProxmoxAPI, vmid: int):
    """Stop a VM, wait for it to actually stop, then delete it.

    The wait is the point. This used to post a stop and sleep five seconds,
    which is a race a 24 GB guest loses: Proxmox then refuses the delete with
    "VM is running - destroy failed", the error was logged and swallowed, and
    the VM stayed on the node forever. The session row said destroyed while
    the disk and the pool slot were still held, so nothing reported the leak.
    """
    logger.info(f"Destroying VM {vmid}")
    try:
        status = proxmox.nodes(PROXMOX_NODE).qemu(vmid).status.current.get()
        if status.get('status') == 'running':
            proxmox.nodes(PROXMOX_NODE).qemu(vmid).status.stop.post()
            deadline = time.monotonic() + VM_STOP_TIMEOUT_SECONDS
            while True:
                current = proxmox.nodes(PROXMOX_NODE).qemu(vmid).status.current.get()
                if current.get('status') != 'running':
                    break
                if time.monotonic() >= deadline:
                    # Deleting now would fail and be swallowed, leaving the VM
                    # on the node with nothing saying so. Say so instead.
                    logger.error(
                        "VM %s did not stop within %ss, NOT deleting. It is "
                        "still on the node and still holding a pool slot.",
                        vmid, VM_STOP_TIMEOUT_SECONDS,
                    )
                    return
                time.sleep(VM_STOP_POLL_SECONDS)

        proxmox.nodes(PROXMOX_NODE).qemu(vmid).delete()
        logger.info(f"VM {vmid} destroyed")
    except Exception as e:
        # A VM removed outside this service, by hand in the Proxmox UI or by
        # another operator, is not a teardown failure: the session still
        # closes and the student is still released. Reporting it as an error
        # sends whoever greps the log during an incident after a problem that
        # does not exist.
        if "does not exist" in str(e):
            logger.info("VM %s was already gone, nothing to destroy", vmid)
        else:
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

def write_core_traefik_routes(domain: str) -> None:
    """Write the routes for the long-lived services.

    Traefik runs with the file provider only. No Docker socket is mounted, so
    every traefik.* label in docker-compose.yml is inert, including the ones
    that were supposed to publish the RDP gateway. Generating the routes here
    keeps the hostnames derived from DOMAIN, which a static file cannot do,
    and follows the pattern the per-session routes already use.
    """
    route_file = os.path.join(TRAEFIK_DYNAMIC_DIR, "core-services.yml")
    config = f"""# Auto-generated. Hostnames follow DOMAIN, which a static file cannot.
http:
  routers:
    core-lti:
      rule: "Host(`lti.{domain}`)"
      entryPoints: [web, websecure]
      service: core-lti
    core-api:
      rule: "Host(`api.{domain}`)"
      entryPoints: [web, websecure]
      service: core-api
    core-rdp:
      rule: "Host(`rdp.{domain}`)"
      entryPoints: [web, websecure]
      service: core-rdp
    core-rdp-ws:
      rule: "Host(`rdp.{domain}`) && PathPrefix(`/ws`)"
      entryPoints: [web, websecure]
      service: core-rdp-ws
  services:
    core-lti:
      loadBalancer:
        servers:
          - url: "http://lti-server:8000"
    core-api:
      loadBalancer:
        servers:
          - url: "http://lab-api:8000"
    core-rdp:
      loadBalancer:
        servers:
          - url: "http://rdp-gateway:8080"
    core-rdp-ws:
      loadBalancer:
        servers:
          - url: "http://rdp-gateway:8081"
"""
    try:
        os.makedirs(TRAEFIK_DYNAMIC_DIR, exist_ok=True)
        with open(route_file, "w") as handle:
            handle.write(config)
        logger.info("Wrote core Traefik routes for domain %s", domain)
    except Exception as exc:
        logger.error("Failed to write core Traefik routes: %s", type(exc).__name__)


# Per-session browser channels served from inside the VM. The terminal is a
# container and is always routed; these are ports on the VM itself and are
# routed only when a course asks for them, so a course whose image listens on
# neither does not get two routes to a closed port.
# app is 3000, not 8080. Labs 3, 7 and 8 run llama-server, and the Lab 8
# container, on 8080 inside the VM, so publishing Open WebUI there would
# collide with the student's own server in the one lab that needs both.
VM_CHANNEL_PORTS = {"jupyter": 8888, "app": 3000}

# Channels whose port must answer before their route is published.
#
# JupyterLab is enabled at boot, so a closed 8888 after the guest agent
# answers is a real fault, most likely the networkd wait-online stall. A
# route to it would 502 and read to a student as a broken lab.
#
# Open WebUI on 3000 is deliberately absent: it stays stopped until the
# student runs `csc228-webui start` in the Lab 7 voice section, so its route
# publishes unconditionally and the expected 502 is explained by the lab
# text. Probing it would drop the route every student needs.
PROBED_CHANNELS = frozenset({"jupyter"})
# ponytail: blocking connect, called from sync spawn code. Short on purpose.
# Move to asyncio.open_connection if spawn ever becomes async.
CHANNEL_PROBE_TIMEOUT_SECONDS = 2
# How long to keep waiting for a probed channel before giving up on it.
#
# A single probe immediately after SSH is a race, and it lost: systemd marks
# csc228-jupyter active as soon as the process starts, while JupyterLab takes
# longer to bind 8888. The first run of this probed four seconds after the
# unit went active, found the port closed, withheld the route for the whole
# session, and logged a fault on a VM that was fine.
CHANNEL_READY_TIMEOUT_SECONDS = int(os.getenv("CHANNEL_READY_TIMEOUT_SECONDS", "90"))
CHANNEL_READY_POLL_SECONDS = 3


def _parse_channels(raw) -> tuple:
    """Split a stored channel list. NULL or empty means the terminal only."""
    if not raw:
        return ()
    return tuple(name.strip() for name in str(raw).split(",") if name.strip())


def port_open(host: str, port: int,
              timeout: float = CHANNEL_PROBE_TIMEOUT_SECONDS) -> bool:
    """True when something accepts a TCP connection. Never raises."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_port(host: str, port: int,
                  timeout: float = CHANNEL_READY_TIMEOUT_SECONDS) -> bool:
    """Poll a port until it answers or the budget runs out.

    A service can be systemd-active seconds before it binds, so a single
    probe is a race. Returns as soon as the port answers, so a healthy VM
    costs one connect.
    """
    deadline = time.monotonic() + timeout
    while True:
        if port_open(host, port):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(CHANNEL_READY_POLL_SECONDS)


def ready_channels(vm_ip: Optional[str], channels,
                   timeout: float = CHANNEL_READY_TIMEOUT_SECONDS) -> list:
    """Narrow requested channels to the ones worth publishing.

    A probed channel whose port never answers is dropped, so the student
    gets a terminal rather than a route that 502s. An unprobed channel is
    always published.

    Without an address nothing can be probed, so only unprobed channels
    survive.
    """
    ready = []
    for channel in channels:
        if channel not in VM_CHANNEL_PORTS:
            logger.warning("Unknown channel %s requested, skipping", channel)
            continue
        if channel not in PROBED_CHANNELS:
            ready.append(channel)
            continue
        if not vm_ip:
            logger.warning("No address to probe for channel %s, skipping", channel)
            continue
        if wait_for_port(vm_ip, VM_CHANNEL_PORTS[channel], timeout=timeout):
            ready.append(channel)
        else:
            logger.warning(
                "Channel %s never answered on %s within %ss, publishing "
                "without it",
                channel, VM_CHANNEL_PORTS[channel], timeout,
            )
    return ready


def write_traefik_route(
    session_id: str,
    container_name: str,
    domain: str,
    vm_ip: str = None,
    channels: tuple = (),
):
    """Write every route for one session into one file.

    One file and one write, rather than a later second pass, because the VM
    address is already known here: the ttyd container is built around an ssh
    command naming it. Splitting the write would mean a session whose file
    was rewritten mid-provision, and Traefik reloads on file change.

    `channels` names the VM-side channels to publish, from VM_CHANNEL_PORTS.
    Empty is the default and reproduces exactly the file written before this
    existed, so every course that asks for nothing is untouched. Each channel
    is a separate hostname rather than a path prefix, because the wildcard
    tunnel ingress matches one label and because JupyterLab and Open WebUI
    both expect to be served at the root.
    """
    route_file = os.path.join(TRAEFIK_DYNAMIC_DIR, f"session-{session_id}.yml")

    routers = f"""    ttyd-{session_id}:
      rule: "Host(`lab-{session_id}.{domain}`)"
      entryPoints:
        - web
      service: ttyd-{session_id}
"""
    services = f"""    ttyd-{session_id}:
      loadBalancer:
        servers:
          - url: "http://{container_name}:7681"
"""

    for channel in channels:
        port = VM_CHANNEL_PORTS.get(channel)
        if port is None:
            logger.warning("Unknown session channel %r, not routed", channel)
            continue
        if not vm_ip:
            logger.warning(
                "Channel %r needs the VM address and none was given, not routed",
                channel,
            )
            continue
        routers += f"""    {channel}-{session_id}:
      rule: "Host(`{channel}-{session_id}.{domain}`)"
      entryPoints:
        - web
      service: {channel}-{session_id}
"""
        services += f"""    {channel}-{session_id}:
      loadBalancer:
        servers:
          - url: "http://{vm_ip}:{port}"
"""

    config = (
        f"# Auto-generated routes for session {session_id}\n"
        "http:\n  routers:\n" + routers + "  services:\n" + services
    )
    try:
        with open(route_file, 'w') as f:
            f.write(config)
        logger.info(
            "Wrote Traefik routes for session %s: terminal%s",
            session_id,
            "".join(f", {c}" for c in channels),
        )
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
    timing_path: str,
    persist: bool = False,
    record: bool = True,
    ssh_user: Optional[str] = None,
    nested: Optional[bool] = None,
    channels: tuple = (),
    ssh_auth: Optional[str] = None,
) -> Optional[str]:
    """Spawn a ttyd container for web terminal access.

    `persist` wraps the remote shell in tmux. ttyd runs its command once per
    client connection, so without it a closed browser tab kills the ssh
    session and everything running in it; a three-hour lab loses its work to
    a dropped network. `tmux new-session -A` attaches to the existing shell
    when one is there and creates it when it is not, so the shell lives on
    the VM rather than in the browser connection.

    `record` wraps the whole thing in `script`. Off for families that do not
    record, which also means no recording is finalized on teardown.
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

        # Create recording directory
        recording_dir = os.path.dirname(recording_path)
        os.makedirs(recording_dir, exist_ok=True)

        # Command that wraps SSH with script for recording
        # Use sshpass for password authentication (RHA images use password auth by default)
        # Passwords are passed via environment variables to avoid shell quoting issues
        recording_rel_path = os.path.relpath(recording_path, RECORDINGS_DIR)
        timing_rel_path = os.path.relpath(timing_path, RECORDINGS_DIR)

        # The course family decides, falling back to the deployment default.
        # The Red Hat Academy images need the nested hop. CSC 228 has no
        # nested VM and no kiosk user, so the hop fails outright.
        user = ssh_user or SSH_USER
        use_nested = NESTED_SSH_ENABLED if nested is None else nested
        # The deployment password is the Red Hat Academy default, which the
        # CSC 228 image does not use. Its family authenticates with the
        # orchestrator key, already mounted into this container at /keys.
        use_key = ssh_auth == "key"
        # A bind source is resolved on the host, so the host path is the only
        # correct source. Without it the mount silently yields an empty
        # directory, which is how key auth failed the first time.
        key_host_dir = TTYD_KEY_HOST_DIR or os.path.dirname(SSH_PRIVATE_KEY_PATH)
        if use_key and not TTYD_KEY_HOST_DIR:
            logger.error(
                "TTYD_KEY_HOST_DIR is not set, so the terminal's key mount "
                "will use the in-container path %s as a host source and the "
                "key will be missing. Key logins will fail.",
                key_host_dir,
            )
        ssh_opts = "-t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
        if use_key:
            prefix = f"ssh -i {TTYD_KEY_PATH} -o IdentitiesOnly=yes {ssh_opts}"
        else:
            prefix = f"sshpass -e ssh {ssh_opts}"

        if use_nested:
            # Chain SSH: first connect to outer VM, then directly to nested workstation
            # Nested VMs are already started and workstation is verified reachable by the provisioning process
            # Use SSHPASS env var (-e flag) for outer connection (kiosk uses password)
            # Inner connection to student@workstation uses SSH keys (no password needed)
            inner_connect = f"ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {NESTED_SSH_USER}@{NESTED_SSH_HOST}"
            ssh_command = f"{prefix} {user}@{vm_ip} {inner_connect}"
            logger.info(f"Nested SSH enabled: connecting to {NESTED_SSH_USER}@{NESTED_SSH_HOST} via {user}@{vm_ip}")
            env_vars = {
                "SSHPASS": SSH_PASSWORD,
            }
        else:
            # Direct SSH to the VM only
            remote = ""
            if persist:
                # -A attaches to `lab` when it exists and creates it when it
                # does not, so a reconnect lands in the same shell.
                remote = " tmux new-session -A -s lab"
            ssh_command = f"{prefix} {user}@{vm_ip}{remote}"
            env_vars = {
                "SSHPASS": SSH_PASSWORD,
            }

        # Build the ttyd command with script recording wrapper
        ttyd_command = ["ttyd", "--writable", "--port", "7681"]
        if record:
            ttyd_command += [
                "script", "-q", "-f",
                f"-t/recordings/{timing_rel_path}",
                f"/recordings/{recording_rel_path}",
                "-c", ssh_command,
            ]
        else:
            # No script wrapper, so no recording is written and none is
            # finalized on teardown. sh -c keeps the quoting identical.
            ttyd_command += ["sh", "-c", ssh_command]

        # Use custom image with SSH client installed
        container = docker_client.containers.run(
            "vm-lab-ttyd:latest",
            command=ttyd_command,
            name=container_name,
            detach=True,
            network=DOCKER_NETWORK,
            environment=env_vars,
            volumes={
                key_host_dir: {
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
        write_traefik_route(
            session_id, container_name, domain,
            vm_ip=vm_ip, channels=tuple(channels),
        )

        logger.info(
            "Spawned ttyd container %s (recording=%s, auth=%s)",
            container_name, "on" if record else "off", "key" if use_key else "password",
        )
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
            await reap_stuck_sessions(db)
            await sweep_orphans(db)
            await reclaim_idle_sessions(db)
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
        await destroy_session_internal(
            db, row['session_id'], row['vm_id'], reason="expired"
        )


STUCK_SESSION_SQL = """
SELECT session_id, vm_id, status
FROM vm_sessions
WHERE status IN ('provisioning', 'starting')
  AND created_at < CURRENT_TIMESTAMP - make_interval(mins => $1)
"""


async def reap_stuck_sessions(db: asyncpg.Pool):
    """Destroy sessions that never finished coming up. Never raises.

    Only 'running' sessions were ever reaped, so a session whose clone or
    boot failed sat in 'provisioning' forever. Two things made that worse
    than untidy.

    The student sees a provisioning page that will never finish, because
    find_existing_session returns sessions in these states.

    And since one live lab per class is now enforced by a partial unique
    index over exactly these states, a stuck session blocks the student from
    starting another one. Before that index they could launch again and get
    a second VM; now the failed clone locks them out until someone
    intervenes. This closes a door that change opened.

    Teardown already tolerates a session with no VM, which matters because a
    session that failed early has a NULL vm_id.
    """
    try:
        stuck = await db.fetch(STUCK_SESSION_SQL, STUCK_SESSION_MINUTES)
    except Exception as exc:
        logger.warning("Could not list stuck sessions: %s", type(exc).__name__)
        return

    for row in stuck:
        logger.warning(
            "Reaping session %s stuck in %s for over %s minutes",
            row["session_id"], row["status"], STUCK_SESSION_MINUTES,
        )
        try:
            await destroy_session_internal(
                db, row["session_id"], row["vm_id"], reason="provisioning_timeout"
            )
        except Exception as exc:
            # One bad row must not stop the rest from being released.
            logger.error(
                "Failed to reap stuck session %s: %s",
                row["session_id"], type(exc).__name__,
            )


# A session row in one of these states no longer owns its VM or container.
ORPHAN_DEAD_STATES = ("destroyed", "error")


async def _orphan_session_ids(db: asyncpg.Pool, candidates: list) -> set:
    """Of these session ids, which no longer own anything.

    A session is an owner unless its row says otherwise, so an id this
    cannot resolve is treated as still owned. Deleting a VM because a query
    failed is the one outcome worth engineering against.
    """
    if not candidates:
        return set()
    try:
        rows = await db.fetch(
            """
            SELECT session_id, status
            FROM vm_sessions
            WHERE session_id = ANY($1::text[])
            """,
            candidates,
        )
    except Exception as exc:
        logger.warning(
            "Orphan sweep could not read sessions, treating all as owned: %s",
            type(exc).__name__,
        )
        return set()

    known = {row["session_id"]: row["status"] for row in rows}
    orphans = set()
    for session_id in candidates:
        status = known.get(session_id)
        if status is None:
            # No row at all. The session was deleted from the database while
            # its VM survived, which is how most of these arise.
            orphans.add(session_id)
        elif status in ORPHAN_DEAD_STATES:
            orphans.add(session_id)
    return orphans


async def sweep_orphans(db: asyncpg.Pool):
    """Find student VMs and terminal containers whose session is gone.

    Nothing reaped these. destroy_vm used to post a stop, sleep five
    seconds, and issue a delete that Proxmox refused while the guest was
    still shutting down; the error was logged and swallowed, so the VM
    stayed on the node while the session row read destroyed. Seven had
    accumulated against a pool of about twelve, which is most of it.

    Reports by default and deletes only when ORPHAN_REAP_ENABLED is set, so
    the matching can be checked against a real node before it is trusted to
    act. Never raises.
    """
    verb = "Reaping" if ORPHAN_REAP_ENABLED else "Would reap"

    if proxmox_api:
        try:
            guests = proxmox_api.nodes(PROXMOX_NODE).qemu.get()
        except Exception as exc:
            logger.warning(
                "Orphan sweep could not list VMs: %s", type(exc).__name__
            )
            guests = []
        named = {}
        for guest in guests:
            name = str(guest.get("name") or "")
            if name.startswith("student-") and not guest.get("template"):
                named[name[len("student-"):]] = guest.get("vmid")
        for session_id in sorted(await _orphan_session_ids(db, list(named))):
            vmid = named[session_id]
            logger.warning(
                "%s orphaned VM %s (student-%s): its session no longer owns it",
                verb, vmid, session_id,
            )
            if ORPHAN_REAP_ENABLED:
                await asyncio.to_thread(destroy_vm, proxmox_api, vmid)

    if docker_client:
        try:
            containers = docker_client.containers.list(all=True)
        except Exception as exc:
            logger.warning(
                "Orphan sweep could not list containers: %s", type(exc).__name__
            )
            containers = []
        named = {
            c.name[len("ttyd-"):]: c
            for c in containers
            if c.name.startswith("ttyd-")
        }
        for session_id in sorted(await _orphan_session_ids(db, list(named))):
            logger.warning(
                "%s orphaned terminal container ttyd-%s", verb, session_id
            )
            if ORPHAN_REAP_ENABLED:
                try:
                    named[session_id].remove(force=True)
                except Exception as exc:
                    logger.error(
                        "Could not remove ttyd-%s: %s",
                        session_id, type(exc).__name__,
                    )


IDLE_CANDIDATE_SQL = """
SELECT s.session_id, s.vm_id, s.vm_ip, s.idle_since, t.idle_reclaim_minutes
FROM vm_sessions s
JOIN lab_templates t ON s.lab_slug LIKE t.slug_prefix || '%'
WHERE s.status = 'running'
  AND t.idle_reclaim_minutes IS NOT NULL
"""


async def _probe_http_json(url: str, timeout: float):
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


async def reclaim_idle_sessions(db: asyncpg.Pool):
    """Destroy sessions whose student has gone for good. Never raises.

    Only families that set idle_reclaim_minutes are considered, so every
    other course is untouched. A session must look idle continuously for the
    whole window: idle_since is cleared the moment any signal reports
    activity, so a student who returns resets the clock.

    Any failure holds the VM. Reclaiming a working lab is far worse than
    holding an abandoned one.
    """
    if not proxmox_api:
        return

    try:
        candidates = await db.fetch(IDLE_CANDIDATE_SQL)
    except Exception as exc:
        logger.warning(
            "Idle reclaim could not list candidates: %s", type(exc).__name__
        )
        return

    for row in candidates:
        session_id = row["session_id"]
        try:
            idle = await idle_reclaim.session_is_idle(
                proxmox_api, PROXMOX_NODE, row["vm_id"], row["vm_ip"],
                csc228_home.guest_exec, _probe_http_json,
            )
        except Exception as exc:
            logger.warning(
                "Idle probe failed for %s, holding the VM: %s",
                session_id, type(exc).__name__,
            )
            continue

        if not idle:
            if row["idle_since"] is not None:
                await db.execute(
                    "UPDATE vm_sessions SET idle_since = NULL WHERE session_id = $1",
                    session_id,
                )
            continue

        if row["idle_since"] is None:
            await db.execute(
                "UPDATE vm_sessions SET idle_since = CURRENT_TIMESTAMP "
                "WHERE session_id = $1",
                session_id,
            )
            logger.info("Session %s looks idle, starting the clock", session_id)
            continue

        idle_for = (datetime.now(timezone.utc) - row["idle_since"]).total_seconds()
        if idle_for < row["idle_reclaim_minutes"] * 60:
            continue

        logger.info(
            "Reclaiming %s after %.0f minutes idle", session_id, idle_for / 60
        )
        await destroy_session_internal(
            db, session_id, row["vm_id"], reason="idle_reclaimed"
        )


async def register_desktop_access(db, session_id: str, vm_ip: str) -> bool:
    """Record desktop access for a session. Never raises.

    This runs after the VM is healthy and the terminal already works, so a
    refusal returns False and leaves the student with ttyd. Raising here
    would fail a working lab over a missing desktop.
    """
    if not BROWSER_RDP_ENABLED:
        return False

    try:
        target = access.validated_target(
            host=vm_ip,
            username=RDP_USERNAME,
            credential_ref=LAB_RDP_CREDENTIAL_REF,
            port=RDP_PORT,
            security=RDP_SECURITY,
        )
    except (access.InvalidRdpTarget, access.CredentialUnavailable) as exc:
        logger.error(
            "Desktop access not registered for session %s: %s",
            session_id,
            type(exc).__name__,
        )
        return False

    try:
        await db.execute(
            access.UPSERT_DESKTOP_ACCESS_SQL,
            session_id,
            target.host,
            target.port,
            target.username,
            target.security,
            LAB_RDP_CREDENTIAL_REF,
        )
    except Exception as exc:
        logger.error(
            "Desktop access record failed for session %s: %s",
            session_id,
            type(exc).__name__,
        )
        return False

    logger.info("Registered desktop access for session %s", session_id)
    return True


async def revoke_session_access(db, session_id: str) -> None:
    """Revoke every access record for a session. Never raises.

    Called before the container and the VM go away. A reference that outlives
    the address it names could be redeemed against whatever occupies that
    address next.
    """
    try:
        await db.execute(access.REVOKE_SESSION_ACCESS_SQL, session_id)
    except Exception as exc:
        logger.error(
            "Failed to revoke access for session %s: %s",
            session_id,
            type(exc).__name__,
        )


async def _session_was_recorded(db: asyncpg.Pool, session_id: str) -> bool:
    """Whether this session's family records terminals.

    Unknown counts as recorded, so a database that cannot answer keeps
    today's behaviour rather than silently dropping a real recording.
    """
    try:
        row = await db.fetchrow(
            """
            SELECT coalesce(t.terminal_recording, TRUE) AS recorded
            FROM vm_sessions s
            LEFT JOIN lab_templates t ON s.lab_slug LIKE t.slug_prefix || '%'
            WHERE s.session_id = $1
            """,
            session_id,
        )
    except Exception as exc:
        logger.warning(
            "Could not tell whether %s was recorded: %s",
            session_id, type(exc).__name__,
        )
        return True
    return True if row is None else bool(row["recorded"])


async def release_session_home(db: asyncpg.Pool, session_id: str):
    """Revoke this session's NAS grant. Never raises.

    The key is read back from the row rather than recomputed, so a change to
    the derivation can never revoke a different student's directory.

    A session with no key never had a home, which is every NOS session and
    every CSC 228 session that failed to attach.
    """
    if not CSC228_NAS_VMID or not proxmox_api:
        return
    try:
        row = await db.fetchrow(
            "SELECT vm_ip, home_key FROM vm_sessions WHERE session_id = $1",
            session_id,
        )
    except Exception as exc:
        logger.warning(
            "Could not read the home key for %s: %s", session_id, type(exc).__name__
        )
        return
    if not row or not row["home_key"] or not row["vm_ip"]:
        return
    revoked = await csc228_home.revoke_home(
        proxmox_api, PROXMOX_NODE, CSC228_NAS_VMID, row["vm_ip"]
    )
    if not revoked:
        # Worth an alarm: the export keeps serving an address that is about
        # to be recycled onto another student's VM.
        logger.error(
            "Session %s: NAS grant for %s was NOT revoked", session_id, row["vm_ip"]
        )


async def destroy_session_internal(
    db: asyncpg.Pool, session_id: str, vm_id: int, reason: str = "ended"
):
    """Internal function to destroy a session.

    `reason` is recorded so a student who returns to a destroyed VM can be
    told why it went away. Silent destruction looks like a crash.
    """
    try:
        await db.execute(
            "UPDATE vm_sessions SET destroyed_reason = $2 WHERE session_id = $1",
            session_id, reason,
        )
    except Exception as exc:
        # A missing column on an older database must not block teardown.
        logger.warning(
            "Could not record destroy reason for %s: %s", session_id, type(exc).__name__
        )
    # Revoke access before anything it names disappears.
    await revoke_session_access(db, session_id)

    # Release the NAS grant before the VM that holds the mount disappears.
    # Reached by a clean end, expiry, idle reclaim, and the stuck reaper,
    # because this is the only teardown path.
    await release_session_home(db, session_id)

    # Finalize recording before destroying container. Skipped for a family
    # that does not record, which otherwise logged a duration and a null
    # size for a file that was never written.
    if await _session_was_recorded(db, session_id):
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
        SELECT session_id, url, vm_ip, status, user_name, course_title, lab_slug,
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
            SELECT session_id, url, vm_ip, status, user_name, course_title, lab_slug,
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
        # Two very different situations, and telling them apart is the whole
        # point. An access link that names no lab was never going to grade
        # anything. A LAB link that carries no sourcedid means the
        # Brightspace item is not graded, which silently costs every student
        # in the course every grade for that lab: `lab grade` reports "no
        # gradebook column" and nothing else says why. A whole NOS 220 term
        # passed that way.
        if body.lab_slug and not body.sourcedid:
            logger.warning(
                "NOT GRADED: the launch for lab %r (resource_link_id=%r) "
                "carried no sourcedid, so no grade can be passed back. The "
                "Brightspace item for this lab is not associated with a "
                "grade item. Fix it in the course, not here.",
                body.lab_slug, body.resource_link_id or "<none>",
            )
        else:
            logger.info(
                "Launch carried no lab slug (resource_link_id=%r), so there "
                "is nothing to grade. Normal for an access link.",
                body.resource_link_id or "<none>",
            )
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


@app.post(
    "/api/access/desktop/redeem",
    dependencies=[Depends(require_service_token)],
)
async def redeem_desktop_access(body: DesktopRedeemRequest):
    """Exchange one browser reference for the private guacd parameters.

    Called only by the RDP gateway, over the internal service token. The
    reference is consumed by the statement that reads it, so a replay finds
    nothing. Neither the reference nor the resolved password is logged, and
    the 404 body names no target detail.
    """
    db = await get_db()

    row = await db.fetchrow(
        access.REDEEM_DESKTOP_TOKEN_SQL, access.hash_token(body.token)
    )
    if not row:
        logger.info("Desktop access reference was not redeemable")
        raise HTTPException(status_code=404, detail="No redeemable desktop access")

    try:
        parameters = access.connection_parameters(row)
    except (access.InvalidRdpTarget, access.CredentialUnavailable) as exc:
        logger.error(
            "Desktop access record for session %s is unusable: %s",
            row["session_id"],
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=502, detail="Desktop access is not usable"
        ) from exc

    logger.info("Redeemed desktop access for session %s", row["session_id"])
    return {
        "session_id": row["session_id"],
        "protocol": "rdp",
        "parameters": parameters,
    }


@app.post(
    "/api/session/{session_id}/desktop/token",
    dependencies=[Depends(require_service_token)],
)
async def mint_desktop_access(session_id: str, ttl_seconds: int = 60):
    """Attach a fresh single-use reference to an existing desktop record.

    The lti-server calls this for a student whose signed launch cookie names
    the session. Only the hash is stored, so this response is the one and
    only time the reference exists outside the browser.
    """
    db = await get_db()

    token = access.mint_desktop_token()
    row = await db.fetchrow(
        access.ASSIGN_DESKTOP_TOKEN_SQL,
        session_id,
        access.hash_token(token),
        str(ttl_seconds),
    )
    if not row:
        raise HTTPException(status_code=404, detail="No desktop access for session")

    logger.info("Minted desktop access reference for session %s", session_id)
    return {"token": token, "expires_in": ttl_seconds}


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
        SELECT session_id, url, vm_ip, status, user_name, course_title, lab_slug,
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
               created_at, expires_at, started_at, home_attached,
               notebooks_available
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

    # Only asked once the session is ready and the mode could be offered, so
    # a provisioning poll does not pay for a query whose answer is fixed.
    desktop_record = False
    if ready and BROWSER_RDP_ENABLED:
        desktop_record = bool(
            await db.fetchrow(access.DESKTOP_ACCESS_EXISTS_SQL, session_id)
        )

    return SessionStatus(
        session_id=session_id,
        status=status,
        ready=ready,
        desktop_record=desktop_record,
        url=row['url'] if ready else None,
        error_message=status_message if status == 'error' else None,
        steps=steps,
        progress_percent=progress,
        estimated_seconds_remaining=estimated_remaining,
        # A database still on 011 has no column, which reads as no
        # persistence. The page then tells the student to download their
        # work, which is the safe answer when we do not know.
        persistent_home=bool(_optional_column(row, "home_attached")),
        notebooks_available=_optional_column(row, "notebooks_available"),
    )


@app.get(
    "/api/session/{session_id}/grades",
    dependencies=[Depends(require_service_token)],
)
async def get_session_grades(session_id: str):
    """List this session's newest grade per cell, in student-facing terms.

    Gated by the service token like the other internal reads: the browser
    never reaches this route directly, only lti-server, which derives
    session_id from its own signed session cookie before calling here.
    """
    db = await get_db()
    grades = await session_grade_summary(db, session_id=session_id)
    return {"grades": grades}


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

    # Clone VM from the template this course resolves to. An unmapped course
    # resolves to the deployment default, which is what it cloned before this
    # lookup existed.
    template_choice = await resolve_lab_template(
        db, request.lab_slug, request.course_id
    )

    # Expiry follows the template, because the course family is what knows
    # how long its labs run. A four-hour lab against the four-hour default
    # loses the VM to the first break a student takes.
    session_hours = min(
        request.session_hours or template_choice.session_hours or DEFAULT_SESSION_HOURS,
        MAX_SESSION_HOURS,
    )
    expires_at = datetime.utcnow() + timedelta(hours=session_hours)

    course_session_key = request.course_session_key or request.session_key

    # One lab per student per class. A second launch returns the session the
    # student already has rather than cloning another VM: each one holds a
    # slot out of roughly twelve on this host, and two terminals onto two
    # different VMs is a student doing a lab twice and submitting the wrong
    # one. The partial unique index in migration 010 is what makes this safe
    # under a double click; this check is what makes it friendly.
    if course_session_key:
        existing = await db.fetchrow(
            """
            SELECT session_id, url, status, expires_at
            FROM vm_sessions
            WHERE course_session_key = $1
              AND status IN ('provisioning', 'starting', 'running')
            ORDER BY created_at DESC
            LIMIT 1
            """,
            course_session_key,
        )
        if existing:
            logger.info(
                "Reusing session %s for course key: already %s",
                existing["session_id"], existing["status"],
            )
            return {
                "session_id": existing["session_id"],
                "url": existing["url"],
                "status": existing["status"],
                "expires_at": existing["expires_at"],
                "reused": True,
            }

    # The row is written before the clone, and the clone happens in the
    # background task with everything else.
    #
    # Cloning inline made this request last as long as the copy. A linked
    # clone finishes in seconds and hid that. A full clone of a 128 GiB disk
    # does not, and a request held open that long is terminated by the
    # Cloudflare tunnel at about 100 seconds, so the student sees a failure
    # while the clone continues and completes, leaving a virtual machine no
    # session owns. The launch page already polls the status endpoint, which
    # is the mechanism this is supposed to use.
    await db.execute(
        """
        INSERT INTO vm_sessions (
            session_id, session_key, course_session_key, user_id, user_email, user_name,
            course_id, course_title, assignment_id, assignment_title,
            vm_ip, vm_name, vm_id, url, status, expires_at, lab_slug
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, $11, NULL, $12, 'provisioning', $13, $14)
        """,
        session_id, request.session_key, course_session_key, request.user_id, request.user_email,
        request.user_name, request.course_id, request.course_title,
        request.assignment_id, request.assignment_title, vm_name, url, expires_at,
        request.lab_slug
    )

    grade_token = await assign_grade_token(db, session_id)

    await log_event(db, session_id, 'accepted', {
        'user_id': request.user_id,
        'course_id': request.course_id,
        'template_id': template_choice.template_id,
    })

    # Clone, start, and wait for readiness in background
    async def finalize_provisioning():
        try:
            try:
                # In a worker thread. clone_vm is synchronous and the
                # wait_for_task loop inside it sleeps with time.sleep for as
                # long as the copy takes, which on a full clone is minutes.
                # Run on the event loop it stalls every other request in
                # lab-api, including the health check, and the container is
                # marked unhealthy while one student's disk copies.
                vmid = await asyncio.to_thread(
                    clone_vm, proxmox_api, session_id, vm_name, template_choice
                )
            except Exception as clone_error:
                logger.error(
                    "Failed to clone template %s for course %s: %s",
                    template_choice.template_id,
                    request.course_id,
                    clone_error,
                )
                await db.execute(
                    "UPDATE vm_sessions SET status = 'error', "
                    "status_message = 'Clone failed' WHERE session_id = $1",
                    session_id,
                )
                return

            await db.execute(
                "UPDATE vm_sessions SET vm_id = $2, status = 'starting' WHERE session_id = $1",
                session_id, vmid,
            )
            logger.info(f"Cloned VM {vm_name} (ID: {vmid}) on Proxmox")

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

            # Attach the persistent home before the terminal exists, so the
            # student's first shell already sees it. Never raises: a lab
            # without a home is worse than no lab, so a failure here leaves
            # home_attached FALSE and the launch page tells the student to
            # download their work.
            if template_choice.persistent_home and CSC228_NAS_VMID:
                if request.user_id:
                    key = csc228_home.home_key(HOME_KEY_ISSUER, request.user_id)
                    attached = await csc228_home.provision_home(
                        proxmox_api, PROXMOX_NODE, CSC228_NAS_VMID,
                        vmid, vm_ip, key,
                    )
                    await db.execute(
                        "UPDATE vm_sessions SET home_key = $2, home_attached = $3 "
                        "WHERE session_id = $1",
                        session_id, key, attached,
                    )
                    if not attached:
                        logger.warning(
                            "Session %s has no persistent home, continuing "
                            "without it. The preceding line names the cause "
                            "and which host to examine.",
                            session_id,
                        )
                else:
                    # home_key refuses an empty subject rather than hashing
                    # one, because every such student would share a directory.
                    logger.error(
                        "Session %s: no user id, cannot derive a home key",
                        session_id,
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
            terminal_user = template_choice.ssh_user or SSH_USER
            use_nested_hop = (
                NESTED_SSH_ENABLED if template_choice.nested_ssh is None
                else template_choice.nested_ssh
            )
            if use_nested_hop:
                # Wait for system to be fully booted (not just SSH port open)
                logger.info(f"Waiting for system to be fully booted on {vm_ip}...")
                login_ready = await wait_for_ssh_login(vm_ip, terminal_user, SSH_PASSWORD, timeout=180)
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

            # Probe before publishing, so a closed port leaves the student a
            # terminal rather than a route that 502s. Off the loop because
            # each probe is a blocking connect.
            published_channels = await asyncio.to_thread(
                ready_channels, vm_ip, template_choice.channels
            )
            if "jupyter" in template_choice.channels:
                # Tri-state: only a family that wants notebooks gets an
                # answer recorded, so no NOS student is warned about a
                # feature their course never had.
                notebooks = "jupyter" in published_channels
                await db.execute(
                    "UPDATE vm_sessions SET notebooks_available = $2 "
                    "WHERE session_id = $1",
                    session_id, notebooks,
                )
                if not notebooks:
                    logger.error(
                        "Session %s: JupyterLab did not answer on 8888. It is "
                        "enabled at boot, so this is a fault on the VM.",
                        session_id,
                    )

            # Spawn ttyd container
            container_id = spawn_ttyd_container(
                session_id, vm_ip, DOMAIN,
                recording_path, timing_path,
                persist=template_choice.terminal_persist,
                record=template_choice.terminal_recording,
                ssh_user=template_choice.ssh_user,
                nested=template_choice.nested_ssh,
                channels=tuple(published_channels),
                ssh_auth=template_choice.ssh_auth,
            )

            if container_id:
                # Registered before the session is marked running, so the
                # first poll that reports ready reports the desktop with it.
                # A refusal returns False and leaves the terminal alone.
                desktop_registered = await register_desktop_access(
                    db, session_id, vm_ip
                )

                await db.execute(
                    """
                    UPDATE vm_sessions
                    SET status = 'running', started_at = CURRENT_TIMESTAMP,
                        container_id = $2, container_name = $3, status_message = NULL
                    WHERE session_id = $1
                    """,
                    session_id, container_id, f"ttyd-{session_id}"
                )
                await log_event(
                    db,
                    session_id,
                    'desktop_access',
                    {'registered': desktop_registered},
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
        # The row is written as provisioning and the clone has not started.
        # Reporting "starting" here would tell the launch page the machine
        # exists before anything has been cloned.
        status="provisioning",
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
        SELECT session_id, url, vm_ip, status, user_name, course_title, lab_slug,
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
