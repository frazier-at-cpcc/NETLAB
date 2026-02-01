# On-Demand Red Hat VM Lab with Web Console

## Overview

This architecture enables on-demand provisioning of Red Hat VMs for students, accessible via dynamic web URLs without VPN or authentication. Students launch labs directly from their LMS (Canvas, Blackboard, Moodle, etc.) via LTI integration and are automatically redirected to their provisioned VM terminal.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LEARNING MANAGEMENT SYSTEM                            │
│                    (Canvas, Blackboard, Moodle, etc.)                       │
│                                                                              │
│   Student clicks "Launch Lab" assignment → LTI 1.3 launch request           │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ LTI 1.3 Launch (OIDC + JWT)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            LTI TOOL SERVER                                   │
│                     https://lti.yourdomain.com                              │
│                                                                              │
│  • Validates LTI launch (JWT signature, nonce, claims)                      │
│  • Extracts: user_id, course_id, assignment_id                              │
│  • Checks for existing session or provisions new VM                         │
│  • Redirects student to their VM URL                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ Provision Request / Session Lookup
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              STUDENT ACCESS                                  │
│              https://lab-{session-id}.yourdomain.com                        │
│                      (No auth - direct terminal)                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CLOUDFLARE TUNNEL                                    │
│                    (Wildcard: *.lab.yourdomain.com)                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TRAEFIK REVERSE PROXY                                │
│              Routes lab-{session-id} → ttyd instance for that VM            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     PER-VM TTYD CONTAINERS                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ ttyd:7681   │  │ ttyd:7682   │  │ ttyd:7683   │  │ ttyd:7684   │  ...   │
│  │ → VM1 SSH   │  │ → VM2 SSH   │  │ → VM3 SSH   │  │ → VM4 SSH   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ORCHESTRATION API                                    │
│                                                                              │
│  POST /api/provision  →  Creates VM + ttyd + returns URL                    │
│  DELETE /api/{id}     →  Destroys VM + ttyd                                 │
│  GET /api/sessions    →  List active sessions                               │
│  GET /api/session/by-user/{user_id}  →  Find existing session               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         VM HYPERVISOR (libvirt/KVM)                          │
│                                                                              │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐                    │
│  │   RHEL VM 1   │  │   RHEL VM 2   │  │   RHEL VM 3   │       ...          │
│  │   16 GB RAM   │  │   16 GB RAM   │  │   16 GB RAM   │                    │
│  │   4 vCPU      │  │   4 vCPU      │  │   4 vCPU      │                    │
│  │  10.10.10.11  │  │  10.10.10.12  │  │  10.10.10.13  │                    │
│  └───────────────┘  └───────────────┘  └───────────────┘                    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │              Base QCOW2 (Red Hat Academy - Read Only)                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## LTI Integration Architecture

### LTI 1.3 Launch Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│     LMS      │     │  LTI Server  │     │ Orchestrator │     │   Student    │
│  (Canvas)    │     │              │     │     API      │     │   Browser    │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │                    │
       │  1. Student clicks │                    │                    │
       │     "Launch Lab"   │                    │                    │
       │ ─────────────────► │                    │                    │
       │                    │                    │                    │
       │  2. OIDC Login     │                    │                    │
       │     Initiation     │                    │                    │
       │ ◄───────────────── │                    │                    │
       │                    │                    │                    │
       │  3. Auth Request   │                    │                    │
       │ ─────────────────► │                    │                    │
       │                    │                    │                    │
       │  4. ID Token (JWT) │                    │                    │
       │     with LTI claims│                    │                    │
       │ ─────────────────► │                    │                    │
       │                    │                    │                    │
       │                    │  5. Validate JWT   │                    │
       │                    │     Extract user   │                    │
       │                    │                    │                    │
       │                    │  6. Check/Create   │                    │
       │                    │     Session        │                    │
       │                    │ ─────────────────► │                    │
       │                    │                    │                    │
       │                    │  7. Return VM URL  │                    │
       │                    │ ◄───────────────── │                    │
       │                    │                    │                    │
       │                    │  8. HTTP 302       │                    │
       │                    │     Redirect       │                    │
       │                    │ ──────────────────────────────────────► │
       │                    │                    │                    │
       │                    │                    │      9. SSH Terminal
       │                    │                    │         in Browser │
       │                    │                    │                    │
```

### LTI Server Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/lti/jwks` | GET | Public keys for JWT verification |
| `/lti/login` | GET/POST | OIDC login initiation |
| `/lti/launch` | POST | Main LTI launch handler |
| `/lti/config` | GET | LTI tool configuration JSON |

---

## Component Details

### 1. LTI Tool Server (Python FastAPI + PyLTI1p3)

The LTI server handles authentication from the LMS and provisions VMs for students.

```python
# lti/main.py
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from pylti1p3.contrib.fastapi import (
    FastAPIOIDCLogin,
    FastAPIMessageLaunch,
    FastAPICacheDataStorage,
    FastAPISessionService
)
from pylti1p3.tool_config import ToolConfJsonFile
import httpx
import os

app = FastAPI()

# LTI Configuration
TOOL_CONFIG = ToolConfJsonFile(os.path.join(os.path.dirname(__file__), 'lti_config.json'))
CACHE = FastAPICacheDataStorage()
ORCHESTRATOR_API = os.getenv("ORCHESTRATOR_API", "http://lab-api:8000")
DOMAIN = os.getenv("DOMAIN", "lab.yourdomain.com")

def get_launch_data_storage():
    return CACHE

def get_tool_conf():
    return TOOL_CONFIG


@app.get("/lti/jwks")
async def jwks():
    """Return public keys for JWT verification by the LMS"""
    tool_conf = get_tool_conf()
    return JSONResponse(tool_conf.get_jwks())


@app.route("/lti/login", methods=["GET", "POST"])
async def login(request: Request):
    """OIDC Login Initiation - Step 1 of LTI 1.3 launch"""
    tool_conf = get_tool_conf()
    session_service = FastAPISessionService(request)

    oidc_login = FastAPIOIDCLogin(
        request,
        tool_conf,
        session_service=session_service,
        launch_data_storage=get_launch_data_storage()
    )

    target_link_uri = request.query_params.get('target_link_uri')
    return oidc_login.enable_check_cookies().redirect(target_link_uri)


@app.post("/lti/launch")
async def launch(request: Request):
    """
    Main LTI Launch Handler
    - Validates the JWT from the LMS
    - Extracts user information
    - Provisions or retrieves VM session
    - Redirects student to their VM
    """
    tool_conf = get_tool_conf()
    session_service = FastAPISessionService(request)

    message_launch = FastAPIMessageLaunch(
        request,
        tool_conf,
        session_service=session_service,
        launch_data_storage=get_launch_data_storage()
    )

    # Validate the launch
    message_launch.validate()

    # Extract user information from LTI claims
    launch_data = message_launch.get_launch_data()

    user_id = launch_data.get('sub')  # Unique user ID from LMS
    user_email = launch_data.get('email', '')
    user_name = launch_data.get('name', 'Student')

    # Course and assignment context
    context = launch_data.get('https://purl.imsglobal.org/spec/lti/claim/context', {})
    course_id = context.get('id', 'unknown')
    course_title = context.get('title', 'Unknown Course')

    resource = launch_data.get('https://purl.imsglobal.org/spec/lti/claim/resource_link', {})
    assignment_id = resource.get('id', 'default')
    assignment_title = resource.get('title', 'Lab Assignment')

    # Create a composite key for this user's session in this course/assignment
    session_key = f"{user_id}:{course_id}:{assignment_id}"

    async with httpx.AsyncClient() as client:
        # Check if user already has an active session
        existing = await client.get(
            f"{ORCHESTRATOR_API}/api/session/by-key/{session_key}"
        )

        if existing.status_code == 200:
            # User has existing VM - redirect to it
            session_data = existing.json()
            return RedirectResponse(url=session_data['url'], status_code=302)

        # No existing session - provision new VM
        provision_response = await client.post(
            f"{ORCHESTRATOR_API}/api/provision",
            json={
                "session_key": session_key,
                "user_id": user_id,
                "user_email": user_email,
                "user_name": user_name,
                "course_id": course_id,
                "course_title": course_title,
                "assignment_id": assignment_id,
                "assignment_title": assignment_title
            }
        )

        if provision_response.status_code != 200:
            raise HTTPException(
                status_code=503,
                detail="Failed to provision lab environment. Please try again."
            )

        session_data = provision_response.json()

        # Redirect student to their new VM
        return RedirectResponse(url=session_data['url'], status_code=302)


@app.get("/lti/config")
async def config():
    """
    Returns LTI tool configuration for easy LMS setup
    Instructors can use this URL when adding the tool to their LMS
    """
    base_url = os.getenv("LTI_BASE_URL", "https://lti.yourdomain.com")

    return JSONResponse({
        "title": "Red Hat Academy Lab Environment",
        "description": "Launch on-demand RHEL virtual machines for hands-on labs",
        "oidc_initiation_url": f"{base_url}/lti/login",
        "target_link_uri": f"{base_url}/lti/launch",
        "public_jwk_url": f"{base_url}/lti/jwks",
        "scopes": [
            "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
            "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
            "https://purl.imsglobal.org/spec/lti-ags/scope/score"
        ],
        "extensions": [
            {
                "platform": "canvas.instructure.com",
                "settings": {
                    "placements": [
                        {
                            "placement": "assignment_selection",
                            "message_type": "LtiResourceLinkRequest"
                        },
                        {
                            "placement": "link_selection",
                            "message_type": "LtiResourceLinkRequest"
                        }
                    ]
                }
            }
        ]
    })
```

### 2. LTI Configuration File

```json
// lti/lti_config.json
{
    "https://canvas.instructure.com": {
        "client_id": "YOUR_CLIENT_ID_FROM_CANVAS",
        "auth_login_url": "https://canvas.instructure.com/api/lti/authorize_redirect",
        "auth_token_url": "https://canvas.instructure.com/login/oauth2/token",
        "key_set_url": "https://canvas.instructure.com/api/lti/security/jwks",
        "deployment_ids": ["YOUR_DEPLOYMENT_ID"],
        "private_key_file": "/app/keys/private.pem",
        "public_key_file": "/app/keys/public.pem"
    },
    "https://your-institution.blackboard.com": {
        "client_id": "YOUR_BLACKBOARD_CLIENT_ID",
        "auth_login_url": "https://your-institution.blackboard.com/api/v1/gateway/oidcauth",
        "auth_token_url": "https://your-institution.blackboard.com/api/v1/gateway/oauth2/jwttoken",
        "key_set_url": "https://your-institution.blackboard.com/api/v1/gateway/keys",
        "deployment_ids": ["YOUR_DEPLOYMENT_ID"],
        "private_key_file": "/app/keys/private.pem",
        "public_key_file": "/app/keys/public.pem"
    }
}
```

### 3. VM Management (libvirt/KVM)

VMs are created as thin clones using QCOW2 backing files for instant provisioning:

```bash
# Use backing file for instant clone from base QCOW
qemu-img create -f qcow2 -b /var/lib/libvirt/images/rhel-base.qcow2 \
    -F qcow2 /var/lib/libvirt/images/student-{session-id}.qcow2

# Clones are thin-provisioned - only differences stored
# Base image stays read-only, instant provisioning
```

### 4. Web Terminal: ttyd

**Why ttyd for this use case:**
- Single binary, ultra-lightweight
- No authentication by default (direct access)
- WebSocket-based, works through any firewall
- Direct SSH passthrough

```bash
# ttyd command (spawned per VM)
ttyd --port 7681 --writable ssh -o StrictHostKeyChecking=no student@10.10.10.11
```

Each VM gets its own ttyd container that auto-connects via SSH.

### 5. Tunnel Solution: Cloudflare Tunnel

| Solution | Dynamic URLs | Free Tier | Setup Complexity |
|----------|--------------|-----------|------------------|
| **Cloudflare Tunnel** | Wildcard DNS | Generous | Medium |
| Tailscale Funnel | Limited | Yes | Easy |
| ngrok | Yes | Limited | Easy |
| Self-hosted (frp) | Yes | Yes | Hard |

**Recommendation: Cloudflare Tunnel** with wildcard DNS (`*.lab.yourdomain.com`)

---

## Implementation Stack

```
┌────────────────────────────────────────────┐
│           Recommended Tech Stack           │
├────────────────────────────────────────────┤
│  LTI Server:   Python FastAPI + PyLTI1p3
│  API:          Python FastAPI
│  VM Mgmt:      libvirt Python bindings
│  Web Console:  ttyd (Docker containers)
│  Tunnel:       Cloudflare Tunnel (cloudflared)
│  Proxy:        Traefik (auto SSL, dynamic routing)
│  Database:     PostgreSQL (sessions, LTI state)
└────────────────────────────────────────────┘
```

---

## Workflow: Student Session Lifecycle (LTI)

```
1. LTI LAUNCH FROM LMS
   ┌──────────────────────────────────────────────────────────┐
   │  Student clicks "Launch Lab" in Canvas/Blackboard/Moodle │
   │  LMS sends LTI 1.3 launch request with JWT               │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
2. LTI VALIDATION & USER IDENTIFICATION
   ┌──────────────────────────────────────────────────────────┐
   │  • LTI server validates JWT signature                    │
   │  • Extracts: user_id, email, course_id, assignment_id   │
   │  • Creates session key: user_id:course_id:assignment_id │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
3. SESSION CHECK
   ┌──────────────────────────────────────────────────────────┐
   │  Does user have existing VM for this assignment?         │
   │                                                          │
   │  YES → Redirect to existing VM URL                       │
   │  NO  → Continue to provision                             │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
4. VM CREATION (< 5 seconds with backing file)
   ┌──────────────────────────────────────────────────────────┐
   │  • Generate unique session ID (e.g., x7k9m2p4)           │
   │  • Create thin clone from base QCOW2                     │
   │  • Define VM in libvirt (16GB RAM, 4 vCPU)              │
   │  • Start VM                                              │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
5. TTYD CONTAINER SPAWN
   ┌──────────────────────────────────────────────────────────┐
   │  • Start ttyd container linked to VM's SSH               │
   │  • Register with Traefik for dynamic subdomain           │
   │  • No authentication configured                          │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
6. AUTOMATIC REDIRECT
   ┌──────────────────────────────────────────────────────────┐
   │  LTI server redirects student browser to:                │
   │  https://lab-x7k9m2p4.yourdomain.com                     │
   │                                                          │
   │  Student sees SSH terminal immediately - no extra clicks │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
7. SESSION ACTIVE
   ┌──────────────────────────────────────────────────────────┐
   │  • Student works in terminal                             │
   │  • Re-launching from LMS returns to same VM              │
   │  • Full 16GB RHEL environment                            │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
8. CLEANUP (Manual or automatic timeout)
   ┌──────────────────────────────────────────────────────────┐
   │  • Stop and remove ttyd container                        │
   │  • Stop and undefine VM                                  │
   │  • Delete student QCOW2 overlay                          │
   │  • Free resources                                        │
   └──────────────────────────────────────────────────────────┘
```

---

## Docker Compose

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.web.address=:80"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - lab-network

  # LTI Tool Server
  lti-server:
    build: ./lti
    environment:
      ORCHESTRATOR_API: http://lab-api:8000
      LTI_BASE_URL: https://lti.yourdomain.com
      DOMAIN: lab.yourdomain.com
      DATABASE_URL: postgresql://lti:${LTI_DB_PASS}@postgres:5432/lti
    volumes:
      - ./lti/keys:/app/keys:ro
      - ./lti/lti_config.json:/app/lti_config.json:ro
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.lti.rule=Host(`lti.yourdomain.com`)"
      - "traefik.http.routers.lti.tls=true"
      - "traefik.http.services.lti.loadbalancer.server.port=8000"
    depends_on:
      - postgres
      - lab-api
    networks:
      - lab-network

  # VM Orchestration API
  lab-api:
    build: ./api
    volumes:
      - /var/run/libvirt/libvirt-sock:/var/run/libvirt/libvirt-sock
      - /var/lib/libvirt/images:/var/lib/libvirt/images
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      BASE_QCOW: /var/lib/libvirt/images/rhel-academy-base.qcow2
      VM_RAM_MB: 16384
      VM_VCPUS: 4
      DOMAIN: lab.yourdomain.com
      DATABASE_URL: postgresql://lab:${LAB_DB_PASS}@postgres:5432/lab
    depends_on:
      - postgres
    networks:
      - lab-network

  # PostgreSQL for session persistence
  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init-db.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - lab-network

  cloudflared:
    image: cloudflare/cloudflared
    command: tunnel run
    environment:
      TUNNEL_TOKEN: ${CF_TUNNEL_TOKEN}
    networks:
      - lab-network

networks:
  lab-network:
    driver: bridge

volumes:
  postgres_data:
```

---

## Database Schema

```sql
-- init-db.sql

-- Create databases
CREATE DATABASE lti;
CREATE DATABASE lab;

-- Create users
CREATE USER lti WITH PASSWORD 'lti_password';
CREATE USER lab WITH PASSWORD 'lab_password';

GRANT ALL PRIVILEGES ON DATABASE lti TO lti;
GRANT ALL PRIVILEGES ON DATABASE lab TO lab;

-- LTI Database Tables
\c lti;

CREATE TABLE lti_platforms (
    id SERIAL PRIMARY KEY,
    issuer VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    deployment_id VARCHAR(255),
    auth_login_url TEXT,
    auth_token_url TEXT,
    key_set_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE lti_nonces (
    id SERIAL PRIMARY KEY,
    nonce VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE lti_launches (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    course_id VARCHAR(255),
    assignment_id VARCHAR(255),
    session_key VARCHAR(512) UNIQUE NOT NULL,
    vm_session_id VARCHAR(64),
    launched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_lti_launches_session_key ON lti_launches(session_key);
CREATE INDEX idx_lti_launches_user ON lti_launches(user_id);

-- Lab Database Tables
\c lab;

CREATE TABLE vm_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) UNIQUE NOT NULL,
    session_key VARCHAR(512),
    user_id VARCHAR(255),
    user_email VARCHAR(255),
    user_name VARCHAR(255),
    course_id VARCHAR(255),
    course_title VARCHAR(255),
    assignment_id VARCHAR(255),
    assignment_title VARCHAR(255),
    vm_ip VARCHAR(15),
    vm_name VARCHAR(128),
    overlay_path TEXT,
    container_id VARCHAR(128),
    url TEXT,
    status VARCHAR(32) DEFAULT 'running',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE INDEX idx_vm_sessions_session_key ON vm_sessions(session_key);
CREATE INDEX idx_vm_sessions_user ON vm_sessions(user_id);
CREATE INDEX idx_vm_sessions_status ON vm_sessions(status);
```

---

## Orchestration API (Updated with LTI Support)

```python
# api/main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import libvirt
import docker
import secrets
import string
import time
import os
import subprocess
import asyncpg
from contextlib import asynccontextmanager

# Database connection
DATABASE_URL = os.getenv("DATABASE_URL")

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db = await asyncpg.create_pool(DATABASE_URL)
    yield
    await app.state.db.close()

app = FastAPI(lifespan=lifespan)
docker_client = docker.from_env()
libvirt_conn = libvirt.open("qemu:///system")

DOMAIN = os.getenv("DOMAIN", "lab.yourdomain.com")
BASE_QCOW = os.getenv("BASE_QCOW", "/var/lib/libvirt/images/rhel-academy-base.qcow2")
VM_NETWORK = "10.10.10"


class ProvisionRequest(BaseModel):
    session_key: Optional[str] = None
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    course_id: Optional[str] = None
    course_title: Optional[str] = None
    assignment_id: Optional[str] = None
    assignment_title: Optional[str] = None


class Session(BaseModel):
    session_id: str
    url: str
    vm_ip: str
    status: str
    user_name: Optional[str] = None
    course_title: Optional[str] = None
    assignment_title: Optional[str] = None


def generate_session_id():
    """Generate 8-char alphanumeric ID"""
    chars = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(8))


async def get_next_vm_index(db):
    """Get next available VM index based on database"""
    result = await db.fetchval(
        "SELECT COALESCE(MAX(CAST(SUBSTRING(vm_ip FROM '[0-9]+$') AS INTEGER)), 10) + 1 FROM vm_sessions WHERE status = 'running'"
    )
    return result


@app.get("/api/session/by-key/{session_key}")
async def get_session_by_key(session_key: str):
    """Find existing session by composite key (user:course:assignment)"""
    db = app.state.db

    row = await db.fetchrow(
        """
        SELECT session_id, url, vm_ip, status, user_name, course_title, assignment_title
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
async def provision_vm(request: ProvisionRequest):
    """Provision a new VM for a student"""
    db = app.state.db

    session_id = generate_session_id()
    vm_index = await get_next_vm_index(db)
    vm_ip = f"{VM_NETWORK}.{vm_index}"
    vm_name = f"student-{session_id}"

    # 1. Create QCOW2 overlay (thin clone)
    overlay_path = f"/var/lib/libvirt/images/{vm_name}.qcow2"
    subprocess.run([
        "qemu-img", "create", "-f", "qcow2",
        "-b", BASE_QCOW, "-F", "qcow2", overlay_path
    ], check=True)

    # 2. Define and start VM with 16GB RAM, 4 vCPU
    vm_xml = f"""
    <domain type='kvm'>
      <name>{vm_name}</name>
      <memory unit='GiB'>16</memory>
      <vcpu>4</vcpu>
      <os>
        <type arch='x86_64'>hvm</type>
        <boot dev='hd'/>
      </os>
      <devices>
        <disk type='file' device='disk'>
          <driver name='qemu' type='qcow2'/>
          <source file='{overlay_path}'/>
          <target dev='vda' bus='virtio'/>
        </disk>
        <interface type='network'>
          <source network='lab-net'/>
          <model type='virtio'/>
        </interface>
        <graphics type='vnc' port='-1'/>
      </devices>
    </domain>
    """

    dom = libvirt_conn.defineXML(vm_xml)
    dom.create()

    # 3. Wait for VM to be ready
    time.sleep(30)  # In production, poll for SSH availability

    # 4. Spawn ttyd container for this VM (no auth)
    container = docker_client.containers.run(
        "tsl0922/ttyd",
        command=f"ttyd --writable ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null student@{vm_ip}",
        name=f"ttyd-{session_id}",
        detach=True,
        network="vm-lab_lab-network",
        labels={
            "traefik.enable": "true",
            f"traefik.http.routers.ttyd-{session_id}.rule": f"Host(`lab-{session_id}.{DOMAIN}`)",
            f"traefik.http.routers.ttyd-{session_id}.tls": "true",
            f"traefik.http.services.ttyd-{session_id}.loadbalancer.server.port": "7681",
        }
    )

    url = f"https://lab-{session_id}.{DOMAIN}"

    # 5. Store session in database
    await db.execute(
        """
        INSERT INTO vm_sessions
        (session_id, session_key, user_id, user_email, user_name,
         course_id, course_title, assignment_id, assignment_title,
         vm_ip, vm_name, overlay_path, container_id, url, status, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'running',
                CURRENT_TIMESTAMP + INTERVAL '4 hours')
        """,
        session_id, request.session_key, request.user_id, request.user_email,
        request.user_name, request.course_id, request.course_title,
        request.assignment_id, request.assignment_title, vm_ip, vm_name,
        overlay_path, container.id, url
    )

    return Session(
        session_id=session_id,
        url=url,
        vm_ip=vm_ip,
        status="running",
        user_name=request.user_name,
        course_title=request.course_title,
        assignment_title=request.assignment_title
    )


@app.delete("/api/{session_id}")
async def destroy_session(session_id: str):
    """Destroy a VM session and clean up resources"""
    db = app.state.db

    row = await db.fetchrow(
        "SELECT vm_name, container_id, overlay_path FROM vm_sessions WHERE session_id = $1",
        session_id
    )

    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    # 1. Stop and remove ttyd container
    try:
        container = docker_client.containers.get(f"ttyd-{session_id}")
        container.stop()
        container.remove()
    except Exception:
        pass

    # 2. Destroy and undefine VM
    try:
        dom = libvirt_conn.lookupByName(row['vm_name'])
        dom.destroy()
        dom.undefine()
    except Exception:
        pass

    # 3. Delete overlay QCOW2
    try:
        os.remove(row['overlay_path'])
    except Exception:
        pass

    # 4. Update database
    await db.execute(
        "UPDATE vm_sessions SET status = 'destroyed' WHERE session_id = $1",
        session_id
    )

    return {"status": "destroyed"}


@app.get("/api/sessions")
async def list_sessions():
    """List all active sessions"""
    db = app.state.db

    rows = await db.fetch(
        """
        SELECT session_id, url, vm_ip, status, user_name, course_title,
               assignment_title, created_at, last_accessed
        FROM vm_sessions
        WHERE status = 'running'
        ORDER BY created_at DESC
        """
    )

    return [dict(row) for row in rows]
```

---

## LMS Configuration

### Canvas LMS Setup

1. **Admin → Developer Keys → Add LTI Key**

```
Key Name: Red Hat Academy Labs
Redirect URIs: https://lti.yourdomain.com/lti/launch
Configure Method: Manual Entry

Title: Red Hat Academy Lab Environment
Description: Launch on-demand RHEL virtual machines
Target Link URI: https://lti.yourdomain.com/lti/launch
OpenID Connect Initiation URL: https://lti.yourdomain.com/lti/login
JWK Method: Public JWK URL
Public JWK URL: https://lti.yourdomain.com/lti/jwks
```

2. **Course → Settings → Apps → Add App**

```
Configuration Type: By Client ID
Client ID: [From Developer Key]
```

3. **Create Assignment**

```
Submission Type: External Tool
External Tool URL: https://lti.yourdomain.com/lti/launch
```

### Blackboard Setup

1. **System Admin → LTI Tool Providers → Register Provider Domain**

```
Provider Domain: lti.yourdomain.com
Tool Status: Approved
```

2. **Create LTI 1.3 Placement**

```
Name: Red Hat Academy Labs
OIDC Auth Request Endpoint: https://lti.yourdomain.com/lti/login
Tool Redirect Endpoint: https://lti.yourdomain.com/lti/launch
Tool JWKS Endpoint: https://lti.yourdomain.com/lti/jwks
```

### Moodle Setup

1. **Site Administration → Plugins → External Tool → Manage Tools**

```
Tool Name: Red Hat Academy Labs
Tool URL: https://lti.yourdomain.com/lti/launch
LTI Version: LTI 1.3
Public Keyset URL: https://lti.yourdomain.com/lti/jwks
Initiate Login URL: https://lti.yourdomain.com/lti/login
Redirection URI: https://lti.yourdomain.com/lti/launch
```

---

## Generate LTI Keys

```bash
# Generate RSA key pair for LTI JWT signing
mkdir -p lti/keys

# Private key
openssl genrsa -out lti/keys/private.pem 2048

# Public key
openssl rsa -in lti/keys/private.pem -pubout -out lti/keys/public.pem

# Set permissions
chmod 600 lti/keys/private.pem
chmod 644 lti/keys/public.pem
```

---

## Cloudflare Tunnel Setup

```bash
# 1. Install cloudflared on host
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
  -o /usr/local/bin/cloudflared
chmod +x /usr/local/bin/cloudflared

# 2. Authenticate
cloudflared tunnel login

# 3. Create tunnel
cloudflared tunnel create student-labs

# 4. Configure wildcard DNS in Cloudflare dashboard
# Add CNAME: *.lab.yourdomain.com -> <tunnel-id>.cfargotunnel.com
# Add CNAME: lti.yourdomain.com -> <tunnel-id>.cfargotunnel.com

# 5. Config file (~/.cloudflared/config.yml)
tunnel: <tunnel-id>
credentials-file: /root/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: "lti.yourdomain.com"
    service: http://localhost:80
  - hostname: "*.lab.yourdomain.com"
    service: http://localhost:80
  - service: http_status:404

# 6. Run as service
cloudflared service install
systemctl start cloudflared
```

---

## VM Base Image Setup

The base QCOW2 needs a pre-configured user for passwordless SSH:

```bash
# Inside the base VM before converting to template:

# 1. Create student user with no password (SSH key only)
useradd -m student
mkdir -p /home/student/.ssh

# 2. Generate keypair on host, add public key to VM
echo "ssh-ed25519 AAAA... lab-orchestrator" >> /home/student/.ssh/authorized_keys
chmod 700 /home/student/.ssh
chmod 600 /home/student/.ssh/authorized_keys
chown -R student:student /home/student/.ssh

# 3. Allow passwordless sudo (optional, for labs)
echo "student ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/student

# 4. Ensure SSH starts on boot
systemctl enable sshd

# 5. Clean up and seal the image
# Remove SSH host keys (regenerated on first boot)
rm -f /etc/ssh/ssh_host_*

# Clear machine-id
truncate -s 0 /etc/machine-id

# Power off and mark as template
poweroff
```

---

## Hardware Requirements

| Concurrent VMs | RAM Required | CPU Cores | Storage |
|----------------|--------------|-----------|---------|
| 5 students | 80 GB | 20+ | 250 GB SSD |
| 10 students | 160 GB | 40+ | 500 GB SSD |
| 15 students | 240 GB | 60+ | 750 GB SSD |
| 20 students | 320 GB | 80+ | 1 TB NVMe |

*Based on 16 GB RAM + 4 vCPU per VM, plus host overhead*

**Recommended server for 10 concurrent students:**
- 192 GB RAM (allows headroom)
- Dual Xeon or EPYC (48+ cores)
- 1 TB NVMe storage
- 10 Gbps NIC (for tunnel bandwidth)

---

## Security Considerations

| Control | Implementation |
|---------|----------------|
| **LTI Authentication** | JWT validation ensures only LMS-authenticated users can provision |
| **URL obscurity** | 8-char random session ID = 2.8 trillion combinations |
| **Session binding** | Each user gets same VM for course/assignment combo |
| **Session expiry** | Auto-destroy after 4 hours of inactivity |
| **Network isolation** | VMs on isolated bridge, no inter-VM traffic |
| **HTTPS only** | Cloudflare enforces TLS on all endpoints |

### Auto-Cleanup Implementation

```python
# Add to API: Auto-cleanup expired sessions
from apscheduler.schedulers.asyncio import AsyncIOScheduler

scheduler = AsyncIOScheduler()

@scheduler.scheduled_job('interval', minutes=15)
async def cleanup_expired():
    db = app.state.db

    # Find expired sessions
    expired = await db.fetch(
        """
        SELECT session_id FROM vm_sessions
        WHERE status = 'running' AND expires_at < CURRENT_TIMESTAMP
        """
    )

    for row in expired:
        await destroy_session(row['session_id'])

scheduler.start()
```

---

## Student Experience

```
1. Student logs into Canvas/Blackboard/Moodle

2. Student navigates to course and clicks "Launch Lab" assignment

3. LMS authenticates and sends LTI launch to our server

4. LTI server provisions VM (or retrieves existing one)

5. Student is automatically redirected to:
   https://lab-x7k9m2p4.yourdomain.com

   ┌─────────────────────────────────────────────────────────┐
   │ [student@rhel-lab ~]$ _                                 │
   │                                                         │
   │                                                         │
   │                                                         │
   └─────────────────────────────────────────────────────────┘

6. Student works in terminal (full RHEL environment, 16GB RAM)

7. If student clicks "Launch Lab" again, returns to SAME VM

8. Session auto-expires after 4 hours or instructor manually destroys
```

---

## Directory Structure

```
/opt/vm-lab/
├── docker-compose.yml
├── .env                          # Secrets and config
├── init-db.sql                   # Database initialization
├── api/
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
├── lti/
│   ├── Dockerfile
│   ├── main.py
│   ├── requirements.txt
│   ├── lti_config.json           # LMS configurations
│   └── keys/
│       ├── private.pem           # JWT signing key
│       └── public.pem            # JWT verification key
└── cloudflared/
    └── config.yml

/var/lib/libvirt/images/
├── rhel-academy-base.qcow2       # Read-only template
├── student-x7k9m2p4.qcow2        # Thin clone (active)
├── student-abc12345.qcow2        # Thin clone (active)
└── ...
```

---

## Requirements Files

### api/requirements.txt

```
fastapi==0.104.1
uvicorn==0.24.0
libvirt-python==10.0.0
docker==6.1.3
pydantic==2.5.2
asyncpg==0.29.0
apscheduler==3.10.4
```

### lti/requirements.txt

```
fastapi==0.104.1
uvicorn==0.24.0
PyLTI1p3==2.0.0
httpx==0.25.2
asyncpg==0.29.0
python-jose[cryptography]==3.3.0
```

---

## Environment Variables (.env)

```bash
# Database
POSTGRES_PASSWORD=secure_postgres_password
LTI_DB_PASS=lti_password
LAB_DB_PASS=lab_password

# Cloudflare Tunnel
CF_TUNNEL_TOKEN=your_tunnel_token

# Domain
DOMAIN=lab.yourdomain.com
LTI_BASE_URL=https://lti.yourdomain.com

# VM Configuration
BASE_QCOW=/var/lib/libvirt/images/rhel-academy-base.qcow2
VM_RAM_MB=16384
VM_VCPUS=4
```

---

## Next Steps

1. Set up host server with KVM/libvirt
2. Prepare Red Hat Academy base QCOW2 image
3. Generate LTI RSA keys
4. Configure Cloudflare Tunnel with DNS entries
5. Deploy Docker Compose stack
6. Register LTI tool with your LMS
7. Create test assignment and verify flow
8. (Optional) Build instructor dashboard for monitoring
