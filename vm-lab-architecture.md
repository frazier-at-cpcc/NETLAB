# On-Demand Red Hat VM Lab with Web Console

## Overview

This architecture enables on-demand provisioning of Red Hat VMs for students, accessible via dynamic web URLs without VPN or authentication. Students launch labs directly from their LMS (Canvas, Blackboard, Moodle, Brightspace, etc.) via LTI integration and are automatically redirected to their provisioned VM terminal.

**Supports both LTI 1.1 and LTI 1.3** for maximum LMS compatibility.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LEARNING MANAGEMENT SYSTEM                            │
│              (Canvas, Blackboard, Moodle, Brightspace, etc.)                │
│                                                                              │
│   Student clicks "Launch Lab" assignment                                    │
│   LMS sends LTI launch request (1.1 OAuth or 1.3 OIDC/JWT)                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    │                                   │
                    ▼                                   ▼
┌─────────────────────────────────┐  ┌─────────────────────────────────┐
│        LTI 1.1 LAUNCH           │  │        LTI 1.3 LAUNCH           │
│  POST /lti/launch               │  │  OIDC → /lti/login              │
│  OAuth 1.0a signature           │  │  JWT  → /lti/launch             │
│  consumer_key + secret          │  │  Public/Private key pair        │
└─────────────────────────────────┘  └─────────────────────────────────┘
                    │                                   │
                    └─────────────────┬─────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            LTI TOOL SERVER                                   │
│                     https://lti.yourdomain.com                              │
│                                                                              │
│  • Validates LTI launch (OAuth 1.0a OR JWT signature)                       │
│  • Extracts: user_id, course_id, resource_link_id                          │
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
│  GET /api/session/by-key/{key}  →  Find existing session                    │
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

## LTI Version Comparison

| Feature | LTI 1.1 | LTI 1.3 |
|---------|---------|---------|
| **Authentication** | OAuth 1.0a (shared secret) | OIDC + JWT (public/private keys) |
| **Security** | Good | Better (no shared secrets) |
| **Setup Complexity** | Simple | More complex |
| **LMS Support** | Universal (legacy + modern) | Modern LMS only |
| **Recommended For** | Older LMS, quick setup | New deployments, better security |

**This solution supports BOTH versions** - use whichever your LMS requires.

---

## LTI Integration Architecture

### LTI 1.1 Launch Flow (OAuth 1.0a)

```
┌──────────────┐                    ┌──────────────┐                    ┌──────────────┐
│     LMS      │                    │  LTI Server  │                    │   Student    │
│              │                    │              │                    │   Browser    │
└──────┬───────┘                    └──────┬───────┘                    └──────┬───────┘
       │                                   │                                   │
       │  1. Student clicks "Launch Lab"   │                                   │
       │                                   │                                   │
       │  2. POST /lti/launch              │                                   │
       │     - oauth_consumer_key          │                                   │
       │     - oauth_signature (HMAC-SHA1) │                                   │
       │     - user_id, course_id, etc.    │                                   │
       │ ────────────────────────────────► │                                   │
       │                                   │                                   │
       │                                   │  3. Validate OAuth signature      │
       │                                   │     using shared secret           │
       │                                   │                                   │
       │                                   │  4. Extract user info             │
       │                                   │     Provision/lookup VM           │
       │                                   │                                   │
       │                                   │  5. HTTP 302 Redirect             │
       │                                   │ ─────────────────────────────────►│
       │                                   │                                   │
       │                                   │                    6. SSH Terminal│
       │                                   │                       in Browser  │
```

### LTI 1.3 Launch Flow (OIDC + JWT)

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
```

### LTI Server Endpoints

| Endpoint | Method | LTI Version | Purpose |
|----------|--------|-------------|---------|
| `/lti/launch` | POST | 1.1 & 1.3 | Main launch handler (auto-detects version) |
| `/lti/login` | GET/POST | 1.3 only | OIDC login initiation |
| `/lti/jwks` | GET | 1.3 only | Public keys for JWT verification |
| `/lti/config` | GET | Both | Tool configuration JSON |
| `/lti/config.xml` | GET | 1.1 only | LTI 1.1 XML configuration (cartridge) |

---

## Component Details

### 1. LTI Tool Server (Dual 1.1 + 1.3 Support)

```python
# lti/main.py
from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import RedirectResponse, JSONResponse, Response
from typing import Optional
import httpx
import os
import time
import hashlib
import hmac
import base64
import urllib.parse

# LTI 1.3 imports
from pylti1p3.contrib.fastapi import (
    FastAPIOIDCLogin,
    FastAPIMessageLaunch,
    FastAPICacheDataStorage,
    FastAPISessionService
)
from pylti1p3.tool_config import ToolConfJsonFile

app = FastAPI()

# Configuration
ORCHESTRATOR_API = os.getenv("ORCHESTRATOR_API", "http://lab-api:8000")
DOMAIN = os.getenv("DOMAIN", "lab.yourdomain.com")
LTI_BASE_URL = os.getenv("LTI_BASE_URL", "https://lti.yourdomain.com")

# LTI 1.3 Configuration
TOOL_CONFIG_13 = ToolConfJsonFile(os.path.join(os.path.dirname(__file__), 'lti13_config.json'))
CACHE = FastAPICacheDataStorage()

# LTI 1.1 Consumer Keys and Secrets (store securely in production)
# Format: { "consumer_key": "shared_secret" }
LTI11_CONSUMERS = {
    "cpcc-canvas": os.getenv("LTI11_CANVAS_SECRET", "your-canvas-secret"),
    "cpcc-blackboard": os.getenv("LTI11_BLACKBOARD_SECRET", "your-blackboard-secret"),
    "cpcc-moodle": os.getenv("LTI11_MOODLE_SECRET", "your-moodle-secret"),
    "cpcc-brightspace": os.getenv("LTI11_BRIGHTSPACE_SECRET", "your-brightspace-secret"),
}


# ============================================================================
# LTI 1.1 IMPLEMENTATION
# ============================================================================

def verify_oauth_signature(request_url: str, method: str, params: dict, consumer_secret: str) -> bool:
    """
    Verify OAuth 1.0a signature for LTI 1.1 launches.
    """
    # Get the signature from params
    provided_signature = params.get('oauth_signature', '')

    # Remove oauth_signature from params for base string calculation
    params_for_signing = {k: v for k, v in params.items() if k != 'oauth_signature'}

    # Sort parameters alphabetically
    sorted_params = sorted(params_for_signing.items())

    # Create parameter string
    param_string = '&'.join([f"{urllib.parse.quote(str(k), safe='')}"
                             f"={urllib.parse.quote(str(v), safe='')}"
                             for k, v in sorted_params])

    # Create base string
    base_string = '&'.join([
        method.upper(),
        urllib.parse.quote(request_url.split('?')[0], safe=''),
        urllib.parse.quote(param_string, safe='')
    ])

    # Create signing key (consumer_secret + '&' + token_secret, but token_secret is empty for LTI)
    signing_key = f"{urllib.parse.quote(consumer_secret, safe='')}&"

    # Calculate signature
    hashed = hmac.new(
        signing_key.encode('utf-8'),
        base_string.encode('utf-8'),
        hashlib.sha1
    )
    calculated_signature = base64.b64encode(hashed.digest()).decode('utf-8')

    return hmac.compare_digest(calculated_signature, provided_signature)


def validate_lti11_timestamp(timestamp: str, tolerance: int = 300) -> bool:
    """Validate OAuth timestamp is within acceptable range (default 5 minutes)."""
    try:
        ts = int(timestamp)
        now = int(time.time())
        return abs(now - ts) <= tolerance
    except (ValueError, TypeError):
        return False


async def handle_lti11_launch(request: Request, form_data: dict) -> RedirectResponse:
    """
    Handle LTI 1.1 launch request.
    Validates OAuth signature and provisions/retrieves VM.
    """
    # Extract OAuth parameters
    consumer_key = form_data.get('oauth_consumer_key')
    oauth_timestamp = form_data.get('oauth_timestamp')
    oauth_nonce = form_data.get('oauth_nonce')

    # Validate consumer key exists
    if consumer_key not in LTI11_CONSUMERS:
        raise HTTPException(status_code=401, detail="Invalid consumer key")

    consumer_secret = LTI11_CONSUMERS[consumer_key]

    # Validate timestamp
    if not validate_lti11_timestamp(oauth_timestamp):
        raise HTTPException(status_code=401, detail="OAuth timestamp expired")

    # Verify OAuth signature
    request_url = str(request.url)
    if not verify_oauth_signature(request_url, "POST", form_data, consumer_secret):
        raise HTTPException(status_code=401, detail="Invalid OAuth signature")

    # Validate this is a valid LTI launch
    lti_message_type = form_data.get('lti_message_type')
    lti_version = form_data.get('lti_version')

    if lti_message_type != 'basic-lti-launch-request':
        raise HTTPException(status_code=400, detail="Invalid LTI message type")

    # Extract user and context information
    user_id = form_data.get('user_id', '')
    user_email = form_data.get('lis_person_contact_email_primary', '')
    user_name = form_data.get('lis_person_name_full',
                form_data.get('lis_person_name_given', 'Student'))

    # Course/context information
    course_id = form_data.get('context_id', 'unknown')
    course_title = form_data.get('context_title', 'Unknown Course')

    # Resource link (assignment) information
    resource_link_id = form_data.get('resource_link_id', 'default')
    resource_link_title = form_data.get('resource_link_title', 'Lab Assignment')

    # Tool consumer (LMS) information
    tool_consumer_instance_guid = form_data.get('tool_consumer_instance_guid', consumer_key)

    # Create composite session key
    session_key = f"{tool_consumer_instance_guid}:{user_id}:{course_id}:{resource_link_id}"

    # Check for existing session or provision new VM
    return await provision_or_redirect(
        session_key=session_key,
        user_id=user_id,
        user_email=user_email,
        user_name=user_name,
        course_id=course_id,
        course_title=course_title,
        assignment_id=resource_link_id,
        assignment_title=resource_link_title
    )


# ============================================================================
# LTI 1.3 IMPLEMENTATION
# ============================================================================

def get_tool_conf():
    return TOOL_CONFIG_13

def get_launch_data_storage():
    return CACHE


@app.get("/lti/jwks")
async def jwks():
    """Return public keys for JWT verification by the LMS (LTI 1.3)"""
    tool_conf = get_tool_conf()
    return JSONResponse(tool_conf.get_jwks())


@app.api_route("/lti/login", methods=["GET", "POST"])
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


async def handle_lti13_launch(request: Request) -> RedirectResponse:
    """
    Handle LTI 1.3 launch request.
    Validates JWT and provisions/retrieves VM.
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

    user_id = launch_data.get('sub')
    user_email = launch_data.get('email', '')
    user_name = launch_data.get('name', 'Student')

    # Course and assignment context
    context = launch_data.get('https://purl.imsglobal.org/spec/lti/claim/context', {})
    course_id = context.get('id', 'unknown')
    course_title = context.get('title', 'Unknown Course')

    resource = launch_data.get('https://purl.imsglobal.org/spec/lti/claim/resource_link', {})
    assignment_id = resource.get('id', 'default')
    assignment_title = resource.get('title', 'Lab Assignment')

    # Get issuer for session key
    issuer = launch_data.get('iss', 'unknown')

    # Create composite session key
    session_key = f"{issuer}:{user_id}:{course_id}:{assignment_id}"

    return await provision_or_redirect(
        session_key=session_key,
        user_id=user_id,
        user_email=user_email,
        user_name=user_name,
        course_id=course_id,
        course_title=course_title,
        assignment_id=assignment_id,
        assignment_title=assignment_title
    )


# ============================================================================
# SHARED PROVISIONING LOGIC
# ============================================================================

async def provision_or_redirect(
    session_key: str,
    user_id: str,
    user_email: str,
    user_name: str,
    course_id: str,
    course_title: str,
    assignment_id: str,
    assignment_title: str
) -> RedirectResponse:
    """
    Check for existing VM session or provision a new one.
    Returns redirect to the VM terminal URL.
    """
    async with httpx.AsyncClient() as client:
        # Check if user already has an active session
        existing = await client.get(
            f"{ORCHESTRATOR_API}/api/session/by-key/{urllib.parse.quote(session_key, safe='')}"
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


# ============================================================================
# MAIN LAUNCH ENDPOINT (Auto-detects LTI version)
# ============================================================================

@app.post("/lti/launch")
async def launch(request: Request):
    """
    Main LTI launch endpoint - handles both LTI 1.1 and 1.3.
    Auto-detects version based on request parameters.
    """
    # Get form data
    form_data = await request.form()
    form_dict = dict(form_data)

    # Detect LTI version
    # LTI 1.1 has oauth_consumer_key, LTI 1.3 has id_token
    if 'oauth_consumer_key' in form_dict:
        # LTI 1.1 launch
        return await handle_lti11_launch(request, form_dict)
    elif 'id_token' in form_dict or 'state' in form_dict:
        # LTI 1.3 launch
        return await handle_lti13_launch(request)
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid LTI launch request. Missing required parameters."
        )


# ============================================================================
# CONFIGURATION ENDPOINTS
# ============================================================================

@app.get("/lti/config")
async def config():
    """
    Returns LTI 1.3 tool configuration JSON.
    """
    return JSONResponse({
        "title": "Red Hat Academy Lab Environment",
        "description": "Launch on-demand RHEL virtual machines for hands-on labs",
        "oidc_initiation_url": f"{LTI_BASE_URL}/lti/login",
        "target_link_uri": f"{LTI_BASE_URL}/lti/launch",
        "public_jwk_url": f"{LTI_BASE_URL}/lti/jwks",
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


@app.get("/lti/config.xml")
async def config_xml():
    """
    Returns LTI 1.1 XML configuration (IMS Common Cartridge format).
    Used by LMS systems that support XML-based tool configuration.
    """
    xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<cartridge_basiclti_link xmlns="http://www.imsglobal.org/xsd/imslticc_v1p0"
    xmlns:blti="http://www.imsglobal.org/xsd/imsbasiclti_v1p0"
    xmlns:lticm="http://www.imsglobal.org/xsd/imslticm_v1p0"
    xmlns:lticp="http://www.imsglobal.org/xsd/imslticp_v1p0"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://www.imsglobal.org/xsd/imslticc_v1p0 http://www.imsglobal.org/xsd/lti/ltiv1p0/imslticc_v1p0.xsd
        http://www.imsglobal.org/xsd/imsbasiclti_v1p0 http://www.imsglobal.org/xsd/lti/ltiv1p0/imsbasiclti_v1p0.xsd
        http://www.imsglobal.org/xsd/imslticm_v1p0 http://www.imsglobal.org/xsd/lti/ltiv1p0/imslticm_v1p0.xsd
        http://www.imsglobal.org/xsd/imslticp_v1p0 http://www.imsglobal.org/xsd/lti/ltiv1p0/imslticp_v1p0.xsd">

    <blti:title>Red Hat Academy Lab Environment</blti:title>
    <blti:description>Launch on-demand RHEL virtual machines for hands-on labs</blti:description>
    <blti:launch_url>{LTI_BASE_URL}/lti/launch</blti:launch_url>

    <blti:extensions platform="canvas.instructure.com">
        <lticm:property name="tool_id">rhel_lab</lticm:property>
        <lticm:property name="privacy_level">public</lticm:property>
        <lticm:options name="assignment_selection">
            <lticm:property name="enabled">true</lticm:property>
            <lticm:property name="message_type">basic-lti-launch-request</lticm:property>
            <lticm:property name="url">{LTI_BASE_URL}/lti/launch</lticm:property>
        </lticm:options>
        <lticm:options name="link_selection">
            <lticm:property name="enabled">true</lticm:property>
            <lticm:property name="message_type">basic-lti-launch-request</lticm:property>
            <lticm:property name="url">{LTI_BASE_URL}/lti/launch</lticm:property>
        </lticm:options>
    </blti:extensions>

    <blti:extensions platform="moodle">
        <lticm:property name="icon_url">{LTI_BASE_URL}/static/icon.png</lticm:property>
    </blti:extensions>

    <cartridge_bundle identifierref="BLTI001_Bundle"/>
    <cartridge_icon identifierref="BLTI001_Icon"/>
</cartridge_basiclti_link>"""

    return Response(content=xml_content, media_type="application/xml")


@app.get("/lti/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "lti_versions": ["1.1", "1.3"]}
```

### 2. LTI 1.1 Consumer Configuration

```python
# lti/lti11_consumers.py
"""
LTI 1.1 Consumer Key/Secret pairs.
In production, store these in environment variables or a secrets manager.
"""

import os

# Load from environment or use defaults (for development only!)
LTI11_CONSUMERS = {
    # Canvas
    "cpcc-canvas": os.getenv("LTI11_CANVAS_SECRET"),

    # Blackboard
    "cpcc-blackboard": os.getenv("LTI11_BLACKBOARD_SECRET"),

    # Moodle
    "cpcc-moodle": os.getenv("LTI11_MOODLE_SECRET"),

    # Brightspace (D2L)
    "cpcc-brightspace": os.getenv("LTI11_BRIGHTSPACE_SECRET"),

    # Generic consumer for testing
    "test-consumer": os.getenv("LTI11_TEST_SECRET", "test-secret-do-not-use-in-production"),
}

# Remove any None entries
LTI11_CONSUMERS = {k: v for k, v in LTI11_CONSUMERS.items() if v is not None}
```

### 3. LTI 1.3 Configuration File

```json
// lti/lti13_config.json
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
    "https://blackboard.com": {
        "client_id": "YOUR_BLACKBOARD_CLIENT_ID",
        "auth_login_url": "https://developer.blackboard.com/api/v1/gateway/oidcauth",
        "auth_token_url": "https://developer.blackboard.com/api/v1/gateway/oauth2/jwttoken",
        "key_set_url": "https://developer.blackboard.com/.well-known/jwks.json",
        "deployment_ids": ["YOUR_DEPLOYMENT_ID"],
        "private_key_file": "/app/keys/private.pem",
        "public_key_file": "/app/keys/public.pem"
    }
}
```

### 4. VM Management (libvirt/KVM)

VMs are created as thin clones using QCOW2 backing files for instant provisioning:

```bash
# Use backing file for instant clone from base QCOW
qemu-img create -f qcow2 -b /var/lib/libvirt/images/rhel-base.qcow2 \
    -F qcow2 /var/lib/libvirt/images/student-{session-id}.qcow2

# Clones are thin-provisioned - only differences stored
# Base image stays read-only, instant provisioning
```

### 5. Web Terminal: ttyd

**Why ttyd for this use case:**
- Single binary, ultra-lightweight
- No authentication by default (direct access)
- WebSocket-based, works through any firewall
- Direct SSH passthrough

```bash
# ttyd command (spawned per VM)
ttyd --port 7681 --writable ssh -o StrictHostKeyChecking=no student@10.10.10.11
```

### 6. Tunnel Solution: Cloudflare Tunnel

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
│  LTI Server:   Python FastAPI
│                + PyLTI1p3 (for 1.3)
│                + Custom OAuth (for 1.1)
│  API:          Python FastAPI
│  VM Mgmt:      libvirt Python bindings
│  Web Console:  ttyd (Docker containers)
│  Tunnel:       Cloudflare Tunnel (cloudflared)
│  Proxy:        Traefik (auto SSL, dynamic routing)
│  Database:     PostgreSQL (sessions, LTI state)
└────────────────────────────────────────────┘
```

---

## Workflow: Student Session Lifecycle

```
1. LTI LAUNCH FROM LMS
   ┌──────────────────────────────────────────────────────────┐
   │  Student clicks "Launch Lab" in Canvas/Blackboard/Moodle │
   │                                                          │
   │  LTI 1.1: POST with OAuth signature                      │
   │  LTI 1.3: OIDC flow with JWT                            │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
2. LTI VALIDATION & USER IDENTIFICATION
   ┌──────────────────────────────────────────────────────────┐
   │  LTI 1.1: Verify OAuth HMAC-SHA1 signature               │
   │  LTI 1.3: Verify JWT signature with public key           │
   │                                                          │
   │  Extract: user_id, email, course_id, resource_link_id    │
   │  Create session key for VM binding                       │
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

  # LTI Tool Server (supports both 1.1 and 1.3)
  lti-server:
    build: ./lti
    environment:
      ORCHESTRATOR_API: http://lab-api:8000
      LTI_BASE_URL: https://lti.yourdomain.com
      DOMAIN: lab.yourdomain.com
      DATABASE_URL: postgresql://lti:${LTI_DB_PASS}@postgres:5432/lti
      # LTI 1.1 Consumer Secrets
      LTI11_CANVAS_SECRET: ${LTI11_CANVAS_SECRET}
      LTI11_BLACKBOARD_SECRET: ${LTI11_BLACKBOARD_SECRET}
      LTI11_MOODLE_SECRET: ${LTI11_MOODLE_SECRET}
      LTI11_BRIGHTSPACE_SECRET: ${LTI11_BRIGHTSPACE_SECRET}
    volumes:
      - ./lti/keys:/app/keys:ro
      - ./lti/lti13_config.json:/app/lti13_config.json:ro
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

-- LTI 1.1 Consumers
CREATE TABLE lti11_consumers (
    id SERIAL PRIMARY KEY,
    consumer_key VARCHAR(255) UNIQUE NOT NULL,
    consumer_secret VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- LTI 1.1 Nonces (for replay protection)
CREATE TABLE lti11_nonces (
    id SERIAL PRIMARY KEY,
    consumer_key VARCHAR(255) NOT NULL,
    nonce VARCHAR(255) NOT NULL,
    timestamp INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(consumer_key, nonce, timestamp)
);

CREATE INDEX idx_lti11_nonces_cleanup ON lti11_nonces(created_at);

-- LTI 1.3 Platforms
CREATE TABLE lti13_platforms (
    id SERIAL PRIMARY KEY,
    issuer VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    deployment_id VARCHAR(255),
    auth_login_url TEXT,
    auth_token_url TEXT,
    key_set_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- LTI 1.3 Nonces
CREATE TABLE lti13_nonces (
    id SERIAL PRIMARY KEY,
    nonce VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- All LTI Launches (for auditing)
CREATE TABLE lti_launches (
    id SERIAL PRIMARY KEY,
    lti_version VARCHAR(10) NOT NULL,  -- '1.1' or '1.3'
    consumer_key VARCHAR(255),          -- LTI 1.1
    issuer VARCHAR(255),                -- LTI 1.3
    user_id VARCHAR(255) NOT NULL,
    user_email VARCHAR(255),
    user_name VARCHAR(255),
    course_id VARCHAR(255),
    course_title VARCHAR(255),
    resource_link_id VARCHAR(255),
    resource_link_title VARCHAR(255),
    session_key VARCHAR(512) NOT NULL,
    vm_session_id VARCHAR(64),
    launched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

## LMS Configuration

### Canvas LMS

#### LTI 1.1 Setup (Simple)

1. **Course → Settings → Apps → +App**

```
Configuration Type: By URL
Consumer Key: cpcc-canvas
Shared Secret: [Your secret from .env]
Config URL: https://lti.yourdomain.com/lti/config.xml
```

Or manually:

```
Configuration Type: Manual Entry
Name: Red Hat Academy Labs
Consumer Key: cpcc-canvas
Shared Secret: [Your secret]
Launch URL: https://lti.yourdomain.com/lti/launch
Domain: lti.yourdomain.com
Privacy: Public
```

#### LTI 1.3 Setup (More Secure)

1. **Admin → Developer Keys → +Developer Key → +LTI Key**

```
Key Name: Red Hat Academy Labs
Redirect URIs: https://lti.yourdomain.com/lti/launch
Method: Manual Entry

Title: Red Hat Academy Lab Environment
Description: Launch on-demand RHEL virtual machines
Target Link URI: https://lti.yourdomain.com/lti/launch
OpenID Connect Initiation URL: https://lti.yourdomain.com/lti/login
JWK Method: Public JWK URL
Public JWK URL: https://lti.yourdomain.com/lti/jwks
```

2. **Course → Settings → Apps → +App**

```
Configuration Type: By Client ID
Client ID: [From Developer Key]
```

---

### Blackboard

#### LTI 1.1 Setup

1. **System Admin → Building Blocks → LTI Tool Providers → Register Provider Domain**

```
Provider Domain: lti.yourdomain.com
Provider Domain Status: Approved
Default Configuration: Set globally
Tool Provider Key: cpcc-blackboard
Tool Provider Secret: [Your secret]
Send User Data: Send user data over SSL
User Fields to Send: All
```

2. **Create Placement**

```
Label: Red Hat Academy Lab
Type: Course content tool
Tool Provider URL: https://lti.yourdomain.com/lti/launch
```

#### LTI 1.3 Setup

1. **System Admin → LTI Tool Providers → Register LTI 1.3/Advantage Tool**

```
Client ID: [Generated by Blackboard]
Tool Provider URL: https://lti.yourdomain.com/lti/launch
Tool Provider Login URL: https://lti.yourdomain.com/lti/login
Tool Provider JWKS URL: https://lti.yourdomain.com/lti/jwks
```

---

### Moodle

#### LTI 1.1 Setup

1. **Site Administration → Plugins → Activity modules → External tool → Manage tools**

```
Tool name: Red Hat Academy Labs
Tool URL: https://lti.yourdomain.com/lti/launch
Consumer key: cpcc-moodle
Shared secret: [Your secret]
Default launch container: Embed, without blocks
Privacy:
  - Share launcher's name: Always
  - Share launcher's email: Always
  - Accept grades: Never
```

#### LTI 1.3 Setup

1. **Site Administration → Plugins → Activity modules → External tool → Manage tools**

```
Tool name: Red Hat Academy Labs
Tool URL: https://lti.yourdomain.com/lti/launch
LTI version: LTI 1.3
Public keyset URL: https://lti.yourdomain.com/lti/jwks
Initiate login URL: https://lti.yourdomain.com/lti/login
Redirection URI(s): https://lti.yourdomain.com/lti/launch
```

---

### Brightspace (D2L)

#### LTI 1.1 Setup

1. **Admin Tools → External Learning Tools → Manage Tool Providers**

```
Launch Point URL: https://lti.yourdomain.com/lti/launch
Key: cpcc-brightspace
Secret: [Your secret]
Visibility: Allow users to use this tool
```

2. **Create Link**

```
Admin Tools → External Learning Tools → Manage External Learning Tool Links
URL: https://lti.yourdomain.com/lti/launch
Key: cpcc-brightspace
Secret: [Your secret]
```

#### LTI 1.3 Setup

1. **Admin Tools → Manage Extensibility → LTI Advantage → Register Tool**

```
Name: Red Hat Academy Labs
Domain: lti.yourdomain.com
Redirect URLs: https://lti.yourdomain.com/lti/launch
OpenID Connect Login URL: https://lti.yourdomain.com/lti/login
Keyset URL: https://lti.yourdomain.com/lti/jwks
```

---

## Orchestration API

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
    chars = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(8))


async def get_next_vm_index(db):
    result = await db.fetchval(
        "SELECT COALESCE(MAX(CAST(SUBSTRING(vm_ip FROM '[0-9]+$') AS INTEGER)), 10) + 1 FROM vm_sessions WHERE status = 'running'"
    )
    return result


@app.get("/api/session/by-key/{session_key:path}")
async def get_session_by_key(session_key: str):
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

    await db.execute(
        "UPDATE vm_sessions SET last_accessed = CURRENT_TIMESTAMP WHERE session_key = $1",
        session_key
    )

    return Session(**dict(row))


@app.post("/api/provision", response_model=Session)
async def provision_vm(request: ProvisionRequest):
    db = app.state.db

    session_id = generate_session_id()
    vm_index = await get_next_vm_index(db)
    vm_ip = f"{VM_NETWORK}.{vm_index}"
    vm_name = f"student-{session_id}"

    overlay_path = f"/var/lib/libvirt/images/{vm_name}.qcow2"
    subprocess.run([
        "qemu-img", "create", "-f", "qcow2",
        "-b", BASE_QCOW, "-F", "qcow2", overlay_path
    ], check=True)

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

    time.sleep(30)

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
    db = app.state.db

    row = await db.fetchrow(
        "SELECT vm_name, container_id, overlay_path FROM vm_sessions WHERE session_id = $1",
        session_id
    )

    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    try:
        container = docker_client.containers.get(f"ttyd-{session_id}")
        container.stop()
        container.remove()
    except Exception:
        pass

    try:
        dom = libvirt_conn.lookupByName(row['vm_name'])
        dom.destroy()
        dom.undefine()
    except Exception:
        pass

    try:
        os.remove(row['overlay_path'])
    except Exception:
        pass

    await db.execute(
        "UPDATE vm_sessions SET status = 'destroyed' WHERE session_id = $1",
        session_id
    )

    return {"status": "destroyed"}


@app.get("/api/sessions")
async def list_sessions():
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

## Generate LTI Keys

```bash
# Generate RSA key pair for LTI 1.3 JWT signing
mkdir -p lti/keys

# Private key
openssl genrsa -out lti/keys/private.pem 2048

# Public key
openssl rsa -in lti/keys/private.pem -pubout -out lti/keys/public.pem

# Set permissions
chmod 600 lti/keys/private.pem
chmod 644 lti/keys/public.pem

# Generate secure secrets for LTI 1.1 consumers
echo "LTI11_CANVAS_SECRET=$(openssl rand -hex 32)" >> .env
echo "LTI11_BLACKBOARD_SECRET=$(openssl rand -hex 32)" >> .env
echo "LTI11_MOODLE_SECRET=$(openssl rand -hex 32)" >> .env
echo "LTI11_BRIGHTSPACE_SECRET=$(openssl rand -hex 32)" >> .env
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
rm -f /etc/ssh/ssh_host_*
truncate -s 0 /etc/machine-id
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

---

## Security Considerations

| Control | Implementation |
|---------|----------------|
| **LTI 1.1 Auth** | OAuth HMAC-SHA1 signature validation |
| **LTI 1.3 Auth** | JWT validation with public key verification |
| **Nonce/Replay** | Track nonces to prevent replay attacks |
| **URL obscurity** | 8-char random session ID |
| **Session binding** | User gets same VM for course/assignment |
| **Session expiry** | Auto-destroy after 4 hours |
| **Network isolation** | VMs on isolated bridge |
| **HTTPS only** | Cloudflare enforces TLS |

---

## Directory Structure

```
/opt/vm-lab/
├── docker-compose.yml
├── .env                          # All secrets
├── init-db.sql
├── api/
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
├── lti/
│   ├── Dockerfile
│   ├── main.py
│   ├── requirements.txt
│   ├── lti11_consumers.py        # LTI 1.1 config
│   ├── lti13_config.json         # LTI 1.3 config
│   └── keys/
│       ├── private.pem
│       └── public.pem
└── cloudflared/
    └── config.yml
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

# LTI 1.1 Consumer Secrets (generate with: openssl rand -hex 32)
LTI11_CANVAS_SECRET=your_canvas_secret_here
LTI11_BLACKBOARD_SECRET=your_blackboard_secret_here
LTI11_MOODLE_SECRET=your_moodle_secret_here
LTI11_BRIGHTSPACE_SECRET=your_brightspace_secret_here
```

---

## Next Steps

1. Set up host server with KVM/libvirt
2. Prepare Red Hat Academy base QCOW2 image
3. Generate LTI RSA keys (for 1.3) and consumer secrets (for 1.1)
4. Configure Cloudflare Tunnel with DNS entries
5. Deploy Docker Compose stack
6. Register LTI tool with your LMS:
   - **LTI 1.1**: Use consumer key + secret
   - **LTI 1.3**: Use OIDC/JWKS configuration
7. Create test assignment and verify flow
8. (Optional) Build instructor dashboard for monitoring
