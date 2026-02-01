"""
LTI Tool Server - Dual LTI 1.1 and 1.3 Support

Handles LMS authentication and redirects students to their provisioned VMs.
"""

import os
import time
import hashlib
import hmac
import base64
import urllib.parse
import secrets
import json
import logging
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import RedirectResponse, JSONResponse, Response, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import httpx
import asyncpg

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

ORCHESTRATOR_API = os.getenv("ORCHESTRATOR_API", "http://lab-api:8000")
DOMAIN = os.getenv("DOMAIN", "lab.yourdomain.com")
LTI_BASE_URL = os.getenv("LTI_BASE_URL", "https://lti.yourdomain.com")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://lti:lti@localhost:5432/lti")
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_hex(32))

# LTI 1.1 Consumer Keys and Secrets
LTI11_CONSUMERS = {
    "cpcc-canvas": os.getenv("LTI11_CANVAS_SECRET"),
    "cpcc-blackboard": os.getenv("LTI11_BLACKBOARD_SECRET"),
    "cpcc-moodle": os.getenv("LTI11_MOODLE_SECRET"),
    "cpcc-brightspace": os.getenv("LTI11_BRIGHTSPACE_SECRET"),
    "test-consumer": os.getenv("LTI11_TEST_SECRET", "test-secret-dev-only"),
}

# Remove None entries
LTI11_CONSUMERS = {k: v for k, v in LTI11_CONSUMERS.items() if v is not None}

# OAuth timestamp tolerance (5 minutes)
OAUTH_TIMESTAMP_TOLERANCE = 300

# Nonce expiry (90 minutes)
NONCE_EXPIRY_SECONDS = 5400


# ============================================================================
# Application Setup
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - setup and teardown."""
    # Setup database pool
    app.state.db = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=2,
        max_size=10
    )
    logger.info("Database pool created")

    yield

    # Cleanup
    await app.state.db.close()
    logger.info("Database pool closed")


app = FastAPI(
    title="Red Hat Academy Lab - LTI Server",
    description="LTI 1.1 and 1.3 Tool Provider for VM Lab Environment",
    version="1.0.0",
    lifespan=lifespan
)

# Add session middleware for LTI 1.3 OIDC flow
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="lti_session",
    max_age=3600
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
# Database Helpers
# ============================================================================

async def get_db():
    """Get database connection from pool."""
    return app.state.db


async def check_and_store_nonce(
    db: asyncpg.Pool,
    consumer_key: str,
    nonce: str,
    timestamp: int
) -> bool:
    """
    Check if nonce has been used and store it if not.
    Returns True if nonce is valid (not used before), False otherwise.
    """
    try:
        await db.execute(
            """
            INSERT INTO lti11_nonces (consumer_key, nonce, timestamp_val)
            VALUES ($1, $2, $3)
            """,
            consumer_key, nonce, timestamp
        )
        return True
    except asyncpg.UniqueViolationError:
        return False


async def log_launch(
    db: asyncpg.Pool,
    lti_version: str,
    user_id: str,
    session_key: str,
    **kwargs
):
    """Log an LTI launch for auditing."""
    await db.execute(
        """
        INSERT INTO lti_launches (
            lti_version, consumer_key, issuer, user_id, user_email, user_name,
            roles, course_id, course_title, resource_link_id, resource_link_title,
            tool_consumer_instance_guid, session_key, client_ip, user_agent
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        """,
        lti_version,
        kwargs.get('consumer_key'),
        kwargs.get('issuer'),
        user_id,
        kwargs.get('user_email'),
        kwargs.get('user_name'),
        kwargs.get('roles'),
        kwargs.get('course_id'),
        kwargs.get('course_title'),
        kwargs.get('resource_link_id'),
        kwargs.get('resource_link_title'),
        kwargs.get('tool_consumer_guid'),
        session_key,
        kwargs.get('client_ip'),
        kwargs.get('user_agent')
    )


# ============================================================================
# LTI 1.1 Implementation
# ============================================================================

def verify_oauth_signature(
    request_url: str,
    method: str,
    params: Dict[str, Any],
    consumer_secret: str
) -> bool:
    """
    Verify OAuth 1.0a HMAC-SHA1 signature for LTI 1.1 launches.
    """
    provided_signature = params.get('oauth_signature', '')

    # Build parameters for signing (exclude oauth_signature)
    params_for_signing = {
        k: v for k, v in params.items()
        if k != 'oauth_signature' and v is not None
    }

    # Sort parameters alphabetically
    sorted_params = sorted(params_for_signing.items())

    # Create parameter string
    param_string = '&'.join([
        f"{urllib.parse.quote(str(k), safe='')}"
        f"={urllib.parse.quote(str(v), safe='')}"
        for k, v in sorted_params
    ])

    # Parse URL and remove query string for base URL
    parsed_url = urllib.parse.urlparse(request_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

    # Create signature base string
    base_string = '&'.join([
        method.upper(),
        urllib.parse.quote(base_url, safe=''),
        urllib.parse.quote(param_string, safe='')
    ])

    # Create signing key (consumer_secret + '&' + token_secret)
    # Token secret is empty for LTI
    signing_key = f"{urllib.parse.quote(consumer_secret, safe='')}&"

    # Calculate HMAC-SHA1 signature
    hashed = hmac.new(
        signing_key.encode('utf-8'),
        base_string.encode('utf-8'),
        hashlib.sha1
    )
    calculated_signature = base64.b64encode(hashed.digest()).decode('utf-8')

    # Compare signatures (constant-time comparison)
    return hmac.compare_digest(calculated_signature, provided_signature)


def validate_oauth_timestamp(timestamp: str, tolerance: int = OAUTH_TIMESTAMP_TOLERANCE) -> bool:
    """Validate OAuth timestamp is within acceptable range."""
    try:
        ts = int(timestamp)
        now = int(time.time())
        return abs(now - ts) <= tolerance
    except (ValueError, TypeError):
        return False


async def handle_lti11_launch(
    request: Request,
    form_data: Dict[str, Any],
    db: asyncpg.Pool
) -> RedirectResponse:
    """
    Handle LTI 1.1 launch request.
    Validates OAuth 1.0a signature and provisions/retrieves VM.
    """
    # Extract OAuth parameters
    consumer_key = form_data.get('oauth_consumer_key')
    oauth_timestamp = form_data.get('oauth_timestamp', '')
    oauth_nonce = form_data.get('oauth_nonce', '')
    oauth_signature_method = form_data.get('oauth_signature_method', '')

    logger.info(f"LTI 1.1 launch from consumer: {consumer_key}")

    # Validate consumer key
    if consumer_key not in LTI11_CONSUMERS:
        logger.warning(f"Unknown consumer key: {consumer_key}")
        raise HTTPException(status_code=401, detail="Invalid consumer key")

    consumer_secret = LTI11_CONSUMERS[consumer_key]

    # Validate signature method
    if oauth_signature_method != 'HMAC-SHA1':
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported signature method: {oauth_signature_method}"
        )

    # Validate timestamp
    if not validate_oauth_timestamp(oauth_timestamp):
        raise HTTPException(status_code=401, detail="OAuth timestamp expired or invalid")

    # Check nonce (replay attack prevention)
    nonce_valid = await check_and_store_nonce(
        db, consumer_key, oauth_nonce, int(oauth_timestamp)
    )
    if not nonce_valid:
        raise HTTPException(status_code=401, detail="OAuth nonce already used")

    # Build request URL for signature verification
    request_url = str(request.url)

    # Verify OAuth signature
    if not verify_oauth_signature(request_url, "POST", form_data, consumer_secret):
        logger.warning(f"Invalid OAuth signature for consumer: {consumer_key}")
        raise HTTPException(status_code=401, detail="Invalid OAuth signature")

    # Validate LTI message type
    lti_message_type = form_data.get('lti_message_type', '')
    if lti_message_type != 'basic-lti-launch-request':
        raise HTTPException(
            status_code=400,
            detail=f"Invalid LTI message type: {lti_message_type}"
        )

    # Extract user information
    user_id = form_data.get('user_id', '')
    if not user_id:
        raise HTTPException(status_code=400, detail="Missing user_id")

    user_email = form_data.get('lis_person_contact_email_primary', '')
    user_name = form_data.get('lis_person_name_full') or \
                form_data.get('lis_person_name_given', 'Student')
    roles = form_data.get('roles', '')

    # Course/context information
    course_id = form_data.get('context_id', 'unknown')
    course_title = form_data.get('context_title', 'Unknown Course')

    # Resource link (assignment) information
    resource_link_id = form_data.get('resource_link_id', 'default')
    resource_link_title = form_data.get('resource_link_title', 'Lab Assignment')

    # Tool consumer instance
    tool_consumer_guid = form_data.get('tool_consumer_instance_guid', consumer_key)

    # Create composite session key
    session_key = f"{tool_consumer_guid}:{user_id}:{course_id}:{resource_link_id}"

    # Log the launch
    await log_launch(
        db,
        lti_version='1.1',
        user_id=user_id,
        session_key=session_key,
        consumer_key=consumer_key,
        user_email=user_email,
        user_name=user_name,
        roles=roles,
        course_id=course_id,
        course_title=course_title,
        resource_link_id=resource_link_id,
        resource_link_title=resource_link_title,
        tool_consumer_guid=tool_consumer_guid,
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get('user-agent')
    )

    # Provision or redirect to existing VM
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
# LTI 1.3 Implementation
# ============================================================================

def load_lti13_config() -> Dict[str, Any]:
    """Load LTI 1.3 platform configurations."""
    config_path = os.path.join(os.path.dirname(__file__), 'lti13_config.json')
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)
    return {}


def get_private_key() -> str:
    """Load private key for JWT signing."""
    key_path = os.path.join(os.path.dirname(__file__), 'keys', 'private.pem')
    if os.path.exists(key_path):
        with open(key_path, 'r') as f:
            return f.read()
    return ""


def get_public_key() -> str:
    """Load public key for JWKS."""
    key_path = os.path.join(os.path.dirname(__file__), 'keys', 'public.pem')
    if os.path.exists(key_path):
        with open(key_path, 'r') as f:
            return f.read()
    return ""


@app.get("/lti/jwks")
async def jwks():
    """
    Return public keys in JWKS format for JWT verification by the LMS.
    Required for LTI 1.3.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    import base64

    public_key_pem = get_public_key()
    if not public_key_pem:
        return JSONResponse({"keys": []})

    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )

        # Get the public numbers
        numbers = public_key.public_numbers()

        # Convert to base64url encoding
        def int_to_base64url(n, length):
            data = n.to_bytes(length, byteorder='big')
            return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

        # RSA key size in bytes
        key_size = (numbers.n.bit_length() + 7) // 8

        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "lti-key-1",
            "n": int_to_base64url(numbers.n, key_size),
            "e": int_to_base64url(numbers.e, 3)
        }

        return JSONResponse({"keys": [jwk]})
    except Exception as e:
        logger.error(f"Error generating JWKS: {e}")
        return JSONResponse({"keys": []})


@app.api_route("/lti/login", methods=["GET", "POST"])
async def lti13_login(request: Request):
    """
    OIDC Login Initiation endpoint for LTI 1.3.
    Step 1 of the LTI 1.3 launch flow.
    """
    # Get parameters from query or form
    if request.method == "GET":
        params = dict(request.query_params)
    else:
        form = await request.form()
        params = dict(form)

    iss = params.get('iss')
    login_hint = params.get('login_hint')
    target_link_uri = params.get('target_link_uri', f"{LTI_BASE_URL}/lti/launch")
    lti_message_hint = params.get('lti_message_hint', '')
    client_id = params.get('client_id', '')

    if not iss or not login_hint:
        raise HTTPException(
            status_code=400,
            detail="Missing required parameters: iss and login_hint"
        )

    # Load platform config
    config = load_lti13_config()
    platform_config = config.get(iss)

    if not platform_config:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown platform issuer: {iss}"
        )

    # Generate state and nonce
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    # Store state in session
    request.session['lti_state'] = state
    request.session['lti_nonce'] = nonce
    request.session['lti_iss'] = iss

    # Build authentication request URL
    auth_params = {
        'scope': 'openid',
        'response_type': 'id_token',
        'response_mode': 'form_post',
        'prompt': 'none',
        'client_id': platform_config.get('client_id', client_id),
        'redirect_uri': f"{LTI_BASE_URL}/lti/launch",
        'login_hint': login_hint,
        'state': state,
        'nonce': nonce,
    }

    if lti_message_hint:
        auth_params['lti_message_hint'] = lti_message_hint

    auth_url = platform_config['auth_login_url']
    auth_request_url = f"{auth_url}?{urllib.parse.urlencode(auth_params)}"

    return RedirectResponse(url=auth_request_url, status_code=302)


async def handle_lti13_launch(
    request: Request,
    form_data: Dict[str, Any],
    db: asyncpg.Pool
) -> RedirectResponse:
    """
    Handle LTI 1.3 launch request.
    Validates JWT and provisions/retrieves VM.
    """
    from jose import jwt, JWTError

    id_token = form_data.get('id_token')
    state = form_data.get('state')

    if not id_token:
        raise HTTPException(status_code=400, detail="Missing id_token")

    # Verify state matches session
    session_state = request.session.get('lti_state')
    if state != session_state:
        logger.warning("State mismatch in LTI 1.3 launch")
        raise HTTPException(status_code=401, detail="Invalid state parameter")

    # Decode JWT header to get issuer
    try:
        unverified_header = jwt.get_unverified_header(id_token)
        unverified_claims = jwt.get_unverified_claims(id_token)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid JWT: {e}")

    iss = unverified_claims.get('iss')

    # Load platform config
    config = load_lti13_config()
    platform_config = config.get(iss)

    if not platform_config:
        raise HTTPException(status_code=400, detail=f"Unknown platform: {iss}")

    # Fetch platform's public keys
    try:
        async with httpx.AsyncClient() as client:
            jwks_response = await client.get(platform_config['key_set_url'])
            jwks = jwks_response.json()
    except Exception as e:
        logger.error(f"Failed to fetch JWKS from {platform_config['key_set_url']}: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify token")

    # Verify JWT
    try:
        from jose.constants import ALGORITHMS
        claims = jwt.decode(
            id_token,
            jwks,
            algorithms=['RS256'],
            audience=platform_config.get('client_id'),
            issuer=iss
        )
    except JWTError as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail=f"JWT verification failed: {e}")

    # Verify nonce
    session_nonce = request.session.get('lti_nonce')
    if claims.get('nonce') != session_nonce:
        raise HTTPException(status_code=401, detail="Invalid nonce")

    # Extract user information
    user_id = claims.get('sub', '')
    if not user_id:
        raise HTTPException(status_code=400, detail="Missing user identifier")

    user_email = claims.get('email', '')
    user_name = claims.get('name', 'Student')

    # Context claims
    context = claims.get('https://purl.imsglobal.org/spec/lti/claim/context', {})
    course_id = context.get('id', 'unknown')
    course_title = context.get('title', 'Unknown Course')

    # Resource link claims
    resource = claims.get('https://purl.imsglobal.org/spec/lti/claim/resource_link', {})
    assignment_id = resource.get('id', 'default')
    assignment_title = resource.get('title', 'Lab Assignment')

    # Roles
    roles = ','.join(claims.get('https://purl.imsglobal.org/spec/lti/claim/roles', []))

    # Create session key
    session_key = f"{iss}:{user_id}:{course_id}:{assignment_id}"

    # Log the launch
    await log_launch(
        db,
        lti_version='1.3',
        user_id=user_id,
        session_key=session_key,
        issuer=iss,
        user_email=user_email,
        user_name=user_name,
        roles=roles,
        course_id=course_id,
        course_title=course_title,
        resource_link_id=assignment_id,
        resource_link_title=assignment_title,
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get('user-agent')
    )

    # Clear session state
    request.session.pop('lti_state', None)
    request.session.pop('lti_nonce', None)
    request.session.pop('lti_iss', None)

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
# Shared Provisioning Logic
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
    async with httpx.AsyncClient(timeout=120.0) as client:
        # Check if user already has an active session
        encoded_key = urllib.parse.quote(session_key, safe='')
        try:
            existing = await client.get(
                f"{ORCHESTRATOR_API}/api/session/by-key/{encoded_key}"
            )

            if existing.status_code == 200:
                session_data = existing.json()
                logger.info(f"Found existing session for {user_name}: {session_data.get('url')}")
                return RedirectResponse(url=session_data['url'], status_code=302)
        except httpx.RequestError as e:
            logger.error(f"Error checking existing session: {e}")

        # No existing session - provision new VM
        logger.info(f"Provisioning new VM for {user_name} ({user_email})")

        try:
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
                error_detail = provision_response.text
                logger.error(f"Provisioning failed: {error_detail}")
                raise HTTPException(
                    status_code=503,
                    detail="Failed to provision lab environment. Please try again."
                )

            session_data = provision_response.json()
            logger.info(f"Provisioned VM: {session_data.get('url')}")

            return RedirectResponse(url=session_data['url'], status_code=302)

        except httpx.RequestError as e:
            logger.error(f"Error provisioning VM: {e}")
            raise HTTPException(
                status_code=503,
                detail="Lab service temporarily unavailable. Please try again."
            )


# ============================================================================
# Main Launch Endpoint
# ============================================================================

@app.post("/lti/launch")
async def launch(request: Request):
    """
    Main LTI launch endpoint - handles both LTI 1.1 and 1.3.
    Auto-detects version based on request parameters.
    """
    db = await get_db()
    form = await request.form()
    form_data = dict(form)

    logger.info(f"LTI launch request received with {len(form_data)} parameters")

    # Detect LTI version based on parameters
    if 'oauth_consumer_key' in form_data:
        # LTI 1.1 launch
        logger.info("Detected LTI 1.1 launch")
        return await handle_lti11_launch(request, form_data, db)
    elif 'id_token' in form_data:
        # LTI 1.3 launch (after OIDC redirect)
        logger.info("Detected LTI 1.3 launch")
        return await handle_lti13_launch(request, form_data, db)
    else:
        logger.warning(f"Invalid LTI launch - unrecognized parameters: {list(form_data.keys())}")
        raise HTTPException(
            status_code=400,
            detail="Invalid LTI launch request. Missing required parameters."
        )


# ============================================================================
# Configuration Endpoints
# ============================================================================

@app.get("/lti/config")
async def config_json():
    """
    Returns LTI 1.3 tool configuration JSON.
    Use this URL when configuring the tool in your LMS.
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
                        {"placement": "assignment_selection", "message_type": "LtiResourceLinkRequest"},
                        {"placement": "link_selection", "message_type": "LtiResourceLinkRequest"}
                    ]
                }
            }
        ],
        "claims": ["sub", "name", "email", "iss"],
        "messages": [
            {"type": "LtiResourceLinkRequest", "target_link_uri": f"{LTI_BASE_URL}/lti/launch"}
        ]
    })


@app.get("/lti/config.xml")
async def config_xml():
    """
    Returns LTI 1.1 XML configuration (IMS Common Cartridge format).
    Use this URL when configuring the tool via XML in your LMS.
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
    <blti:description>Launch on-demand RHEL virtual machines for hands-on labs. Each student gets their own dedicated VM with 16GB RAM.</blti:description>
    <blti:launch_url>{LTI_BASE_URL}/lti/launch</blti:launch_url>

    <blti:extensions platform="canvas.instructure.com">
        <lticm:property name="tool_id">rhel_lab</lticm:property>
        <lticm:property name="privacy_level">public</lticm:property>
        <lticm:property name="domain">{urllib.parse.urlparse(LTI_BASE_URL).netloc}</lticm:property>
        <lticm:options name="assignment_selection">
            <lticm:property name="enabled">true</lticm:property>
            <lticm:property name="message_type">basic-lti-launch-request</lticm:property>
            <lticm:property name="url">{LTI_BASE_URL}/lti/launch</lticm:property>
            <lticm:property name="text">Red Hat Academy Lab</lticm:property>
        </lticm:options>
        <lticm:options name="link_selection">
            <lticm:property name="enabled">true</lticm:property>
            <lticm:property name="message_type">basic-lti-launch-request</lticm:property>
            <lticm:property name="url">{LTI_BASE_URL}/lti/launch</lticm:property>
            <lticm:property name="text">Red Hat Academy Lab</lticm:property>
        </lticm:options>
    </blti:extensions>

    <blti:extensions platform="moodle">
        <lticm:property name="icon_url">{LTI_BASE_URL}/static/icon.png</lticm:property>
    </blti:extensions>

    <blti:extensions platform="blackboard.com">
        <lticm:property name="domain">{urllib.parse.urlparse(LTI_BASE_URL).netloc}</lticm:property>
    </blti:extensions>

    <blti:vendor>
        <lticp:code>cpcc</lticp:code>
        <lticp:name>Central Piedmont Community College</lticp:name>
        <lticp:description>Red Hat Academy VM Lab Environment</lticp:description>
        <lticp:url>https://www.cpcc.edu</lticp:url>
    </blti:vendor>

    <cartridge_bundle identifierref="BLTI001_Bundle"/>
    <cartridge_icon identifierref="BLTI001_Icon"/>
</cartridge_basiclti_link>"""

    return Response(content=xml_content, media_type="application/xml")


# ============================================================================
# Health and Status Endpoints
# ============================================================================

@app.get("/lti/health")
async def health():
    """Health check endpoint."""
    db_healthy = False
    try:
        db = await get_db()
        await db.fetchval("SELECT 1")
        db_healthy = True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")

    return JSONResponse({
        "status": "healthy" if db_healthy else "degraded",
        "lti_versions": ["1.1", "1.3"],
        "database": "connected" if db_healthy else "disconnected",
        "configured_consumers": len(LTI11_CONSUMERS)
    })


@app.get("/")
async def root():
    """Root endpoint with basic info."""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Red Hat Academy Lab - LTI Server</title>
        <style>
            body { font-family: system-ui, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            h1 { color: #cc0000; }
            code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
            .endpoint { margin: 10px 0; }
        </style>
    </head>
    <body>
        <h1>Red Hat Academy Lab Environment</h1>
        <p>LTI Tool Provider for on-demand RHEL virtual machines.</p>

        <h2>Supported LTI Versions</h2>
        <ul>
            <li><strong>LTI 1.1</strong> - OAuth 1.0a authentication</li>
            <li><strong>LTI 1.3</strong> - OIDC + JWT authentication</li>
        </ul>

        <h2>Configuration Endpoints</h2>
        <div class="endpoint">
            <strong>LTI 1.1 XML Config:</strong>
            <code><a href="/lti/config.xml">/lti/config.xml</a></code>
        </div>
        <div class="endpoint">
            <strong>LTI 1.3 JSON Config:</strong>
            <code><a href="/lti/config">/lti/config</a></code>
        </div>
        <div class="endpoint">
            <strong>JWKS (LTI 1.3):</strong>
            <code><a href="/lti/jwks">/lti/jwks</a></code>
        </div>

        <h2>Launch Endpoint</h2>
        <div class="endpoint">
            <code>POST /lti/launch</code> - Auto-detects LTI version
        </div>

        <h2>Health Check</h2>
        <div class="endpoint">
            <code><a href="/lti/health">/lti/health</a></code>
        </div>
    </body>
    </html>
    """)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
