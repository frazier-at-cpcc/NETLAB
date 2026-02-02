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
from datetime import datetime, timedelta

from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import RedirectResponse, JSONResponse, Response, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import httpx
import asyncpg
import redis

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
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/1")

# Redis client for token storage (shared between workers)
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

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

# Token storage uses Redis (shared between workers)
TOKEN_EXPIRY_SECONDS = 4 * 3600  # 4 hours
TOKEN_PREFIX = "instructor_token:"


def generate_instructor_token(session_data: dict) -> str:
    """Generate a token for instructor session and store it in Redis."""
    token = secrets.token_urlsafe(32)
    key = f"{TOKEN_PREFIX}{token}"
    redis_client.setex(key, TOKEN_EXPIRY_SECONDS, json.dumps(session_data))
    logger.info(f"Stored token in Redis: {key[:30]}...")
    return token


def get_instructor_session(token: str) -> Optional[dict]:
    """Get instructor session data from token (from Redis)."""
    if not token:
        return None
    key = f"{TOKEN_PREFIX}{token}"
    data = redis_client.get(key)
    if not data:
        logger.debug(f"Token not found in Redis: {key[:30]}...")
        return None
    return json.loads(data)


def update_instructor_session(token: str, session_data: dict):
    """Update instructor session data in Redis."""
    if not token:
        return
    key = f"{TOKEN_PREFIX}{token}"
    # Get current TTL and preserve it
    ttl = redis_client.ttl(key)
    if ttl > 0:
        redis_client.setex(key, ttl, json.dumps(session_data))


def get_token_from_request(request: Request) -> Optional[str]:
    """Extract instructor token from request header or query param."""
    # Check Authorization header first
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    # Fall back to query parameter
    return request.query_params.get("_token")


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
# same_site="none" and https_only=True required for iframe embedding from LMS
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="lti_session",
    max_age=3600,
    same_site="none",
    https_only=True
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files and templates
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# Instructor role patterns (LTI standard roles)
INSTRUCTOR_ROLES = [
    "Instructor",
    "urn:lti:role:ims/lis/Instructor",
    "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor",
    "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Instructor",
    "Administrator",
    "urn:lti:role:ims/lis/Administrator",
    "http://purl.imsglobal.org/vocab/lis/v2/membership#Administrator",
    "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Administrator",
    "ContentDeveloper",
    "urn:lti:role:ims/lis/ContentDeveloper",
    "http://purl.imsglobal.org/vocab/lis/v2/membership#ContentDeveloper",
    "TeachingAssistant",
    "urn:lti:role:ims/lis/TeachingAssistant",
    "http://purl.imsglobal.org/vocab/lis/v2/membership#Mentor",
]


def is_instructor(roles: str) -> bool:
    """Check if the user has an instructor role."""
    if not roles:
        return False
    role_list = [r.strip() for r in roles.replace(',', ' ').split()]
    for role in role_list:
        for instructor_role in INSTRUCTOR_ROLES:
            if instructor_role.lower() in role.lower():
                return True
    return False


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

    # Debug logging
    logger.info(f"OAuth Debug - Base URL: {base_url}")
    logger.info(f"OAuth Debug - Provided signature: {provided_signature}")
    logger.info(f"OAuth Debug - Calculated signature: {calculated_signature}")
    logger.info(f"OAuth Debug - Signatures match: {hmac.compare_digest(calculated_signature, provided_signature)}")

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
    # Use LTI_BASE_URL to get the external URL that the LMS used for signing
    request_url = f"{LTI_BASE_URL}/lti/launch"
    logger.debug(f"OAuth verification URL: {request_url}")

    # Verify OAuth signature
    if not verify_oauth_signature(request_url, "POST", form_data, consumer_secret):
        logger.warning(f"Invalid OAuth signature for consumer: {consumer_key}")
        logger.warning(f"Signature verification failed with URL: {request_url}")
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

    # Provision or redirect to existing VM (or show instructor dashboard)
    return await provision_or_redirect(
        request=request,
        session_key=session_key,
        user_id=user_id,
        user_email=user_email,
        user_name=user_name,
        course_id=course_id,
        course_title=course_title,
        assignment_id=resource_link_id,
        assignment_title=resource_link_title,
        roles=roles
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
        request=request,
        session_key=session_key,
        user_id=user_id,
        user_email=user_email,
        user_name=user_name,
        course_id=course_id,
        course_title=course_title,
        assignment_id=assignment_id,
        assignment_title=assignment_title,
        roles=roles
    )


# ============================================================================
# Shared Provisioning Logic
# ============================================================================

async def provision_or_redirect(
    request: Request,
    session_key: str,
    user_id: str,
    user_email: str,
    user_name: str,
    course_id: str,
    course_title: str,
    assignment_id: str,
    assignment_title: str,
    roles: str = ""
) -> Response:
    """
    Check for existing VM session or provision a new one.
    Shows a loading page with progress for new sessions.
    For instructors, returns the instructor dashboard instead.
    """
    # Check if user is an instructor
    if is_instructor(roles):
        logger.info(f"Instructor detected: {user_name} ({user_email})")

        # Generate a token for this instructor session (avoids third-party cookie issues)
        session_data = {
            'instructor': True,
            'user_id': user_id,
            'user_email': user_email,
            'user_name': user_name,
            'course_id': course_id,
            'course_title': course_title,
            'roles': roles
        }
        instructor_token = generate_instructor_token(session_data)
        logger.info(f"Generated instructor token for {user_name}")

        # Render instructor dashboard with token
        return templates.TemplateResponse(
            "instructor_dashboard.html",
            {
                "request": request,
                "user_id": user_id,
                "user_email": user_email,
                "user_name": user_name,
                "course_id": course_id,
                "course_title": course_title,
                "api_base": "",  # Use relative URLs
                "instructor_token": instructor_token  # Pass token to frontend
            }
        )

    # Store session context in cookie for later use (recreate, etc.)
    request.session['session_key'] = session_key
    request.session['user_id'] = user_id
    request.session['user_email'] = user_email
    request.session['user_name'] = user_name
    request.session['course_id'] = course_id
    request.session['course_title'] = course_title
    request.session['assignment_id'] = assignment_id
    request.session['assignment_title'] = assignment_title

    async with httpx.AsyncClient(timeout=120.0) as client:
        # Check if user already has an active session
        encoded_key = urllib.parse.quote(session_key, safe='')
        try:
            existing = await client.get(
                f"{ORCHESTRATOR_API}/api/session/by-key/{encoded_key}"
            )

            if existing.status_code == 200:
                session_data = existing.json()
                session_id = session_data.get('session_id')
                session_status = session_data.get('status')
                logger.info(f"Found existing session for {user_name}: {session_data.get('url')} (status: {session_status})")

                # Store the current session ID in cookie
                request.session['current_session_id'] = session_id

                # If session is fully running, show the control page (not direct redirect)
                if session_status == 'running':
                    return templates.TemplateResponse(
                        "lab_loading.html",
                        {
                            "request": request,
                            "session_id": session_id,
                            "lab_url": session_data.get('url'),
                            "user_name": user_name,
                            "course_title": course_title,
                            "assignment_title": assignment_title,
                            "initial_status": "running"
                        }
                    )

                # If session is still starting, show the loading page
                if session_status == 'starting':
                    return templates.TemplateResponse(
                        "lab_loading.html",
                        {
                            "request": request,
                            "session_id": session_id,
                            "lab_url": session_data.get('url'),
                            "user_name": user_name,
                            "course_title": course_title,
                            "assignment_title": assignment_title,
                            "initial_status": "starting"
                        }
                    )

                # For other statuses (error, destroyed), provision a new VM
                logger.info(f"Existing session has status '{session_status}', provisioning new VM")
        except httpx.RequestError as e:
            logger.error(f"Error checking existing session: {e}")

        # No existing session - show ready state, wait for user to click Start Lab
        logger.info(f"No existing session for {user_name} ({user_email}), showing ready state")

        # Return the template in "ready" state - user must click Start Lab to provision
        return templates.TemplateResponse(
            "lab_loading.html",
            {
                "request": request,
                "session_id": "",  # No session yet
                "lab_url": "",
                "user_name": user_name,
                "course_title": course_title,
                "assignment_title": assignment_title,
                "initial_status": "ready",
                # Pass session context for the Start Lab button
                "session_key": session_key,
                "user_id": user_id,
                "user_email": user_email,
                "course_id": course_id,
                "assignment_id": assignment_id
            }
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
# Instructor Dashboard
# ============================================================================

@app.get("/lti/dashboard")
async def instructor_dashboard(request: Request):
    """
    Instructor dashboard page. Requires valid instructor session.
    """
    # Check if user has instructor session
    if not request.session.get('instructor'):
        return HTMLResponse(
            content="<h1>Access Denied</h1><p>You must launch this tool from your LMS as an instructor.</p>",
            status_code=403
        )

    return templates.TemplateResponse(
        "instructor_dashboard.html",
        {
            "request": request,
            "user_id": request.session.get('user_id', ''),
            "user_email": request.session.get('user_email', ''),
            "user_name": request.session.get('user_name', 'Instructor'),
            "course_id": request.session.get('course_id', ''),
            "course_title": request.session.get('course_title', 'Course'),
            "api_base": ""  # Use relative URLs through proxy
        }
    )


# ============================================================================
# API Proxy for Instructor Dashboard
# ============================================================================

@app.get("/api/recordings")
async def proxy_recordings(request: Request):
    """Proxy recordings API for instructor dashboard."""
    token = get_token_from_request(request)
    session_data = get_instructor_session(token)
    if not session_data or not session_data.get('instructor'):
        raise HTTPException(status_code=403, detail="Instructor access required")

    async with httpx.AsyncClient(timeout=30.0) as client:
        params = {k: v for k, v in request.query_params.items() if k != '_token'}
        response = await client.get(f"{ORCHESTRATOR_API}/api/recordings", params=params)
        return JSONResponse(content=response.json(), status_code=response.status_code)


@app.get("/api/recordings/{recording_id}")
async def proxy_recording_detail(request: Request, recording_id: int):
    """Proxy single recording detail."""
    token = get_token_from_request(request)
    session_data = get_instructor_session(token)
    if not session_data or not session_data.get('instructor'):
        raise HTTPException(status_code=403, detail="Instructor access required")

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(f"{ORCHESTRATOR_API}/api/recordings/{recording_id}")
        return JSONResponse(content=response.json(), status_code=response.status_code)


@app.get("/api/recordings/{recording_id}/view")
async def proxy_recording_view(request: Request, recording_id: int):
    """Proxy recording view (plain text)."""
    token = get_token_from_request(request)
    session_data = get_instructor_session(token)
    if not session_data or not session_data.get('instructor'):
        raise HTTPException(status_code=403, detail="Instructor access required")

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(f"{ORCHESTRATOR_API}/api/recordings/{recording_id}/view")
        return Response(content=response.text, media_type="text/plain")


@app.get("/api/recordings/{recording_id}/download")
async def proxy_recording_download(request: Request, recording_id: int):
    """Proxy recording download."""
    token = get_token_from_request(request)
    session_data = get_instructor_session(token)
    if not session_data or not session_data.get('instructor'):
        raise HTTPException(status_code=403, detail="Instructor access required")

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(f"{ORCHESTRATOR_API}/api/recordings/{recording_id}/download")
        return Response(
            content=response.content,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename=session-{recording_id}.log"}
        )


@app.get("/api/recordings/{recording_id}/timing")
async def proxy_recording_timing(request: Request, recording_id: int):
    """Proxy recording timing file download."""
    token = get_token_from_request(request)
    session_data = get_instructor_session(token)
    if not session_data or not session_data.get('instructor'):
        raise HTTPException(status_code=403, detail="Instructor access required")

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(f"{ORCHESTRATOR_API}/api/recordings/{recording_id}/timing")
        return Response(
            content=response.content,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename=session-{recording_id}.timing"}
        )


@app.get("/api/recordings/{recording_id}/cast")
async def proxy_recording_cast(request: Request, recording_id: int):
    """Proxy recording in asciicast format for asciinema player."""
    token = get_token_from_request(request)
    session_data = get_instructor_session(token)
    if not session_data or not session_data.get('instructor'):
        raise HTTPException(status_code=403, detail="Instructor access required")

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(f"{ORCHESTRATOR_API}/api/recordings/{recording_id}/cast")
        return Response(content=response.content, media_type="application/json")


@app.get("/api/sessions")
async def proxy_sessions(request: Request):
    """Proxy sessions list for instructor dashboard."""
    token = get_token_from_request(request)
    session_data = get_instructor_session(token)
    if not session_data or not session_data.get('instructor'):
        raise HTTPException(status_code=403, detail="Instructor access required")

    async with httpx.AsyncClient(timeout=30.0) as client:
        params = {k: v for k, v in request.query_params.items() if k != '_token'}
        response = await client.get(f"{ORCHESTRATOR_API}/api/sessions", params=params)
        return JSONResponse(content=response.json(), status_code=response.status_code)


@app.get("/api/stats")
async def proxy_stats(request: Request):
    """Proxy stats for instructor dashboard."""
    token = get_token_from_request(request)
    logger.info(f"Stats request - Token received: {token[:20] if token else 'None'}...")
    session_data = get_instructor_session(token)
    logger.info(f"Session data found: {session_data is not None}")
    if not session_data or not session_data.get('instructor'):
        raise HTTPException(status_code=403, detail="Instructor access required")

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(f"{ORCHESTRATOR_API}/api/stats")
        return JSONResponse(content=response.json(), status_code=response.status_code)


# ============================================================================
# Session Status API (for student loading page)
# ============================================================================

@app.get("/api/session/{session_id}/status")
async def proxy_session_status(session_id: str):
    """
    Proxy session status for the student loading page.

    This endpoint does NOT require authentication since it's called
    from the loading page before the session is fully established.
    The session_id acts as an implicit authentication token.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(f"{ORCHESTRATOR_API}/api/session/{session_id}/status")
            if response.status_code == 404:
                raise HTTPException(status_code=404, detail="Session not found")
            return JSONResponse(content=response.json(), status_code=response.status_code)
        except httpx.RequestError as e:
            logger.error(f"Error fetching session status: {e}")
            raise HTTPException(status_code=503, detail="Unable to fetch session status")


@app.post("/api/provision")
async def provision_student_vm(request: Request):
    """
    Provision a new VM for a student.

    This endpoint is called by the student when they click "Start Lab"
    in the loading page. It receives the session context and provisions
    a new VM via the orchestrator API.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    session_key = body.get('session_key')
    user_id = body.get('user_id')
    user_email = body.get('user_email', '')
    user_name = body.get('user_name', 'Student')
    course_id = body.get('course_id', 'unknown')
    course_title = body.get('course_title', 'Unknown Course')
    assignment_id = body.get('assignment_id', 'default')
    assignment_title = body.get('assignment_title', 'Lab Assignment')

    if not session_key or not user_id:
        raise HTTPException(status_code=400, detail="Missing required fields: session_key and user_id")

    logger.info(f"Provisioning VM for {user_name} ({user_email}) via Start Lab button")

    async with httpx.AsyncClient(timeout=120.0) as client:
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
            session_id = session_data.get('session_id')
            logger.info(f"Provisioned VM via Start Lab: {session_data.get('url')}")

            # Store the current session ID in cookie
            request.session['current_session_id'] = session_id

            return JSONResponse(content={
                "status": "starting",
                "session_id": session_id,
                "url": session_data.get('url')
            })

        except httpx.RequestError as e:
            logger.error(f"Error provisioning VM: {e}")
            raise HTTPException(
                status_code=503,
                detail="Lab service temporarily unavailable. Please try again."
            )


@app.delete("/api/session/{session_id}")
async def stop_student_session(request: Request, session_id: str):
    """
    Stop/destroy a student's VM session.

    Authorization: The session ID is only known to the authenticated user
    who received it via the LTI-authenticated page. Session IDs are random
    and unguessable, providing security through obscurity combined with
    the LTI authentication that preceded this request.
    """
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.delete(f"{ORCHESTRATOR_API}/api/{session_id}")
            if response.status_code == 404:
                raise HTTPException(status_code=404, detail="Session not found")
            if response.status_code != 200:
                logger.error(f"Failed to stop session {session_id}: {response.status_code} - {response.text}")
                raise HTTPException(status_code=response.status_code, detail="Failed to stop session")
            logger.info(f"Session {session_id} stopped successfully")
            return JSONResponse(content={"status": "stopped"}, status_code=200)
        except httpx.RequestError as e:
            logger.error(f"Error stopping session: {e}")
            raise HTTPException(status_code=503, detail="Unable to stop session")


@app.post("/api/session/{session_id}/recreate")
async def recreate_student_session(request: Request, session_id: str):
    """
    Recreate a student's VM session (stop existing and start new).

    Returns the new session details.
    """
    async with httpx.AsyncClient(timeout=120.0) as client:
        # First, get the original session info from lab-api
        try:
            session_response = await client.get(f"{ORCHESTRATOR_API}/api/session/{session_id}/status")
            if session_response.status_code != 200:
                raise HTTPException(status_code=404, detail="Session not found")
            original_session = session_response.json()
        except httpx.RequestError as e:
            logger.error(f"Error fetching session info: {e}")
            raise HTTPException(status_code=503, detail="Unable to fetch session info")

        # Extract session context from the original session
        session_key = original_session.get('session_key', '')
        user_id = original_session.get('user_id', '')
        user_email = original_session.get('user_email', '')
        user_name = original_session.get('user_name', '')
        course_id = original_session.get('course_id', '')
        course_title = original_session.get('course_title', '')
        assignment_id = original_session.get('assignment_id', '')
        assignment_title = original_session.get('assignment_title', '')
        # First, destroy the existing session
        try:
            await client.delete(f"{ORCHESTRATOR_API}/api/{session_id}")
            logger.info(f"Destroyed old session {session_id} for recreate")
        except httpx.RequestError as e:
            logger.warning(f"Error destroying old session (continuing): {e}")

        # Provision a new session
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
                logger.error(f"Reprovisioning failed: {error_detail}")
                raise HTTPException(status_code=503, detail="Failed to recreate lab environment")

            session_data = provision_response.json()
            new_session_id = session_data.get('session_id')

            # Update the session cookie with new session ID
            request.session['current_session_id'] = new_session_id

            logger.info(f"Recreated session: old={session_id}, new={new_session_id}")

            return JSONResponse(content={
                "status": "recreating",
                "session_id": new_session_id,
                "url": session_data.get('url')
            })

        except httpx.RequestError as e:
            logger.error(f"Error provisioning new session: {e}")
            raise HTTPException(status_code=503, detail="Unable to create new session")


# ============================================================================
# Demo VM Endpoints for Instructor
# ============================================================================

@app.get("/api/demo-vm")
async def get_demo_vm(request: Request):
    """Get the instructor's current demo VM status."""
    token = get_token_from_request(request)
    session_data = get_instructor_session(token)
    if not session_data or not session_data.get('instructor'):
        raise HTTPException(status_code=403, detail="Instructor access required")

    demo_session_id = session_data.get('demo_vm_session_id')
    if not demo_session_id:
        return JSONResponse(content={"status": "inactive"})

    # Check if the session is still valid
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(f"{ORCHESTRATOR_API}/api/session/{demo_session_id}")
            if response.status_code == 200:
                vm_session = response.json()
                if vm_session.get('status') in ['running', 'starting']:
                    return JSONResponse(content={
                        "status": "active",
                        "session_id": demo_session_id,
                        "url": vm_session.get('url'),
                        "vm_ip": vm_session.get('vm_ip'),
                        "expires_at": vm_session.get('expires_at'),
                        "created_at": vm_session.get('created_at')
                    })
        except Exception as e:
            logger.error(f"Error checking demo VM status: {e}")

    # Session no longer valid, clear from token data
    if token and session_data:
        session_data.pop('demo_vm_session_id', None)
        update_instructor_session(token, session_data)
    return JSONResponse(content={"status": "inactive"})


@app.post("/api/demo-vm")
async def launch_demo_vm(request: Request):
    """Launch a demo VM for the instructor."""
    token = get_token_from_request(request)
    session_data = get_instructor_session(token)
    if not session_data or not session_data.get('instructor'):
        raise HTTPException(status_code=403, detail="Instructor access required")

    # Check if instructor already has an active demo VM
    existing_session_id = session_data.get('demo_vm_session_id')
    if existing_session_id:
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(f"{ORCHESTRATOR_API}/api/session/{existing_session_id}")
                if response.status_code == 200:
                    vm_session = response.json()
                    if vm_session.get('status') in ['running', 'starting']:
                        return JSONResponse(content={
                            "status": "active",
                            "session_id": existing_session_id,
                            "url": vm_session.get('url'),
                            "vm_ip": vm_session.get('vm_ip'),
                            "expires_at": vm_session.get('expires_at'),
                            "created_at": vm_session.get('created_at')
                        })
            except Exception:
                pass

    # Provision a new demo VM
    user_id = session_data.get('user_id', 'instructor')
    user_email = session_data.get('user_email', 'instructor@local')
    user_name = session_data.get('user_name', 'Instructor')
    course_id = session_data.get('course_id', 'demo')
    course_title = session_data.get('course_title', 'Demo')

    # Create a unique session key for the demo VM
    demo_session_key = f"demo:{user_id}:{course_id}:{secrets.token_hex(4)}"

    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            provision_response = await client.post(
                f"{ORCHESTRATOR_API}/api/provision",
                json={
                    "session_key": demo_session_key,
                    "user_id": user_id,
                    "user_email": user_email,
                    "user_name": f"{user_name} (Demo)",
                    "course_id": course_id,
                    "course_title": course_title,
                    "assignment_id": "instructor-demo",
                    "assignment_title": "Instructor Demo VM",
                    "session_hours": 2  # Demo VMs get 2 hours by default
                }
            )

            if provision_response.status_code != 200:
                error_detail = provision_response.text
                logger.error(f"Demo VM provisioning failed: {error_detail}")
                raise HTTPException(
                    status_code=503,
                    detail="Failed to provision demo VM. Please try again."
                )

            vm_data = provision_response.json()
            demo_session_id = vm_data.get('session_id')

            # Store the demo VM session ID in the instructor's token data
            if token and session_data:
                session_data['demo_vm_session_id'] = demo_session_id
                update_instructor_session(token, session_data)

            logger.info(f"Provisioned demo VM for {user_name}: {vm_data.get('url')}")

            return JSONResponse(content={
                "status": "active",
                "session_id": demo_session_id,
                "url": vm_data.get('url'),
                "vm_ip": vm_data.get('vm_ip'),
                "expires_at": vm_data.get('expires_at'),
                "created_at": vm_data.get('created_at')
            })

        except httpx.RequestError as e:
            logger.error(f"Error provisioning demo VM: {e}")
            raise HTTPException(
                status_code=503,
                detail="Lab service temporarily unavailable. Please try again."
            )


@app.post("/api/demo-vm/extend")
async def extend_demo_vm(request: Request):
    """Extend the instructor's demo VM session by 1 hour."""
    token = get_token_from_request(request)
    session_data = get_instructor_session(token)
    if not session_data or not session_data.get('instructor'):
        raise HTTPException(status_code=403, detail="Instructor access required")

    demo_session_id = session_data.get('demo_vm_session_id')
    if not demo_session_id:
        raise HTTPException(status_code=404, detail="No active demo VM found")

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.post(f"{ORCHESTRATOR_API}/api/{demo_session_id}/extend")

            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Failed to extend session")

            vm_data = response.json()
            return JSONResponse(content={
                "status": "extended",
                "expires_at": vm_data.get('expires_at')
            })

        except httpx.RequestError as e:
            logger.error(f"Error extending demo VM: {e}")
            raise HTTPException(status_code=503, detail="Failed to extend session")


@app.delete("/api/demo-vm")
async def destroy_demo_vm(request: Request):
    """Destroy the instructor's demo VM."""
    token = get_token_from_request(request)
    session_data = get_instructor_session(token)
    if not session_data or not session_data.get('instructor'):
        raise HTTPException(status_code=403, detail="Instructor access required")

    demo_session_id = session_data.get('demo_vm_session_id')
    if not demo_session_id:
        raise HTTPException(status_code=404, detail="No active demo VM found")

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.delete(f"{ORCHESTRATOR_API}/api/{demo_session_id}")

            # Clear the demo VM from token data regardless of result
            if token and session_data:
                session_data.pop('demo_vm_session_id', None)
                update_instructor_session(token, session_data)

            if response.status_code not in [200, 404]:
                logger.warning(f"Demo VM destruction returned status {response.status_code}")

            return JSONResponse(content={"status": "destroyed"})

        except httpx.RequestError as e:
            logger.error(f"Error destroying demo VM: {e}")
            # Clear from token anyway
            if token and session_data:
                session_data.pop('demo_vm_session_id', None)
                update_instructor_session(token, session_data)
            raise HTTPException(status_code=503, detail="Failed to destroy demo VM")


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
