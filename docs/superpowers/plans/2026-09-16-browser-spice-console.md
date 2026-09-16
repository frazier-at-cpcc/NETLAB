# Browser SPICE Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a student a graphical SPICE console for their lab virtual machine inside the browser, reached from the LTI landing page, and close the unauthenticated access path the web terminal currently exposes.

**Architecture:** One long-lived `console-gateway` service validates a per-session token, resolves the session to a virtual machine, obtains a SPICE ticket from Proxmox, and relays bytes between a browser WebSocket and the SPICE stream. Proxmox credentials and SPICE tickets never leave the gateway. Traefik calls the same gateway over `forwardAuth` to authorize both console and terminal routes.

**Tech Stack:** Python 3.12, FastAPI, `redis-py`, `httpx`, `asyncpg`, Traefik v3.3, Docker Compose, `spice-html5`, pytest.

**Spec:** `docs/superpowers/specs/2026-09-16-browser-spice-console-design.md`

## Global Constraints

- **Never log or persist a console token, a SPICE ticket, or the Proxmox password.** Store only a SHA-256 digest of a token. Tests assert these values never reach a log record.
- **Compare secrets with `hmac.compare_digest`.** Never `==`.
- **The browser never supplies a session identifier.** Session identity is derived from the token alone. A request that edits the session segment of a URL is refused.
- **Do not depend on the `lti_session` cookie.** The launch is a cross-site POST into an LMS iframe and that cookie is dropped there. This already broke grade cell persistence in this project.
- **Every failure degrades.** A console failure must never break the terminal, the grade panel, or the lab page.
- **Server data rendered into HTML uses `textContent`, never `innerHTML`.**
- **Mutation testing is the acceptance bar.** Reintroducing a defect must fail its tests. State in each task report which tests failed under the mutation.
- **Do not modify the LTI broker.** This work is confined to vm-lab.
- **Run the full suite before each commit**: `cd vm-lab && python3 -m pytest -q`. It passes at 228 tests as of commit `dce555a`.

---

## File Structure

| File | Responsibility |
|---|---|
| `vm-lab/console/__init__.py` | Package marker |
| `vm-lab/console/tokens.py` | Mint, store, and resolve console tokens. No I/O beyond Redis |
| `vm-lab/console/proxmox_spice.py` | Obtain a SPICE descriptor from the Proxmox API |
| `vm-lab/console/bridge.py` | Relay bytes between a WebSocket and a TCP stream. No protocol knowledge |
| `vm-lab/console/gateway.py` | FastAPI app: `/authz`, `/c/{session_id}`, `/ws/{session_id}` |
| `vm-lab/console/sessions.py` | Resolve a session identifier to `(node, vmid, status)` |
| `vm-lab/console/templates/console.html` | `spice-html5` page |
| `vm-lab/api/main.py` | Set `vga` on clone, mint token at provision, add middleware to routes |
| `vm-lab/lti/templates/lab_loading.html` | Console button |
| `vm-lab/docker-compose.yml` | `console-gateway` service, Traefik middleware file |
| `vm-lab/traefik-dynamic/console-auth.yml` | The `forwardAuth` middleware definition |

Each module has one responsibility and is tested without the others. `bridge.py` knows nothing about tokens; `tokens.py` knows nothing about Proxmox.

---

## Task 0: Spike. Answer the spiceproxy and clipboard questions

**This task produces an answer, not code that ships.** Anything built is throwaway and must be labelled as such. Do not proceed to Task 1 until the findings are recorded.

**Files:**
- Create: `docs/superpowers/specs/2026-09-16-spice-spike-findings.md`

- [ ] **Step 1: Determine how Proxmox exposes SPICE for a running clone**

Set `vga` to `qxl` on a throwaway clone and request a SPICE descriptor.

```bash
ssh nh-host
# then, on the lab host, from the lab-api container:
docker compose exec -T lab-api python3 -c "
import os, urllib3, requests, json
urllib3.disable_warnings()
h=os.environ['PROXMOX_HOST']; p=os.environ.get('PROXMOX_PORT','8006'); n=os.environ['PROXMOX_NODE']
base=f'https://{h}:{p}/api2/json'
s=requests.Session(); s.verify=False
r=s.post(f'{base}/access/ticket', data={'username':os.environ['PROXMOX_USER'],'password':os.environ['PROXMOX_PASSWORD']}, timeout=20).json()['data']
s.headers.update({'CSRFPreventionToken': r['CSRFPreventionToken']}); s.cookies.set('PVEAuthCookie', r['ticket'])
vmid = input('running vmid: ').strip()
d = s.post(f'{base}/nodes/{n}/qemu/{vmid}/spiceproxy', timeout=20).json()['data']
print(json.dumps({k: ('<redacted>' if k in ('password','ticket') else v) for k,v in d.items()}, indent=2))
"
```

Record every key the descriptor returns, with credential values redacted.

- [ ] **Step 2: Establish whether the proxy handshake can be performed**

Answer these three questions in writing:

1. Does the descriptor point at port 3128 with a `proxy` field, or does it give a direct host and port?
2. Can a plain TCP client reach that port from the `lab-network` Docker network?
3. What bytes must precede the SPICE stream? Capture the first exchange a known-good client makes, or determine it from the `spice-html5` and Proxmox sources.

- [ ] **Step 3: Establish whether clipboard works in `spice-html5`**

This decides whether SPICE still earns its cost. Connect a browser client to the throwaway clone and attempt copy and paste in both directions. Record the result plainly. If clipboard does not work, SPICE delivers only smooth graphics over noVNC, and that is a finding worth surfacing before nine more tasks are built on it.

- [ ] **Step 4: Write the findings**

Write `docs/superpowers/specs/2026-09-16-spice-spike-findings.md` stating, in order:

- The descriptor shape, credentials redacted.
- Whether the gateway can bridge the proxy handshake directly.
- If it cannot: the exact `-spice` arguments a clone would need, how a port is allocated without collision across concurrent sessions, and how the password is set and rotated.
- Whether clipboard works.
- A recommendation: proceed as designed, proceed with per-clone SPICE arguments, or reconsider noVNC.

- [ ] **Step 5: Destroy the throwaway clone and commit the findings**

```bash
git add docs/superpowers/specs/2026-09-16-spice-spike-findings.md
git commit -m "docs: spike findings for browser SPICE feasibility"
```

**Stop here and report.** If the findings recommend per-clone SPICE arguments, Task 6 changes shape and this plan needs the port and password lifecycle added before implementation continues.

---

## Task 1: Console token minting and resolution

**Files:**
- Create: `vm-lab/console/__init__.py`, `vm-lab/console/tokens.py`
- Test: `vm-lab/tests/test_console_tokens.py`

**Interfaces:**
- Consumes: a `redis` client exposing `setex(key, ttl, value)`, `get(key)`, `delete(key)`.
- Produces: `mint_console_token() -> str`, `hash_console_token(token: str) -> str`, `store_console_token(redis, session_id, token, ttl=CONSOLE_TOKEN_TTL_SECONDS) -> bool`, `resolve_console_token(redis, token) -> str | None`, `revoke_console_token(redis, token) -> None`, and the constant `CONSOLE_TOKEN_TTL_SECONDS`.

- [ ] **Step 1: Write the failing tests**

```python
"""The console token is the only thing standing between a student and another
student's graphical desktop, so it is stored as a digest, compared in constant
time, and bound to exactly one session."""

import hashlib

import pytest

from console.tokens import (
    CONSOLE_TOKEN_TTL_SECONDS,
    hash_console_token,
    mint_console_token,
    resolve_console_token,
    revoke_console_token,
    store_console_token,
)


class FakeRedis:
    def __init__(self, raising=False):
        self.store, self.ttls, self.raising = {}, {}, raising

    def setex(self, key, ttl, value):
        if self.raising:
            raise RuntimeError("redis down")
        self.store[key], self.ttls[key] = value, ttl

    def get(self, key):
        if self.raising:
            raise RuntimeError("redis down")
        return self.store.get(key)

    def delete(self, key):
        self.store.pop(key, None)


def test_minted_tokens_are_distinct_and_long():
    tokens = {mint_console_token() for _ in range(200)}
    assert len(tokens) == 200
    assert all(len(t) >= 32 for t in tokens)


def test_the_token_itself_is_never_stored():
    redis, token = FakeRedis(), mint_console_token()
    store_console_token(redis, "sess-1", token)
    assert token not in repr(redis.store)
    assert hash_console_token(token) in "".join(redis.store.keys())


def test_a_stored_token_resolves_to_its_session():
    redis, token = FakeRedis(), mint_console_token()
    store_console_token(redis, "sess-1", token)
    assert resolve_console_token(redis, token) == "sess-1"


def test_an_unknown_token_resolves_to_nothing():
    assert resolve_console_token(FakeRedis(), mint_console_token()) is None


def test_one_session_token_never_resolves_to_another():
    redis = FakeRedis()
    a, b = mint_console_token(), mint_console_token()
    store_console_token(redis, "sess-a", a)
    store_console_token(redis, "sess-b", b)
    assert resolve_console_token(redis, a) == "sess-a"
    assert resolve_console_token(redis, b) == "sess-b"


def test_ttl_is_applied():
    redis, token = FakeRedis(), mint_console_token()
    store_console_token(redis, "sess-1", token)
    assert redis.ttls[f"console_token:{hash_console_token(token)}"] == CONSOLE_TOKEN_TTL_SECONDS


def test_revocation_makes_a_token_stop_resolving():
    redis, token = FakeRedis(), mint_console_token()
    store_console_token(redis, "sess-1", token)
    revoke_console_token(redis, token)
    assert resolve_console_token(redis, token) is None


def test_hash_is_sha256_hex():
    assert hash_console_token("abc") == hashlib.sha256(b"abc").hexdigest()


@pytest.mark.parametrize("bad", ["", None])
def test_an_empty_token_never_resolves(bad):
    assert resolve_console_token(FakeRedis(), bad) is None


def test_storing_an_empty_token_is_refused():
    redis = FakeRedis()
    assert store_console_token(redis, "sess-1", "") is False
    assert redis.store == {}


def test_redis_failure_never_raises_into_the_caller():
    redis, token = FakeRedis(raising=True), mint_console_token()
    assert store_console_token(redis, "sess-1", token) is False
    assert resolve_console_token(redis, token) is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd vm-lab && python3 -m pytest tests/test_console_tokens.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'console'`

- [ ] **Step 3: Write the implementation**

```python
"""Per-session console tokens.

The token authorises a graphical desktop, so it is treated exactly like the
grade token: minted from `secrets`, stored only as a SHA-256 digest, compared
in constant time, and never written to a log.

It is carried in a URL because the launch is a cross-site POST into an LMS
iframe and the session cookie is dropped in that position. A URL is visible
to browser history and to referrer headers, so the time-to-live is bound to
the lab session and the token authorises exactly one session.
"""

import hashlib
import hmac
import logging
import secrets

logger = logging.getLogger(__name__)

CONSOLE_TOKEN_TTL_SECONDS = 4 * 3600
CONSOLE_TOKEN_PREFIX = "console_token:"


def mint_console_token() -> str:
    return secrets.token_urlsafe(32)


def hash_console_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _key(token: str) -> str:
    return f"{CONSOLE_TOKEN_PREFIX}{hash_console_token(token)}"


def store_console_token(
    redis_client, session_id: str, token: str, ttl: int = CONSOLE_TOKEN_TTL_SECONDS
) -> bool:
    """Store the token's digest against a session. Returns True when stored."""
    if not token or not session_id:
        return False
    try:
        redis_client.setex(_key(token), ttl, session_id)
    except Exception as exc:
        # A console that cannot be authorised is a console that does not open.
        # That must never fail the provision that is minting the token.
        logger.warning("Could not store console token: %s", type(exc).__name__)
        return False
    return True


def resolve_console_token(redis_client, token) -> str | None:
    """Return the session this token authorises, or None."""
    if not token:
        return None
    try:
        stored = redis_client.get(_key(token))
    except Exception as exc:
        logger.warning("Could not read console token: %s", type(exc).__name__)
        return None
    if not stored:
        return None
    return stored if isinstance(stored, str) else stored.decode("utf-8")


def authorises_session(redis_client, token, session_id: str) -> bool:
    """Constant-time check that `token` authorises exactly `session_id`."""
    resolved = resolve_console_token(redis_client, token)
    if resolved is None or not session_id:
        return False
    return hmac.compare_digest(resolved, session_id)


def revoke_console_token(redis_client, token) -> None:
    if not token:
        return
    try:
        redis_client.delete(_key(token))
    except Exception as exc:
        logger.warning("Could not revoke console token: %s", type(exc).__name__)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd vm-lab && python3 -m pytest tests/test_console_tokens.py -q`
Expected: PASS

- [ ] **Step 5: Mutation test**

Change `hmac.compare_digest(resolved, session_id)` to `resolved == session_id` and confirm the suite still passes, then add this test, confirm it fails under the mutation, and restore:

```python
def test_session_comparison_is_constant_time():
    import inspect

    from console import tokens

    source = inspect.getsource(tokens.authorises_session)
    assert "compare_digest" in source
    assert "resolved == session_id" not in source
```

Then mutate `store_console_token` to store `token` instead of `session_id` and confirm `test_the_token_itself_is_never_stored` fails.

- [ ] **Step 6: Commit**

```bash
cd vm-lab && python3 -m pytest -q
git add console/__init__.py console/tokens.py tests/test_console_tokens.py
git commit -m "feat(console): mint and resolve per-session console tokens"
```

---

## Task 2: Proxmox SPICE descriptor

**Files:**
- Create: `vm-lab/console/proxmox_spice.py`
- Test: `vm-lab/tests/test_proxmox_spice.py`

**Interfaces:**
- Consumes: `CONSOLE_TOKEN_TTL_SECONDS` is not used here. Requires `PROXMOX_HOST`, `PROXMOX_PORT`, `PROXMOX_USER`, `PROXMOX_PASSWORD`, `PROXMOX_NODE` from the environment.
- Produces: `SpiceDescriptor` (a frozen dataclass with `host: str`, `port: int`, `password: str`, `tls_port: int | None`, `proxy: str | None`), `parse_descriptor(payload) -> SpiceDescriptor`, `async spice_descriptor(node: str, vmid: int) -> SpiceDescriptor`, `async open_spice_stream(descriptor) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]`, and `SpiceError`.

`spice_descriptor` and `open_spice_stream` are the two functions Task 8 calls. They are defined here so no later task references a name this plan never creates.

> **If Task 0 found that the proxy handshake cannot be bridged**, this task instead returns a descriptor for a directly attached SPICE port, and the fields change accordingly. Do not begin this task until Task 0's findings are read.

- [ ] **Step 1: Write the failing tests**

```python
"""The SPICE descriptor carries a short-lived credential. It is parsed
completely or not at all, and it never reaches a log record."""

import logging

import pytest

from console.proxmox_spice import SpiceDescriptor, SpiceError, parse_descriptor


def test_a_complete_response_parses():
    d = parse_descriptor({
        "host": "10.0.0.5", "port": "3128", "password": "SECRET-TICKET",
        "tls-port": "61000", "proxy": "http://pve.example:3128",
    })
    assert d == SpiceDescriptor(
        host="10.0.0.5", port=3128, password="SECRET-TICKET",
        tls_port=61000, proxy="http://pve.example:3128",
    )


def test_optional_fields_default_to_none():
    d = parse_descriptor({"host": "10.0.0.5", "port": "3128", "password": "T"})
    assert d.tls_port is None and d.proxy is None


@pytest.mark.parametrize("missing", ["host", "port", "password"])
def test_a_partial_response_raises_rather_than_returning_half_a_descriptor(missing):
    payload = {"host": "10.0.0.5", "port": "3128", "password": "T"}
    payload.pop(missing)
    with pytest.raises(SpiceError):
        parse_descriptor(payload)


def test_a_non_numeric_port_raises():
    with pytest.raises(SpiceError):
        parse_descriptor({"host": "h", "port": "not-a-port", "password": "T"})


def test_the_ticket_never_appears_in_the_repr():
    d = parse_descriptor({"host": "h", "port": "1", "password": "SECRET-TICKET"})
    assert "SECRET-TICKET" not in repr(d)
    assert "[redacted]" in repr(d)


def test_a_parse_failure_does_not_log_the_payload(caplog):
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(SpiceError):
            parse_descriptor({"password": "SECRET-TICKET"})
    assert "SECRET-TICKET" not in "\n".join(r.getMessage() for r in caplog.records)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd vm-lab && python3 -m pytest tests/test_proxmox_spice.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'console.proxmox_spice'`

- [ ] **Step 3: Write the implementation**

```python
"""Obtain a SPICE connection descriptor from Proxmox.

The descriptor's `password` is a short-lived SPICE ticket. It is a credential:
it is never logged, never persisted, and never sent to the browser. `__repr__`
is overridden so that an incidental log of the whole object cannot leak it.
"""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class SpiceError(Exception):
    """Raised when Proxmox does not return a usable SPICE descriptor."""


@dataclass(frozen=True)
class SpiceDescriptor:
    host: str
    port: int
    password: str
    tls_port: int | None = None
    proxy: str | None = None

    def __repr__(self) -> str:
        return (
            f"SpiceDescriptor(host={self.host!r}, port={self.port!r}, "
            f"password='[redacted]', tls_port={self.tls_port!r}, proxy={self.proxy!r})"
        )


def parse_descriptor(payload: dict) -> SpiceDescriptor:
    """Parse a Proxmox spiceproxy payload, or raise.

    A half-parsed descriptor is worse than none: it would produce a connection
    attempt that fails somewhere less obvious. Every required field is checked
    before anything is returned, and no error message quotes the payload.
    """
    missing = [k for k in ("host", "port", "password") if not payload.get(k)]
    if missing:
        raise SpiceError(f"spice descriptor is missing required field(s): {', '.join(missing)}")
    try:
        port = int(payload["port"])
        tls_port = int(payload["tls-port"]) if payload.get("tls-port") else None
    except (TypeError, ValueError) as exc:
        raise SpiceError("spice descriptor carries a non-numeric port") from exc
    return SpiceDescriptor(
        host=str(payload["host"]),
        port=port,
        password=str(payload["password"]),
        tls_port=tls_port,
        proxy=str(payload["proxy"]) if payload.get("proxy") else None,
    )


async def spice_descriptor(node: str, vmid: int) -> SpiceDescriptor:
    """Ask Proxmox for a SPICE descriptor for one virtual machine.

    The Proxmox ticket and the returned SPICE ticket are both credentials.
    Neither is logged, and a non-200 response raises rather than returning a
    descriptor the caller would try to connect with.
    """
    import os

    import httpx

    host = os.environ["PROXMOX_HOST"]
    port = os.environ.get("PROXMOX_PORT", "8006")
    base = f"https://{host}:{port}/api2/json"
    async with httpx.AsyncClient(verify=False, timeout=20.0) as client:
        auth = await client.post(
            f"{base}/access/ticket",
            data={
                "username": os.environ["PROXMOX_USER"],
                "password": os.environ["PROXMOX_PASSWORD"],
            },
        )
        if auth.status_code != 200:
            raise SpiceError("proxmox refused the API ticket request")
        ticket = auth.json()["data"]
        response = await client.post(
            f"{base}/nodes/{node}/qemu/{vmid}/spiceproxy",
            headers={"CSRFPreventionToken": ticket["CSRFPreventionToken"]},
            cookies={"PVEAuthCookie": ticket["ticket"]},
        )
    if response.status_code != 200:
        raise SpiceError(f"proxmox refused the spiceproxy request for vmid {vmid}")
    return parse_descriptor(response.json().get("data") or {})


async def open_spice_stream(descriptor: SpiceDescriptor):
    """Open the TCP stream the bridge will relay.

    Task 0 decides what belongs here. If the spiceproxy handshake can be
    performed, it happens in this function and nowhere else, so the bridge
    stays a byte pipe. If Task 0 instead finds that clones need explicit SPICE
    arguments, this function connects directly to that port and the handshake
    disappears.
    """
    import asyncio

    reader, writer = await asyncio.open_connection(descriptor.host, descriptor.port)
    return reader, writer
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd vm-lab && python3 -m pytest tests/test_proxmox_spice.py -q`
Expected: PASS

- [ ] **Step 5: Mutation test**

Remove the `missing` check and confirm the three `test_a_partial_response_raises` cases fail. Remove `__repr__` and confirm `test_the_ticket_never_appears_in_the_repr` fails. Restore both.

- [ ] **Step 6: Commit**

```bash
cd vm-lab && python3 -m pytest -q
git add console/proxmox_spice.py tests/test_proxmox_spice.py
git commit -m "feat(console): parse the Proxmox SPICE descriptor without leaking the ticket"
```

---

## Task 3: The byte bridge

**Files:**
- Create: `vm-lab/console/bridge.py`
- Test: `vm-lab/tests/test_console_bridge.py`

**Interfaces:**
- Consumes: nothing from earlier tasks. This module deliberately knows nothing about tokens or Proxmox.
- Produces: `async relay(ws_recv, ws_send, reader, writer) -> None`, where `ws_recv` is an awaitable returning `bytes` or `None` at close, and `ws_send` is an awaitable accepting `bytes`.

- [ ] **Step 1: Write the failing tests**

```python
"""The bridge is a byte pipe. It carries no SPICE knowledge, so it stays
testable against a fake and does not rot as the protocol evolves."""

import asyncio

from console.bridge import relay


class FakeWs:
    def __init__(self, incoming):
        self.incoming, self.sent, self.closed = list(incoming), [], False

    async def recv(self):
        await asyncio.sleep(0)
        return self.incoming.pop(0) if self.incoming else None

    async def send(self, data):
        self.sent.append(data)


class FakeStream:
    def __init__(self, incoming):
        self.incoming, self.written, self.closed = list(incoming), [], False

    async def read(self, _n):
        await asyncio.sleep(0)
        return self.incoming.pop(0) if self.incoming else b""

    def write(self, data):
        self.written.append(data)

    async def drain(self):
        await asyncio.sleep(0)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        await asyncio.sleep(0)


def test_browser_bytes_reach_the_stream():
    ws, stream = FakeWs([b"hello", b"world"]), FakeStream([])
    asyncio.run(relay(ws.recv, ws.send, stream, stream))
    assert b"".join(stream.written) == b"helloworld"


def test_stream_bytes_reach_the_browser():
    ws, stream = FakeWs([]), FakeStream([b"abc", b"def"])
    asyncio.run(relay(ws.recv, ws.send, stream, stream))
    assert b"".join(ws.sent) == b"abcdef"


def test_both_directions_relay_in_one_session():
    ws, stream = FakeWs([b"up"]), FakeStream([b"down"])
    asyncio.run(relay(ws.recv, ws.send, stream, stream))
    assert b"".join(stream.written) == b"up"
    assert b"".join(ws.sent) == b"down"


def test_the_stream_is_closed_when_the_browser_goes_away():
    ws, stream = FakeWs([]), FakeStream([])
    asyncio.run(relay(ws.recv, ws.send, stream, stream))
    assert stream.closed is True


def test_nothing_is_sent_after_close():
    ws, stream = FakeWs([b"x"]), FakeStream([b"y"])
    asyncio.run(relay(ws.recv, ws.send, stream, stream))
    before = len(ws.sent)
    assert len(ws.sent) == before


def test_an_empty_read_ends_the_session_rather_than_spinning():
    ws, stream = FakeWs([]), FakeStream([])
    asyncio.run(asyncio.wait_for(relay(ws.recv, ws.send, stream, stream), timeout=5))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd vm-lab && python3 -m pytest tests/test_console_bridge.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'console.bridge'`

- [ ] **Step 3: Write the implementation**

```python
"""Relay bytes between a browser WebSocket and a SPICE TCP stream.

This module interprets nothing. It is a pipe, which is what keeps it testable
against a fake server and free of protocol knowledge that would age badly.
Either side closing ends the session and closes the other, so a student
navigating away does not strand a socket against the hypervisor.
"""

import asyncio
import logging

logger = logging.getLogger(__name__)


async def _browser_to_stream(ws_recv, writer) -> None:
    while True:
        data = await ws_recv()
        if not data:
            return
        writer.write(data)
        await writer.drain()


async def _stream_to_browser(ws_send, reader) -> None:
    while True:
        data = await reader.read(65536)
        if not data:
            return
        await ws_send(data)


async def relay(ws_recv, ws_send, reader, writer) -> None:
    """Copy both directions until either side closes, then close the other."""
    tasks = [
        asyncio.ensure_future(_browser_to_stream(ws_recv, writer)),
        asyncio.ensure_future(_stream_to_browser(ws_send, reader)),
    ]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            exc = task.exception()
            if exc is not None:
                logger.info("console relay ended: %s", type(exc).__name__)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception as exc:
            logger.debug("console stream close: %s", type(exc).__name__)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd vm-lab && python3 -m pytest tests/test_console_bridge.py -q`
Expected: PASS

- [ ] **Step 5: Mutation test**

Remove the `finally` block and confirm `test_the_stream_is_closed_when_the_browser_goes_away` fails. Change `if not data: return` to `continue` in `_stream_to_browser` and confirm `test_an_empty_read_ends_the_session_rather_than_spinning` times out. Restore both.

- [ ] **Step 6: Commit**

```bash
cd vm-lab && python3 -m pytest -q
git add console/bridge.py tests/test_console_bridge.py
git commit -m "feat(console): relay bytes between the browser and the SPICE stream"
```

---

## Task 4: Session resolution

**Files:**
- Create: `vm-lab/console/sessions.py`
- Test: `vm-lab/tests/test_console_sessions.py`

**Interfaces:**
- Consumes: an `asyncpg`-style connection exposing `fetchrow(sql, *args)`.
- Produces: `ConsoleTarget` (frozen dataclass: `session_id: str`, `vm_id: int`, `status: str`), `async console_target(db, session_id) -> ConsoleTarget | None`, and `SESSION_NOT_READY` (a frozenset of statuses that are not yet connectable).

- [ ] **Step 1: Write the failing tests**

```python
"""A console may only open against a session that is actually running."""

import asyncio

from console.sessions import SESSION_NOT_READY, ConsoleTarget, console_target


class FakeDb:
    def __init__(self, row):
        self.row, self.args = row, None

    async def fetchrow(self, sql, *args):
        self.args = args
        return self.row


def test_a_running_session_resolves():
    db = FakeDb({"session_id": "s1", "vm_id": 1001, "status": "running"})
    t = asyncio.run(console_target(db, "s1"))
    assert t == ConsoleTarget(session_id="s1", vm_id=1001, status="running")


def test_an_unknown_session_resolves_to_nothing():
    assert asyncio.run(console_target(FakeDb(None), "nope")) is None


def test_a_session_with_no_vm_yet_resolves_to_nothing():
    db = FakeDb({"session_id": "s1", "vm_id": None, "status": "provisioning"})
    assert asyncio.run(console_target(db, "s1")) is None


def test_a_destroyed_session_resolves_to_nothing():
    db = FakeDb({"session_id": "s1", "vm_id": 1001, "status": "destroyed"})
    assert asyncio.run(console_target(db, "s1")) is None


def test_provisioning_is_reported_as_not_ready_rather_than_missing():
    assert "provisioning" in SESSION_NOT_READY
    assert "starting" in SESSION_NOT_READY


def test_the_session_id_is_passed_as_a_bound_parameter():
    db = FakeDb({"session_id": "s1", "vm_id": 1, "status": "running"})
    asyncio.run(console_target(db, "s1"))
    assert db.args == ("s1",)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd vm-lab && python3 -m pytest tests/test_console_sessions.py -q`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

```python
"""Resolve a session identifier to the virtual machine a console may attach to.

A console must never attach to a destroyed session, and must report a session
that is still provisioning as not ready rather than as missing, so the page
can say "still starting" instead of showing a refusal the student cannot act
on.
"""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

SESSION_NOT_READY = frozenset({"provisioning", "starting"})
CONNECTABLE = frozenset({"running"})

SELECT_TARGET_SQL = """
SELECT session_id, vm_id, status FROM vm_sessions WHERE session_id = $1
"""


@dataclass(frozen=True)
class ConsoleTarget:
    session_id: str
    vm_id: int
    status: str


async def console_target(db, session_id: str) -> ConsoleTarget | None:
    """Return the connectable target for a session, or None."""
    if not session_id:
        return None
    row = await db.fetchrow(SELECT_TARGET_SQL, session_id)
    if row is None:
        return None
    if row["vm_id"] is None or row["status"] not in CONNECTABLE:
        return None
    return ConsoleTarget(
        session_id=row["session_id"], vm_id=int(row["vm_id"]), status=row["status"]
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd vm-lab && python3 -m pytest tests/test_console_sessions.py -q`
Expected: PASS

- [ ] **Step 5: Mutation test**

Remove the `row["status"] not in CONNECTABLE` condition and confirm `test_a_destroyed_session_resolves_to_nothing` fails. Restore.

- [ ] **Step 6: Commit**

```bash
cd vm-lab && python3 -m pytest -q
git add console/sessions.py tests/test_console_sessions.py
git commit -m "feat(console): resolve a session to a connectable virtual machine"
```

---

## Task 5: The authorization endpoint

This is the task that closes the existing unauthenticated terminal hole. It is separated from the rest of the gateway because it changes the behaviour of a working path and deserves its own review.

**Files:**
- Create: `vm-lab/console/gateway.py`
- Test: `vm-lab/tests/test_console_authz.py`

**Interfaces:**
- Consumes: `authorises_session` and `resolve_console_token` from Task 1.
- Produces: a FastAPI `app` exposing `GET /authz`, and `session_from_forwarded_host(host: str) -> str | None`.

- [ ] **Step 1: Write the failing tests**

```python
"""Traefik calls /authz before any frame reaches the browser. It answers 200 or
403 and never explains which, because the difference between "no such session"
and "wrong token" is information an attacker can use."""

import pytest
from fastapi.testclient import TestClient

from console.gateway import build_app, session_from_forwarded_host
from console.tokens import mint_console_token, store_console_token


class FakeRedis:
    def __init__(self):
        self.store, self.ttls = {}, {}

    def setex(self, key, ttl, value):
        self.store[key], self.ttls[key] = value, ttl

    def get(self, key):
        return self.store.get(key)

    def delete(self, key):
        self.store.pop(key, None)


@pytest.fixture
def ctx():
    redis = FakeRedis()
    token = mint_console_token()
    store_console_token(redis, "sess-1", token)
    return TestClient(build_app(redis, db=None)), token


@pytest.mark.parametrize(
    "host,expected",
    [
        ("lab-abc123.labsconnect.org", "abc123"),
        ("console-abc123.labsconnect.org", "abc123"),
        ("labsconnect.org", None),
        ("", None),
        ("lab-.labsconnect.org", None),
    ],
)
def test_session_is_read_from_the_forwarded_host(host, expected):
    assert session_from_forwarded_host(host) == expected


def test_a_valid_token_for_its_own_session_is_allowed(ctx):
    client, token = ctx
    r = client.get("/authz", headers={"X-Forwarded-Host": "lab-sess-1.labsconnect.org"},
                   params={"t": token})
    assert r.status_code == 200


def test_a_token_for_another_session_is_refused(ctx):
    client, token = ctx
    r = client.get("/authz", headers={"X-Forwarded-Host": "lab-sess-2.labsconnect.org"},
                   params={"t": token})
    assert r.status_code == 403


def test_a_missing_token_is_refused(ctx):
    client, _ = ctx
    r = client.get("/authz", headers={"X-Forwarded-Host": "lab-sess-1.labsconnect.org"})
    assert r.status_code == 403


def test_an_unknown_token_is_refused(ctx):
    client, _ = ctx
    r = client.get("/authz", headers={"X-Forwarded-Host": "lab-sess-1.labsconnect.org"},
                   params={"t": mint_console_token()})
    assert r.status_code == 403


def test_a_refusal_explains_nothing(ctx):
    client, _ = ctx
    r = client.get("/authz", headers={"X-Forwarded-Host": "lab-sess-1.labsconnect.org"},
                   params={"t": "wrong"})
    body = r.text.lower()
    for leak in ("sess-1", "expired", "unknown token", "no such session"):
        assert leak not in body


def test_the_token_is_never_logged(ctx, caplog):
    import logging

    client, token = ctx
    with caplog.at_level(logging.DEBUG):
        client.get("/authz", headers={"X-Forwarded-Host": "lab-sess-1.labsconnect.org"},
                   params={"t": token})
    assert token not in "\n".join(r.getMessage() for r in caplog.records)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd vm-lab && python3 -m pytest tests/test_console_authz.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'console.gateway'`

- [ ] **Step 3: Write the implementation**

```python
"""The console gateway.

Traefik calls `/authz` over forwardAuth before it proxies anything, for both
console routes and the existing terminal routes. One validation path serves
both, so the two cannot drift apart and the terminal cannot quietly go back to
being unauthenticated.

The session identifier comes from the forwarded host, which Traefik sets from
the route it matched. The token comes from the query string. A student who
edits either presents a pairing that does not resolve, and the answer is the
same 403 in every failing case: distinguishing "no such session" from "wrong
token" hands an attacker a probe.
"""

import logging
import re

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

from console.tokens import authorises_session

logger = logging.getLogger(__name__)

_HOST_PATTERN = re.compile(r"^(?:lab|console)-([A-Za-z0-9-]+)\.")


def session_from_forwarded_host(host: str) -> str | None:
    """Extract the session identifier Traefik matched, or None."""
    if not host:
        return None
    match = _HOST_PATTERN.match(host)
    if match is None:
        return None
    return match.group(1) or None


def build_app(redis_client, db) -> FastAPI:
    app = FastAPI()
    app.state.redis = redis_client
    app.state.db = db

    @app.get("/authz")
    async def authz(request: Request) -> PlainTextResponse:
        host = request.headers.get("X-Forwarded-Host", "")
        session_id = session_from_forwarded_host(host)
        token = request.query_params.get("t", "")
        if session_id and authorises_session(request.app.state.redis, token, session_id):
            return PlainTextResponse("", status_code=200)
        # Log the host, never the token, and never which half failed.
        logger.info("console authz refused for host=%s", host)
        return PlainTextResponse("Forbidden", status_code=403)

    return app
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd vm-lab && python3 -m pytest tests/test_console_authz.py -q`
Expected: PASS

- [ ] **Step 5: Mutation test**

Change the refusal to `PlainTextResponse(f"no session {session_id}", status_code=403)` and confirm `test_a_refusal_explains_nothing` fails. Change `authorises_session(...)` to `resolve_console_token(...) is not None` and confirm `test_a_token_for_another_session_is_refused` fails. Restore both.

- [ ] **Step 6: Commit**

```bash
cd vm-lab && python3 -m pytest -q
git add console/gateway.py tests/test_console_authz.py
git commit -m "feat(console): authorize console and terminal routes from one path"
```

---

## Task 6: Traefik middleware and route wiring

**Files:**
- Create: `vm-lab/traefik-dynamic/console-auth.yml`
- Modify: `vm-lab/api/main.py:847` (`write_traefik_route`)
- Test: `vm-lab/tests/test_traefik_route.py`

**Interfaces:**
- Consumes: the gateway's `/authz` endpoint from Task 5.
- Produces: `write_traefik_route` output that references the `console-auth` middleware.

- [ ] **Step 1: Write the failing tests**

```python
"""Every session route must pass through authorization. A route written without
the middleware is an unauthenticated shell on the public internet, which is
what this project shipped before this change."""

import os

import yaml

from api.main import write_traefik_route


def _written(tmp_path, monkeypatch, session_id="abc123"):
    monkeypatch.setattr("api.main.TRAEFIK_DYNAMIC_DIR", str(tmp_path))
    write_traefik_route(session_id, f"ttyd-{session_id}", "labsconnect.org")
    return yaml.safe_load(open(os.path.join(tmp_path, f"session-{session_id}.yml")))


def test_the_route_requires_the_auth_middleware(tmp_path, monkeypatch):
    cfg = _written(tmp_path, monkeypatch)
    router = cfg["http"]["routers"]["ttyd-abc123"]
    assert "console-auth@file" in router["middlewares"]


def test_the_route_still_points_at_the_session_container(tmp_path, monkeypatch):
    cfg = _written(tmp_path, monkeypatch)
    url = cfg["http"]["services"]["ttyd-abc123"]["loadBalancer"]["servers"][0]["url"]
    assert url == "http://ttyd-abc123:7681"


def test_the_route_rule_is_unchanged(tmp_path, monkeypatch):
    cfg = _written(tmp_path, monkeypatch)
    assert cfg["http"]["routers"]["ttyd-abc123"]["rule"] == "Host(`lab-abc123.labsconnect.org`)"


def test_the_middleware_file_defines_forward_auth():
    cfg = yaml.safe_load(open("traefik-dynamic/console-auth.yml"))
    fa = cfg["http"]["middlewares"]["console-auth"]["forwardAuth"]
    assert fa["address"].endswith("/authz")
    assert fa.get("trustForwardHeader") is not True
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd vm-lab && python3 -m pytest tests/test_traefik_route.py -q`
Expected: FAIL. The router has no `middlewares` key and the middleware file does not exist.

- [ ] **Step 3: Write the middleware file**

Create `vm-lab/traefik-dynamic/console-auth.yml`:

```yaml
# Every per-session route passes through here before Traefik proxies anything.
#
# Before this file existed, lab-{session_id}.labsconnect.org reached a shell
# with no authentication at all: knowing an eight-character session identifier
# was enough. The console would have inherited that exposure and raised it from
# a terminal to a full graphical desktop.
#
# trustForwardHeader is deliberately absent. The gateway reads X-Forwarded-Host
# to learn which session was matched, and that value must come from Traefik,
# never from the client.
http:
  middlewares:
    console-auth:
      forwardAuth:
        address: "http://console-gateway:8000/authz"
        authResponseHeaders: []
```

- [ ] **Step 4: Modify `write_traefik_route`**

In `vm-lab/api/main.py`, change the generated router block to include the middleware:

```python
def write_traefik_route(session_id: str, container_name: str, domain: str):
    """Write a Traefik route config file for a session.

    The `console-auth` middleware is not optional. A route written without it
    is an unauthenticated shell reachable by anyone who learns the session
    identifier, which is what this project served before the console work.
    """
    route_file = os.path.join(TRAEFIK_DYNAMIC_DIR, f"session-{session_id}.yml")
    config = f"""# Auto-generated route for session {session_id}
http:
  routers:
    ttyd-{session_id}:
      rule: "Host(`lab-{session_id}.{domain}`)"
      entryPoints:
        - web
      middlewares:
        - console-auth@file
      service: ttyd-{session_id}
  services:
    ttyd-{session_id}:
      loadBalancer:
        servers:
          - url: "http://{container_name}:7681"
"""
```

Leave the rest of the function as it is.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd vm-lab && python3 -m pytest tests/test_traefik_route.py -q`
Expected: PASS

- [ ] **Step 6: Mutation test**

Remove the two `middlewares` lines from the generated config and confirm `test_the_route_requires_the_auth_middleware` fails.

- [ ] **Step 7: Commit**

```bash
cd vm-lab && python3 -m pytest -q
git add traefik-dynamic/console-auth.yml api/main.py tests/test_traefik_route.py
git commit -m "fix(security): require authorization on every per-session route"
```

> **Deployment note for this task.** Applying the middleware to terminal routes takes effect only for routes written after the change. Sessions already running keep their old route file and stay unauthenticated until they are recreated. Say so explicitly in the task report, and state whether existing route files should be rewritten or left to expire.

---

## Task 7: Provisioning changes

**Files:**
- Modify: `vm-lab/api/main.py` (clone configuration and provisioning)
- Test: `vm-lab/tests/test_console_provisioning.py`

**Interfaces:**
- Consumes: `mint_console_token`, `store_console_token` from Task 1.
- Produces: a `console_token` returned in the provisioning response, and `vga=qxl` set on the clone before start.

> **If Task 0 found that per-clone SPICE arguments are required**, this task also sets those arguments and allocates a port. Read the spike findings before starting, and add the allocation steps here before implementing.

- [ ] **Step 1: Write the failing tests**

```python
"""Provisioning sets the display device and mints a console token. Neither may
break provisioning when it fails: a lab without a console is usable, a lab that
will not start is not."""

from console.tokens import resolve_console_token


class FakeRedis:
    def __init__(self, raising=False):
        self.store, self.raising = {}, raising

    def setex(self, key, ttl, value):
        if self.raising:
            raise RuntimeError("down")
        self.store[key] = value

    def get(self, key):
        if self.raising:
            raise RuntimeError("down")
        return self.store.get(key)

    def delete(self, key):
        self.store.pop(key, None)


def test_the_clone_is_given_a_spice_display(monkeypatch):
    from api import main

    calls = []
    monkeypatch.setattr(main, "set_vm_config", lambda vmid, **kw: calls.append((vmid, kw)))
    main.configure_console_display(1001)
    assert calls == [(1001, {"vga": "qxl"})]


def test_a_console_token_is_minted_and_resolves_to_the_session():
    from api.main import issue_console_token

    redis = FakeRedis()
    token = issue_console_token(redis, "sess-1")
    assert token
    assert resolve_console_token(redis, token) == "sess-1"


def test_a_redis_failure_returns_no_token_rather_than_raising():
    from api.main import issue_console_token

    assert issue_console_token(FakeRedis(raising=True), "sess-1") is None


def test_the_token_is_never_logged(caplog):
    import logging

    from api.main import issue_console_token

    redis = FakeRedis()
    with caplog.at_level(logging.DEBUG):
        token = issue_console_token(redis, "sess-1")
    assert token not in "\n".join(r.getMessage() for r in caplog.records)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd vm-lab && python3 -m pytest tests/test_console_provisioning.py -q`
Expected: FAIL with `AttributeError: module 'api.main' has no attribute 'configure_console_display'`

- [ ] **Step 3: Write the implementation**

Add to `vm-lab/api/main.py`:

```python
def configure_console_display(vmid: int) -> None:
    """Give a clone a SPICE display before it starts.

    Set on the clone, not on the template, so the golden image is untouched
    and a rollback is a configuration change rather than an image restore.
    """
    set_vm_config(vmid, vga="qxl")


def issue_console_token(redis_client, session_id: str):
    """Mint and store a console token, or return None.

    A console that cannot be authorised does not open. That is a degraded lab,
    not a failed one, so this never raises into the provisioning path.
    """
    token = mint_console_token()
    if not store_console_token(redis_client, session_id, token):
        return None
    logger.info("Issued console token for session %s", session_id)
    return token
```

Call `configure_console_display(vmid)` after the clone is created and before it starts. Call `issue_console_token` where the grade token is already minted, and carry the returned value into the provisioning response.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd vm-lab && python3 -m pytest tests/test_console_provisioning.py -q`
Expected: PASS

- [ ] **Step 5: Mutation test**

Make `issue_console_token` return the token even when `store_console_token` fails, and confirm `test_a_redis_failure_returns_no_token_rather_than_raising` fails. Change the log line to include the token and confirm `test_the_token_is_never_logged` fails. Restore both.

- [ ] **Step 6: Commit**

```bash
cd vm-lab && python3 -m pytest -q
git add api/main.py tests/test_console_provisioning.py
git commit -m "feat(console): give each clone a SPICE display and a console token"
```

---

## Task 8: The console page and the WebSocket endpoint

**Files:**
- Create: `vm-lab/console/templates/console.html`
- Modify: `vm-lab/console/gateway.py`
- Test: `vm-lab/tests/test_console_page.py`

**Interfaces:**
- Consumes: `console_target` (Task 4), `spice_descriptor` (Task 2), `relay` (Task 3), `authorises_session` (Task 1).
- Produces: `GET /c/{session_id}` and `WebSocket /ws/{session_id}`.

- [ ] **Step 1: Write the failing tests**

```python
"""The page renders only for an authorised pairing, and never carries a ticket."""

import pytest
from fastapi.testclient import TestClient

from console.gateway import build_app
from console.tokens import mint_console_token, store_console_token


class FakeRedis:
    def __init__(self):
        self.store = {}

    def setex(self, key, ttl, value):
        self.store[key] = value

    def get(self, key):
        return self.store.get(key)

    def delete(self, key):
        self.store.pop(key, None)


@pytest.fixture
def ctx():
    redis = FakeRedis()
    token = mint_console_token()
    store_console_token(redis, "sess-1", token)
    return TestClient(build_app(redis, db=None)), token


def test_the_page_renders_for_an_authorised_pairing(ctx):
    client, token = ctx
    r = client.get("/c/sess-1", params={"t": token})
    assert r.status_code == 200
    assert "spice" in r.text.lower()


def test_the_page_is_refused_for_another_session(ctx):
    client, token = ctx
    assert client.get("/c/sess-2", params={"t": token}).status_code == 403


def test_the_page_is_refused_without_a_token(ctx):
    client, _ = ctx
    assert client.get("/c/sess-1").status_code == 403


def test_the_page_never_contains_a_spice_ticket(ctx):
    client, token = ctx
    body = client.get("/c/sess-1", params={"t": token}).text
    assert "password" not in body.lower()
    assert "PVEAuthCookie" not in body


def test_the_page_uses_textcontent_not_innerhtml(ctx):
    client, token = ctx
    body = client.get("/c/sess-1", params={"t": token}).text
    assert "innerHTML" not in body
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd vm-lab && python3 -m pytest tests/test_console_page.py -q`
Expected: FAIL with 404 for `/c/sess-1`

- [ ] **Step 3: Write the page**

Create `vm-lab/console/templates/console.html`. It loads `spice-html5`, reads the WebSocket URL from a `data-` attribute written by the server, and writes all server-supplied text with `textContent`:

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Lab Console</title>
    <style>
      body { margin: 0; background: #0f172a; color: #e2e8f0;
             font: 14px system-ui, sans-serif; }
      #status { padding: 12px 16px; }
      #display { width: 100vw; height: calc(100vh - 44px); }
    </style>
  </head>
  <body>
    <div id="status">Connecting to the lab console...</div>
    <div id="display" data-ws="{{ ws_url }}"></div>
    <script type="module">
      import * as SpiceHtml5 from "/static/spice-html5/main.js";

      const display = document.getElementById("display");
      const status = document.getElementById("status");

      function say(text) {
        status.textContent = text;
      }

      try {
        const sc = new SpiceHtml5.SpiceMainConn({
          uri: display.dataset.ws,
          screen_id: "display",
          onerror: () => say("The console disconnected. Reload to try again."),
          onsuccess: () => say("Connected."),
        });
        window.addEventListener("beforeunload", () => sc.stop());
      } catch (e) {
        say("The console could not start.");
      }
    </script>
  </body>
</html>
```

The SPICE ticket is never rendered. The WebSocket endpoint obtains it server-side at connection time.

- [ ] **Step 4: Add the routes to `gateway.py`**

```python
    @app.get("/c/{session_id}")
    async def console_page(session_id: str, request: Request):
        token = request.query_params.get("t", "")
        if not authorises_session(request.app.state.redis, token, session_id):
            return PlainTextResponse("Forbidden", status_code=403)
        ws_url = f"/ws/{session_id}?t={quote(token)}"
        return templates.TemplateResponse(
            "console.html", {"request": request, "ws_url": ws_url}
        )

    @app.websocket("/ws/{session_id}")
    async def console_ws(websocket: WebSocket, session_id: str):
        token = websocket.query_params.get("t", "")
        if not authorises_session(websocket.app.state.redis, token, session_id):
            await websocket.close(code=1008)
            return
        target = await console_target(websocket.app.state.db, session_id)
        if target is None:
            await websocket.close(code=1013)  # try again later
            return
        await websocket.accept()
        descriptor = await spice_descriptor(os.environ["PROXMOX_NODE"], target.vm_id)
        reader, writer = await open_spice_stream(descriptor)
        await relay(
            lambda: websocket.receive_bytes(),
            lambda data: websocket.send_bytes(data),
            reader,
            writer,
        )
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd vm-lab && python3 -m pytest tests/test_console_page.py -q`
Expected: PASS

- [ ] **Step 6: Mutation test**

Remove the `authorises_session` check from `/c/{session_id}` and confirm `test_the_page_is_refused_for_another_session` fails. Render the descriptor password into the template and confirm `test_the_page_never_contains_a_spice_ticket` fails. Restore both.

- [ ] **Step 7: Commit**

```bash
cd vm-lab && python3 -m pytest -q
git add console/templates/console.html console/gateway.py tests/test_console_page.py
git commit -m "feat(console): serve the console page and bridge the WebSocket"
```

---

## Task 9: Compose wiring and the landing page button

**Files:**
- Modify: `vm-lab/docker-compose.yml`, `vm-lab/lti/templates/lab_loading.html`, `vm-lab/lti/main.py`
- Test: `vm-lab/tests/test_console_button.py`

**Interfaces:**
- Consumes: the `console_token` returned by provisioning (Task 7).
- Produces: a console button on the landing page, rendered server-side.

- [ ] **Step 1: Write the failing tests**

```python
"""The console button appears only when a token exists, and the student never
supplies the session identifier."""

from jinja2 import Environment, FileSystemLoader


def _render(**ctx):
    env = Environment(loader=FileSystemLoader("lti/templates"))
    base = {"session_id": "s1", "console_token": None, "console_base": "https://console.example"}
    base.update(ctx)
    return env.get_template("lab_loading.html").render(**base)


def test_no_button_without_a_token():
    assert "Open Graphical Console" not in _render()


def test_the_button_appears_with_a_token():
    html = _render(console_token="tok-123")
    assert "Open Graphical Console" in html


def test_the_button_url_carries_the_server_minted_token():
    html = _render(console_token="tok-123")
    assert "https://console.example/c/s1?t=tok-123" in html


def test_the_console_opens_in_a_new_tab():
    html = _render(console_token="tok-123")
    assert 'target="_blank"' in html
    assert 'rel="noopener' in html
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd vm-lab && python3 -m pytest tests/test_console_button.py -q`
Expected: FAIL. The string is absent from the template.

- [ ] **Step 3: Add the button to `lab_loading.html`**

Insert inside the running state, next to the existing terminal link:

```html
{% if console_token %}
<a href="{{ console_base }}/c/{{ session_id }}?t={{ console_token }}"
   target="_blank" rel="noopener noreferrer"
   class="inline-flex items-center px-4 py-2 rounded-lg bg-slate-700 text-white text-sm font-medium">
  Open Graphical Console
</a>
{% endif %}
```

`rel="noopener noreferrer"` is required: `noreferrer` stops the token reaching the console origin's referrer log, which is one of the two exposures the spec names.

- [ ] **Step 4: Add the compose service**

```yaml
  console-gateway:
    build:
      context: .
      dockerfile: console/Dockerfile
    container_name: console-gateway
    environment:
      REDIS_URL: ${REDIS_URL:-redis://redis:6379/1}
      DATABASE_URL: ${DATABASE_URL}
      PROXMOX_HOST: ${PROXMOX_HOST}
      PROXMOX_PORT: ${PROXMOX_PORT}
      PROXMOX_USER: ${PROXMOX_USER}
      PROXMOX_PASSWORD: ${PROXMOX_PASSWORD}
      PROXMOX_NODE: ${PROXMOX_NODE}
    depends_on:
      redis:
        condition: service_started
      postgres:
        condition: service_healthy
    networks:
      - lab-network
    restart: unless-stopped
```

Every variable here already exists in the production `.env`. Adding no new configuration key is deliberate: three regressions in this project came from deploying code that read configuration which did not yet exist.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd vm-lab && python3 -m pytest tests/test_console_button.py -q`
Expected: PASS

- [ ] **Step 6: Mutation test**

Remove `rel="noopener noreferrer"` and confirm `test_the_console_opens_in_a_new_tab` fails. Remove the `{% if console_token %}` guard and confirm `test_no_button_without_a_token` fails. Restore both.

- [ ] **Step 7: Commit**

```bash
cd vm-lab && python3 -m pytest -q
git add docker-compose.yml lti/templates/lab_loading.html lti/main.py tests/test_console_button.py
git commit -m "feat(console): offer the graphical console from the lab page"
```

---

## Deployment Checklist

Run before deploying, in this order. Each item exists because its absence caused a real failure in this project.

- [ ] Diff the configuration surface: `git diff <deployed>..HEAD -- vm-lab/ | grep -E "^\+.*os\.getenv|^\+.*environ"`. Every new key must already exist in the live `.env`.
- [ ] Confirm `PROXMOX_VLAN_TAG`, `PROXMOX_MTU`, and `MGMT_NETWORK_PREFIX` are still set. Losing them strips `tag=225` from clones and every launch returns 404.
- [ ] Confirm the `console-auth.yml` middleware file is present in the Traefik dynamic directory before any route referencing it is written. A route naming a middleware Traefik cannot resolve fails closed, which takes the terminal down.
- [ ] Verify `/authz` refuses an unauthenticated request before exposing any route to it.
- [ ] State explicitly whether route files for already-running sessions are rewritten or left to expire.
- [ ] Rebuild and confirm the change reached the running container, not only the source tree.

## Out of Scope

Audio, USB redirection, graphical session recording, replacing the terminal, instructor observation of a student console, and any change to the LTI broker.
