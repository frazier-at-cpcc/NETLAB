# Browser SPICE Console Design

**Date:** 2026-09-16
**Status:** Approved for planning
**Scope:** vm-lab. The LTI broker is not modified by this work.

## Goal

Give a student a graphical console for their lab virtual machine inside the
browser, reached from the existing LTI landing page, without installing a
native client. Close the unauthenticated access path that the current web
terminal exposes, in the same change.

## Decisions Already Made

These were settled during brainstorming and are not reopened by the
implementation.

| Question | Decision |
|---|---|
| Console protocol | SPICE, not noVNC |
| Required capabilities | Clipboard copy and paste, smooth graphical performance |
| Excluded capabilities | Audio, USB redirection |
| Authorization | Per-session signed token, applied to the existing terminal routes as well |
| Recording | No graphical capture. Access events only |

Audio and USB redirection are excluded because `spice-html5` cannot deliver
them. USB redirection requires `usbredir` in a native client and cannot work
in a browser at any effort level. Excluding both keeps the browser client
viable.

## Current State

Three facts about the deployed system constrain this design. Each was
verified against production on 2026-09-16.

**The template has no SPICE device.** Proxmox VM 500, `rhcsa10-standalone`,
has `vga` unset. For `ostype: l26` that means standard VGA. The template also
runs `bios: ovmf` and has the guest agent enabled.

**`vga` is settable per clone.** The Proxmox API accepts a `vga` change on a
cloned virtual machine before it starts, so the golden image does not need
rebuilding. Rollback is a configuration change rather than an image restore.

**The existing terminal routes have no authentication.**
`write_traefik_route` in `vm-lab/api/main.py` emits a router with no
middleware, so `lab-{session_id}.labsconnect.org` reaches a shell for anyone
holding an eight-character session identifier.

## Architecture

One long-lived service, **console-gateway**, joins the vm-lab compose stack.
Nothing is spawned per session.

The gateway is the only component on the console path that holds Proxmox
credentials, and the only component that sees a SPICE ticket. Neither value
reaches the browser. This property is what makes the token gate meaningful,
and it is the reason a single gateway was chosen over a per-session sidecar.

```
Browser ──WebSocket──> console-gateway ──SPICE──> Proxmox ──> lab VM
                            │
                            ├── Redis: token digest to session
                            ├── Postgres: session to vmid and node
                            └── Proxmox API: SPICE ticket
```

Traefik fronts the gateway and calls it again, over `forwardAuth`, to
authorize both console routes and the existing terminal routes.

## Components

### `vm-lab/console/tokens.py`

Mints and verifies the console token.

- `mint_console_token()` returns an opaque token from `secrets.token_urlsafe(32)`.
- `hash_console_token(token)` returns a SHA-256 digest.
- `store_console_token(redis, session_id, token, ttl)` writes the digest,
  never the token.
- `resolve_console_token(redis, token)` returns the session identifier or
  `None`.

The token itself is never written to Redis, never written to Postgres, and
never logged. Only the digest is stored, matching how `grade_token_hash` is
already handled in `vm_sessions`. Comparison uses `hmac.compare_digest`.

### `vm-lab/console/proxmox_spice.py`

Obtains a SPICE connection descriptor from Proxmox.

- `spice_descriptor(node, vmid)` calls the Proxmox `spiceproxy` endpoint and
  returns the host, port, TLS settings, and ticket.

The returned ticket is short lived and is treated as a credential. It is
passed to the bridge in memory and never logged, never persisted, and never
sent to the browser.

### `vm-lab/console/bridge.py`

Relays bytes between the browser WebSocket and the SPICE stream.

- `relay(websocket, reader, writer)` copies in both directions until either
  side closes, then closes the other.

The bridge performs no interpretation of SPICE frames. It is a byte pipe, so
it stays testable against a fake server and carries no protocol knowledge
that would rot as SPICE evolves.

### `vm-lab/console/gateway.py`

The FastAPI application.

- `GET /authz` is the Traefik `forwardAuth` target. It returns 200 when the
  presented token resolves to the session the request addresses, and 403
  otherwise. It returns no detail in either case.
- `GET /c/{session_id}` serves the console page when the token is valid.
- `WebSocket /ws/{session_id}` validates the token, resolves the session to a
  virtual machine, obtains a ticket, and bridges.

### `vm-lab/console/templates/console.html`

Serves `spice-html5` against the WebSocket endpoint. Server data is written
with `textContent`, never `innerHTML`, matching the rule the grade panel
already follows.

### Changes to existing files

| File | Change |
|---|---|
| `vm-lab/api/main.py` | Set `vga: qxl` on clone before start. Mint and store the console token during provisioning |
| `vm-lab/api/main.py` | `write_traefik_route` references the `forwardAuth` middleware |
| `vm-lab/lti/templates/lab_loading.html` | Add a console button, rendered server-side with the token |

The terminal container is not modified. One validation path serves both the
console and the terminal, so the two cannot drift apart.

## Authorization

The landing page renders the console URL server-side with the token
embedded. The browser never chooses, supplies, or edits a session
identifier. A student who alters the session segment of the URL presents a
token that does not resolve to that session, and `/authz` refuses.

**The token travels in a URL.** It is therefore exposed to browser history
and to any referrer header. The mitigations are a time-to-live bound to the
session and a binding to exactly one session, so a leaked token grants
nothing after the lab ends and nothing outside that lab. A cookie is not a
usable alternative: the launch is a cross-site POST into an LMS iframe, and
this project has already established that the `lti_session` cookie is
dropped in that position. That failure silently broke grade cell
persistence, and the console must not repeat it.

Applying the same middleware to the terminal routes closes the existing
unauthenticated shell. That is a behaviour change to a working path, so it
is its own task with its own tests.

## Error Handling

Every failure degrades rather than breaking the lab page.

| Condition | Behaviour |
|---|---|
| Token absent, expired, or bound to another session | 403 with no detail |
| Virtual machine not yet running | A "still starting" state, not an error |
| Proxmox unreachable or refusing | 503, logged without credentials |
| SPICE stream closes | The WebSocket closes cleanly |

The console failing must never break the terminal or the grade panel. Those
paths are independent and remain usable when the console does not work.

## Testing

Every defect fixed in this work must fail a test when deliberately
reintroduced. That is the acceptance bar the rest of this project uses, and
it applies here.

**Token unit tests.** Minting produces distinct values. Only the digest is
stored. An expired entry resolves to `None`. A token for one session never
resolves to another. Comparison is constant time.

**Ticket unit tests.** The descriptor is parsed correctly from a mocked
Proxmox response. A failure response raises rather than returning a partial
descriptor. The ticket never appears in any log record.

**Authorization tests.** `/authz` returns 200 for a valid pairing and 403
for absent, expired, malformed, and wrong-session tokens. A request that
edits the session segment is refused.

**Bridge tests.** A fake SPICE server proves bytes relay in both directions,
that closing either side closes the other, and that no data is buffered
after close.

**Route tests.** `write_traefik_route` emits the middleware reference for
both console and terminal routes. A route without it fails the test.

## Out of Scope

- Audio and USB redirection. Neither is achievable in a browser client.
- Graphical session recording. Access events are recorded; frames are not.
- Replacing the web terminal. The console supplements it.
- Any change to the LTI broker.
- Instructor observation of a student console.

## Open Question, To Be Answered First

Proxmox exposes no plain SPICE TCP socket. The `spiceproxy` endpoint returns
a descriptor pointing at the node's proxy on port 3128 with a short-lived
ticket, and that proxy performs its own handshake before the SPICE stream
begins. A plain WebSocket-to-TCP relay cannot complete that handshake
unaided.

The first task is a spike that answers one question: can the gateway perform
the spiceproxy handshake, or must each clone be given explicit SPICE
arguments with a managed port and password?

The answer changes the provisioning task. If per-clone SPICE arguments are
required, port allocation and password lifecycle join this design, and the
provisioning path grows accordingly. The spike exists so that is discovered
before implementation rather than during it. Its output is an answer.
Anything built to reach it is throwaway.
