# Proxmox VNC Browser Console Access - Implementation Plan

## Overview

This document outlines the implementation plan for adding browser-based VNC console access from Proxmox to LabsConnect. This feature will allow students and instructors to view the graphical console of their VMs directly in their browser, complementing the existing SSH terminal (ttyd) access.

## Current Architecture

The codebase currently uses **ttyd** (web terminal) for SSH-based access to VMs:
- Students launch via LTI from their LMS
- A VM is provisioned from a Proxmox template
- A ttyd container is spawned that SSHs into the VM
- Traefik routes `lab-{session_id}.{domain}` to the ttyd container

## Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Browser                                    │
│  ┌─────────────────┐    ┌─────────────────────────────────────────┐ │
│  │  Terminal Tab   │    │            Console Tab                   │ │
│  │   (ttyd)        │    │  ┌─────────────────────────────────┐    │ │
│  │                 │    │  │        noVNC Client              │    │ │
│  └────────┬────────┘    │  │   (JavaScript VNC viewer)        │    │ │
│           │             │  └────────────┬────────────────────┘    │ │
└───────────┼─────────────────────────────┼─────────────────────────┘
            │                             │
            ▼                             ▼ WebSocket
┌──────────────────────┐    ┌─────────────────────────────────────────┐
│   ttyd Container     │    │       VNC WebSocket Proxy               │
│   (existing)         │    │   (websockify in lab-api)               │
└──────────────────────┘    └────────────────┬────────────────────────┘
                                             │
                                             ▼
                            ┌─────────────────────────────────────────┐
                            │         Proxmox VE API                   │
                            │   POST /nodes/{node}/qemu/{vmid}/       │
                            │         vncproxy                         │
                            │   → Returns: ticket + port               │
                            └─────────────────────────────────────────┘
```

---

## Implementation Phases

### Phase 1: Backend VNC Proxy Endpoint (lab-api)

**Files to modify:**
- `vm-lab/api/main.py`
- `vm-lab/api/requirements.txt`

**Tasks:**

1. **Add VNC ticket endpoint** (`POST /api/session/{session_id}/vnc-ticket`)
   - Validate session ownership and status (must be "running")
   - Call Proxmox API to get VNC ticket:
     ```python
     result = proxmox.nodes(node).qemu(vmid).vncproxy.post(websocket=1)
     # Returns: {'ticket': '...', 'port': 5900, 'upid': '...'}
     ```
   - Return ticket and WebSocket connection info to frontend

2. **Add WebSocket proxy endpoint** (`/api/vnc/{session_id}/ws`)
   - Authenticate the session via query parameter or header
   - Establish WebSocket connection to Proxmox VNC port
   - Bidirectionally proxy WebSocket frames between browser and Proxmox
   - Handle connection lifecycle (open, close, errors)

3. **Add configuration options**
   ```python
   VNC_ENABLED = os.environ.get("VNC_ENABLED", "true").lower() == "true"
   ```

4. **Add dependencies**
   ```
   websockets>=12.0
   ```

**Proxmox API Details:**
```python
# Get VNC WebSocket ticket
proxmox.nodes(node).qemu(vmid).vncproxy.post(websocket=1)
# Response: {
#   'ticket': 'PVEVNC:64A3BC9E::...',
#   'port': '5900',
#   'upid': 'UPID:host1:...',
#   'user': 'root@pam'
# }

# The WebSocket URL format for Proxmox:
# wss://{proxmox_host}:{proxmox_port}/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={ticket}
```

---

### Phase 2: Frontend noVNC Integration

**Files to add:**
- `vm-lab/lti/static/js/novnc/` (noVNC library)
- `vm-lab/lti/static/js/vnc-client.js`
- `vm-lab/lti/static/css/vnc.css`
- `vm-lab/lti/templates/vnc_console.html`

**Tasks:**

1. **Add noVNC library**
   - Download noVNC v1.4.0+ from https://github.com/novnc/noVNC
   - Include core files: `core/rfb.js`, `core/util/`, `core/decoders/`, `vendor/`
   - noVNC is MIT licensed

2. **Create VNC viewer template** (`vnc_console.html`)
   - Full-viewport VNC canvas
   - Toolbar with controls:
     - Fullscreen toggle
     - Send Ctrl+Alt+Del
     - Clipboard sync button
     - Scale/fit mode selector
     - Connection status indicator
     - Disconnect button
   - Mobile-friendly touch support
   - Keyboard capture handling

3. **Create VNC client JavaScript** (`vnc-client.js`)
   ```javascript
   class LabVNCClient {
     constructor(sessionId, container) {
       this.sessionId = sessionId;
       this.container = container;
       this.rfb = null;
     }

     async connect() {
       // 1. Get VNC ticket from our API
       const ticketResponse = await fetch(`/api/session/${this.sessionId}/vnc-ticket`, {
         method: 'POST',
         headers: { 'Authorization': `Bearer ${this.token}` }
       });
       const { wsUrl, ticket } = await ticketResponse.json();

       // 2. Connect via noVNC RFB client
       this.rfb = new RFB(this.container, wsUrl, {
         credentials: { password: ticket }
       });

       // 3. Set up event handlers
       this.rfb.addEventListener('connect', () => this.onConnect());
       this.rfb.addEventListener('disconnect', (e) => this.onDisconnect(e));
       this.rfb.addEventListener('credentialsrequired', () => this.onCredentialsRequired());
     }

     sendCtrlAltDel() {
       this.rfb?.sendCtrlAltDel();
     }

     disconnect() {
       this.rfb?.disconnect();
     }
   }
   ```

4. **Create VNC styles** (`vnc.css`)
   - Canvas sizing and positioning
   - Toolbar styling consistent with existing UI
   - Connection overlay states
   - Mobile responsive layout

---

### Phase 3: Unified Lab Session Page

**Files to modify:**
- `vm-lab/lti/templates/` (new unified template)
- `vm-lab/lti/main.py` (routing updates)

**Tasks:**

1. **Create unified session page** (`lab_session.html`)
   - Tab interface: "Terminal" | "Console"
   - Terminal tab: iframe to existing ttyd URL
   - Console tab: noVNC viewer (lazy-loaded on click)
   - Session info header (VM name, IP, time remaining)
   - Tab state persistence via localStorage

2. **Update LTI routing**
   - Add route `/lti/session/{session_id}` for unified view
   - Keep existing direct ttyd route for backwards compatibility
   - Add route `/lti/session/{session_id}/console` for VNC-only view

3. **Update student redirect flow**
   - After provisioning, redirect to unified session page
   - Default to Terminal tab (existing behavior)
   - Allow `?tab=console` query param to open Console tab

---

### Phase 4: Database & Session Updates

**Files to modify:**
- `vm-lab/db/init-db.sql` (or migration script)
- `vm-lab/api/main.py` (session model)

**Tasks:**

1. **Add VNC fields to session table**
   ```sql
   ALTER TABLE vm_sessions ADD COLUMN vnc_enabled BOOLEAN DEFAULT TRUE;
   ALTER TABLE vm_sessions ADD COLUMN vnc_last_connected_at TIMESTAMP;
   ```

2. **Update session response model**
   ```python
   class SessionResponse(BaseModel):
       # ... existing fields ...
       vnc_enabled: bool = True
       vnc_url: Optional[str] = None
   ```

3. **Track VNC usage** (optional)
   - Log VNC connections for analytics
   - Track bandwidth/connection duration

---

### Phase 5: Instructor Dashboard Enhancements

**Files to modify:**
- `vm-lab/lti/templates/instructor_dashboard.html`
- `vm-lab/lti/static/js/dashboard.js`

**Tasks:**

1. **Add "View Console" button** for active sessions
   - Opens VNC viewer in modal overlay
   - Read-only mode option (view without interaction)
   - Useful for helping students or monitoring exams

2. **Add console screenshot capability**
   - Capture current VNC frame as PNG
   - Download or attach to session record
   - Useful for documentation/evidence

3. **Update session details view**
   - Show VNC availability status
   - Show last VNC connection time

---

### Phase 6: Security Hardening

**Tasks:**

1. **VNC ticket validation**
   - Proxmox tickets expire after ~30 seconds
   - Implement ticket refresh mechanism
   - Validate session ownership before every ticket request

2. **WebSocket authentication**
   - Require valid session token on WebSocket upgrade
   - Validate session is in "running" state
   - Terminate WebSocket if session expires

3. **Rate limiting**
   - Limit ticket requests: 10/minute per session
   - Limit WebSocket connections: 2 concurrent per session
   - Log suspicious patterns

4. **CORS and origin validation**
   - Validate WebSocket Origin header
   - Only allow connections from known domains

---

## File Change Summary

| File | Action | Description |
|------|--------|-------------|
| `vm-lab/api/main.py` | Modify | Add VNC endpoints, WebSocket proxy |
| `vm-lab/api/requirements.txt` | Modify | Add `websockets>=12.0` |
| `vm-lab/db/init-db.sql` | Modify | Add VNC columns |
| `vm-lab/lti/main.py` | Modify | Add VNC routes |
| `vm-lab/lti/templates/vnc_console.html` | **New** | VNC viewer page |
| `vm-lab/lti/templates/lab_session.html` | **New** | Unified tab interface |
| `vm-lab/lti/static/js/novnc/` | **New** | noVNC library files |
| `vm-lab/lti/static/js/vnc-client.js` | **New** | VNC connection logic |
| `vm-lab/lti/static/css/vnc.css` | **New** | VNC viewer styles |
| `vm-lab/lti/templates/instructor_dashboard.html` | Modify | Add console view button |
| `vm-lab/lti/static/js/dashboard.js` | Modify | Add console functionality |

---

## Testing Plan

### Unit Tests
- VNC ticket endpoint returns valid ticket
- Session validation rejects invalid sessions
- WebSocket proxy handles connection lifecycle

### Integration Tests
- End-to-end VNC connection to running VM
- Tab switching between Terminal and Console
- Instructor dashboard console view

### Browser Compatibility
- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)
- Mobile Safari (iOS)
- Mobile Chrome (Android)

### Performance Tests
- VNC responsiveness on slow connections
- Multiple concurrent VNC sessions
- Memory usage of noVNC client

---

## Configuration Options

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `VNC_ENABLED` | `true` | Enable/disable VNC feature globally |
| `VNC_DEFAULT_TAB` | `terminal` | Default tab for new sessions |
| `VNC_TICKET_RATE_LIMIT` | `10` | Max ticket requests per minute |
| `VNC_MAX_CONNECTIONS` | `2` | Max concurrent VNC connections per session |

---

## Rollout Plan

1. **Development** - Implement on feature branch
2. **Testing** - Deploy to staging environment
3. **Beta** - Enable for select courses/instructors
4. **GA** - Enable for all users with feature flag
5. **Default** - Make Console tab visible by default

---

## Future Enhancements

- **SPICE support** - Better Windows VM experience with audio/USB
- **Session recording** - Record VNC sessions like terminal sessions
- **Collaborative viewing** - Multiple instructors viewing same console
- **Console screenshots** - Automatic periodic screenshots for review
