# Proxmox Console Access (VNC & SPICE) - Implementation Plan

## Overview

This document outlines the implementation plan for adding browser-based **VNC and SPICE** console access from Proxmox to LabsConnect. This feature will allow students and instructors to view the graphical console of their VMs directly in their browser, complementing the existing SSH terminal (ttyd) access.

### VNC vs SPICE Comparison

| Feature | VNC | SPICE |
|---------|-----|-------|
| **Protocol** | Remote Frame Buffer (RFB) | SPICE protocol |
| **Best for** | Linux VMs, simple use cases | Windows VMs, rich desktop experience |
| **Audio support** | No | Yes |
| **USB redirection** | No | Yes (with agent) |
| **Clipboard sync** | Basic | Full bidirectional |
| **Multi-monitor** | No | Yes |
| **Performance** | Good | Better (adaptive streaming) |
| **Browser library** | noVNC (mature) | spice-html5 (official) |
| **Proxmox support** | Native | Native |

**Recommendation:** Implement both protocols and let users/admins choose based on VM type:
- **VNC** as default for Linux VMs (simpler, lighter)
- **SPICE** recommended for Windows VMs (better experience)

## Current Architecture

The codebase currently uses **ttyd** (web terminal) for SSH-based access to VMs:
- Students launch via LTI from their LMS
- A VM is provisioned from a Proxmox template
- A ttyd container is spawned that SSHs into the VM
- Traefik routes `lab-{session_id}.{domain}` to the ttyd container

## Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Browser                                         │
│  ┌───────────────┐  ┌─────────────────────────────────────────────────────┐ │
│  │ Terminal Tab  │  │                  Console Tab                         │ │
│  │   (ttyd)      │  │  ┌─────────────────┐  ┌─────────────────────────┐   │ │
│  │               │  │  │   noVNC Client  │  │   spice-html5 Client    │   │ │
│  │               │  │  │   (VNC viewer)  │  │    (SPICE viewer)       │   │ │
│  └───────┬───────┘  │  └────────┬────────┘  └───────────┬─────────────┘   │ │
│          │          │           │                       │                  │ │
└──────────┼──────────────────────┼───────────────────────┼──────────────────┘
           │                      │                       │
           ▼                      ▼ WebSocket             ▼ WebSocket
┌──────────────────┐   ┌──────────────────────────────────────────────────────┐
│ ttyd Container   │   │              Console WebSocket Proxy                  │
│ (existing)       │   │                   (lab-api)                           │
└──────────────────┘   └──────────────────────┬───────────────────────────────┘
                                              │
                                              ▼
                       ┌──────────────────────────────────────────────────────┐
                       │                  Proxmox VE API                       │
                       │  ┌────────────────────┐  ┌────────────────────────┐  │
                       │  │ POST /qemu/{vmid}/ │  │ POST /qemu/{vmid}/     │  │
                       │  │     vncproxy       │  │     spiceproxy         │  │
                       │  │ → ticket + port    │  │ → ticket + proxy URL   │  │
                       │  └────────────────────┘  └────────────────────────┘  │
                       └──────────────────────────────────────────────────────┘
```

---

## Implementation Phases

### Phase 1: Backend Console Proxy Endpoints (lab-api)

**Files to modify:**
- `vm-lab/api/main.py`
- `vm-lab/api/requirements.txt`

**Tasks:**

#### 1.1 VNC Endpoint (`POST /api/session/{session_id}/vnc-ticket`)

- Validate session ownership and status (must be "running")
- Call Proxmox API to get VNC ticket:
  ```python
  result = proxmox.nodes(node).qemu(vmid).vncproxy.post(websocket=1)
  # Returns: {'ticket': '...', 'port': 5900, 'upid': '...'}
  ```
- Return ticket and WebSocket connection info to frontend

#### 1.2 SPICE Endpoint (`POST /api/session/{session_id}/spice-ticket`)

- Validate session ownership and status (must be "running")
- Call Proxmox API to get SPICE ticket:
  ```python
  result = proxmox.nodes(node).qemu(vmid).spiceproxy.post()
  # Returns: {
  #   'host': 'proxmox-host',
  #   'port': '3128',
  #   'ticket': 'SPICE-TICKET-...',
  #   'password': '...',
  #   'tls-port': '...',
  #   'type': 'spice',
  #   ...
  # }
  ```
- Return connection parameters to frontend

#### 1.3 WebSocket Proxy Endpoints

```python
# VNC WebSocket proxy
@app.websocket("/api/vnc/{session_id}/ws")
async def vnc_websocket_proxy(websocket: WebSocket, session_id: str):
    # Authenticate session
    # Connect to Proxmox VNC WebSocket
    # Bidirectionally proxy frames

# SPICE WebSocket proxy
@app.websocket("/api/spice/{session_id}/ws")
async def spice_websocket_proxy(websocket: WebSocket, session_id: str):
    # Authenticate session
    # Connect to Proxmox SPICE WebSocket
    # Bidirectionally proxy frames
```

#### 1.4 Configuration Options

```python
CONSOLE_ENABLED = os.environ.get("CONSOLE_ENABLED", "true").lower() == "true"
CONSOLE_DEFAULT_PROTOCOL = os.environ.get("CONSOLE_DEFAULT_PROTOCOL", "vnc")  # "vnc" or "spice"
VNC_ENABLED = os.environ.get("VNC_ENABLED", "true").lower() == "true"
SPICE_ENABLED = os.environ.get("SPICE_ENABLED", "true").lower() == "true"
```

#### 1.5 Dependencies

```
websockets>=12.0
```

**Proxmox API Details:**

```python
# VNC WebSocket ticket
proxmox.nodes(node).qemu(vmid).vncproxy.post(websocket=1)
# Response: {
#   'ticket': 'PVEVNC:64A3BC9E::...',
#   'port': '5900',
#   'upid': 'UPID:host1:...',
#   'user': 'root@pam'
# }

# SPICE proxy ticket
proxmox.nodes(node).qemu(vmid).spiceproxy.post()
# Response: {
#   'host': '192.168.1.10',
#   'tls-port': '61000',
#   'password': 'random-password',
#   'ticket': 'SPICE-ticket-string',
#   'type': 'spice',
#   'toggle-fullscreen': 'shift+f11',
#   'release-cursor': 'ctrl+alt',
#   'secure-attention': 'ctrl+alt+end',
#   'proxy': 'http://...'  # optional
# }

# VNC WebSocket URL format:
# wss://{proxmox_host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={ticket}

# SPICE WebSocket URL format:
# wss://{proxmox_host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/spicewebsocket?port={tls-port}&ticket={ticket}
```

---

### Phase 2: Frontend Console Client Integration

**Files to add:**
- `vm-lab/lti/static/js/novnc/` (noVNC library)
- `vm-lab/lti/static/js/spice-html5/` (SPICE HTML5 library)
- `vm-lab/lti/static/js/console-client.js`
- `vm-lab/lti/static/css/console.css`
- `vm-lab/lti/templates/console_viewer.html`

**Tasks:**

#### 2.1 Add noVNC Library

- Download noVNC v1.4.0+ from https://github.com/novnc/noVNC
- Include core files: `core/rfb.js`, `core/util/`, `core/decoders/`, `vendor/`
- License: MPL-2.0 (compatible)

#### 2.2 Add spice-html5 Library

- Download from https://gitlab.freedesktop.org/spice/spice-html5
- Include core files: `spicemsg.js`, `spiceconn.js`, `display.js`, `inputs.js`, etc.
- License: LGPL-3.0

#### 2.3 Create Unified Console Client (`console-client.js`)

```javascript
class LabConsoleClient {
  constructor(sessionId, container, protocol = 'vnc') {
    this.sessionId = sessionId;
    this.container = container;
    this.protocol = protocol;  // 'vnc' or 'spice'
    this.client = null;
  }

  async connect() {
    if (this.protocol === 'vnc') {
      await this.connectVNC();
    } else if (this.protocol === 'spice') {
      await this.connectSPICE();
    }
  }

  async connectVNC() {
    // 1. Get VNC ticket from our API
    const response = await fetch(`/api/session/${this.sessionId}/vnc-ticket`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${this.token}` }
    });
    const { wsUrl, ticket } = await response.json();

    // 2. Connect via noVNC RFB client
    this.client = new RFB(this.container, wsUrl, {
      credentials: { password: ticket }
    });

    this.setupVNCEventHandlers();
  }

  async connectSPICE() {
    // 1. Get SPICE ticket from our API
    const response = await fetch(`/api/session/${this.sessionId}/spice-ticket`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${this.token}` }
    });
    const { wsUrl, password, ...config } = await response.json();

    // 2. Connect via spice-html5 client
    this.client = new SpiceMainConn({
      uri: wsUrl,
      password: password,
      screen_id: this.container.id,
      onerror: (e) => this.onError(e),
      onsuccess: () => this.onConnect(),
      ...config
    });

    this.setupSPICEEventHandlers();
  }

  // Common controls
  sendCtrlAltDel() {
    if (this.protocol === 'vnc') {
      this.client?.sendCtrlAltDel();
    } else {
      this.client?.sendCtrlAltDel();
    }
  }

  disconnect() {
    if (this.protocol === 'vnc') {
      this.client?.disconnect();
    } else {
      this.client?.stop();
    }
  }

  // Protocol switching
  async switchProtocol(newProtocol) {
    this.disconnect();
    this.protocol = newProtocol;
    await this.connect();
  }
}
```

#### 2.4 Create Console Viewer Template (`console_viewer.html`)

- Full-viewport canvas for VNC/SPICE
- Toolbar with controls:
  - Protocol selector (VNC / SPICE dropdown)
  - Fullscreen toggle
  - Send Ctrl+Alt+Del
  - Send Ctrl+Alt+F1 through F12 (for Linux VTs)
  - Clipboard sync button (SPICE only indicator)
  - Scale/fit mode selector
  - Connection status indicator
  - Audio toggle (SPICE only)
  - Disconnect button
- Mobile-friendly touch support
- Keyboard capture handling
- Auto-reconnect on disconnect

#### 2.5 Create Console Styles (`console.css`)

- Canvas sizing and positioning
- Toolbar styling consistent with existing UI
- Protocol indicator badges
- Connection overlay states
- Mobile responsive layout
- SPICE audio indicator

---

### Phase 3: Unified Lab Session Page

**Files to modify/add:**
- `vm-lab/lti/templates/lab_session.html` (new)
- `vm-lab/lti/main.py` (routing updates)

**Tasks:**

#### 3.1 Create Unified Session Page (`lab_session.html`)

```html
<!-- Tab interface -->
<div class="tab-bar">
  <button data-tab="terminal" class="active">Terminal (SSH)</button>
  <button data-tab="console">Console (VNC/SPICE)</button>
</div>

<!-- Terminal tab -->
<div id="terminal-tab" class="tab-content active">
  <iframe src="{{ ttyd_url }}" class="full-viewport"></iframe>
</div>

<!-- Console tab -->
<div id="console-tab" class="tab-content">
  <div class="console-toolbar">
    <select id="protocol-select">
      <option value="vnc">VNC</option>
      <option value="spice">SPICE (recommended for Windows)</option>
    </select>
    <!-- Other controls -->
  </div>
  <div id="console-container"></div>
</div>
```

#### 3.2 Update LTI Routing

```python
# Unified session view
@app.get("/lti/session/{session_id}")
async def session_view(session_id: str, tab: str = "terminal"):
    # Render unified page with tab parameter

# Direct console view (for embedding/linking)
@app.get("/lti/session/{session_id}/console")
async def console_view(session_id: str, protocol: str = "vnc"):
    # Render console-only page

# Keep existing ttyd route for backwards compatibility
```

#### 3.3 Update Student Redirect Flow

- After provisioning, redirect to unified session page
- Default to Terminal tab (existing behavior)
- Allow query params: `?tab=console&protocol=spice`
- Store user preference in localStorage

---

### Phase 4: Database & Session Updates

**Files to modify:**
- `vm-lab/db/init-db.sql` (or migration script)
- `vm-lab/api/main.py` (session model)

**Tasks:**

#### 4.1 Add Console Fields to Session Table

```sql
-- Add console-related columns
ALTER TABLE vm_sessions ADD COLUMN console_enabled BOOLEAN DEFAULT TRUE;
ALTER TABLE vm_sessions ADD COLUMN console_protocol VARCHAR(10) DEFAULT 'vnc';
ALTER TABLE vm_sessions ADD COLUMN console_last_connected_at TIMESTAMP;

-- Track console usage
CREATE TABLE IF NOT EXISTS console_connections (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(16) REFERENCES vm_sessions(session_id),
    protocol VARCHAR(10) NOT NULL,  -- 'vnc' or 'spice'
    connected_at TIMESTAMP DEFAULT NOW(),
    disconnected_at TIMESTAMP,
    duration_seconds INTEGER,
    client_info JSONB  -- browser, resolution, etc.
);
```

#### 4.2 Update Session Response Model

```python
class SessionResponse(BaseModel):
    # ... existing fields ...
    console_enabled: bool = True
    console_protocols: List[str] = ["vnc", "spice"]
    console_default_protocol: str = "vnc"
    console_url: Optional[str] = None
```

#### 4.3 Per-Template Protocol Configuration

```python
# Allow templates to specify preferred protocol
# e.g., Windows template defaults to SPICE
class TemplateConfig(BaseModel):
    template_id: int
    default_console_protocol: str = "vnc"
    console_protocols_enabled: List[str] = ["vnc", "spice"]
```

---

### Phase 5: Instructor Dashboard Enhancements

**Files to modify:**
- `vm-lab/lti/templates/instructor_dashboard.html`
- `vm-lab/lti/static/js/dashboard.js`

**Tasks:**

#### 5.1 Add "View Console" Button for Active Sessions

- Opens console viewer in modal overlay
- Protocol selector in modal
- Read-only mode option (view without keyboard/mouse input)
- Useful for helping students or monitoring exams

#### 5.2 Add Console Screenshot Capability

- Capture current console frame as PNG
- Works for both VNC and SPICE
- Download or attach to session record
- Useful for documentation/evidence

#### 5.3 Update Session Details View

- Show console availability status
- Show available protocols (VNC, SPICE)
- Show last console connection time
- Show active console connections count

#### 5.4 Console Analytics (optional)

- Track console vs terminal usage
- Track VNC vs SPICE preference
- Session duration by access method

---

### Phase 6: Security Hardening

**Tasks:**

#### 6.1 Ticket Validation

- Proxmox VNC tickets expire after ~30 seconds
- Proxmox SPICE tickets also have short TTL
- Implement ticket refresh mechanism for long sessions
- Validate session ownership before every ticket request

#### 6.2 WebSocket Authentication

- Require valid session token on WebSocket upgrade
- Validate session is in "running" state
- Terminate WebSocket if session expires or is destroyed
- Implement heartbeat to detect stale connections

#### 6.3 Rate Limiting

- Limit ticket requests: 10/minute per session
- Limit WebSocket connections: 2 concurrent per session per protocol
- Log suspicious patterns (rapid reconnects, etc.)

#### 6.4 CORS and Origin Validation

- Validate WebSocket Origin header
- Only allow connections from known domains
- Reject connections from unexpected origins

#### 6.5 Input Sanitization (SPICE)

- SPICE supports file transfer and USB - consider disabling if not needed
- Validate clipboard data size limits
- Log large data transfers

---

## File Change Summary

| File | Action | Description |
|------|--------|-------------|
| `vm-lab/api/main.py` | Modify | Add VNC & SPICE endpoints, WebSocket proxies |
| `vm-lab/api/requirements.txt` | Modify | Add `websockets>=12.0` |
| `vm-lab/db/init-db.sql` | Modify | Add console columns, connections table |
| `vm-lab/lti/main.py` | Modify | Add console routes |
| `vm-lab/lti/templates/console_viewer.html` | **New** | Unified console viewer page |
| `vm-lab/lti/templates/lab_session.html` | **New** | Unified session with tabs |
| `vm-lab/lti/static/js/novnc/` | **New** | noVNC library files |
| `vm-lab/lti/static/js/spice-html5/` | **New** | spice-html5 library files |
| `vm-lab/lti/static/js/console-client.js` | **New** | Unified console connection logic |
| `vm-lab/lti/static/css/console.css` | **New** | Console viewer styles |
| `vm-lab/lti/templates/instructor_dashboard.html` | Modify | Add console view button |
| `vm-lab/lti/static/js/dashboard.js` | Modify | Add console functionality |

---

## Testing Plan

### Unit Tests
- VNC ticket endpoint returns valid ticket
- SPICE ticket endpoint returns valid connection params
- Session validation rejects invalid sessions
- WebSocket proxy handles connection lifecycle for both protocols

### Integration Tests
- End-to-end VNC connection to running Linux VM
- End-to-end SPICE connection to running Windows VM
- Protocol switching mid-session
- Tab switching between Terminal and Console
- Instructor dashboard console view

### Browser Compatibility
- Chrome (latest) - VNC & SPICE
- Firefox (latest) - VNC & SPICE
- Safari (latest) - VNC & SPICE
- Edge (latest) - VNC & SPICE
- Mobile Safari (iOS) - VNC only (SPICE limited)
- Mobile Chrome (Android) - VNC only (SPICE limited)

### Performance Tests
- Console responsiveness on slow connections
- Multiple concurrent console sessions
- Memory usage of noVNC vs spice-html5 clients
- Bandwidth comparison: VNC vs SPICE

### VM Type Tests
- Linux VM with VNC (primary)
- Linux VM with SPICE
- Windows VM with VNC
- Windows VM with SPICE (primary)

---

## Configuration Options

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `CONSOLE_ENABLED` | `true` | Enable/disable console feature globally |
| `CONSOLE_DEFAULT_PROTOCOL` | `vnc` | Default protocol when not specified |
| `VNC_ENABLED` | `true` | Enable/disable VNC protocol |
| `SPICE_ENABLED` | `true` | Enable/disable SPICE protocol |
| `CONSOLE_DEFAULT_TAB` | `terminal` | Default tab for new sessions |
| `CONSOLE_TICKET_RATE_LIMIT` | `10` | Max ticket requests per minute |
| `CONSOLE_MAX_CONNECTIONS` | `2` | Max concurrent connections per session |
| `SPICE_AUDIO_ENABLED` | `true` | Enable SPICE audio streaming |
| `SPICE_USB_ENABLED` | `false` | Enable SPICE USB redirection |
| `SPICE_FILE_TRANSFER_ENABLED` | `false` | Enable SPICE file transfer |

---

## Rollout Plan

1. **Development** - Implement on feature branch
2. **Testing** - Deploy to staging environment
3. **Beta (VNC only)** - Enable VNC for select courses
4. **Beta (SPICE)** - Enable SPICE for Windows VM courses
5. **GA** - Enable for all users with feature flags
6. **Default** - Make Console tab visible by default

---

## Future Enhancements

- **Session recording** - Record VNC/SPICE sessions for playback
- **Collaborative viewing** - Multiple instructors viewing same console
- **Console screenshots** - Automatic periodic screenshots for review
- **Audio recording** - Record SPICE audio (for accessibility review)
- **Remote USB** - Allow USB device passthrough (lab equipment)
- **Multi-monitor** - SPICE multi-monitor support for complex labs
