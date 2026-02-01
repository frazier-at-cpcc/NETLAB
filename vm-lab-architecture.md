# On-Demand Red Hat VM Lab with Web Console

## Overview

This architecture enables on-demand provisioning of Red Hat VMs for students, accessible via dynamic web URLs without VPN or authentication. Students receive a URL and immediately get an SSH terminal in their browser.

---

## High-Level Architecture

```
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

## Component Details

### 1. VM Management (libvirt/KVM)

VMs are created as thin clones using QCOW2 backing files for instant provisioning:

```bash
# Use backing file for instant clone from base QCOW
qemu-img create -f qcow2 -b /var/lib/libvirt/images/rhel-base.qcow2 \
    -F qcow2 /var/lib/libvirt/images/student-{session-id}.qcow2

# Clones are thin-provisioned - only differences stored
# Base image stays read-only, instant provisioning
```

### 2. Web Terminal: ttyd

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

### 3. Tunnel Solution: Cloudflare Tunnel

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
│  Frontend:     Simple landing page (optional)
│  API:          Python FastAPI
│  VM Mgmt:      libvirt Python bindings
│  Web Console:  ttyd (Docker containers)
│  Tunnel:       Cloudflare Tunnel (cloudflared)
│  Proxy:        Traefik (auto SSL, dynamic routing)
│  Database:     SQLite or Redis (sessions)
└────────────────────────────────────────────┘
```

---

## Workflow: Student Session Lifecycle

```
1. PROVISION REQUEST
   ┌──────────────────────────────────────────────────────────┐
   │  Instructor triggers VM provisioning                      │
   │  (via API call or admin panel)                           │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
2. VM CREATION (< 5 seconds with backing file)
   ┌──────────────────────────────────────────────────────────┐
   │  • Generate unique session ID (e.g., x7k9m2p4)           │
   │  • Create thin clone from base QCOW2                     │
   │  • Define VM in libvirt (16GB RAM, 4 vCPU)              │
   │  • Start VM                                              │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
3. TTYD CONTAINER SPAWN
   ┌──────────────────────────────────────────────────────────┐
   │  • Start ttyd container linked to VM's SSH               │
   │  • Register with Traefik for dynamic subdomain           │
   │  • No authentication configured                          │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
4. URL DELIVERY
   ┌──────────────────────────────────────────────────────────┐
   │  Return to instructor:                                    │
   │  https://lab-x7k9m2p4.yourdomain.com                      │
   │  (No VPN, works through any firewall)                    │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
5. SESSION ACTIVE
   ┌──────────────────────────────────────────────────────────┐
   │  • Student clicks link → instant SSH terminal            │
   │  • Full 16GB RHEL environment                            │
   │  • Optional: Time limit / idle timeout                   │
   └──────────────────────────────────────────────────────────┘
                              │
                              ▼
6. CLEANUP (Manual or automatic timeout)
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
```

---

## Orchestration API (Python FastAPI)

```python
# api/main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import libvirt
import docker
import secrets
import string
import time
import os
import subprocess

app = FastAPI()
docker_client = docker.from_env()
libvirt_conn = libvirt.open("qemu:///system")

DOMAIN = "lab.yourdomain.com"
BASE_QCOW = "/var/lib/libvirt/images/rhel-academy-base.qcow2"
VM_NETWORK = "10.10.10"
sessions = {}  # In production, use Redis/PostgreSQL

class Session(BaseModel):
    session_id: str
    url: str
    vm_ip: str
    status: str

def generate_session_id():
    """Generate 8-char alphanumeric ID"""
    chars = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(8))

@app.post("/api/provision", response_model=Session)
async def provision_vm():
    session_id = generate_session_id()
    vm_index = len(sessions) + 11  # Start at .11
    vm_ip = f"{VM_NETWORK}.{vm_index}"

    # 1. Create QCOW2 overlay (thin clone)
    overlay_path = f"/var/lib/libvirt/images/student-{session_id}.qcow2"
    subprocess.run([
        "qemu-img", "create", "-f", "qcow2",
        "-b", BASE_QCOW, "-F", "qcow2", overlay_path
    ], check=True)

    # 2. Define and start VM with 16GB RAM, 4 vCPU
    vm_xml = f"""
    <domain type='kvm'>
      <name>student-{session_id}</name>
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

    # 3. Wait for VM to get IP (simplified - use DHCP lease or cloud-init)
    time.sleep(30)  # In production, poll for SSH availability

    # 4. Spawn ttyd container for this VM (no auth)
    ttyd_port = 7680 + vm_index
    container = docker_client.containers.run(
        "tsl0922/ttyd",
        command=f"ttyd --writable ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null student@{vm_ip}",
        name=f"ttyd-{session_id}",
        detach=True,
        network="lab-network",
        labels={
            "traefik.enable": "true",
            f"traefik.http.routers.ttyd-{session_id}.rule": f"Host(`lab-{session_id}.{DOMAIN}`)",
            f"traefik.http.services.ttyd-{session_id}.loadbalancer.server.port": "7681",
        }
    )

    url = f"https://lab-{session_id}.{DOMAIN}"

    sessions[session_id] = {
        "session_id": session_id,
        "url": url,
        "vm_ip": vm_ip,
        "status": "running",
        "container_id": container.id,
        "overlay_path": overlay_path,
        "created_at": time.time()
    }

    return Session(session_id=session_id, url=url, vm_ip=vm_ip, status="running")

@app.delete("/api/{session_id}")
async def destroy_session(session_id: str):
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = sessions[session_id]

    # 1. Stop and remove ttyd container
    try:
        container = docker_client.containers.get(f"ttyd-{session_id}")
        container.stop()
        container.remove()
    except: pass

    # 2. Destroy and undefine VM
    try:
        dom = libvirt_conn.lookupByName(f"student-{session_id}")
        dom.destroy()
        dom.undefine()
    except: pass

    # 3. Delete overlay QCOW2
    try:
        os.remove(session["overlay_path"])
    except: pass

    del sessions[session_id]
    return {"status": "destroyed"}

@app.get("/api/sessions")
async def list_sessions():
    return list(sessions.values())
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

# 5. Config file (~/.cloudflared/config.yml)
tunnel: <tunnel-id>
credentials-file: /root/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: "*.lab.yourdomain.com"
    service: http://localhost:80  # Traefik
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

Since there's no authentication, security relies on:

| Control | Implementation |
|---------|----------------|
| **URL obscurity** | 8-char random session ID = 2.8 trillion combinations |
| **Session expiry** | Auto-destroy after X hours of inactivity |
| **Rate limiting** | Limit provision requests per IP |
| **Network isolation** | VMs on isolated bridge, no inter-VM traffic |
| **HTTPS only** | Cloudflare enforces TLS |

### Auto-Cleanup Implementation

```python
# Add to API: Auto-cleanup after 4 hours
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()

@scheduler.scheduled_job('interval', minutes=15)
def cleanup_expired():
    now = time.time()
    for sid, session in list(sessions.items()):
        if now - session['created_at'] > 4 * 3600:  # 4 hours
            destroy_session(sid)

scheduler.start()
```

---

## Student Experience

```
1. Instructor provisions VM via API or admin panel

2. Instructor shares URL with student:
   "Your lab environment: https://lab-x7k9m2p4.yourdomain.com"

3. Student clicks link → browser opens → SSH terminal appears immediately

   ┌─────────────────────────────────────────────────────────┐
   │ [student@rhel-lab ~]$ _                                 │
   │                                                         │
   │                                                         │
   │                                                         │
   └─────────────────────────────────────────────────────────┘

4. Student works in terminal (full RHEL environment, 16GB RAM)

5. Session auto-expires or instructor manually destroys
```

---

## Alternative Web Terminal Options

| Option | Pros | Cons | Best For |
|--------|------|------|----------|
| **ttyd** | Ultra-lightweight, no auth | Terminal only | This use case |
| Apache Guacamole | Full SSH/VNC/RDP, session recording | Heavier setup | Multi-protocol needs |
| Wetty | SSH over WebSocket | Requires Node.js | Existing SSH setups |
| noVNC | Full GUI desktop access | Needs VNC server | GUI-based labs |

---

## Directory Structure

```
/opt/vm-lab/
├── docker-compose.yml
├── .env                      # CF_TUNNEL_TOKEN, etc.
├── api/
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
└── cloudflared/
    └── config.yml

/var/lib/libvirt/images/
├── rhel-academy-base.qcow2   # Read-only template
├── student-x7k9m2p4.qcow2    # Thin clone (active)
├── student-abc12345.qcow2    # Thin clone (active)
└── ...
```

---

## API Requirements (requirements.txt)

```
fastapi==0.104.1
uvicorn==0.24.0
python-libvirt==10.0.0
docker==6.1.3
pydantic==2.5.2
apscheduler==3.10.4
```

---

## Next Steps

1. Set up host server with KVM/libvirt
2. Prepare Red Hat Academy base QCOW2 image
3. Configure Cloudflare Tunnel with wildcard DNS
4. Deploy Docker Compose stack
5. Test provisioning workflow
6. (Optional) Build admin UI for instructors
