# Design Document: Robust VM Lifecycle Management

**Date**: 2026-02-08
**Status**: PROPOSED
**Triggered by**: Production incident — 30 orphaned VMs accumulated when DHCP server failed

---

## 1. Executive Summary

On 2026-02-08, a DHCP server outage on the 172.16.120.0/24 management network caused 30 VMs to be cloned and started in Proxmox but never receive IP addresses. These VMs transitioned to `status='error'` with `status_message='IP timeout'` in the database. Because the cleanup loop (`cleanup_expired_sessions`) only targets sessions with `status='running' AND expires_at < CURRENT_TIMESTAMP`, these error-state VMs were **never cleaned up**. They continued consuming Proxmox resources (16GB RAM each, 480GB total) with no automated recovery path. Manual intervention was required to stop and delete all 30 VMs and update 32 database records.

This document proposes nine incremental improvements to the VM lifecycle, ordered by priority. The P0 improvements would have directly prevented today's incident. The remaining improvements address related resilience gaps.

---

## 2. Current State Analysis

### Session State Machine

```
provisioning -> starting -> running -> destroyed
                    |                      ^
                    +----> error            |
                                           |
                           (NO auto path) -+
```

**Key problem**: There is no automated transition from `error` to `destroyed`. Error-state sessions and their VMs persist indefinitely.

### Cleanup Loop (`api/main.py`)

```python
async def cleanup_expired_sessions(db):
    expired = await db.fetch("""
        SELECT session_id, vm_id FROM vm_sessions
        WHERE status = 'running' AND expires_at < CURRENT_TIMESTAMP
    """)
    for row in expired:
        await destroy_session_internal(db, row['session_id'], row['vm_id'])
```

This query exclusively targets `running` sessions past their expiry. Sessions in `starting`, `error`, or `provisioning` states are **invisible to cleanup** regardless of age.

### Error Handling in `finalize_provisioning()`

When provisioning fails (IP timeout, SSH timeout, etc.), the code:
1. Sets `status='error'` in the database
2. Sets `status_message` with the error reason
3. Returns — **leaving the Proxmox VM running**

No VM cleanup occurs on failure. The VM persists until manual intervention.

### VM ID Allocation

`allocate_vm_id()` queries Proxmox for all existing VMIDs and picks the first unused one. Two concurrent provisions can both select the same VMID before either clone completes, causing a conflict.

---

## 3. Proposed Improvements

### 3.1 Immediate Cleanup on Provisioning Failure [P0]

**Problem**: When `finalize_provisioning()` fails, it sets `status='error'` but leaves the VM running in Proxmox. This is the most direct cause of today's incident.

**Solution**: Extract error handling into a helper that always destroys the VM:

```python
async def fail_provisioning(db, session_id, vmid, error_message):
    """Handle provisioning failure: update DB and clean up VM."""
    logger.error(f"Provisioning failed for {session_id}: {error_message}")

    await db.execute(
        "UPDATE vm_sessions SET status = 'error', status_message = $2 "
        "WHERE session_id = $1",
        session_id, error_message
    )
    await log_event(db, session_id, 'provisioning_failed', {
        'error': error_message, 'vm_id': vmid
    })

    # Clean up the VM immediately
    if vmid and proxmox_api:
        try:
            destroy_vm(proxmox_api, vmid)
            logger.info(f"Cleaned up VM {vmid} after provisioning failure")
        except Exception as cleanup_err:
            logger.error(
                f"CRITICAL: Failed to cleanup VM {vmid} after error. "
                f"Will be cleaned by reconciliation loop. Error: {cleanup_err}"
            )
```

Replace each error path in `finalize_provisioning()` with calls to this helper.

**Impact**: If this had been in place, the 30 orphaned VMs would have been destroyed within seconds of their IP timeout.

**Files**: `api/main.py`
**Complexity**: Low (1 hour)

---

### 3.2 Error State VM Auto-Cleanup [P0]

**Problem**: Even with 3.1, edge cases can leave error-state VMs (e.g., the cleanup call itself fails). The cleanup loop should be the safety net.

**Solution**: Expand the cleanup query to also target error-state and stale starting sessions:

```sql
-- Existing: clean expired running sessions
SELECT session_id, vm_id FROM vm_sessions
WHERE status = 'running' AND expires_at < CURRENT_TIMESTAMP

UNION ALL

-- NEW: clean error-state sessions older than TTL
SELECT session_id, vm_id FROM vm_sessions
WHERE status = 'error'
  AND created_at < CURRENT_TIMESTAMP - INTERVAL '1 minute' * $1

UNION ALL

-- NEW: clean stale starting sessions (stuck provisioning)
SELECT session_id, vm_id FROM vm_sessions
WHERE status = 'starting'
  AND created_at < CURRENT_TIMESTAMP - INTERVAL '1 minute' * $2
```

**New configuration**:

| Variable | Default | Description |
|----------|---------|-------------|
| `ERROR_STATE_TTL_MINUTES` | `30` | Auto-cleanup error-state sessions after this many minutes |
| `STALE_STARTING_TTL_MINUTES` | `20` | Auto-cleanup stuck starting sessions after this many minutes |

**Files**: `api/main.py`
**Complexity**: Low (1-2 hours)

---

### 3.3 Proxmox-to-DB State Reconciliation [P0]

**Problem**: VMs can exist in Proxmox with no matching active DB record (orphans from crashes, failed destroys, manual operations). Conversely, the DB can show sessions as `running` when the VM no longer exists in Proxmox (ghosts).

**Solution**: Add a periodic reconciliation task (every 15 minutes) that:

1. Queries Proxmox for all VMs in the managed VMID range
2. Queries the DB for all non-destroyed sessions
3. **Orphans** (VM in Proxmox, no active session): Destroy the VM
4. **Ghosts** (Session says running, VM gone): Mark session as destroyed, clean up container

```python
RECONCILIATION_INTERVAL_SECONDS = int(os.getenv("RECONCILIATION_INTERVAL_SECONDS", "900"))

async def reconcile_proxmox_db(db):
    if not proxmox_api:
        return

    # Single API call to get all VMs
    all_vms = proxmox_api.cluster.resources.get(type='vm')
    proxmox_vmids = {
        vm['vmid'] for vm in all_vms
        if VM_ID_START <= vm['vmid'] < VM_ID_END
        and vm['vmid'] != PROXMOX_TEMPLATE_ID
    }

    # Get all active sessions from DB
    active_sessions = await db.fetch("""
        SELECT session_id, vm_id FROM vm_sessions
        WHERE status NOT IN ('destroyed') AND vm_id IS NOT NULL
    """)
    db_vmids = {row['vm_id']: row['session_id'] for row in active_sessions}

    # Destroy orphan VMs
    for vmid in (proxmox_vmids - set(db_vmids.keys())):
        logger.warning(f"Reconciliation: destroying orphaned VM {vmid}")
        destroy_vm(proxmox_api, vmid)

    # Fix ghost sessions
    for vm_id, session_id in db_vmids.items():
        if vm_id not in proxmox_vmids:
            logger.warning(f"Reconciliation: ghost session {session_id} (VM {vm_id} gone)")
            await db.execute(
                "UPDATE vm_sessions SET status='destroyed', destroyed_at=NOW() "
                "WHERE session_id = $1", session_id
            )
            destroy_ttyd_container(session_id)
```

**Safety guard**: Excludes VMIDs outside `[VM_ID_START, VM_ID_END)` and the template VM.

**Files**: `api/main.py`
**Complexity**: Medium (2-3 hours)

---

### 3.4 Retry with Exponential Backoff [P1]

**Problem**: Transient Proxmox API failures (network blip, brief overload) cause immediate provisioning failure with no retry.

**Solution**: Add a retry utility for Proxmox operations:

```python
MAX_RETRIES = int(os.getenv("PROXMOX_MAX_RETRIES", "3"))
RETRY_BASE_DELAY = float(os.getenv("PROXMOX_RETRY_BASE_DELAY", "2.0"))

async def retry_proxmox(name, func, *args, **kwargs):
    for attempt in range(MAX_RETRIES + 1):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY * (2 ** attempt) + random.uniform(0, 1)
                logger.warning(f"Proxmox '{name}' failed (attempt {attempt+1}), retrying in {delay:.1f}s: {e}")
                await asyncio.sleep(delay)
            else:
                raise
```

Apply to: `clone_vm()`, `start_vm()`, `destroy_vm()`, `wait_for_task()`.

**Files**: `api/main.py`
**Complexity**: Medium (2-3 hours)

---

### 3.5 VM ID Allocation with DB Locking [P1]

**Problem**: `allocate_vm_id()` has a race condition — two concurrent provisions can pick the same VMID.

**Solution**: Use a database table with `FOR UPDATE SKIP LOCKED` (same pattern as existing `ip_allocations`):

```sql
CREATE TABLE IF NOT EXISTS vmid_allocations (
    vmid INTEGER PRIMARY KEY,
    session_id VARCHAR(64),
    allocated_at TIMESTAMP WITH TIME ZONE,
    released_at TIMESTAMP WITH TIME ZONE
);

-- Populate pool
INSERT INTO vmid_allocations (vmid)
SELECT generate_series(1000, 9998)
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION allocate_vmid(p_session_id VARCHAR(64))
RETURNS INTEGER AS $$
DECLARE v_vmid INTEGER;
BEGIN
    UPDATE vmid_allocations
    SET session_id = p_session_id, allocated_at = NOW(), released_at = NULL
    WHERE vmid = (
        SELECT vmid FROM vmid_allocations
        WHERE session_id IS NULL OR released_at IS NOT NULL
        ORDER BY vmid LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING vmid INTO v_vmid;
    RETURN v_vmid;
END;
$$ LANGUAGE plpgsql;
```

**Files**: `init-db.sql`, `api/main.py`
**Complexity**: Medium (2-3 hours)

---

### 3.6 Circuit Breaker for Proxmox API [P1]

**Problem**: When Proxmox is down, every provision request makes an API call, waits for timeout, and fails. No mechanism to fail fast.

**Solution**: Simple circuit breaker with three states: CLOSED (normal), OPEN (fail fast), HALF_OPEN (testing recovery).

```python
class ProxmoxCircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=60.0):
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0.0
        # ... (standard circuit breaker logic)

    def can_execute(self) -> bool: ...
    def record_success(self): ...
    def record_failure(self): ...
```

Usage in provision endpoint:
```python
if not proxmox_circuit.can_execute():
    raise HTTPException(503, "Lab infrastructure temporarily unavailable")
```

Expose state in `/health` endpoint.

**Files**: `api/main.py`
**Complexity**: Medium (2-3 hours)

---

### 3.7 Active Health Monitoring [P1]

**Problem**: If a VM crashes mid-session, the student's terminal hangs indefinitely. No detection mechanism exists.

**Solution**: Periodic check (every 60s) using a single Proxmox `cluster.resources.get()` call:

```python
async def check_running_sessions(db):
    all_vms = proxmox_api.cluster.resources.get(type='vm')
    running_vmids = {vm['vmid'] for vm in all_vms if vm.get('status') == 'running'}

    sessions = await db.fetch(
        "SELECT session_id, vm_id FROM vm_sessions WHERE status='running' AND vm_id IS NOT NULL"
    )

    for row in sessions:
        if row['vm_id'] not in running_vmids:
            await db.execute(
                "UPDATE vm_sessions SET status='error', status_message='vm_unhealthy' "
                "WHERE session_id = $1", row['session_id']
            )
```

**New configuration**:

| Variable | Default | Description |
|----------|---------|-------------|
| `HEALTH_CHECK_INTERVAL_SECONDS` | `60` | How often to verify running VMs are still alive |
| `HEALTH_CHECK_ENABLED` | `true` | Enable/disable health monitoring |

**Files**: `api/main.py`
**Complexity**: Low-Medium (1-2 hours)

---

### 3.8 Metrics and Observability [P2]

**Problem**: No structured way to detect resource exhaustion or high error rates before they become incidents.

**Solution**: Extend the `/health` endpoint with operational metrics:

```python
{
    "status": "healthy",
    "sessions_running": 5,
    "sessions_starting": 2,
    "sessions_error": 0,
    "sessions_error_last_hour": 0,
    "proxmox_managed_vms": 7,
    "circuit_breaker_state": "closed",
    "cleanup_loop_last_run": "2026-02-08T21:30:00Z",
    "reconciliation_last_run": "2026-02-08T21:25:00Z"
}
```

Future phases could add Prometheus metrics and webhook alerting.

**Files**: `api/main.py`
**Complexity**: Low (1 hour)

---

### 3.9 Graceful Shutdown [P2]

**Problem**: When the API container stops, in-flight provisioning tasks are abruptly cancelled, potentially leaving VMs in partial state.

**Solution**: Track active provisioning tasks and drain them during shutdown:

```python
active_provisions: set = set()

# In lifespan shutdown:
if active_provisions:
    logger.info(f"Waiting for {len(active_provisions)} active provisions...")
    done, pending = await asyncio.wait(active_provisions, timeout=120)
    for task in pending:
        task.cancel()
```

Reject new provisions during shutdown with HTTP 503.

**Files**: `api/main.py`
**Complexity**: Medium (2-3 hours)

---

## 4. Implementation Sequence

### Sprint 1: Stop the Bleeding (P0)

| # | Improvement | Est. Time |
|---|-------------|-----------|
| 1 | Immediate cleanup on provisioning failure (3.1) | 1 hr |
| 2 | Error state VM auto-cleanup (3.2) | 2 hrs |
| 3 | Proxmox-to-DB state reconciliation (3.3) | 3 hrs |

**After Sprint 1**: The system will never leave orphaned VMs after provisioning failures, will auto-clean error-state VMs within 30 minutes, and will detect/fix any VM-DB inconsistencies every 15 minutes.

### Sprint 2: Resilience (P1)

| # | Improvement | Est. Time |
|---|-------------|-----------|
| 4 | VM ID allocation with DB locking (3.5) | 3 hrs |
| 5 | Retry with exponential backoff (3.4) | 3 hrs |
| 6 | Circuit breaker (3.6) | 3 hrs |
| 7 | Active health monitoring (3.7) | 2 hrs |

### Sprint 3: Operations (P2)

| # | Improvement | Est. Time |
|---|-------------|-----------|
| 8 | Metrics and observability (3.8) | 1 hr |
| 9 | Graceful shutdown (3.9) | 3 hrs |

---

## 5. New Configuration Variables

| Variable | Default | Sprint | Description |
|----------|---------|--------|-------------|
| `ERROR_STATE_TTL_MINUTES` | `30` | 1 | Auto-cleanup error sessions after N minutes |
| `STALE_STARTING_TTL_MINUTES` | `20` | 1 | Auto-cleanup stuck starting sessions after N minutes |
| `RECONCILIATION_INTERVAL_SECONDS` | `900` | 1 | Proxmox-DB reconciliation interval |
| `PROXMOX_MAX_RETRIES` | `3` | 2 | Max retries for Proxmox API calls |
| `PROXMOX_RETRY_BASE_DELAY` | `2.0` | 2 | Base delay for exponential backoff (seconds) |
| `CIRCUIT_BREAKER_THRESHOLD` | `5` | 2 | Failures before circuit opens |
| `CIRCUIT_BREAKER_RECOVERY_SECONDS` | `60` | 2 | How long circuit stays open |
| `HEALTH_CHECK_INTERVAL_SECONDS` | `60` | 2 | Health check frequency |
| `HEALTH_CHECK_ENABLED` | `true` | 2 | Enable/disable health monitoring |

---

## 6. Database Migration (Sprint 2 only)

Sprint 1 requires **no database migration** — only Python code changes and new env vars.

Sprint 2 requires adding the `vmid_allocations` table (see section 3.5 for full SQL).

---

## 7. Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Reconciliation destroys legitimate VMs | VMID range filter excludes template and out-of-range VMs; all destroys logged |
| Error TTL too short | Default 30 min is generous; section 3.1 handles immediate cleanup anyway |
| Circuit breaker too aggressive | Threshold of 5 with 60s recovery is conservative; configurable |
| DB VMID locking causes contention | `SKIP LOCKED` avoids blocking; pool of 8999 IDs is large |
| Health check adds API load | Single `cluster.resources` call per interval, not per-session |

---

## 8. Testing Checklist

- [ ] Create a session, manually set `status='error'` in DB, verify VM is auto-destroyed within 30 minutes
- [ ] Create a VM in Proxmox in managed range with no DB record, verify reconciliation destroys it
- [ ] Destroy a VM directly in Proxmox while session is `running`, verify DB updates to `destroyed`
- [ ] Block DHCP, provision a VM, verify VM is destroyed immediately after IP timeout
- [ ] Send 5 concurrent provision requests, verify all get unique VMIDs (after Sprint 2)
- [ ] Stop Proxmox API, attempt 5+ provisions, verify circuit opens and 503 returned (after Sprint 2)
