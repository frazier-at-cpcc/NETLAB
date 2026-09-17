-- Access records for a VM session, one row per access mode.
--
-- vm_sessions.url stays as it is. It remains the terminal URL and the
-- compatibility alias that the launch page and the instructor dashboard
-- already read. This table holds what that single column cannot: a second
-- mode, its lifetime, and the server-side connection details that the
-- browser must never receive.
--
-- Nothing in the token_hash, rdp_host, or credential_ref columns is ever
-- logged or returned to a student-facing response.

CREATE TABLE IF NOT EXISTS vm_session_access (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES vm_sessions(session_id),
    mode VARCHAR(16) NOT NULL,

    -- Public surface. The URL a student is sent to, and the Traefik route
    -- that has to be torn down with the session.
    url TEXT,
    route_id VARCHAR(128),

    -- Gateway surface. token_hash is a hash of the single-use browser
    -- token. The token itself is never stored, so a database read cannot
    -- reconstruct one.
    gateway_connection_id VARCHAR(128),
    token_hash VARCHAR(64),

    -- Private target. Reachable only from the gateway to guacd.
    rdp_host VARCHAR(45),
    rdp_port INTEGER,
    credential_ref TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_accessed TIMESTAMPTZ,

    CONSTRAINT valid_access_mode CHECK (mode IN ('terminal', 'desktop')),
    CONSTRAINT valid_access_rdp_port
      CHECK (rdp_port IS NULL OR rdp_port BETWEEN 1 AND 65535),
    UNIQUE (session_id, mode)
);

-- Token lookup is the hot path on every desktop connect, and it must find
-- at most one live row.
CREATE UNIQUE INDEX IF NOT EXISTS idx_vm_session_access_token
  ON vm_session_access (token_hash)
  WHERE token_hash IS NOT NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_vm_session_access_session
  ON vm_session_access (session_id);

CREATE INDEX IF NOT EXISTS idx_vm_session_access_expiry
  ON vm_session_access (expires_at)
  WHERE revoked_at IS NULL;
