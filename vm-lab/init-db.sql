-- ============================================================================
-- LTI Database Schema
-- ============================================================================

\c lti;

-- LTI 1.1 Consumer Keys and Secrets
CREATE TABLE IF NOT EXISTS lti11_consumers (
    id SERIAL PRIMARY KEY,
    consumer_key VARCHAR(255) UNIQUE NOT NULL,
    consumer_secret VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast lookup
CREATE INDEX IF NOT EXISTS idx_lti11_consumers_key ON lti11_consumers(consumer_key);

-- LTI 1.1 Nonces for replay attack prevention
CREATE TABLE IF NOT EXISTS lti11_nonces (
    id SERIAL PRIMARY KEY,
    consumer_key VARCHAR(255) NOT NULL,
    nonce VARCHAR(255) NOT NULL,
    timestamp_val INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(consumer_key, nonce, timestamp_val)
);

-- Index for nonce cleanup
CREATE INDEX IF NOT EXISTS idx_lti11_nonces_created ON lti11_nonces(created_at);
CREATE INDEX IF NOT EXISTS idx_lti11_nonces_lookup ON lti11_nonces(consumer_key, nonce, timestamp_val);

-- LTI 1.3 Platform Registrations
CREATE TABLE IF NOT EXISTS lti13_platforms (
    id SERIAL PRIMARY KEY,
    issuer VARCHAR(512) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    deployment_id VARCHAR(255),
    auth_login_url TEXT NOT NULL,
    auth_token_url TEXT NOT NULL,
    key_set_url TEXT NOT NULL,
    name VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_lti13_platforms_issuer ON lti13_platforms(issuer);

-- LTI 1.3 Nonces
CREATE TABLE IF NOT EXISTS lti13_nonces (
    id SERIAL PRIMARY KEY,
    nonce VARCHAR(255) UNIQUE NOT NULL,
    state VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_lti13_nonces_expires ON lti13_nonces(expires_at);

-- All LTI Launch Records (Audit Log)
CREATE TABLE IF NOT EXISTS lti_launches (
    id SERIAL PRIMARY KEY,
    lti_version VARCHAR(10) NOT NULL,
    consumer_key VARCHAR(255),
    issuer VARCHAR(512),
    user_id VARCHAR(255) NOT NULL,
    user_email VARCHAR(255),
    user_name VARCHAR(255),
    roles TEXT,
    course_id VARCHAR(255),
    course_title VARCHAR(255),
    resource_link_id VARCHAR(255),
    resource_link_title VARCHAR(255),
    tool_consumer_instance_guid VARCHAR(255),
    session_key VARCHAR(512) NOT NULL,
    vm_session_id VARCHAR(64),
    client_ip VARCHAR(45),
    user_agent TEXT,
    launched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_lti_launches_session_key ON lti_launches(session_key);
CREATE INDEX IF NOT EXISTS idx_lti_launches_user ON lti_launches(user_id);
CREATE INDEX IF NOT EXISTS idx_lti_launches_course ON lti_launches(course_id);
CREATE INDEX IF NOT EXISTS idx_lti_launches_time ON lti_launches(launched_at);

-- Session state for LTI 1.3 OIDC flow
CREATE TABLE IF NOT EXISTS lti13_session_state (
    id SERIAL PRIMARY KEY,
    state VARCHAR(255) UNIQUE NOT NULL,
    session_data JSONB NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_lti13_session_state_expires ON lti13_session_state(expires_at);

-- Function to clean up old nonces (run periodically)
CREATE OR REPLACE FUNCTION cleanup_old_nonces() RETURNS void AS $$
BEGIN
    -- Delete LTI 1.1 nonces older than 90 minutes
    DELETE FROM lti11_nonces WHERE created_at < NOW() - INTERVAL '90 minutes';

    -- Delete expired LTI 1.3 nonces
    DELETE FROM lti13_nonces WHERE expires_at < NOW();

    -- Delete expired session states
    DELETE FROM lti13_session_state WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Lab/VM Session Database Schema
-- ============================================================================

\c lab;

-- VM Sessions
CREATE TABLE IF NOT EXISTS vm_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) UNIQUE NOT NULL,
    session_key VARCHAR(512),

    -- User information
    user_id VARCHAR(255),
    user_email VARCHAR(255),
    user_name VARCHAR(255),

    -- Course/Assignment context
    course_id VARCHAR(255),
    course_title VARCHAR(255),
    assignment_id VARCHAR(255),
    assignment_title VARCHAR(255),

    -- VM details
    vm_ip VARCHAR(45),
    vm_name VARCHAR(128),
    vm_uuid VARCHAR(36),
    overlay_path TEXT,

    -- Container details
    container_id VARCHAR(128),
    container_name VARCHAR(128),
    ttyd_port INTEGER,

    -- Access URL
    url TEXT NOT NULL,

    -- Status tracking
    status VARCHAR(32) DEFAULT 'provisioning',
    status_message TEXT,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    last_accessed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    destroyed_at TIMESTAMP WITH TIME ZONE,

    -- Constraints
    CONSTRAINT valid_status CHECK (status IN ('provisioning', 'starting', 'running', 'stopping', 'stopped', 'destroyed', 'error'))
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_vm_sessions_session_key ON vm_sessions(session_key);
CREATE INDEX IF NOT EXISTS idx_vm_sessions_user ON vm_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_vm_sessions_status ON vm_sessions(status);
CREATE INDEX IF NOT EXISTS idx_vm_sessions_expires ON vm_sessions(expires_at) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS idx_vm_sessions_course ON vm_sessions(course_id);

-- VM Session Events (Audit Log)
CREATE TABLE IF NOT EXISTS vm_session_events (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES vm_sessions(session_id),
    event_type VARCHAR(64) NOT NULL,
    event_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vm_events_session ON vm_session_events(session_id);
CREATE INDEX IF NOT EXISTS idx_vm_events_time ON vm_session_events(created_at);

-- Resource usage tracking
CREATE TABLE IF NOT EXISTS resource_usage (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) REFERENCES vm_sessions(session_id),
    cpu_percent DECIMAL(5,2),
    memory_mb INTEGER,
    disk_mb INTEGER,
    network_rx_bytes BIGINT,
    network_tx_bytes BIGINT,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_resource_usage_session ON resource_usage(session_id);
CREATE INDEX IF NOT EXISTS idx_resource_usage_time ON resource_usage(recorded_at);

-- IP address allocation tracking
CREATE TABLE IF NOT EXISTS ip_allocations (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    session_id VARCHAR(64) REFERENCES vm_sessions(session_id),
    allocated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT valid_ip CHECK (ip_address ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
);

CREATE INDEX IF NOT EXISTS idx_ip_allocations_available ON ip_allocations(released_at) WHERE released_at IS NULL;

-- Initialize IP pool (10.10.10.11 - 10.10.10.254)
INSERT INTO ip_allocations (ip_address)
SELECT '10.10.10.' || generate_series(11, 254)
ON CONFLICT DO NOTHING;

-- Function to allocate next available IP
CREATE OR REPLACE FUNCTION allocate_ip(p_session_id VARCHAR(64))
RETURNS VARCHAR(45) AS $$
DECLARE
    v_ip VARCHAR(45);
BEGIN
    UPDATE ip_allocations
    SET session_id = p_session_id,
        allocated_at = CURRENT_TIMESTAMP,
        released_at = NULL
    WHERE ip_address = (
        SELECT ip_address
        FROM ip_allocations
        WHERE session_id IS NULL OR released_at IS NOT NULL
        ORDER BY ip_address
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING ip_address INTO v_ip;

    RETURN v_ip;
END;
$$ LANGUAGE plpgsql;

-- Function to release IP
CREATE OR REPLACE FUNCTION release_ip(p_session_id VARCHAR(64))
RETURNS void AS $$
BEGIN
    UPDATE ip_allocations
    SET released_at = CURRENT_TIMESTAMP
    WHERE session_id = p_session_id;
END;
$$ LANGUAGE plpgsql;

-- View for active sessions with details
CREATE OR REPLACE VIEW active_sessions AS
SELECT
    s.session_id,
    s.user_name,
    s.user_email,
    s.course_title,
    s.assignment_title,
    s.vm_ip,
    s.url,
    s.status,
    s.created_at,
    s.last_accessed,
    s.expires_at,
    EXTRACT(EPOCH FROM (s.expires_at - CURRENT_TIMESTAMP)) / 60 AS minutes_remaining
FROM vm_sessions s
WHERE s.status = 'running';

-- Function to clean up expired sessions (returns list of session_ids to destroy)
CREATE OR REPLACE FUNCTION get_expired_sessions()
RETURNS TABLE(session_id VARCHAR(64)) AS $$
BEGIN
    RETURN QUERY
    SELECT s.session_id
    FROM vm_sessions s
    WHERE s.status = 'running'
      AND s.expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO lab;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO lab;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO lab;

\c lti;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO lti;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO lti;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO lti;
