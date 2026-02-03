-- ============================================================================
-- Migration: Add Console Access Support (VNC/SPICE)
-- ============================================================================
-- Run this migration on existing databases to add console tracking support.
--
-- Usage: psql -U lab -d lab -f 001_add_console_support.sql
-- ============================================================================

-- Add console columns to vm_sessions table
DO $$
BEGIN
    -- Add console_enabled flag
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'vm_sessions' AND column_name = 'console_enabled') THEN
        ALTER TABLE vm_sessions ADD COLUMN console_enabled BOOLEAN DEFAULT TRUE;
        RAISE NOTICE 'Added column: console_enabled';
    ELSE
        RAISE NOTICE 'Column already exists: console_enabled';
    END IF;

    -- Add console_last_connected_at timestamp
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'vm_sessions' AND column_name = 'console_last_connected_at') THEN
        ALTER TABLE vm_sessions ADD COLUMN console_last_connected_at TIMESTAMP WITH TIME ZONE;
        RAISE NOTICE 'Added column: console_last_connected_at';
    ELSE
        RAISE NOTICE 'Column already exists: console_last_connected_at';
    END IF;

    -- Add default_console_protocol
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'vm_sessions' AND column_name = 'default_console_protocol') THEN
        ALTER TABLE vm_sessions ADD COLUMN default_console_protocol VARCHAR(10) DEFAULT 'vnc';
        RAISE NOTICE 'Added column: default_console_protocol';
    ELSE
        RAISE NOTICE 'Column already exists: default_console_protocol';
    END IF;
END $$;

-- Create console_connections table
CREATE TABLE IF NOT EXISTS console_connections (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES vm_sessions(session_id),

    -- Connection details
    protocol VARCHAR(10) NOT NULL,  -- 'vnc' or 'spice'
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    disconnected_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,

    -- Client information
    client_ip VARCHAR(45),
    user_agent TEXT,
    client_info JSONB,  -- Additional client details (browser, resolution, etc.)

    CONSTRAINT valid_protocol CHECK (protocol IN ('vnc', 'spice'))
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_console_connections_session ON console_connections(session_id);
CREATE INDEX IF NOT EXISTS idx_console_connections_protocol ON console_connections(protocol);
CREATE INDEX IF NOT EXISTS idx_console_connections_time ON console_connections(connected_at);

-- Create or replace the console usage statistics view
CREATE OR REPLACE VIEW console_usage_stats AS
SELECT
    s.session_id,
    s.user_name,
    s.user_email,
    s.course_title,
    c.protocol,
    COUNT(*) as connection_count,
    SUM(c.duration_seconds) as total_duration_seconds,
    MIN(c.connected_at) as first_connection,
    MAX(c.connected_at) as last_connection
FROM vm_sessions s
JOIN console_connections c ON s.session_id = c.session_id
GROUP BY s.session_id, s.user_name, s.user_email, s.course_title, c.protocol;

-- Grant permissions
GRANT ALL PRIVILEGES ON console_connections TO lab;
GRANT ALL PRIVILEGES ON console_connections_id_seq TO lab;
GRANT SELECT ON console_usage_stats TO lab;

-- Report migration complete
DO $$
BEGIN
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Migration 001_add_console_support.sql completed successfully!';
    RAISE NOTICE '========================================';
END $$;
