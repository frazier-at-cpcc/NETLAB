ALTER TABLE vm_sessions
  ADD COLUMN IF NOT EXISTS course_session_key VARCHAR(512),
  ADD COLUMN IF NOT EXISTS grade_token_hash VARCHAR(64);

CREATE UNIQUE INDEX IF NOT EXISTS idx_vm_sessions_course_key_running
  ON vm_sessions (course_session_key)
  WHERE status IN ('provisioning', 'starting', 'running');

CREATE TABLE IF NOT EXISTS grade_cells (
    id SERIAL PRIMARY KEY,
    course_session_id VARCHAR(64) NOT NULL REFERENCES vm_sessions(session_id),
    lab_slug VARCHAR(128) NOT NULL,
    resource_link_id VARCHAR(255) NOT NULL,
    outcome_service_url TEXT NOT NULL,
    sourcedid TEXT NOT NULL,
    consumer_key VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (course_session_id, lab_slug)
);

CREATE TABLE IF NOT EXISTS grade_events (
    id SERIAL PRIMARY KEY,
    cell_id INTEGER NOT NULL REFERENCES grade_cells(id),
    idempotency_key VARCHAR(64) NOT NULL UNIQUE,
    slug VARCHAR(128) NOT NULL,
    score_raw NUMERIC NOT NULL,
    score_max NUMERIC NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS grade_deliveries (
    id SERIAL PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES grade_events(id),
    cell_id INTEGER NOT NULL REFERENCES grade_cells(id),
    state VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error TEXT,
    delivered_at TIMESTAMPTZ,
    CONSTRAINT valid_grade_delivery_state
      CHECK (state IN ('PENDING', 'IN_FLIGHT', 'DELIVERED', 'RETRYING', 'DEAD_LETTER', 'SUPERSEDED'))
);

CREATE INDEX IF NOT EXISTS idx_grade_deliveries_due
  ON grade_deliveries (next_attempt_at)
  WHERE state IN ('PENDING', 'RETRYING');
