-- Backfill provenance. A delivery that came from record-store history must be
-- distinguishable from one a student earned through the token channel, because
-- reconciliation keys on that difference.
ALTER TABLE grade_events
  ADD COLUMN IF NOT EXISTS provenance VARCHAR(32) NOT NULL DEFAULT 'token';

-- One attempt per cell, whatever its outcome. A cell whose student has no
-- history must not cause a store query on every later launch.
ALTER TABLE grade_cells
  ADD COLUMN IF NOT EXISTS backfill_attempted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_grade_cells_backfill_pending
  ON grade_cells (id) WHERE backfill_attempted_at IS NULL;
