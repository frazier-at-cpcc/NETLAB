-- Reclaiming abandoned lab VMs.
--
-- Eight-hour sessions exist for the student who genuinely works a long lab,
-- not for the one who walked away. Nothing reclaimed a session early, so a
-- student who finished in two hours held 24 GB for the remaining six.
--
-- tmux made this harder to see rather than easier: closing the tab is now
-- the right thing to do, because the shell survives it, so abandonment is
-- both invisible and durable.
--
-- Opt-in per course family. NULL means never reclaim, which is every course
-- except the one that asks for it.

ALTER TABLE lab_templates
    ADD COLUMN IF NOT EXISTS idle_reclaim_minutes INTEGER;

ALTER TABLE lab_templates
    DROP CONSTRAINT IF EXISTS valid_lab_template_idle;
ALTER TABLE lab_templates
    ADD CONSTRAINT valid_lab_template_idle
    CHECK (idle_reclaim_minutes IS NULL OR idle_reclaim_minutes >= 15);

-- The reaper has to know which family a session belongs to, and the session
-- row did not record the slug it was launched from.
ALTER TABLE vm_sessions
    ADD COLUMN IF NOT EXISTS lab_slug VARCHAR(128);

-- When every signal first agreed the session was abandoned. Cleared the
-- moment any signal reports activity, so the window measures continuous
-- idleness rather than time since launch.
ALTER TABLE vm_sessions
    ADD COLUMN IF NOT EXISTS idle_since TIMESTAMPTZ;

-- Why the VM went away. A student who returns to a destroyed session can be
-- told it was reclaimed as idle; silent destruction looks like a crash.
ALTER TABLE vm_sessions
    ADD COLUMN IF NOT EXISTS destroyed_reason VARCHAR(64);

UPDATE lab_templates
SET idle_reclaim_minutes = 45
WHERE slug_prefix = 'csc228-';

GRANT ALL PRIVILEGES ON lab_templates TO lab;
