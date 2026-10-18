-- Terminal behaviour per course family.
--
-- Three properties that differ between CSC 228 and the NOS courses, kept on
-- lab_templates so that everything a course family needs lives in one row.
--
-- session_hours: DEFAULT_SESSION_HOURS is 4 and CSC 228 labs run three to
-- four hours. A student who takes one break loses the VM mid-lab, so the
-- family asks for the 8-hour ceiling rather than changing the default under
-- every other course.
--
-- terminal_persist: ttyd spawns its command once per client connection, so
-- closing the browser tab kills the ssh session and everything running in
-- it. Wrapping the shell in `tmux new-session -A` moves it onto the VM,
-- where it survives a closed tab, a dropped network, and a different
-- machine. Opt-in because the NOS courses reach the student workstation
-- through a nested ssh hop, which is a different shape.
--
-- terminal_recording: the NOS courses record terminal sessions. CSC 228
-- does not, so no `script` wrapper is started and no recording is finalized
-- on teardown. Defaulting to TRUE leaves every existing course recording
-- exactly as it does today.

ALTER TABLE lab_templates
    ADD COLUMN IF NOT EXISTS session_hours INTEGER,
    ADD COLUMN IF NOT EXISTS terminal_persist BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS terminal_recording BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE lab_templates
    DROP CONSTRAINT IF EXISTS valid_lab_template_hours;
ALTER TABLE lab_templates
    ADD CONSTRAINT valid_lab_template_hours
    CHECK (session_hours IS NULL OR (session_hours > 0 AND session_hours <= 8));

UPDATE lab_templates
SET session_hours = 8,
    terminal_persist = TRUE,
    terminal_recording = FALSE
WHERE slug_prefix = 'csc228-';

GRANT ALL PRIVILEGES ON lab_templates TO lab;
