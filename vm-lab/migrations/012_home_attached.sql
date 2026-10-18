-- Whether this session actually has a persistent home.
--
-- The launch page has to tell a student whether their files survive the
-- session ending, and Lab 0 points them at the page for that answer. The
-- honest source for it is not a per-course flag but what happened to THIS
-- session: provision_home can fail for one student while the course is
-- configured correctly, and a student in that session must be told to
-- download their work rather than be told the course has homes.
--
-- Defaults to FALSE, which is true of every session today, because nothing
-- calls provision_home yet. The page therefore tells students to download
-- their work until the wiring lands, with no second edit needed.

ALTER TABLE vm_sessions
    ADD COLUMN IF NOT EXISTS home_attached BOOLEAN NOT NULL DEFAULT FALSE;
