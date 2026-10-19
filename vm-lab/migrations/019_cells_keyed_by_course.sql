-- Let a student grade any lab they have opened, from any session.
--
-- A grade cell belonged to one VM session: grades.py joins
-- course_session_id straight against vm_sessions.session_id. In NOS 220 a
-- student runs fifteen labs inside one workstation VM, so only the single
-- lab whose link they clicked could pass back. Everything else reported
-- "no gradebook column", which reads to the student as a broken lab and
-- tells them nothing about the cause.
--
-- course_key is the stable guid:user:course value, so every lab link a
-- student opens leaves a cell they keep.
--
-- Added ALONGSIDE rather than replacing course_session_id. Rewriting that
-- column would collapse 332 of 640 cells, because students relaunch the
-- same lab many times and each launch mints a new sourcedid, and all 690
-- grade events hang off the cells that would vanish. A term of real grades
-- is not worth a tidier key.
ALTER TABLE grade_cells
    ADD COLUMN IF NOT EXISTS course_key VARCHAR(255);

UPDATE grade_cells c
SET course_key = s.course_session_key
FROM vm_sessions s
WHERE s.session_id = c.course_session_id
  AND c.course_key IS NULL
  AND s.course_session_key IS NOT NULL;

-- The lookup takes the newest cell for a student, course and lab, so a
-- relaunch supersedes rather than duplicates.
CREATE INDEX IF NOT EXISTS grade_cells_course_key_slug
    ON grade_cells (course_key, lab_slug, created_at DESC);
