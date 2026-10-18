-- One live lab per student per class.
--
-- course_session_key is tool_consumer_guid:user_id:course_id, so it already
-- names exactly "this student in this class". Nothing enforced it: provision
-- created a session every time it was called, and the only thing keeping a
-- student to one VM was that the LTI side looked for an existing session
-- first. A double click, a second tab, or a direct call to the API produced
-- a second VM.
--
-- That costs more than tidiness. Each CSC 228 VM holds 24 GB out of roughly
-- 300, so a duplicate denies a slot to another student, and two terminals
-- onto two different VMs is a student doing the lab twice and submitting
-- from whichever one they happen to be looking at.
--
-- A partial unique index is what makes this safe under a race, because the
-- application check and the insert cannot be atomic across two requests.
-- Destroyed and errored sessions are excluded, so a student can start again
-- once the previous one ends.

CREATE UNIQUE INDEX IF NOT EXISTS one_live_session_per_course_key
    ON vm_sessions (course_session_key)
    WHERE course_session_key IS NOT NULL
      AND status IN ('provisioning', 'starting', 'running');
