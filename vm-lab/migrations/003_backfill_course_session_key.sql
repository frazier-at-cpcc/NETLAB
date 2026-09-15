-- The pre-migration session_key is guid:user_id:context_id:resource_link_id.
-- The course session key is the same value without the final segment.
-- Only rows that can still be reused are worth backfilling.
--
-- Operator note: apply this with `psql -v ON_ERROR_STOP=1` or an equivalent
-- guard. In default autocommit mode, psql prints a constraint violation and
-- still exits 0, so a failed migration looks identical to a successful one
-- and the next cutover step proceeds against an unmigrated database.
--
-- Two reusable sessions for the same student and course that arrived
-- through different resource links will backfill to the same value. The
-- partial unique index idx_vm_sessions_course_key_running rejects the
-- second write, and the whole statement then fails atomically: nothing
-- changes, including rows that had no part in the collision. Detect and
-- resolve this before running the migration rather than at cutover.
UPDATE vm_sessions
   SET course_session_key = regexp_replace(session_key, ':[^:]*$', '')
 WHERE course_session_key IS NULL
   AND session_key IS NOT NULL
   AND session_key <> ''
   -- The part-count guard rejects malformed keys instead of mangling them.
   -- Without it, a five-part key would have only its last segment
   -- stripped, silently producing a corrupted four-part value that still
   -- carries resource-link data.
   AND array_length(string_to_array(session_key, ':'), 1) = 4
   AND status IN ('provisioning', 'starting', 'running');
