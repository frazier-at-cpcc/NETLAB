-- The pre-migration session_key is guid:user_id:context_id:resource_link_id.
-- The course session key is the same value without the final segment.
-- Only rows that can still be reused are worth backfilling.
UPDATE vm_sessions
   SET course_session_key = regexp_replace(session_key, ':[^:]*$', '')
 WHERE course_session_key IS NULL
   AND session_key IS NOT NULL
   AND session_key <> ''
   AND array_length(string_to_array(session_key, ':'), 1) = 4
   AND status IN ('provisioning', 'starting', 'running');
