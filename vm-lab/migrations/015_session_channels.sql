-- Which VM-side channels a course family publishes.
--
-- The channel plumbing existed but nothing asked for it: every call passed
-- no channels, so only the terminal was ever routed. CSC 228 needs
-- JupyterLab for most labs and Open WebUI for the Lab 7 voice work.
--
-- Comma separated rather than an array, because the set is two names today
-- and a text column keeps the migration readable. NULL means the terminal
-- only, which is every other course.
ALTER TABLE lab_templates
    ADD COLUMN IF NOT EXISTS channels VARCHAR(128);

-- Whether notebooks are actually reachable this session.
--
-- Tri-state on purpose. TRUE means the Jupyter route was published, FALSE
-- means the family wanted it and port 8888 did not answer, and NULL means
-- the course does not use notebooks at all. The launch page can then warn
-- only the student whose notebooks are genuinely missing, rather than
-- warning every NOS student about a feature their course never had.
ALTER TABLE vm_sessions
    ADD COLUMN IF NOT EXISTS notebooks_available BOOLEAN;

UPDATE lab_templates
SET channels = 'jupyter,app'
WHERE slug_prefix = 'csc228-';

GRANT ALL PRIVILEGES ON lab_templates TO lab;
