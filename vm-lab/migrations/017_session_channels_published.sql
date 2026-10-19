-- Which channels a session actually published.
--
-- The routes were being written and nothing told the page about them, so a
-- CSC 228 student had a working JupyterLab at jupyter-<id>.<domain> and no
-- way to reach it: the launch page offered only Open Terminal and Open
-- Desktop. notebooks_available answered "are notebooks reachable" but not
-- "what else was published", so Lab 7's Open WebUI had no answer at all.
--
-- Comma separated, matching lab_templates.channels. NULL means the terminal
-- only, which is every course that asks for no channels.
ALTER TABLE vm_sessions
    ADD COLUMN IF NOT EXISTS channels_published VARCHAR(128);
