-- Who the terminal connects as, per course family.
--
-- SSH_USER and NESTED_SSH_ENABLED were deployment-wide. They default to
-- kiosk and true, which is correct for the Red Hat Academy images: the
-- terminal lands on the outer VM as kiosk and jumps to student@workstation
-- inside it.
--
-- CSC 228 has no nested VM and no kiosk user. With the deployment defaults
-- a launch runs `ssh kiosk@<vm-ip> ssh student@workstation`, where neither
-- the user nor the host exists, so the terminal fails and the tmux session
-- that persistence depends on is never created. The course cannot work
-- until this is per-family.
--
-- NULL means "use the deployment default", so every course without a row
-- behaves exactly as it does today.

ALTER TABLE lab_templates
    ADD COLUMN IF NOT EXISTS ssh_user VARCHAR(64),
    ADD COLUMN IF NOT EXISTS nested_ssh BOOLEAN;

UPDATE lab_templates
SET ssh_user = 'student',
    nested_ssh = FALSE
WHERE slug_prefix = 'csc228-';

GRANT ALL PRIVILEGES ON lab_templates TO lab;
