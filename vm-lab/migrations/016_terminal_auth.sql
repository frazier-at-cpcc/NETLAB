-- How the terminal authenticates, per course family.
--
-- SSH_PASSWORD is deployment-wide and holds the Red Hat Academy default,
-- which is correct for the NOS images. The CSC 228 image does not use it, so
-- the terminal failed to log in for every CSC 228 student: a real login
-- attempt returned "Permission denied". The lab provisioned, the home
-- attached, and the student got a terminal they could not use.
--
-- The orchestrator's key is already mounted into the ttyd container at
-- /keys/id_ed25519, so key authentication needs no new plumbing. The image
-- carries the matching public key in student's authorized_keys.
--
-- NULL means the deployment password, which is every other course.
ALTER TABLE lab_templates
    ADD COLUMN IF NOT EXISTS ssh_auth VARCHAR(16);

ALTER TABLE lab_templates
    DROP CONSTRAINT IF EXISTS valid_lab_template_ssh_auth;
ALTER TABLE lab_templates
    ADD CONSTRAINT valid_lab_template_ssh_auth
    CHECK (ssh_auth IS NULL OR ssh_auth IN ('password', 'key'));

UPDATE lab_templates
SET ssh_auth = 'key'
WHERE slug_prefix = 'csc228-';

GRANT ALL PRIVILEGES ON lab_templates TO lab;
