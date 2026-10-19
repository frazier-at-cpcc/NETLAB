-- Whether a course family offers the browser desktop.
--
-- The desktop is a Guacamole RDP session into the Red Hat Academy images.
-- CSC 228 has no desktop to connect to, so the button sat on the page
-- permanently disabled with a note explaining a feature that course does
-- not have. A control that can never work is worse than no control: a
-- student reads it as something broken.
--
-- NULL means the deployment default, which is every course that has one.
ALTER TABLE lab_templates
    ADD COLUMN IF NOT EXISTS desktop_enabled BOOLEAN;

UPDATE lab_templates
SET desktop_enabled = FALSE
WHERE slug_prefix = 'csc228-';

GRANT ALL PRIVILEGES ON lab_templates TO lab;

-- Recorded per session so the status endpoint answers without re-resolving
-- the template. TRUE by default, which is how every course behaved before
-- this existed.
ALTER TABLE vm_sessions
    ADD COLUMN IF NOT EXISTS desktop_supported BOOLEAN NOT NULL DEFAULT TRUE;
