-- Persistent homes, per course family.
--
-- CSC 228 keeps each student's work on a NAS VM so it survives the lab VM
-- being destroyed at expiry or reclaimed as idle. No other course has this,
-- and a course that does not must never attempt it, because the attach runs
-- a script that only the CSC 228 image carries.
--
-- The home key is recorded on the session. Teardown has to revoke exactly
-- the key it granted, and recomputing it then would silently revoke the
-- wrong directory if the derivation ever changed between provision and
-- destroy.

ALTER TABLE lab_templates
    ADD COLUMN IF NOT EXISTS persistent_home BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE vm_sessions
    ADD COLUMN IF NOT EXISTS home_key VARCHAR(32);

UPDATE lab_templates
SET persistent_home = TRUE
WHERE slug_prefix = 'csc228-';

GRANT ALL PRIVILEGES ON lab_templates TO lab;
