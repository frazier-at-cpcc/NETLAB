-- Per-course clone shape.
--
-- Until these columns exist the shape is a property of the deployment:
-- VM_RAM_MB and VM_VCPUS are single environment variables and every course
-- clones at the same size. Two courses on one host cannot differ, which is
-- the state CSC-228 breaks. Its labs measure inference performance and
-- assume 8 vCPUs and 24 GB; the NOS deployment default is 4 and 16 GB.
--
-- Additive, exactly like 006. NULL in either column keeps the deployment
-- default, so every existing course clones what it clones today.
--
-- sockets is deliberately absent. clone_vm pins sockets to 1 and passes
-- cores as the whole vCPU count, because Proxmox multiplies the two. The
-- template's own socket count would otherwise silently double the request:
-- cores=8 against a 2-socket template yields 16 vCPUs, not 8.

ALTER TABLE course_templates
    ADD COLUMN IF NOT EXISTS cores INTEGER,
    ADD COLUMN IF NOT EXISTS memory_mb INTEGER;

ALTER TABLE course_templates
    DROP CONSTRAINT IF EXISTS valid_course_template_cores;
ALTER TABLE course_templates
    ADD CONSTRAINT valid_course_template_cores
    CHECK (cores IS NULL OR cores > 0);

ALTER TABLE course_templates
    DROP CONSTRAINT IF EXISTS valid_course_template_memory;
ALTER TABLE course_templates
    ADD CONSTRAINT valid_course_template_memory
    CHECK (memory_mb IS NULL OR memory_mb >= 1024);

-- 006 records why this grant is repeated: init-db.sql grants only on tables
-- that exist when it runs, and a column added later inherits the table grant,
-- but re-stating it costs nothing and survives a rebuilt database.
GRANT ALL PRIVILEGES ON course_templates TO lab;
