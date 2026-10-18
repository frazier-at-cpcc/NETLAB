-- Per-course-family templates, keyed on the lab slug prefix.
--
-- 006 keyed the template on course_id, which is derived from the Brightspace
-- course shell. That makes every new SECTION of a course a new key: a spring
-- section of CSC 228 has a different context id, matches no row, and falls
-- back to the deployment default. It boots, it runs, and it is the wrong
-- image. The failure is invisible because nothing errors.
--
-- A lab slug names the course family and outlives every shell: csc228-lab-02
-- is csc228-lab-02 in every section, every term. Matching on its prefix maps
-- a course once rather than once per shell.
--
-- Resolution order is slug prefix, then course_id, then the deployment
-- default. The course table stays because it is the only way to give one
-- shell a different image, which is what the RDP pilot used it for.

CREATE TABLE IF NOT EXISTS lab_templates (
    slug_prefix VARCHAR(64) PRIMARY KEY,
    template_id INTEGER NOT NULL,
    -- NULL keeps the deployment snapshot; empty string is a deliberate
    -- choice of none, which a template carrying no snapshot requires.
    snapshot_name VARCHAR(128),
    cores INTEGER,
    memory_mb INTEGER,
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_lab_template_id CHECK (template_id > 0),
    CONSTRAINT valid_lab_template_cores CHECK (cores IS NULL OR cores > 0),
    CONSTRAINT valid_lab_template_memory CHECK (memory_mb IS NULL OR memory_mb >= 1024),
    -- An empty prefix would match every slug in every course.
    CONSTRAINT valid_lab_template_prefix CHECK (length(slug_prefix) > 0)
);

-- See 006: init-db.sql grants only on tables that exist when it runs.
GRANT ALL PRIVILEGES ON lab_templates TO lab;

INSERT INTO lab_templates (slug_prefix, template_id, snapshot_name, cores, memory_mb, note)
VALUES ('csc228-', 2280, '', 8, 24576,
        'CSC 228 Chatbot Programming II. Covers every section, every term.')
ON CONFLICT (slug_prefix) DO NOTHING;
