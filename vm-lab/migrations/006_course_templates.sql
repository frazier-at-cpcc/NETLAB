-- One Proxmox template per course.
--
-- Until this table exists the template is a property of the deployment:
-- PROXMOX_TEMPLATE_ID is a single environment variable and every course
-- clones from it. That is why a capability carried by one image, such as the
-- browser RDP desktop, can only be offered to every course at once.
--
-- The table is additive and holds no default row. A course with no row here
-- resolves to PROXMOX_TEMPLATE_ID and PROXMOX_TEMPLATE_SNAPSHOT, which is
-- exactly what it clones today. Keeping the default in deployment
-- configuration leaves one place to look when asking why a course cloned
-- what it cloned.

CREATE TABLE IF NOT EXISTS course_templates (
    course_id VARCHAR(255) PRIMARY KEY,
    template_id INTEGER NOT NULL,
    -- NULL keeps the deployment's snapshot name. Most mappings only change
    -- the template, and requiring a name on every row would make the common
    -- case verbose and a typo silent.
    snapshot_name VARCHAR(128),
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_course_template_id CHECK (template_id > 0)
);
