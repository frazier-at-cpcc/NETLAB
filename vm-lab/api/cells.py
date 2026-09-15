import logging

logger = logging.getLogger(__name__)

UPSERT_GRADE_CELL_SQL = """
WITH previous AS (
    SELECT sourcedid
    FROM grade_cells
    WHERE course_session_id = $1 AND lab_slug = $2
)
INSERT INTO grade_cells (
    course_session_id, lab_slug, resource_link_id,
    outcome_service_url, sourcedid, consumer_key
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (course_session_id, lab_slug)
DO UPDATE SET
    resource_link_id = EXCLUDED.resource_link_id,
    outcome_service_url = EXCLUDED.outcome_service_url,
    sourcedid = EXCLUDED.sourcedid,
    consumer_key = EXCLUDED.consumer_key,
    updated_at = CURRENT_TIMESTAMP
RETURNING id, (SELECT sourcedid FROM previous) AS previous_sourcedid
"""


async def upsert_grade_cell(
    db,
    *,
    course_session_id,
    lab_slug,
    resource_link_id,
    outcome_service_url,
    sourcedid,
    consumer_key,
) -> int | None:
    if lab_slug is None or sourcedid is None:
        return None
    row = await db.fetchrow(
        UPSERT_GRADE_CELL_SQL,
        course_session_id,
        lab_slug,
        resource_link_id,
        outcome_service_url,
        sourcedid,
        consumer_key,
    )
    if row is None:
        return None

    # The broker mints a distinct sourcedid per resource link. If an
    # instructor pastes the same route on two links, a student's second
    # launch overwrites the first cell's sourcedid here. Overwriting is
    # correct for the ordinary relaunch case, but it silently orphans the
    # first sourcedid's grade column forever, so an operator needs a
    # trail to find it. Never log the sourcedid value itself.
    previous_sourcedid = row["previous_sourcedid"]
    if previous_sourcedid is not None and previous_sourcedid != sourcedid:
        logger.warning(
            "grade cell sourcedid changed on relaunch for "
            "course_session_id=%s lab_slug=%s; the prior sourcedid's "
            "grade column is now orphaned",
            course_session_id,
            lab_slug,
        )

    return row["id"]
