UPSERT_GRADE_CELL_SQL = """
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
RETURNING id
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
    return row["id"]
