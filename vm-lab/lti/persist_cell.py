import logging

logger = logging.getLogger(__name__)


def grade_cell_body(session_id, ctx) -> dict | None:
    if not ctx.lab_slug or not ctx.sourcedid or not ctx.outcome_service_url:
        return None
    return {
        "course_session_id": session_id,
        "lab_slug": ctx.lab_slug,
        "resource_link_id": ctx.resource_link_id,
        "outcome_service_url": ctx.outcome_service_url,
        "sourcedid": ctx.sourcedid,
        "consumer_key": ctx.consumer_key,
    }


async def persist_grade_cell(session_id, ctx, *, post) -> None:
    body = grade_cell_body(session_id, ctx)
    if body is None:
        logger.warning(
            "Skipping grade cell persist; missing fields for resource_link_id=%s",
            ctx.resource_link_id,
        )
        return
    await post(body)
