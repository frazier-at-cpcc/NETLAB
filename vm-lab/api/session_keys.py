def course_session_key(tool_consumer_guid: str, user_id: str, course_id: str) -> str:
    if not tool_consumer_guid or not user_id or not course_id:
        raise ValueError("course session key requires guid, user_id, and course_id")
    return f"{tool_consumer_guid}:{user_id}:{course_id}"


def extract_lab_slug(form_data: dict[str, str]) -> str | None:
    raw = form_data.get("custom_lab_slug") or form_data.get("custom_custom_lab_slug")
    if raw is None:
        return None
    slug = raw.strip()
    return slug or None
