from dataclasses import dataclass

from api.session_keys import course_session_key, extract_lab_slug


@dataclass(frozen=True)
class LaunchContext:
    course_session_key: str
    user_id: str
    user_email: str
    user_name: str
    course_id: str
    course_title: str
    resource_link_id: str
    resource_link_title: str
    tool_consumer_guid: str
    consumer_key: str
    lab_slug: str | None
    outcome_service_url: str | None
    sourcedid: str | None
    roles: str


def _optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def parse_lti11_form(form_data: dict[str, str]) -> LaunchContext:
    user_id = form_data.get("user_id") or ""
    course_id = form_data.get("context_id") or ""
    if not user_id or not course_id:
        raise ValueError("LTI launch requires user_id and context_id")

    consumer_key = form_data.get("oauth_consumer_key") or ""
    tool_consumer_guid = (
        form_data.get("tool_consumer_instance_guid") or consumer_key
    )
    if not tool_consumer_guid:
        raise ValueError("LTI launch requires tool_consumer_instance_guid or oauth_consumer_key")

    return LaunchContext(
        course_session_key=course_session_key(tool_consumer_guid, user_id, course_id),
        user_id=user_id,
        user_email=form_data.get("lis_person_contact_email_primary") or "",
        user_name=form_data.get("lis_person_name_full") or "",
        course_id=course_id,
        course_title=form_data.get("context_title") or "",
        resource_link_id=form_data.get("resource_link_id") or "",
        resource_link_title=form_data.get("resource_link_title") or "",
        tool_consumer_guid=tool_consumer_guid,
        consumer_key=consumer_key,
        lab_slug=extract_lab_slug(form_data),
        outcome_service_url=_optional(form_data.get("lis_outcome_service_url")),
        sourcedid=_optional(form_data.get("lis_result_sourcedid")),
        roles=form_data.get("roles") or "",
    )
