from api.session_keys import course_session_key, extract_lab_slug


def test_course_session_key_omits_resource_link():
    key = course_session_key("guid-1", "user-9", "ctx-3")
    assert key == "guid-1:user-9:ctx-3"
    assert key.count(":") == 2


def test_extract_lab_slug_from_lti11_custom_param():
    assert extract_lab_slug({"custom_lab_slug": "cli-review"}) == "cli-review"


def test_extract_lab_slug_missing_returns_none():
    assert extract_lab_slug({"resource_link_title": "Lab: cli-review"}) is None
