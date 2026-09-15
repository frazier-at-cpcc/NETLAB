from api.session_keys import course_session_key, extract_lab_slug


def test_course_session_key_omits_resource_link():
    key = course_session_key("guid-1", "user-9", "ctx-3")
    assert key == "guid-1:user-9:ctx-3"
    assert key.count(":") == 2


def test_extract_lab_slug_from_lti11_custom_param():
    assert extract_lab_slug({"custom_lab_slug": "cli-review"}) == "cli-review"


def test_extract_lab_slug_missing_returns_none():
    assert extract_lab_slug({"resource_link_title": "Lab: cli-review"}) is None


def test_broker_resource_parameter_names_the_slug():
    assert extract_lab_slug({"custom_resource": "cli-review"}) == "cli-review"


def test_lab_slug_still_wins_over_resource():
    form = {"custom_lab_slug": "files-review", "custom_resource": "cli-review"}
    assert extract_lab_slug(form) == "files-review"


def test_custom_custom_lab_slug_still_wins_over_resource():
    form = {"custom_custom_lab_slug": "files-review", "custom_resource": "cli-review"}
    assert extract_lab_slug(form) == "files-review"


def test_whitespace_only_custom_resource_yields_none():
    assert extract_lab_slug({"custom_resource": "   "}) is None


def test_whitespace_custom_lab_slug_suppresses_custom_resource():
    # Deliberate: empty/whitespace early parameter short-circuits the chain,
    # masking valid later values. This fails safe (no cell vs. wrong routing).
    form = {"custom_lab_slug": "   ", "custom_resource": "cli-review"}
    assert extract_lab_slug(form) is None
