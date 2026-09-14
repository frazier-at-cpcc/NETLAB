from lti.launch_context import parse_lti11_form


def test_parse_lti11_captures_pox_and_slug():
    ctx = parse_lti11_form({
        "oauth_consumer_key": "cpcc-brightspace",
        "user_id": "u1",
        "lis_person_contact_email_primary": "a@email.cpcc.edu",
        "lis_person_name_full": "Ada",
        "context_id": "354303",
        "context_title": "NOS-120",
        "resource_link_id": "rl-cli",
        "resource_link_title": "cli-review",
        "tool_consumer_instance_guid": "brightspace.cpcc.edu",
        "custom_lab_slug": "cli-review",
        "lis_outcome_service_url": "https://brightspace.cpcc.edu/d2l/le/lti/Outcome",
        "lis_result_sourcedid": "cell-1",
        "roles": "Learner",
    })
    assert ctx.course_session_key == "brightspace.cpcc.edu:u1:354303"
    assert ctx.lab_slug == "cli-review"
    assert ctx.sourcedid == "cell-1"
    assert ctx.outcome_service_url.endswith("/Outcome")


def test_parse_lti11_without_outcome_still_builds_session_key():
    ctx = parse_lti11_form({
        "oauth_consumer_key": "cpcc-brightspace",
        "user_id": "u1",
        "context_id": "354303",
        "tool_consumer_instance_guid": "brightspace.cpcc.edu",
        "resource_link_id": "rl-x",
        "roles": "Learner",
    })
    assert ctx.course_session_key == "brightspace.cpcc.edu:u1:354303"
    assert ctx.sourcedid is None
    assert ctx.lab_slug is None
