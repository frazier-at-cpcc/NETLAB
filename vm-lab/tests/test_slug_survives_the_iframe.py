"""The lab slug has to survive from launch to provisioning.

Every launch field is rendered into lab_loading.html and posted back when
the student clicks Start Lab. The slug was the one field that was not: it
was read from the cookie session instead. That page runs inside a
Brightspace iframe, where a SameSite cookie is not sent cross-site, so the
slug arrived at the launch and was gone by the time the VM was provisioned.

The cost was not subtle. No slug means template resolution falls through to
the deployment default, so a CSC 228 student booted the Red Hat image; it
means no persistent home, no JupyterLab or app channel, and the Red Hat
nested-SSH identity. Every Brightspace-launched session for months carried
an empty slug.
"""

import inspect
import pathlib
import re

PAGE = pathlib.Path("lti/templates/lab_loading.html")
LTI = pathlib.Path("lti/main.py")


def _handler(name: str) -> str:
    import ast

    src = LTI.read_text()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    raise AssertionError(f"no handler named {name}")


# --- the page carries it ------------------------------------------------


def test_the_page_receives_the_slug():
    """It cannot post what it was never given."""
    assert '"lab_slug": ctx_lab_slug' in LTI.read_text()


def test_every_page_render_carries_it():
    """Three render paths lead to Start Lab. One missing is one cohort of
    students on the wrong image."""
    body = _handler("provision_or_redirect")
    assert body.count('"lab_slug": ctx_lab_slug') == body.count('"assignment_title": assignment_title,')


def test_the_page_posts_it_with_the_other_launch_fields():
    page = PAGE.read_text()
    assert re.search(r"lab_slug:\s*\"\{\{\s*lab_slug", page)


# --- the handlers read it -----------------------------------------------


def test_start_lab_prefers_the_body_over_the_cookie():
    """The body is what survives the iframe."""
    body = _handler("provision_student_vm")
    assert "lab_slug = body.get('lab_slug') or request.session.get('lab_slug', '')" in body
    assert '"lab_slug": lab_slug,' in body


def test_start_lab_no_longer_reads_the_cookie_alone():
    body = _handler("provision_student_vm")
    assert '"lab_slug": request.session.get' not in body


def test_recreate_takes_the_slug_from_the_session_row():
    """A recreate has the original row, which always has the slug. Reading
    the cookie there put the student on a different image than the lab they
    were already in."""
    body = _handler("recreate_student_session")
    assert "original_session.get('lab_slug')" in body
    assert '"lab_slug": lab_slug,' in body


def test_the_session_row_exposes_the_slug_for_recreate_to_read():
    import sys, types

    for name, attrs in (("asyncpg", {}), ("proxmoxer", {"ProxmoxAPI": object})):
        if name not in sys.modules:
            try:
                __import__(name)
            except ImportError:
                stub = types.ModuleType(name)
                for attr, value in attrs.items():
                    setattr(stub, attr, value)
                sys.modules[name] = stub
    import api.main as m

    assert "lab_slug" in m.Session.model_fields
    src = inspect.getsource(m)
    assert "SELECT session_id, url, vm_ip, status, user_name, course_title, lab_slug," in src


# --- what losing it costs ------------------------------------------------


def test_an_empty_slug_still_resolves_to_the_deployment_default():
    """Unchanged behaviour, recorded here because it is what made the loss
    silent: provisioning succeeded and booted the wrong image."""
    import sys, types

    for name, attrs in (("asyncpg", {}), ("proxmoxer", {"ProxmoxAPI": object})):
        if name not in sys.modules:
            try:
                __import__(name)
            except ImportError:
                stub = types.ModuleType(name)
                for attr, value in attrs.items():
                    setattr(stub, attr, value)
                sys.modules[name] = stub
    import api.main as m

    src = inspect.getsource(m.resolve_lab_template)
    assert "if lab_slug:" in src
