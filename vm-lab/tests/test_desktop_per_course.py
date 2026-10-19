"""A course without a desktop should not show a desktop button.

The browser desktop is a Guacamole RDP session into the Red Hat Academy
images. CSC 228 has none, so the control sat on the page permanently
disabled beside a note explaining a feature that course does not have. A
control that can never work reads as something broken.
"""

import inspect
import pathlib
import sys
import types

PAGE = pathlib.Path("lti/templates/lab_loading.html")


def _load():
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
    return m


def test_a_course_without_a_desktop_reports_it_as_unsupported():
    m = _load()
    access = m.build_access("https://lab-x", True, desktop_supported=False)
    assert access.desktop.supported is False
    assert access.desktop.available is False
    assert access.desktop.reason == m.DESKTOP_UNSUPPORTED


def test_unsupported_is_distinct_from_not_yet_ready():
    """"This course has no desktop" and "the desktop has not come up yet"
    need different answers, or the page cannot tell hiding from waiting."""
    m = _load()
    assert m.DESKTOP_UNSUPPORTED != m.DESKTOP_PENDING
    assert m.DESKTOP_UNSUPPORTED != m.DESKTOP_NOT_PROVISIONED
    assert m.DESKTOP_UNSUPPORTED != m.DESKTOP_DISABLED


def test_every_other_course_still_reports_supported():
    """NOS 120 and NOS 220 must be unchanged."""
    m = _load()
    assert m.build_access("https://lab-x", True).desktop.supported is True


def test_no_desktop_is_registered_for_a_course_without_one():
    """Registering access to a desktop that does not exist writes a record
    nothing can use."""
    src = inspect.getsource(_load())
    assert "if desktop_supported" in src
    assert "desktop_enabled is not False" in src


def test_the_default_is_to_offer_a_desktop():
    """NULL in the column, and an older database with no column at all,
    both have to mean supported."""
    m = _load()
    choice = m.TemplateChoice(template_id=1, snapshot_name="")
    assert choice.desktop_enabled is None
    src = inspect.getsource(m.get_session_status)
    assert 'desktop_supported") is not False' in src


def test_the_page_removes_the_control_rather_than_disabling_it():
    page = PAGE.read_text()
    block = page.split("function applyDesktopAccess")[1][:800]
    assert "desktop.supported === false" in block
    assert "classList.add('hidden')" in block


def test_the_control_comes_back_for_a_course_that_has_one():
    """Hiding must not be sticky across polls, or a desktop that appears
    later would stay hidden."""
    block = PAGE.read_text().split("function applyDesktopAccess")[1][:800]
    assert "classList.remove('hidden')" in block


def test_the_migration_only_turns_it_off_for_csc228():
    sql = pathlib.Path("migrations/018_desktop_per_course.sql").read_text()
    assert "desktop_enabled = FALSE" in sql
    assert "WHERE slug_prefix = 'csc228-'" in sql
    assert "desktop_supported BOOLEAN NOT NULL DEFAULT TRUE" in sql
