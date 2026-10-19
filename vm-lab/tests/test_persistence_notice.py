"""What the launch page tells a student about their files surviving.

Lab 0 points students at the launch page for this answer, so the page is
load-bearing for the lab rather than decorative. The rule is that it states
what is true of THIS session: provision_home can fail for one student while
the course is configured correctly, and that student must be told to
download their work rather than told the course keeps files.

Every unknown resolves to "not saved", because telling a student their work
is kept when it is not is the one failure that costs them the work.
"""

import pathlib
import sys
import types

PAGE = pathlib.Path("lti/templates/lab_loading.html")


def _load_api_main():
    for name, attrs in (("asyncpg", {}), ("proxmoxer", {"ProxmoxAPI": object})):
        if name not in sys.modules:
            try:
                __import__(name)
            except ImportError:
                stub = types.ModuleType(name)
                for attr, value in attrs.items():
                    setattr(stub, attr, value)
                sys.modules[name] = stub
    import api.main as lab_api_main
    return lab_api_main


def test_the_status_payload_carries_the_answer():
    api_main = _load_api_main()
    assert "persistent_home" in api_main.SessionStatus.model_fields


def test_nothing_persists_until_something_says_otherwise():
    """Default FALSE is what makes today correct with no extra work: nothing
    calls provision_home, so every session truthfully reports no
    persistence."""
    api_main = _load_api_main()
    assert api_main.SessionStatus.model_fields["persistent_home"].default is False


def test_the_answer_comes_from_the_session_row():
    import inspect
    api_main = _load_api_main()
    src = inspect.getsource(api_main.get_session_status)
    # The SELECT list specifically. Matching "home_attached" anywhere in the
    # function also matches the line that reads the value back, so dropping
    # the column from the query would otherwise pass.
    assert "started_at, home_attached" in src
    assert 'persistent_home=bool(_optional_column(row, "home_attached"))' in src


def test_an_older_database_reports_no_persistence():
    """A database still on 011 has no column. The absence must read as "not
    saved", never as saved."""
    api_main = _load_api_main()
    assert api_main._optional_column({}, "home_attached") is None
    assert bool(api_main._optional_column({}, "home_attached")) is False


def test_the_page_states_the_unsaved_case_and_names_the_action():
    """A warning that does not say what to do is not a warning."""
    page = PAGE.read_text()
    assert "Files are not saved between" in page
    assert "Download anything you want to keep" in page


def test_the_page_states_the_saved_case_and_its_limit():
    """Telling a student files are kept without saying which files invites
    them to store work outside the home."""
    page = PAGE.read_text()
    assert "Your files are saved." in page
    assert "outside" in page and "~/csc228" in page


def test_the_stop_dialog_agrees_with_the_notice():
    """The dialog and the notice are read seconds apart. Contradicting each
    other teaches a student to trust neither."""
    page = PAGE.read_text()
    assert "persistentHome" in page.split("function confirmStop()")[1]
    assert "All unsaved \\n" not in page


def test_the_unsaved_dialog_wording_is_unchanged_for_every_other_course():
    """NOS 120 and NOS 220 have no persistent home, and their dialog must
    read exactly as it does today."""
    page = PAGE.read_text()
    assert "All unsaved " in page and "work will be lost." in page


def test_the_notice_is_refreshed_on_every_poll():
    """A session that gains or loses its home mid-poll must not leave stale
    text on screen."""
    page = PAGE.read_text()
    assert "renderPersistenceNotice(data.persistent_home);" in page


def test_the_student_facing_text_uses_no_contractions():
    """Student-facing register: no contractions."""
    page = PAGE.read_text()
    for block in ("Files are not saved between", "Your files are saved."):
        assert block in page
    for bad in ("don't", "won't", "isn't", "aren't", "it's "):
        assert bad not in page.split("renderPersistenceNotice")[1].split("function confirmStop")[0]


def test_the_migration_defaults_to_not_saved():
    sql = pathlib.Path("migrations/012_home_attached.sql").read_text()
    assert "home_attached BOOLEAN NOT NULL DEFAULT FALSE" in sql


# --- notebooks -----------------------------------------------------------
#
# The notice exists because JupyterLab is enabled at boot, so a closed 8888
# is a fault rather than a service the student has not started. The route is
# withheld in that case, and without a notice the student would simply find
# a missing feature.


def test_the_page_says_nothing_when_a_course_has_no_notebooks():
    """Tri-state. Every NOS session reports null and must see no notice."""
    page = PAGE.read_text()
    block = page.split("function renderNotebookNotice")[1]
    assert "available === null" in block
    assert "undefined" in block


def test_the_page_says_nothing_when_notebooks_work():
    page = PAGE.read_text()
    block = page.split("function renderNotebookNotice")[1]
    assert "if (available) {" in block


def test_the_notice_tells_the_student_what_still_works_and_what_to_do():
    """A warning that does not say the terminal still works reads as a dead
    lab, and one without a recovery step leaves them stuck."""
    page = PAGE.read_text()
    assert "Notebooks are unavailable this " in page
    assert "The terminal works." in page
    assert "relaunch" in page


def test_the_notebook_notice_is_refreshed_on_every_poll():
    page = PAGE.read_text()
    assert "renderNotebookNotice(data.notebooks_available);" in page
