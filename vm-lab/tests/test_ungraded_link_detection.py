"""Telling an ungraded lab link apart from an access link.

A whole NOS 220 term passed with every graded lab silently unable to pass
back. 463 sessions, none carrying a lab slug, and the only symptom was
`lab grade` reporting "no gradebook column" to the student, who can do
nothing about it. Both code paths returned silently, so the two
misconfigurations were indistinguishable and neither was reported.

An access link that names no lab was never going to grade anything, and
that is normal. A LAB link that carries no sourcedid means the Brightspace
item is not associated with a grade item, which costs every student in the
course every grade for that lab. Those must not look the same in a log.
"""

import inspect
import sys
import types


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
    import api.main as m
    return m


def _persist_cell_source():
    import pathlib
    return pathlib.Path("lti/persist_cell.py").read_text()


# --- the two cases are distinguished ----------------------------------


def test_an_ungraded_lab_link_is_reported_as_a_misconfiguration():
    m = _load_api_main()
    src = inspect.getsource(m)
    assert "if body.lab_slug and not body.sourcedid:" in src
    assert "NOT GRADED" in src


def test_an_access_link_is_not_reported_as_a_problem():
    """Every NOS session launches one, and crying wolf on it would bury the
    real warning."""
    m = _load_api_main()
    src = inspect.getsource(m)
    assert "Normal for an access link" in src


def test_the_warning_names_the_lab_and_the_link():
    """A warning that does not say WHICH lab cannot be acted on, because a
    course has fifteen of them."""
    m = _load_api_main()
    src = inspect.getsource(m)
    block = src.split("NOT GRADED")[1][:400]
    assert "body.lab_slug" in block
    assert "resource_link_id" in block


def test_the_warning_says_where_the_fix_is():
    """The failure is in the course, not in this service, and whoever reads
    the log will otherwise go looking in the wrong place. That is exactly
    what happened."""
    m = _load_api_main()
    assert "Fix it in the course, not here." in inspect.getsource(m)


# --- the launch path reports it too -----------------------------------


def test_the_launch_path_also_names_an_ungraded_lab():
    """The API path only sees launches that reach provisioning. The launch
    stash sees every launch, so it catches an instructor's own test click."""
    src = _persist_cell_source()
    assert "NOT GRADED" in src
    assert 'if fields.get("lab_slug"):' in src


def _store_pending_cell_body():
    """Just that function, not the rest of the module.

    Slicing to end of file swept in four unrelated warnings from other
    functions and made a count-based assertion meaningless.
    """
    src = _persist_cell_source()
    after = src.split("def store_pending_cell")[1]
    lines = after.splitlines()
    body = []
    for line in lines[1:]:
        if line.startswith("def ") or line.startswith("@"):
            break
        body.append(line)
    return "\n".join(body)


def test_the_launch_path_stays_silent_for_an_access_link():
    """The warning has to sit inside the lab_slug guard. Outside it, every
    access-link launch in both NOS courses would warn, and the real signal
    would be buried under hundreds of false ones."""
    body = _store_pending_cell_body()
    assert 'if fields.get("lab_slug"):' in body
    guard = body.index('if fields.get("lab_slug"):')
    warn = body.index("NOT GRADED")
    assert guard < warn, "the warning must be inside the lab_slug guard"
    assert body.count("NOT GRADED") == 1


def test_the_field_the_warning_reads_is_actually_stashed():
    """lab_slug has to be among the flattened fields or the warning would
    report None for every lab and be useless."""
    src = _persist_cell_source()
    fields = src.split("_PENDING_FIELDS = (")[1].split(")")[0]
    assert '"lab_slug"' in fields


# --- behaviour is unchanged -------------------------------------------


def test_nothing_is_persisted_in_either_case():
    """This adds reporting only. A launch with no outcome information still
    stores no cell, because a stale cell would pass a score to the wrong
    column."""
    m = _load_api_main()
    src = inspect.getsource(m)
    assert "return Response(status_code=204)" in src
    assert "return False" in _persist_cell_source()
