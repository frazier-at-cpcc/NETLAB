"""The student has to be able to reach what was published for them.

The routes were being written and nothing told the page about them, so a
CSC 228 student had a working JupyterLab at jupyter-<id>.<domain> and no way
to open it: the page offered Open Terminal and Open Desktop and nothing
else. The channel was live, correct, and invisible.
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


# --- the links are built ------------------------------------------------


def test_a_published_channel_becomes_an_openable_link():
    m = _load()
    links = m.build_channels("abc123", ("jupyter", "app"))
    assert [c.name for c in links] == ["jupyter", "app"]
    assert links[0].url == f"https://jupyter-abc123.{m.DOMAIN}"
    assert links[1].url == f"https://app-abc123.{m.DOMAIN}"


def test_the_hostname_matches_what_the_route_file_uses():
    """One label, <channel>-<session>.<domain>. If these drift the button
    points somewhere Traefik is not listening."""
    m = _load()
    route_writer = inspect.getsource(m.write_traefik_route)
    assert "{channel}-{session_id}.{domain}" in route_writer
    assert "{name}-{session_id}.{DOMAIN}" in inspect.getsource(m.build_channels)


def test_a_course_with_no_channels_gets_no_buttons():
    """Every NOS session. The page must look exactly as it does today."""
    m = _load()
    assert m.build_channels("abc123", ()) == []
    assert m.build_channels("abc123", None) == []


def test_an_unknown_channel_is_not_offered():
    """A typo in the family's channel list must not render a dead button."""
    m = _load()
    assert m.build_channels("abc123", ("jupyter-typo",)) == []


def test_nothing_is_offered_before_the_lab_is_ready():
    """A link published while the VM is still booting 502s on click."""
    m = _load()
    assert m.build_access("https://lab-x", False, session_id="x", channels=("jupyter",)).channels == []
    assert m.build_access("https://lab-x", True, session_id="x", channels=("jupyter",)).channels


def test_the_labels_say_what_the_student_is_opening():
    m = _load()
    labels = {c.name: c.label for c in m.build_channels("x", ("jupyter", "app"))}
    assert labels["jupyter"] == "Open JupyterLab"
    assert labels["app"] == "Open Web UI"


# --- the session records what it published ------------------------------


def test_what_was_published_is_recorded_on_the_session():
    """The page is told the same thing the route file was written from,
    rather than guessing from the family's configuration."""
    m = _load()
    src = inspect.getsource(m)
    assert "SET channels_published = $2" in src
    assert '",".join(published_channels)' in src


def test_the_status_reports_the_recorded_channels():
    m = _load()
    src = inspect.getsource(m.get_session_status)
    assert "channels_published" in src
    assert "channels=published," in src


# --- the page renders them ----------------------------------------------


def test_the_page_renders_a_button_per_channel():
    page = PAGE.read_text()
    assert 'id="channel-buttons"' in page
    assert "function renderChannels(access)" in page


def test_the_buttons_are_refreshed_on_every_poll():
    """A channel that appears once the VM finishes booting must show up
    without the student reloading."""
    assert "renderChannels(data.access);" in PAGE.read_text()


def test_a_session_with_no_channels_renders_nothing():
    page = PAGE.read_text()
    block = page.split("function renderChannels(access)")[1][:600]
    assert "if (!channels.length)" in block
    assert "host.innerHTML = ''" in block
