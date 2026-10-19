"""Accessibility of the launch page.

The page shipped with black text on a near-black header, which is
invisible, no focus indication anywhere, and status changes announced to
nobody. It is embedded in an LMS, so it inherits that product's
accessibility obligations.
"""

import pathlib
import re

PAGE = pathlib.Path("lti/templates/lab_loading.html")


def page() -> str:
    return PAGE.read_text()


# --- contrast -----------------------------------------------------------


def test_no_dark_text_sits_on_the_dark_header():
    """text-cpcc-secondary is #151617. On the near-black header it was
    invisible; the assignment title vanished entirely.

    Text elements only. The logo mark is a dark icon on its own gold tile,
    which is the readable pairing and must stay, so banning the class
    outright would have failed on correct markup.
    """
    body = page()
    header = body.split("<!-- Main Content -->")[0]
    text_elements = re.findall(r"<(?:p|h1|h2|h3|span)\b[^>]*class=\"([^\"]*)\"", header)
    assert text_elements
    offenders = [c for c in text_elements if "text-cpcc-secondary" in c]
    assert offenders == [], f"dark text on the dark header: {offenders}"


def test_the_card_header_subtitle_is_readable():
    assert 'class="text-cpcc-primary text-sm mt-1">{{ assignment_title }}' in page()


def test_dark_on_gold_is_kept_where_it_belongs():
    """Dark text on the gold fill is the readable pairing and must stay."""
    body = page()
    assert "bg-cpcc-primary hover:bg-cpcc-primary-70 text-cpcc-secondary" in body


# --- keyboard -----------------------------------------------------------


def test_every_control_shows_focus():
    """Keyboard users had no indication of focus anywhere on the page."""
    body = page()
    # Buttons and links only. Matching every class that merely mentions a
    # brand colour swept in the header and several layout divs, which are
    # not operable and must not take focus.
    controls = re.findall(r"<(?:button|a)\b[^>]*class=\"([^\"]*)\"", body)
    controls = [c for c in controls if re.search(
        r"bg-cpcc-primary|border-cpcc-primary|border-cpcc-error/40|border-cpcc-neutral/40", c)]
    assert controls
    missing = [c for c in controls if "focus-visible:ring" not in c]
    assert missing == [], f"{len(missing)} controls without a focus ring"


def test_the_focus_ring_uses_the_brand_accent():
    assert "focus-visible:ring-cpcc-primary" in page()


def test_focus_is_not_simply_removed():
    """outline-none alone, with nothing replacing it, is the worst case."""
    body = page()
    for match in re.finditer(r"focus:outline-none", body):
        window = body[match.start():match.start() + 160]
        assert "focus-visible:ring" in window


# --- assistive technology -----------------------------------------------


def test_status_changes_are_announced():
    """The panel swaps between provisioning, ready and error without any
    announcement, so a screen reader user had no idea the lab had come up."""
    body = page()
    assert 'role="status"' in body
    assert 'aria-live="polite"' in body


def test_decorative_icons_are_hidden_from_assistive_tech():
    body = page()
    svgs = re.findall(r"<svg\b[^>]*>", body)
    assert svgs
    unhidden = [s for s in svgs if "aria-hidden" not in s]
    assert unhidden == [], f"{len(unhidden)} icons would be announced"


def test_state_is_not_carried_by_colour_alone():
    """The running pill pairs its dot with the word Running."""
    body = page()
    # Scoped to the running state. Searching the whole page found the word
    # inside an HTML comment first, which proved nothing.
    block = body.split('id="running-state"')[1].split("<!-- Persistence notice")[0]
    assert "Running" in block, "the state must be named, not only coloured"
    assert "rounded-full" in block, "the state needs a visible marker"
    assert 'aria-hidden="true"' in block, "and that marker must not be read out"


# --- structure ----------------------------------------------------------


def test_the_markup_is_balanced():
    """A dropped closing tag during the restyle left an svg open, which
    swallowed the markup after it."""
    body = page()
    for tag in ("div", "span", "svg", "button"):
        opened = len(re.findall(rf"<{tag}[\s>]", body))
        closed = len(re.findall(rf"</{tag}>", body))
        assert opened == closed, f"{tag}: {opened} open, {closed} closed"


def test_dynamically_added_controls_also_show_focus():
    """The channel buttons are built in JavaScript, so they miss any sweep
    over the static markup."""
    body = page()
    # The whole function, not a fixed slice. A character window broke the
    # moment the function grew, which says nothing about the page.
    after = body.split("function renderChannels(access)")[1]
    block = after.split("\n        function ")[0]
    # The full ring, not just the prefix: a partial set still contains
    # "focus-visible:ring" while rendering no visible indicator.
    assert "focus-visible:ring-2" in block
    assert "focus-visible:ring-cpcc-primary" in block
    assert "focus-visible:ring-offset-2" in block
