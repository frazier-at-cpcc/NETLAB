"""The launch page is embedded, not browsed.

It renders inside a Brightspace content frame, which is wide and short. The
page was built as a standalone document: min-h-screen made it at least as
tall as the viewport, a max-w-lg card letterboxed the width, and a 350px
minimum on the card body pushed the lower half below a scrollbar nobody
expects inside an LMS panel. Students could not see the notice telling them
whether their files were saved.
"""

import pathlib
import re

PAGE = pathlib.Path("lti/templates/lab_loading.html")


def page() -> str:
    return PAGE.read_text()


# --- it fills the frame, and only the frame -----------------------------


def test_the_document_is_exactly_the_height_of_the_frame():
    body = page()
    assert re.search(r"<html[^>]*class=\"[^\"]*h-full", body)
    assert re.search(r"<body[^>]*class=\"[^\"]*h-full", body)


def test_the_page_itself_never_scrolls():
    """A scrollbar on the document is the thing being removed."""
    assert re.search(r"<body[^>]*class=\"[^\"]*overflow-hidden", page())


def test_no_rule_forces_the_document_taller_than_the_frame():
    body = page()
    assert "min-h-screen" not in body
    assert "min-h-[350px]" not in body
    assert "h-screen" not in body


# --- the content can actually shrink ------------------------------------


def test_every_flex_ancestor_of_the_card_can_shrink():
    """min-h-0 is what lets a flex child shrink below its content. Without
    it on each level the card refuses to get smaller and the overflow comes
    straight back, which is subtle enough to be worth pinning."""
    body = page()
    assert body.count("min-h-0") >= 4


def test_the_card_body_is_the_only_scrollable_region():
    """If the frame is genuinely too short, the content stays reachable
    without moving the whole document."""
    body = page()
    assert "flex-1 min-h-0 overflow-y-auto" in body
    assert body.count("overflow-y-auto") == 1


# --- it uses the width it is given --------------------------------------


def test_the_card_uses_the_width_of_a_wide_frame():
    """max-w-lg left most of a Brightspace panel as empty letterboxing."""
    body = page()
    assert "max-w-3xl" in body
    assert "max-w-lg" not in body


def test_the_actions_sit_side_by_side_once_there_is_width():
    """Stacked full-width buttons are what made the card too tall."""
    body = page()
    assert body.count("sm:grid-cols-2") >= 2


def test_the_channel_buttons_share_that_grid():
    assert 'id="channel-buttons" class="grid gap-2 sm:grid-cols-2' in page()


def test_the_desktop_note_spans_the_row_rather_than_a_column():
    assert 'id="desktop-note"' in page()
    assert "sm:col-span-2" in page()


# --- narrow frames still work -------------------------------------------


def test_a_narrow_frame_falls_back_to_one_column():
    """The grid is single-column until the sm breakpoint, so a phone or a
    narrow side panel is unchanged."""
    body = page()
    # An unprefixed grid-cols-2 would force two columns at every width. The
    # naive check for the substring matches sm:grid-cols-2 too, so this
    # looks for the class without the breakpoint in front of it.
    unprefixed = re.findall(r"(?<!:)\bgrid-cols-2\b", body)
    assert unprefixed == [], f"{len(unprefixed)} unprefixed grid-cols-2 would break narrow frames"
