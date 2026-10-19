"""The launch page follows the Central Piedmont design system.

Source: cpcc.edu-design.md. Gold #b4a269 on near-black #151617, Franklin
Gothic URW, square geometry, flat surfaces. The page had been built on
#4A4A4A and #F2A900, which are not brand colours, with gradients, pill
corners and heavy shadows the system explicitly rules out.
"""

import pathlib
import re

PAGE = pathlib.Path("lti/templates/lab_loading.html")


def page() -> str:
    return PAGE.read_text()


def _config() -> str:
    return page().split("colors: {")[1].split("fontFamily")[0]


# --- the palette --------------------------------------------------------


def test_the_gold_and_the_dark_are_the_brand_values():
    cfg = _config()
    assert "#b4a269" in cfg
    assert "#151617" in cfg


def test_the_colours_it_used_to_use_are_gone():
    """#4A4A4A and #F2A900 were never brand colours."""
    body = page()
    assert "#4A4A4A" not in body
    assert "#F2A900" not in body


def test_every_token_the_markup_uses_is_defined():
    """A class naming a colour the config dropped renders as nothing, which
    is how an icon lost its background during this change."""
    body = page()
    defined = set(re.findall(r"'?([a-z0-9-]+)'?\s*:\s*'#", _config())) | {"primary", "secondary"}
    used = {u.split("/")[0] for u in re.findall(r"cpcc-([a-z0-9-/]+)", body)}
    assert used <= defined, f"undefined: {sorted(used - defined)}"


# --- the shape language -------------------------------------------------


def test_nothing_is_rounded_past_the_eight_pixel_step():
    """rounded.none dominates; cards soften to 8px and no further.

    rounded-lg is left alone: Tailwind's lg is 8px, the same value as the
    system's rounded.md, so renaming every one would be churn with no
    visual change. What is banned is anything larger.
    """
    body = page()
    assert "rounded-xl" not in body
    assert "rounded-2xl" not in body
    assert "rounded-3xl" not in body


def test_the_actions_are_square():
    assert page().count("rounded-none") >= 4


def test_the_cards_use_the_eight_pixel_step():
    assert page().count("rounded-md") >= 2


# --- flat, not decorated ------------------------------------------------


def test_no_gradients_anywhere():
    """The system is flat: contrast and tone, not blends."""
    assert "bg-gradient" not in page()


def test_no_heavy_shadows():
    """Depth comes from borders and tone, not stacked shadows."""
    body = page()
    assert "shadow-2xl" not in body
    assert "shadow-lg" not in body


def test_the_gold_is_an_accent_not_a_surface():
    """A solid gold header bar used the accent as a background and put
    white text on gold, which fails contrast. Gold marks edges and
    actions."""
    body = page()
    assert '<header class="bg-cpcc-secondary' in body
    assert "border-cpcc-primary" in body


def test_text_on_gold_is_dark():
    """Black on gold is the readable pairing; white on gold is not."""
    body = page()
    import re
    for cls in re.findall(r'class="([^"]*bg-cpcc-primary[^"]*)"', body):
        if "/" in cls:       # a tint, not the solid fill
            continue
        assert "text-white" not in cls, cls


def test_no_scale_on_hover():
    """Hover stays subtle: a colour step, not motion."""
    assert "hover:scale" not in page()


def test_depth_comes_from_borders_instead():
    assert "border-cpcc-neutral" in page()


# --- typography ---------------------------------------------------------


def test_franklin_gothic_leads_the_stack():
    cfg = page()
    assert "franklin-gothic-urw" in cfg
    assert "'sans-serif'" in cfg


def test_the_stack_falls_back_rather_than_fetching_a_webfont():
    """This page renders in an LMS frame; a blocked font request would
    leave the panel unstyled."""
    body = page()
    assert "fonts.googleapis.com" not in body
    assert "Arial" in body


def test_buttons_use_medium_weight_not_bold():
    """Labels are 500. The system never asks for bold."""
    body = page()
    buttons = re.findall(r'class="[^"]*(?:bg-cpcc-primary|border-cpcc-primary)[^"]*"', body)
    assert buttons
    assert not any("font-bold" in b for b in buttons)


# --- one accent ---------------------------------------------------------


def test_the_progress_bar_uses_one_accent():
    """It faded gold into emerald, which is two strong accents at once."""
    assert "to-emerald-500" not in page()
