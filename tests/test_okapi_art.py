from app.cli.okapi_art import PALETTES, render_random_banner


def test_banner_is_recognizable_without_colour() -> None:
    banner = render_random_banner(width=120, color=False)
    assert "OKAPI" in banner
    assert "oo" in banner
    assert "==" in banner or "##" in banner or "--" in banner
    assert "\033[" not in banner


def test_banner_fits_the_small_terminal_variant() -> None:
    banner = render_random_banner(width=40, color=False)
    assert max(len(line) for line in banner.splitlines()) <= 40


def test_colour_rendering_resets_ansi_sequences() -> None:
    banner = render_random_banner(width=80, color=True)
    assert "\033[" in banner
    assert "\033[0m" in banner


def test_palette_names_are_distinct() -> None:
    assert len({palette.name for palette in PALETTES}) == 6
