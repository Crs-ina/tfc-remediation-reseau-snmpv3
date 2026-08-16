import io
import random

from click.testing import CliRunner

from app.cli.okapi import okapi_cli
from app.cli.okapi_art import render_random_banner
from app.cli.ui.animations import animate_boot_sequence
from app.cli.ui.ascii_art import OKAPI_ARTS, OKAPI_TITLES
from app.cli.ui.colors import PALETTES, strip_ansi
from app.cli.ui.splash import PREVIEW_VARIANTS, build_splash, center_multiline, show_splash, visible_width


class RedirectedStream(io.StringIO):
    encoding = "utf-8"

    def isatty(self) -> bool:
        return False


def test_catalog_contains_real_visual_variety() -> None:
    assert len(OKAPI_ARTS) >= 5
    assert len({asset.text for asset in OKAPI_ARTS}) == len(OKAPI_ARTS)
    assert len(OKAPI_TITLES) >= 5
    assert len(PREVIEW_VARIANTS) == 8
    assert len(PALETTES) >= 6


def test_every_animal_has_ears_and_horizontal_stripes() -> None:
    for asset in OKAPI_ARTS:
        assert "/\\" in asset.text or "/  \\" in asset.text
        assert "=" in asset.text


def test_eight_previews_are_distinct_recognizable_and_width_safe() -> None:
    rendered = []
    for index in range(8):
        frame = build_splash(
            width=100,
            color=False,
            unicode=True,
            variant_index=index,
            rng=random.Random(index),
        )
        rendered.append(frame.text)
        assert "OKAPI" in frame.text
        assert "=" in frame.text
        assert max(visible_width(line) for line in frame.text.splitlines()) <= 100
    assert len(set(rendered)) == 8


def test_banner_fits_small_and_exceptionally_narrow_terminals() -> None:
    for width in (59, 40, 24, 12):
        frame = build_splash(width=width, color=False, unicode=False, randomize=False)
        assert max(visible_width(line) for line in frame.text.splitlines()) <= width
        assert "OKAPI"[:width] in frame.text


def test_compatibility_renderer_uses_new_splash() -> None:
    banner = render_random_banner(width=80, color=False)
    assert "OKAPI" in banner
    assert "Network" in banner or "Observe" in banner or "Secure" in banner


def test_colour_rendering_resets_ansi_sequences() -> None:
    frame = build_splash(width=80, color=True, unicode=False, randomize=False)
    assert "\033[" in frame.text
    assert "\033[0m" in frame.text
    assert max(visible_width(line) for line in frame.text.splitlines()) <= 80


def test_center_multiline_ignores_ansi_sequences() -> None:
    value = center_multiline("\033[32mOKAPI\033[0m", 15)
    assert value.startswith(" " * 5)
    assert strip_ansi(value).strip() == "OKAPI"


def test_redirected_output_and_json_mode_never_receive_splash() -> None:
    redirected = RedirectedStream()
    assert show_splash(stream=redirected) is False
    assert redirected.getvalue() == ""
    assert show_splash(stream=redirected, force=True, json_mode=True) is False
    assert redirected.getvalue() == ""


def test_fast_boot_sequence_does_not_sleep() -> None:
    output = io.StringIO()
    sleeps: list[float] = []
    animate_boot_sequence(
        style="steps",
        palette=PALETTES["okapi"],
        colour=False,
        unicode=False,
        fast=True,
        stream=output,
        sleep=sleeps.append,
    )
    assert "OKAPI READY" in output.getvalue()
    assert sleeps == []


def test_okapi_command_exposes_splash_controls_and_preview() -> None:
    runner = CliRunner()
    help_result = runner.invoke(okapi_cli, ["--help"])
    assert help_result.exit_code == 0
    for option in ("--no-splash", "--no-color", "--fast", "--no-animation"):
        assert option in help_result.output

    preview_result = runner.invoke(
        okapi_cli,
        ["preview-splash", "--width", "40", "--no-color", "--ascii"],
    )
    assert preview_result.exit_code == 0
    assert "VARIANT 01" in preview_result.output
    assert "VARIANT 08" in preview_result.output
    assert "\033[" not in preview_result.output
