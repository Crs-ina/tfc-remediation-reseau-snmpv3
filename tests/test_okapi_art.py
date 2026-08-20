import io
import random

import pytest
from click.testing import CliRunner

from app.cli.okapi import okapi_cli
from app.cli.okapi_art import render_random_banner
from app.cli.ui.animations import HIDE_CURSOR, SHOW_CURSOR, animate_boot_sequence, animate_logo
from app.cli.ui.pixel_art import (
    LOGO_DESIGNS,
    LOGO_HEIGHT,
    LOGO_MASK,
    LOGO_WIDTH,
    OKAPI_ARTS,
    OKAPI_TITLES,
    PIXEL_STYLES,
    render_pixel_logo,
)
from app.cli.ui.colors import PALETTES, strip_ansi
from app.cli.ui.splash import (
    ANIMATION_STYLES,
    PREVIEW_VARIANTS,
    build_splash,
    center_multiline,
    show_splash,
    visible_width,
)


class RedirectedStream(io.StringIO):
    encoding = "utf-8"

    def isatty(self) -> bool:
        return False


class InteractiveStream(io.StringIO):
    encoding = "utf-8"

    def isatty(self) -> bool:
        return True


def test_catalog_contains_real_visual_variety() -> None:
    assert len(OKAPI_ARTS) >= 5
    assert len({asset.text for asset in OKAPI_ARTS}) == len(OKAPI_ARTS)
    assert len(OKAPI_TITLES) >= 5
    assert len(PREVIEW_VARIANTS) == 8
    assert len(PALETTES) >= 6


def test_every_logo_skin_keeps_exactly_the_same_geometry() -> None:
    expected_mask = tuple(tuple(character != " " for character in line) for line in render_pixel_logo().splitlines())
    assert expected_mask == LOGO_MASK
    for design in LOGO_DESIGNS:
        for pixel_style in PIXEL_STYLES:
            logo = render_pixel_logo(design, pixel_style)
            lines = logo.splitlines()
            assert len(lines) == LOGO_HEIGHT
            assert {len(line) for line in lines} == {LOGO_WIDTH}
            assert tuple(tuple(character != " " for character in line) for line in lines) == expected_mask


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
        assert frame.design_name in LOGO_DESIGNS
        assert frame.pixel_style in PIXEL_STYLES
        assert len(frame.logo_cells) == sum(sum(row) for row in LOGO_MASK)
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
    normalized = banner.lower()
    assert "network" in normalized or "observe" in normalized or "secure" in normalized


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


def test_interactive_splash_uses_in_place_logo_animation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("WT_SESSION", "okapi-test")
    monkeypatch.setenv("TERM", "xterm-256color")
    interactive = InteractiveStream()
    assert show_splash(
        stream=interactive,
        color=False,
        unicode=True,
        randomize=False,
        animated=True,
        fast=True,
        width=80,
    ) is True
    rendered = interactive.getvalue()
    assert HIDE_CURSOR in rendered
    assert SHOW_CURSOR in rendered
    assert "OKAPI READY" in rendered


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


def test_all_logo_animations_are_in_place_bounded_and_restore_cursor() -> None:
    frame = build_splash(
        width=80,
        color=False,
        unicode=True,
        randomize=False,
        rng=random.Random(9),
    )
    assert set(ANIMATION_STYLES) == {
        "left_to_right",
        "pixel_reveal",
        "scan_line",
        "letter_by_letter",
        "glitch_assembly",
        "shadow_build",
    }
    for style in ANIMATION_STYLES:
        output = io.StringIO()
        sleeps: list[float] = []
        animate_logo(
            frame.text,
            frame.logo_cells,
            style=style,
            unicode=True,
            fast=False,
            stream=output,
            sleep=sleeps.append,
            rng=random.Random(7),
        )
        rendered = output.getvalue()
        assert rendered.startswith(HIDE_CURSOR)
        assert rendered.endswith(SHOW_CURSOR + "\033[0m")
        assert 0.5 <= sum(sleeps) <= 1.5
        assert "Network Remediation Engine" in strip_ansi(rendered)


def test_logo_animation_restores_cursor_when_a_frame_fails() -> None:
    frame = build_splash(width=80, color=False, unicode=True, randomize=False)
    output = io.StringIO()

    def fail_sleep(_: float) -> None:
        raise RuntimeError("animation interrupted")

    with pytest.raises(RuntimeError, match="interrupted"):
        animate_logo(
            frame.text,
            frame.logo_cells,
            style="pixel_reveal",
            unicode=True,
            fast=False,
            stream=output,
            sleep=fail_sleep,
        )
    assert output.getvalue().endswith(SHOW_CURSOR + "\033[0m")


def test_logo_animation_keeps_the_selected_palette() -> None:
    frame = build_splash(width=80, color=True, unicode=False, randomize=False)
    output = io.StringIO()
    animate_logo(
        frame.text,
        frame.logo_cells,
        style=frame.animation_style,
        unicode=False,
        fast=False,
        palette=frame.palette,
        colour=True,
        stream=output,
        sleep=lambda _: None,
    )
    assert frame.palette.title in output.getvalue()


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
