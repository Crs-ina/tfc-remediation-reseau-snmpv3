"""Responsive, random and automation-safe splash screen for OKAPI."""
from __future__ import annotations

import argparse
import random
import shutil
import sys
import textwrap
import unicodedata
from dataclasses import dataclass
from typing import TextIO

from .animations import animate_boot_sequence
from .ascii_art import (
    OKAPI_ARTS,
    OKAPI_MEDIUM,
    OKAPI_SMALL,
    AsciiAsset,
    animals_for_width,
    titles_for_width,
)
from .colors import PALETTES, RESET, Palette, colorize_animal, paint, strip_ansi, supports_ansi, supports_unicode


SPLASH_CONFIG = {
    "enabled": True,
    "randomize": True,
    "animation": True,
    "colors": True,
    "decorations": True,
    "subtitle": "Network Remediation Engine",
}

SUBTITLES = (
    "Network Remediation Engine",
    "SNMPv3 | Network Automation | Remediation",
    "Observe | Detect | Remediate",
    "Secure Network Operations CLI",
)
STARTUP_MESSAGES = (
    "Initializing secure network modules...",
    "Preparing the remediation workspace...",
    "Establishing the SNMPv3 control plane...",
    "Loading guarded remediation policies...",
)
ASCII_DECORATIONS = ("*", "+", ".", "o")
UNICODE_DECORATIONS = ("*", "+", ".", "✦", "✧", "⋆", "·", "°")
LAYOUTS = (
    "mascot-first",
    "title-first",
    "side-by-side",
    "frame",
    "telemetry",
    "constellation",
    "minimal",
    "command-line",
)
ANIMATION_STYLES = ("dots", "progress", "steps")


@dataclass(frozen=True)
class PreviewVariant:
    layout: str
    palette: str
    animal_index: int
    title_index: int
    subtitle_index: int
    animation: str


PREVIEW_VARIANTS = (
    PreviewVariant("mascot-first", "okapi", 0, 0, 0, "steps"),
    PreviewVariant("title-first", "network", 1, 1, 1, "progress"),
    PreviewVariant("side-by-side", "forest", 2, 4, 2, "dots"),
    PreviewVariant("frame", "terminal", 3, 2, 3, "steps"),
    PreviewVariant("telemetry", "cyber", 4, 3, 1, "progress"),
    PreviewVariant("constellation", "mono", 5, 1, 2, "dots"),
    PreviewVariant("minimal", "okapi", 6, 5, 0, "steps"),
    PreviewVariant("command-line", "network", 2, 2, 3, "progress"),
)


@dataclass(frozen=True)
class SplashFrame:
    text: str
    palette: Palette
    animation_style: str
    colour: bool
    unicode: bool
    variant_name: str


def visible_width(text: str) -> int:
    """Measure a terminal line without counting ANSI or combining marks."""

    width = 0
    for character in strip_ansi(text):
        if unicodedata.combining(character):
            continue
        width += 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
    return width


def center_line(text: str, width: int) -> str:
    padding = max(0, width - visible_width(text))
    return " " * (padding // 2) + text


def center_multiline(text: str, width: int) -> str:
    """Centre ANSI-coloured multiline text by its visible width."""

    return "\n".join(center_line(line, width) for line in text.splitlines())


def _center_block(text: str, width: int) -> str:
    """Centre a drawing as one block without deforming its internal spacing."""

    lines = text.splitlines()
    block_width = max((visible_width(line) for line in lines), default=0)
    offset = " " * max(0, (width - block_width) // 2)
    return "\n".join(offset + line.rstrip() for line in lines)


def _fit_line(line: str, width: int) -> str:
    """Defensive fallback for exceptionally narrow terminals."""

    if visible_width(line) <= width:
        return line.rstrip()
    plain = strip_ansi(line)
    return plain[: max(0, width)].rstrip()


def _decorate_row(width: int, symbols: tuple[str, ...], rng: random.Random) -> str:
    if width < 10:
        return ""
    cells = [" "] * width
    for _ in range(rng.randint(1, min(8, max(1, width // 14)))):
        position = rng.randrange(width)
        cells[position] = rng.choice(symbols)
    return "".join(cells).rstrip()


def _stack(*sections: str) -> list[str]:
    lines: list[str] = []
    for section in sections:
        if not section:
            continue
        if lines and lines[-1] != "":
            lines.append("")
        lines.extend(section.splitlines())
    return lines


def _side_by_side(left: str, right: str, width: int) -> list[str] | None:
    left_lines = left.splitlines()
    right_lines = right.splitlines()
    left_width = max((visible_width(line) for line in left_lines), default=0)
    right_width = max((visible_width(line) for line in right_lines), default=0)
    gap = 4
    if left_width + gap + right_width > width:
        return None
    height = max(len(left_lines), len(right_lines))
    left_offset = (height - len(left_lines)) // 2
    right_offset = (height - len(right_lines)) // 2
    combined: list[str] = []
    for row in range(height):
        left_index = row - left_offset
        right_index = row - right_offset
        left_line = left_lines[left_index] if 0 <= left_index < len(left_lines) else ""
        right_line = right_lines[right_index] if 0 <= right_index < len(right_lines) else ""
        padding = " " * (left_width - visible_width(left_line) + gap)
        combined.append(left_line + padding + right_line)
    return combined


def _select_assets(
    *,
    width: int,
    layout: str,
    unicode: bool,
    rng: random.Random,
    forced: PreviewVariant | None,
    side_text_width: int,
) -> tuple[AsciiAsset, AsciiAsset]:
    title_candidates = titles_for_width(max(1, width - (4 if layout == "frame" else 0)), unicode=unicode)
    if forced:
        title = title_candidates[forced.title_index % len(title_candidates)]
    else:
        title = rng.choice(title_candidates)

    right_width = max(title.width, side_text_width, len("[ OKAPI ]"))
    available = width - right_width - 4 if layout == "side-by-side" else width - (4 if layout == "frame" else 0)
    desired = OKAPI_ARTS[forced.animal_index % len(OKAPI_ARTS)] if forced else None
    if desired is not None and desired.width <= available:
        return desired, title

    if layout == "side-by-side":
        candidates = tuple(asset for asset in OKAPI_MEDIUM + OKAPI_SMALL if asset.width <= available)
    elif layout == "minimal":
        candidates = tuple(asset for asset in OKAPI_SMALL if asset.width <= width)
    else:
        candidates = tuple(asset for asset in animals_for_width(width) if asset.width <= width - (4 if layout == "frame" else 0))
    if not candidates:
        candidates = tuple(asset for asset in OKAPI_ARTS if asset.width <= width)
    if not candidates:
        candidates = (OKAPI_SMALL[-1],)
    animal = candidates[forced.animal_index % len(candidates)] if forced else rng.choice(candidates)
    return animal, title


def _compose(
    *,
    width: int,
    layout: str,
    animal: str,
    title: str,
    signature: str,
    subtitle: str,
    startup_message: str,
    decoration_top: str,
    decoration_bottom: str,
    palette: Palette,
    colour: bool,
) -> list[str]:
    accent_subtitle = paint(subtitle, palette.accent, colour)
    muted_startup = paint(startup_message, palette.muted, colour)
    coloured_signature = paint(signature, palette.title, colour)
    centred_animal = _center_block(animal, width)
    centred_title = _center_block(title, width)
    centred_signature = _center_block(coloured_signature, width)
    centred_subtitle = _center_block(accent_subtitle, width)
    centred_startup = _center_block(muted_startup, width)

    if layout == "title-first":
        lines = _stack(centred_title, centred_signature, centred_animal, centred_subtitle, centred_startup)
    elif layout == "side-by-side":
        right = "\n".join((title, "", coloured_signature, accent_subtitle))
        side = _side_by_side(animal, right, width)
        if side is not None:
            lines = _center_block("\n".join(side), width).splitlines()
        else:
            lines = _stack(centred_animal, centred_title, centred_signature, centred_subtitle)
        lines.extend(("", centred_startup))
    elif layout == "frame":
        content = _stack(animal, title, coloured_signature, accent_subtitle)
        inner = min(width - 4, max((visible_width(line) for line in content), default=1))
        content = _stack(
            _center_block(animal, inner),
            _center_block(title, inner),
            _center_block(coloured_signature, inner),
            _center_block(accent_subtitle, inner),
        )
        top = "+-" + "-" * inner + "-+"
        framed = [top]
        for line in content:
            right_padding = " " * max(0, inner - visible_width(line))
            framed.append(f"| {line}{right_padding} |")
        framed.append(top)
        lines = _center_block("\n".join(framed), width).splitlines() + ["", centred_startup]
    elif layout == "telemetry":
        header = paint("[ OKAPI :: SNMPv3 :: AUTHPRIV ]", palette.accent, colour)
        footer_text = (
            "LINK  SECURE  |  POLICY  LOADED  |  MODE  GUARDED"
            if width >= 52
            else "SECURE | POLICY LOADED | GUARDED"
        )
        footer = paint(footer_text, palette.muted, colour)
        lines = _stack(
            _center_block(header, width), centred_title, centred_animal,
            centred_subtitle, _center_block(footer, width), centred_startup,
        )
    elif layout == "constellation":
        lines = _stack(decoration_top, centred_animal, centred_title, centred_signature, centred_subtitle, decoration_bottom, centred_startup)
    elif layout == "minimal":
        lines = _stack(decoration_top, centred_animal, centred_signature, centred_subtitle, centred_startup)
    elif layout == "command-line":
        prompt = paint("$ okapi --initialize --secure", palette.accent, colour)
        pipeline = paint("observe > detect > validate > remediate", palette.muted, colour)
        lines = _stack(
            _center_block(prompt, width), centred_title, centred_animal,
            centred_signature, _center_block(pipeline, width), centred_startup,
        )
    else:
        lines = _stack(decoration_top, centred_animal, centred_title, centred_signature, centred_subtitle, centred_startup)
    return lines


def build_splash(
    *,
    width: int | None = None,
    color: bool | None = None,
    unicode: bool | None = None,
    randomize: bool = True,
    variant_index: int | None = None,
    decorations: bool = True,
    stream: TextIO = sys.stdout,
    rng: random.Random | None = None,
) -> SplashFrame:
    """Build one complete splash without writing to the terminal."""

    width = max(12, width or shutil.get_terminal_size(fallback=(80, 24)).columns)
    use_colour = supports_ansi(stream) if color is None else color
    use_unicode = supports_unicode(stream) if unicode is None else unicode and supports_unicode(stream)
    rng = rng or random.Random()
    forced = PREVIEW_VARIANTS[variant_index % len(PREVIEW_VARIANTS)] if variant_index is not None else None

    if forced:
        layout = forced.layout
        palette = PALETTES[forced.palette]
        subtitle = SUBTITLES[forced.subtitle_index % len(SUBTITLES)]
        animation_style = forced.animation
    elif randomize:
        layout = rng.choice(LAYOUTS)
        palette = rng.choice(tuple(PALETTES.values()))
        subtitle = rng.choice(SUBTITLES)
        animation_style = rng.choice(ANIMATION_STYLES)
    else:
        layout = LAYOUTS[0]
        palette = PALETTES["okapi"]
        subtitle = SPLASH_CONFIG["subtitle"]
        animation_style = "steps"

    if len(subtitle) > width:
        subtitle = "Network Remediation" if width >= 20 else "Network CLI"

    animal_asset, title_asset = _select_assets(
        width=width,
        layout=layout,
        unicode=use_unicode,
        rng=rng,
        forced=forced,
        side_text_width=len(subtitle),
    )
    animal = colorize_animal(textwrap.dedent(animal_asset.text), palette, use_colour)
    title = paint(title_asset.text, palette.title, use_colour)
    symbols = UNICODE_DECORATIONS if use_unicode else ASCII_DECORATIONS
    decoration_top = _decorate_row(width, symbols, rng) if decorations else ""
    decoration_bottom = _decorate_row(width, symbols, rng) if decorations else ""
    startup_message = rng.choice(STARTUP_MESSAGES)
    if len(startup_message) > width:
        startup_message = "Initializing..."
    signature = "[ OKAPI ]"

    raw_lines = _compose(
        width=width,
        layout=layout,
        animal=animal,
        title=title,
        signature=signature,
        subtitle=subtitle,
        startup_message=startup_message,
        decoration_top=decoration_top,
        decoration_bottom=decoration_bottom,
        palette=palette,
        colour=use_colour,
    )
    fitted = [_fit_line(line, width) for line in raw_lines]
    while fitted and not fitted[0]:
        fitted.pop(0)
    while fitted and not fitted[-1]:
        fitted.pop()
    return SplashFrame(
        text="\n".join(fitted),
        palette=palette,
        animation_style=animation_style,
        colour=use_colour,
        unicode=use_unicode,
        variant_name=layout,
    )


def render_splash(**kwargs: object) -> str:
    """Return only the rendered text for callers and tests."""

    return build_splash(**kwargs).text


def show_splash(
    animated: bool = True,
    fast: bool = False,
    randomize: bool = True,
    *,
    color: bool | None = None,
    unicode: bool | None = None,
    decorations: bool = True,
    json_mode: bool = False,
    force: bool = False,
    width: int | None = None,
    variant_index: int | None = None,
    stream: TextIO = sys.stdout,
) -> bool:
    """Display the splash only when doing so cannot pollute automation output."""

    if not SPLASH_CONFIG["enabled"] or json_mode:
        return False
    if not force and not stream.isatty():
        return False

    frame = build_splash(
        width=width,
        color=color,
        unicode=unicode,
        randomize=randomize,
        variant_index=variant_index,
        decorations=decorations,
        stream=stream,
    )
    try:
        stream.write(frame.text + "\n\n")
        stream.flush()
        animate_boot_sequence(
            style=frame.animation_style,
            palette=frame.palette,
            colour=frame.colour,
            unicode=frame.unicode,
            fast=fast or not animated,
            stream=stream,
        )
    finally:
        if frame.colour:
            stream.write(RESET)
            stream.flush()
    return True


def preview_all(
    *,
    width: int = 100,
    color: bool = False,
    unicode: bool = True,
    stream: TextIO = sys.stdout,
) -> None:
    """Print the eight layout identities for visual inspection."""

    unicode = unicode and supports_unicode(stream)
    for index, spec in enumerate(PREVIEW_VARIANTS, start=1):
        separator = "—" if unicode else "-"
        heading = f"VARIANT {index:02d} {separator} {spec.layout.upper()}"
        stream.write(heading + "\n" + "=" * min(width, len(heading)) + "\n")
        frame = build_splash(
            width=width,
            color=color,
            unicode=unicode,
            variant_index=index - 1,
            stream=stream,
            rng=random.Random(1000 + index),
        )
        stream.write(frame.text + "\n\n")
    if color:
        stream.write(RESET)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preview OKAPI splash-screen variants")
    parser.add_argument("--preview", action="store_true", help="show all eight compositions")
    parser.add_argument("--width", type=int, default=100, help="simulated terminal width")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument("--ascii", action="store_true", help="disable Unicode characters")
    parser.add_argument("--fast", action="store_true", help="skip animation delays")
    args = parser.parse_args(argv)
    if args.preview:
        preview_all(width=max(12, args.width), color=not args.no_color, unicode=not args.ascii)
    else:
        show_splash(
            fast=args.fast,
            color=not args.no_color,
            unicode=not args.ascii,
            force=True,
            width=max(12, args.width),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
