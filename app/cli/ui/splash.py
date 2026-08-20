"""Responsive, random and automation-safe splash screen for OKAPI."""
from __future__ import annotations

import argparse
import random
import shutil
import sys
import unicodedata
from dataclasses import dataclass
from typing import TextIO

from .animations import SHOW_CURSOR, animate_boot_sequence, animate_logo
from .pixel_art import (
    LOGO_DESIGNS,
    LOGO_HEIGHT,
    LOGO_MASK,
    LOGO_WIDTH,
    PIXEL_STYLES,
    render_pixel_logo,
)
from .colors import PALETTES, RESET, Palette, paint, strip_ansi, supports_ansi, supports_unicode


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
    "logo-first",
    "signature-first",
    "side-by-side",
    "frame",
    "telemetry",
    "constellation",
    "minimal",
    "command-line",
)
ANIMATION_STYLES = (
    "left_to_right",
    "pixel_reveal",
    "scan_line",
    "letter_by_letter",
    "glitch_assembly",
    "shadow_build",
)


@dataclass(frozen=True)
class PreviewVariant:
    layout: str
    palette: str
    design_index: int
    pixel_style_index: int
    subtitle_index: int
    animation: str


PREVIEW_VARIANTS = (
    PreviewVariant("logo-first", "okapi", 0, 0, 0, "left_to_right"),
    PreviewVariant("signature-first", "network", 1, 1, 1, "pixel_reveal"),
    PreviewVariant("side-by-side", "forest", 2, 2, 2, "scan_line"),
    PreviewVariant("frame", "terminal", 3, 3, 3, "letter_by_letter"),
    PreviewVariant("telemetry", "cyber", 4, 4, 1, "glitch_assembly"),
    PreviewVariant("constellation", "mono", 0, 5, 2, "shadow_build"),
    PreviewVariant("minimal", "okapi", 1, 2, 0, "pixel_reveal"),
    PreviewVariant("command-line", "network", 2, 4, 3, "scan_line"),
)


@dataclass(frozen=True)
class SplashFrame:
    text: str
    palette: Palette
    animation_style: str
    colour: bool
    unicode: bool
    variant_name: str
    design_name: str
    pixel_style: str
    logo_cells: tuple[tuple[int, int], ...]


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


def _select_logo(
    *,
    width: int,
    unicode: bool,
    randomize: bool,
    rng: random.Random,
    forced: PreviewVariant | None,
) -> tuple[str, str, str]:
    """Select design and pixel skin once, then render one stable geometry."""

    design = (
        LOGO_DESIGNS[forced.design_index % len(LOGO_DESIGNS)]
        if forced
        else rng.choice(LOGO_DESIGNS) if randomize else LOGO_DESIGNS[0]
    )
    pixel_style = (
        PIXEL_STYLES[forced.pixel_style_index % len(PIXEL_STYLES)]
        if forced
        else rng.choice(PIXEL_STYLES) if randomize else PIXEL_STYLES[0]
    )
    if width < LOGO_WIDTH:
        return "OKAPI", design, pixel_style
    return render_pixel_logo(design, pixel_style, unicode=unicode), design, pixel_style


def _compose(
    *,
    width: int,
    layout: str,
    logo: str,
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
    centred_logo = _center_block(logo, width)
    centred_signature = _center_block(coloured_signature, width)
    centred_subtitle = _center_block(accent_subtitle, width)
    centred_startup = _center_block(muted_startup, width)

    if layout == "signature-first":
        lines = _stack(centred_signature, centred_logo, centred_subtitle, centred_startup)
    elif layout == "side-by-side":
        right = "\n".join((coloured_signature, "", accent_subtitle))
        side = _side_by_side(logo, right, width)
        if side is not None:
            lines = _center_block("\n".join(side), width).splitlines()
        else:
            lines = _stack(centred_logo, centred_signature, centred_subtitle)
        lines.extend(("", centred_startup))
    elif layout == "frame":
        content = _stack(logo, coloured_signature, accent_subtitle)
        inner = min(width - 4, max((visible_width(line) for line in content), default=1))
        content = _stack(
            _center_block(logo, inner),
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
            _center_block(header, width), centred_logo,
            centred_subtitle, _center_block(footer, width), centred_startup,
        )
    elif layout == "constellation":
        lines = _stack(decoration_top, centred_logo, centred_signature, centred_subtitle, decoration_bottom, centred_startup)
    elif layout == "minimal":
        lines = _stack(centred_logo, centred_signature, centred_subtitle, centred_startup)
    elif layout == "command-line":
        prompt = paint("$ okapi --initialize --secure", palette.accent, colour)
        pipeline = paint("observe > detect > validate > remediate", palette.muted, colour)
        lines = _stack(
            _center_block(prompt, width), centred_logo,
            centred_signature, _center_block(pipeline, width), centred_startup,
        )
    else:
        lines = _stack(decoration_top, centred_logo, centred_signature, centred_subtitle, centred_startup)
    return lines


def _find_logo_cells(lines: list[str], logo_text: str) -> tuple[tuple[int, int], ...]:
    """Locate fixed logo pixels inside the final composition for animation."""

    cells: list[tuple[int, int]] = []
    search_from = 0
    logo_lines = logo_text.splitlines()
    masks = LOGO_MASK if len(logo_lines) == LOGO_HEIGHT else (tuple(True for _ in "OKAPI"),)
    for logo_line, mask in zip(logo_lines, masks, strict=True):
        leading = len(logo_line) - len(logo_line.lstrip())
        needle = logo_line.strip()
        for row in range(search_from, len(lines)):
            plain_line = strip_ansi(lines[row])
            found = plain_line.find(needle)
            if found < 0:
                continue
            origin = found - leading
            cells.extend(
                (row, origin + column)
                for column, filled in enumerate(mask)
                if filled and 0 <= origin + column < len(plain_line)
            )
            search_from = row + 1
            break
    return tuple(cells)


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
        animation_style = "left_to_right"

    if layout == "frame" and width < LOGO_WIDTH + 4:
        layout = "minimal"

    if len(subtitle) > width:
        subtitle = "Network Remediation" if width >= 20 else "Network CLI"

    logo_plain, design_name, pixel_style = _select_logo(
        width=width,
        unicode=use_unicode,
        randomize=randomize,
        rng=rng,
        forced=forced,
    )
    logo = paint(logo_plain, palette.title, use_colour)
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
        logo=logo,
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
    logo_cells = _find_logo_cells(fitted, logo_plain)
    return SplashFrame(
        text="\n".join(fitted),
        palette=palette,
        animation_style=animation_style,
        colour=use_colour,
        unicode=use_unicode,
        variant_name=layout,
        design_name=design_name,
        pixel_style=pixel_style,
        logo_cells=logo_cells,
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
    cursor_animation = animated and stream.isatty() and supports_ansi(stream)
    try:
        if cursor_animation:
            animate_logo(
                frame.text,
                frame.logo_cells,
                style=frame.animation_style,
                unicode=frame.unicode,
                fast=fast,
                palette=frame.palette,
                colour=frame.colour,
                stream=stream,
            )
            stream.write("\n")
        else:
            stream.write(frame.text + "\n\n")
            stream.flush()
        animate_boot_sequence(
            style="steps",
            palette=frame.palette,
            colour=frame.colour,
            unicode=frame.unicode,
            fast=fast or not animated,
            stream=stream,
        )
    finally:
        if cursor_animation:
            stream.write(SHOW_CURSOR)
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
