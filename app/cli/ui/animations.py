"""Small, low-flicker boot animations for interactive terminals."""
from __future__ import annotations

import random
import sys
import time
from collections.abc import Callable, Sequence
from typing import TextIO

from .colors import RESET, Palette, paint, strip_ansi


HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"
CLEAR_LINE = "\033[2K"


BOOT_STEPS = (
    "Loading configuration",
    "Initializing SNMPv3 engine",
    "Loading device inventory",
    "Checking network modules",
    "Loading remediation rules",
    "Preparing CLI interface",
)


def _logo_frame(
    plain_lines: list[str],
    logo_cells: Sequence[tuple[int, int]],
    *,
    visible: set[tuple[int, int]],
    replacements: dict[tuple[int, int], str] | None = None,
) -> str:
    lines = [list(line) for line in plain_lines]
    replacements = replacements or {}
    for cell in logo_cells:
        row, column = cell
        if row >= len(lines) or column >= len(lines[row]):
            continue
        if cell not in visible:
            lines[row][column] = " "
        elif cell in replacements:
            lines[row][column] = replacements[cell]
    return "\n".join("".join(line).rstrip() for line in lines)


def _animation_frames(
    text: str,
    logo_cells: Sequence[tuple[int, int]],
    *,
    style: str,
    unicode: bool,
    rng: random.Random,
) -> list[str]:
    """Build transient frames from one already-selected final logo."""

    plain_lines = strip_ansi(text).splitlines()
    cells = tuple(logo_cells)
    all_cells = set(cells)
    if not cells:
        return []
    columns = sorted({column for _, column in cells})
    rows = sorted({row for row, _ in cells})
    frames: list[str] = []

    if style == "left_to_right":
        for step in range(1, 7):
            threshold = columns[0] + ((columns[-1] - columns[0] + 1) * step // 6)
            visible = {cell for cell in cells if cell[1] <= threshold}
            frames.append(_logo_frame(plain_lines, cells, visible=visible))
    elif style == "pixel_reveal":
        ordered = list(cells)
        rng.shuffle(ordered)
        for step in range(1, 7):
            count = max(1, len(ordered) * step // 6)
            visible = set(ordered[:count])
            frames.append(_logo_frame(plain_lines, cells, visible=visible))
    elif style == "scan_line":
        for row in rows:
            visible = {cell for cell in cells if cell[0] <= row}
            frames.append(_logo_frame(plain_lines, cells, visible=visible))
    elif style == "letter_by_letter":
        origin = min(columns)
        spans = ((0, 4), (6, 10), (12, 16), (18, 22), (24, 26))
        for _, end in spans:
            visible = {cell for cell in cells if cell[1] - origin <= end}
            frames.append(_logo_frame(plain_lines, cells, visible=visible))
    elif style == "glitch_assembly":
        glyphs = ("░", "▒", "▓", "█") if unicode else (".", "+", "#", "@")
        ordered = list(cells)
        rng.shuffle(ordered)
        for step in range(1, 7):
            locked = set(ordered[: len(ordered) * step // 6])
            replacements = {
                cell: rng.choice(glyphs)
                for cell in all_cells - locked
            }
            frames.append(
                _logo_frame(
                    plain_lines,
                    cells,
                    visible=all_cells,
                    replacements=replacements,
                )
            )
    elif style == "shadow_build":
        glyphs = ("░", "▒", "▓", "█") if unicode else (".", "+", "#", "@")
        for glyph in glyphs:
            replacements = {cell: glyph for cell in cells}
            frames.append(
                _logo_frame(
                    plain_lines,
                    cells,
                    visible=all_cells,
                    replacements=replacements,
                )
            )
    else:
        raise ValueError(f"unknown logo animation: {style}")
    return frames


def animate_logo(
    text: str,
    logo_cells: Sequence[tuple[int, int]],
    *,
    style: str,
    unicode: bool,
    fast: bool,
    palette: Palette | None = None,
    colour: bool = False,
    stream: TextIO = sys.stdout,
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
) -> None:
    """Assemble one fixed logo in place and always restore terminal state."""

    frames = _animation_frames(
        text,
        logo_cells,
        style=style,
        unicode=unicode,
        rng=rng or random.Random(),
    )
    line_count = max(1, len(strip_ansi(text).splitlines()))
    rendered = False

    def write_block(block: str) -> None:
        nonlocal rendered
        if rendered:
            stream.write(f"\033[{line_count}A")
        for line in block.splitlines():
            stream.write(f"\r{CLEAR_LINE}{line}\n")
        stream.flush()
        rendered = True

    stream.write(HIDE_CURSOR)
    try:
        if not fast:
            delay = 0.72 / max(1, len(frames))
            for transient in frames:
                rendered_frame = paint(transient, palette.title, colour) if palette else transient
                write_block(rendered_frame)
                sleep(delay)
        write_block(text)
    finally:
        stream.write(SHOW_CURSOR)
        stream.write(RESET)
        stream.flush()


def animate_dots(
    message: str = "Initializing",
    *,
    stream: TextIO = sys.stdout,
    delay: float = 0.10,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Animate one compact status line in place."""

    for dots in (".", "..", "..."):
        stream.write(f"\r\033[2K{message}{dots}")
        stream.flush()
        sleep(delay)
    stream.write("\r\033[2K")


def animate_progress(
    label: str,
    *,
    width: int = 10,
    stream: TextIO = sys.stdout,
    delay: float = 0.035,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Render a compact progress bar on one terminal row."""

    for completed in range(0, width + 1, 2):
        bar = "#" * completed + "-" * (width - completed)
        stream.write(f"\r\033[2K{label:<31} [{bar}]")
        stream.flush()
        sleep(delay)
    stream.write("\n")


def animate_boot_sequence(
    *,
    style: str,
    palette: Palette,
    colour: bool,
    unicode: bool,
    fast: bool,
    stream: TextIO = sys.stdout,
    steps: Sequence[str] = BOOT_STEPS,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Run a credible network boot sequence without full-screen repainting."""

    if fast:
        ready_mark = "✓" if unicode else "+"
        stream.write(paint(f"[{ready_mark}] OKAPI READY\n", palette.success, colour))
        return

    if style == "dots":
        animate_dots(
            "Initializing network modules",
            stream=stream,
            delay=0.08,
            sleep=sleep,
        )
        visible_steps = steps[:3]
        for step in visible_steps:
            mark = "✓" if unicode else "+"
            stream.write(paint(f"[{mark}] {step}\n", palette.accent, colour))
            sleep(0.045)
    elif style == "progress":
        for step in steps[:4]:
            animate_progress(step, stream=stream, delay=0.025, sleep=sleep)
    else:
        for step in steps:
            mark = "✓" if unicode else "+"
            stream.write(paint(f"[{mark}] {step}\n", palette.accent, colour))
            stream.flush()
            sleep(0.055)

    ready_mark = "✓" if unicode else "+"
    stream.write("\n")
    stream.write(paint(f"[{ready_mark}] OKAPI READY\n", palette.success, colour))
    if colour:
        stream.write(RESET)
    stream.flush()
