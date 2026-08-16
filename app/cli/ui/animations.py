"""Small, low-flicker boot animations for interactive terminals."""
from __future__ import annotations

import sys
import time
from collections.abc import Callable, Sequence
from typing import TextIO

from .colors import RESET, Palette, paint


BOOT_STEPS = (
    "Loading configuration",
    "Initializing SNMPv3 engine",
    "Loading device inventory",
    "Checking network modules",
    "Loading remediation rules",
    "Preparing CLI interface",
)


def animate_dots(
    message: str = "Initializing",
    *,
    stream: TextIO = sys.stdout,
    delay: float = 0.10,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Animate one line in place; the mascot itself is never redrawn."""

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
