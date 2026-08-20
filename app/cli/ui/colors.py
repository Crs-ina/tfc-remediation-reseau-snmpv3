"""ANSI colour support for the OKAPI terminal identity."""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from typing import TextIO


RESET = "\033[0m"
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@dataclass(frozen=True)
class Palette:
    name: str
    body: str
    stripe: str
    title: str
    accent: str
    muted: str
    success: str


def _fg(code: str) -> str:
    return f"\033[{code}m"


PALETTES: dict[str, Palette] = {
    "okapi": Palette(
        "okapi", _fg("38;5;94"), _fg("38;5;230"), _fg("38;5;178"),
        _fg("38;5;223"), _fg("38;5;244"), _fg("38;5;82"),
    ),
    "forest": Palette(
        "forest", _fg("38;5;58"), _fg("38;5;230"), _fg("38;5;70"),
        _fg("38;5;35"), _fg("38;5;244"), _fg("38;5;83"),
    ),
    "network": Palette(
        "network", _fg("38;5;31"), _fg("38;5;255"), _fg("38;5;45"),
        _fg("38;5;39"), _fg("38;5;250"), _fg("38;5;82"),
    ),
    "terminal": Palette(
        "terminal", _fg("38;5;28"), _fg("38;5;255"), _fg("38;5;40"),
        _fg("38;5;34"), _fg("38;5;244"), _fg("38;5;46"),
    ),
    "cyber": Palette(
        "cyber", _fg("38;5;93"), _fg("38;5;255"), _fg("38;5;51"),
        _fg("38;5;201"), _fg("38;5;245"), _fg("38;5;87"),
    ),
    "mono": Palette(
        "mono", _fg("38;5;250"), _fg("38;5;255"), _fg("38;5;255"),
        _fg("38;5;248"), _fg("38;5;242"), _fg("38;5;255"),
    ),
}


def strip_ansi(text: str) -> str:
    """Remove terminal control sequences before visible-width calculations."""

    return ANSI_RE.sub("", text)


def supports_ansi(stream: TextIO = sys.stdout) -> bool:
    """Conservatively detect colour support without adding dependencies."""

    if not stream.isatty() or os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    if os.name != "nt":
        return True
    return bool(
        os.environ.get("WT_SESSION")
        or os.environ.get("ANSICON")
        or os.environ.get("ConEmuANSI") == "ON"
        or os.environ.get("TERM_PROGRAM") == "vscode"
        or os.environ.get("TERM", "").startswith("xterm")
    )


def supports_unicode(stream: TextIO = sys.stdout) -> bool:
    """Return whether the stream encoding can represent the decorative glyphs."""

    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        "█✓✦".encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def paint(text: str, colour: str, enabled: bool) -> str:
    if not enabled or not text:
        return text
    return f"{colour}{text}{RESET}"


__all__ = ("ANSI_RE", "PALETTES", "RESET", "Palette", "paint", "strip_ansi", "supports_ansi", "supports_unicode")
