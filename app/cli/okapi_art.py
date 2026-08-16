"""Backward-compatible imports for the modular OKAPI splash package."""
from __future__ import annotations

from .ui.ascii_art import (
    OKAPI_ARTS,
    OKAPI_LARGE,
    OKAPI_MEDIUM,
    OKAPI_SMALL,
    OKAPI_TITLES,
)
from .ui.colors import PALETTES, Palette
from .ui.splash import render_splash


def render_random_banner(*, width: int | None = None, color: bool | None = None) -> str:
    """Preserve the original public helper while using the new renderer."""

    return render_splash(width=width, color=color, randomize=True)


__all__ = (
    "OKAPI_ARTS",
    "OKAPI_LARGE",
    "OKAPI_MEDIUM",
    "OKAPI_SMALL",
    "OKAPI_TITLES",
    "PALETTES",
    "Palette",
    "render_random_banner",
)
