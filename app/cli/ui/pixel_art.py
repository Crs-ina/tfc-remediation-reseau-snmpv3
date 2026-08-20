"""Fixed-geometry pixel-art logos for the OKAPI terminal identity."""
from __future__ import annotations

import textwrap
from dataclasses import dataclass


@dataclass(frozen=True)
class AsciiAsset:
    """A named multiline asset with its measured terminal size."""

    name: str
    text: str
    unicode: bool = False

    @property
    def width(self) -> int:
        return max((len(line) for line in textwrap.dedent(self.text).splitlines()), default=0)

    @property
    def height(self) -> int:
        return len(self.text.splitlines())


# All skins use this single bitmap, so randomization cannot resize or distort
# the word. The I is deliberately narrower; every other letter is five cells.
_GLYPHS: dict[str, tuple[str, ...]] = {
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "K": ("10001", "10010", "10100", "11000", "10100", "10010", "10001"),
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "P": ("11110", "10001", "10001", "11110", "10000", "10000", "10000"),
    "I": ("111", "010", "010", "010", "010", "010", "111"),
}

LOGO_DESIGNS = ("block", "outline", "shadow", "glitch", "layered")
PIXEL_STYLES = ("solid", "shade", "gradient", "outline", "double", "layered")
LETTER_SPANS = ((0, 4), (6, 10), (12, 16), (18, 22), (24, 26))
LOGO_WIDTH = 27
LOGO_HEIGHT = 7


def _logo_mask() -> tuple[tuple[bool, ...], ...]:
    rows: list[tuple[bool, ...]] = []
    for row in range(LOGO_HEIGHT):
        line = "0".join(_GLYPHS[letter][row] for letter in "OKAPI")
        rows.append(tuple(cell == "1" for cell in line))
    return tuple(rows)


LOGO_MASK = _logo_mask()

_UNICODE_PIXELS: dict[str, tuple[str, ...]] = {
    "solid": ("█",),
    "shade": ("▓", "▒"),
    "gradient": ("░", "▒", "▓", "█"),
    "outline": ("▀", "█", "▄"),
    "double": ("╔", "═", "╗", "║", "╚", "╝"),
    "layered": ("▀", "▓", "█", "▒", "▄"),
}
_ASCII_PIXELS: dict[str, tuple[str, ...]] = {
    "solid": ("#",),
    "shade": ("#", "+"),
    "gradient": (".", "+", "#", "@"),
    "outline": ("^", "#", "_"),
    "double": ("+", "=", "+", "|", "+", "+"),
    "layered": ("^", "+", "#", "=", "_"),
}


def _is_edge(row: int, column: int) -> bool:
    for row_delta, column_delta in ((-1, 0), (1, 0), (0, -1), (0, 1)):
        neighbour_row = row + row_delta
        neighbour_column = column + column_delta
        if not (0 <= neighbour_row < LOGO_HEIGHT and 0 <= neighbour_column < LOGO_WIDTH):
            return True
        if not LOGO_MASK[neighbour_row][neighbour_column]:
            return True
    return False


def _pixel_character(
    *,
    design: str,
    pixel_style: str,
    row: int,
    column: int,
    unicode: bool,
) -> str:
    pixels = (_UNICODE_PIXELS if unicode else _ASCII_PIXELS)[pixel_style]
    base = pixels[(row + column) % len(pixels)]
    if design == "outline" and _is_edge(row, column):
        if unicode:
            if row == 0 or not LOGO_MASK[max(0, row - 1)][column]:
                return "▀"
            if row == LOGO_HEIGHT - 1 or not LOGO_MASK[min(LOGO_HEIGHT - 1, row + 1)][column]:
                return "▄"
            return "║"
        return "#"
    if design == "shadow":
        below = row == LOGO_HEIGHT - 1 or not LOGO_MASK[row + 1][column]
        right = column == LOGO_WIDTH - 1 or not LOGO_MASK[row][column + 1]
        if below or right:
            return "▓" if unicode else "@"
    if design == "glitch" and (row * 11 + column * 7) % 9 == 0:
        return ("░", "▒", "▓")[(row + column) % 3] if unicode else (".", "+", "#")[(row + column) % 3]
    if design == "layered":
        layered = ("▀", "▓", "█", "█", "▒", "▓", "▄") if unicode else ("^", "+", "#", "#", "=", "+", "_")
        return layered[row]
    return base


def render_pixel_logo(
    design: str = "block",
    pixel_style: str = "solid",
    *,
    unicode: bool = True,
) -> str:
    """Render one visual skin without changing the OKAPI geometry."""

    if design not in LOGO_DESIGNS:
        raise ValueError(f"unknown logo design: {design}")
    if pixel_style not in PIXEL_STYLES:
        raise ValueError(f"unknown pixel style: {pixel_style}")
    lines: list[str] = []
    for row, mask_row in enumerate(LOGO_MASK):
        line = "".join(
            _pixel_character(
                design=design,
                pixel_style=pixel_style,
                row=row,
                column=column,
                unicode=unicode,
            )
            if filled
            else " "
            for column, filled in enumerate(mask_row)
        )
        lines.append(line)
    return "\n".join(lines)


OKAPI_TITLES = tuple(
    AsciiAsset(
        design,
        render_pixel_logo(design, PIXEL_STYLES[index % len(PIXEL_STYLES)]),
        unicode=True,
    )
    for index, design in enumerate(LOGO_DESIGNS)
)

# Compatibility names now point only to logo skins; no rendered public asset
# contains a mascot or an animal silhouette.
OKAPI_ARTS = OKAPI_TITLES
OKAPI_LARGE = OKAPI_TITLES[:2]
OKAPI_MEDIUM = OKAPI_TITLES[2:4]
OKAPI_SMALL = OKAPI_TITLES[4:]


def titles_for_width(width: int, *, unicode: bool) -> tuple[AsciiAsset, ...]:
    """Return equal-size logo skins, or a narrow-terminal word fallback."""

    if width < LOGO_WIDTH:
        return (AsciiAsset("minimal", "OKAPI"),)
    if unicode:
        return OKAPI_TITLES
    return tuple(
        AsciiAsset(
            design,
            render_pixel_logo(design, PIXEL_STYLES[index % len(PIXEL_STYLES)], unicode=False),
        )
        for index, design in enumerate(LOGO_DESIGNS)
    )
