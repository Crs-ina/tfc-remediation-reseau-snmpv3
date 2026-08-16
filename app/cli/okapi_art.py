"""Responsive, ANSI-optional ASCII identity for the OKAPI terminal application."""
from __future__ import annotations

import random
import shutil
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Palette:
    name: str
    body: str
    stripe: str
    title: str
    accent: str


PALETTES = (
    Palette("nature", "38;5;94", "38;5;230", "38;5;178", "38;5;28"),
    Palette("forest", "38;5;58", "38;5;223", "38;5;70", "38;5;35"),
    Palette("cyber", "38;5;39", "38;5;255", "38;5;129", "38;5;45"),
    Palette("terminal", "38;5;34", "38;5;255", "38;5;40", "38;5;22"),
    Palette("sunset", "38;5;130", "38;5;229", "38;5;214", "38;5;166"),
    Palette("neon", "38;5;51", "38;5;255", "38;5;201", "38;5;93"),
)

# Profile-left adult okapi: broad ears, short giraffid neck, dark body and
# deliberately horizontal hindquarter/leg stripes. The monochrome drawing is
# readable before ANSI styling is applied.
LARGE_OKAPI = r"""
                                  .--.      .--.
                                 /    \____/    \
                            .---'  .-._  _.-.    `---.
                         .-'      /  / \/ \  \        `-.
                      .-'        /  /  oo  \  \          `.
                    .'          /  |   __   |  \           \
                   /           /   |  (__)  |   \           \
              ____/           /     \  --  /     \___        |
          _.-'    `-.        /       `----'        . `-.     |
       .-'          `-._____/          |            \   `.___/
     .'                    /           |             \        `.
    /       .-''''-.      /            |              \         \
   /      .'  .--.  `.   /             |               \         |
  |      /   /    \   \ /              |                |        |
  |     |   |      |   |               |                |        |
  |     |   |      |   |               |                |        |
  |      \   \____/   /                |                |       /
   \      `-._____.-'      .-----------'                |      /
    `.                  .-'      .-----------------.     |   .'
      `-.____________.-'       .'  =  =  =  =  =    `.   |.-'
       /      |      \        /  == == == == == ==    \  |
      /       |       \      |  =  =  =  =  =  =  =    | |
     /        |        \     | == == == == == == ==    | |
    /         |         \     \  =  =  =  =  =  =     /  |
   /          |          \     `.== == == == == == .-'   |
  /           |           \       `--._________.--'      |
 /            |            \          |       |           |
|             |             |         |       |           |
|        ==   |      ==     |    ==   |  ==   |     ==    |
|       ====  |     ====    |   ====  | ====  |    ====   |
|        ==   |      ==     |    ==   |  ==   |     ==    |
|             |             |         |       |           |
 \           / \           /          /       \          /
  `._       /   \       _.'          /         \      _.'
     `-----'     `-----'            /           \----'
        hoof        hoof            hoof        hoof
""".strip("\n")

MEDIUM_OKAPI = r"""
                       /\      /\
                  .---/  \____/  \---.
              _.-'    .-._  _.-.    `-._
           .-'       /  oo\/oo  \       `-.
      ____/         |     __     |         \__
  .--'    `-.        \   (__)   /       .-'   `--.
 /           `-.______`---||---'_____.-'          \
|       .----.      /     ||     \      .----.      |
|      /      \____/      ||      \____/      \     |
|      \                    |                    / |
 \      `-._________________|_________________.-'  /
  `-.        .-============================-.    .'
     `------'  == == == == == == == == ==  `---'
       |  |    =  =  =  =  =  =  =  =  =     |  |
       |==|    == == == == == == == == ==    |==|
       |  |    =  =  =  =  =  =  =  =  =     |  |
       |==|    == == == == == == == == ==    |==|
       /  \      /  \      /  \      /  \     /  \
""".strip("\n")

MINI_OKAPI = r"""
      /\   /\
  .--/  \_/  \--.
 /  o  .---.  o  \__
 \     \___/     _  `.
  `--._____.----' `--'
      |  ===  ===  |
     =|= ===  === =|=
      |   =    =   |
     / \ / \  / \ / \
""".strip("\n")

# Five independently selectable poses; style variations preserve the essential
# silhouette while avoiding a visually static splash screen across launches.
OKAPI_ARTS = {
    "large": (LARGE_OKAPI, LARGE_OKAPI.replace("==", "##"), LARGE_OKAPI.replace("==", "--")),
    "medium": (MEDIUM_OKAPI, MEDIUM_OKAPI.replace("==", "##"), MEDIUM_OKAPI.replace("==", "--")),
    "small": (MINI_OKAPI, MINI_OKAPI.replace("===", "###"), MINI_OKAPI.replace("===", "---")),
}

TITLES = (
    """  OOO  K  K  AAA  PPPP  III
 O   O K K  A   A P   P  I
 O   O KK   AAAAA PPPP   I
 O   O K K  A   A P      I
  OOO  K  K A   A P     III""",
    """####  #  #   ##   ####  ###
#  #  # #   #  #  #  #   #
#  #  ##    ####  ####   #
#  #  # #   #  #  #      #
####  #  #  #  #  #     ###""",
    """[ O K A P I ]  ::  NETWORK REMEDIATION CLI""",
    """/O/  /K/  /A/  /P/  /I/
\\O\\  \\K\\  \\A\\  \\P\\  \\I\\""",
    """* O *  * K *  * A *  * P *  * I *""",
)

DECORATIONS = ("*", "+", ".", "o")


def terminal_width() -> int:
    return shutil.get_terminal_size(fallback=(80, 24)).columns


def _ansi(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def _center(line: str, width: int) -> str:
    return line.center(width) if len(line) <= width else line


def render_random_banner(*, width: int | None = None, color: bool | None = None) -> str:
    """Return a fitting splash; no terminal output or secrets are handled here."""
    width = width or terminal_width()
    size = "large" if width >= 100 else "medium" if width >= 60 else "small"
    enabled = sys.stdout.isatty() if color is None else color
    palette = random.choice(PALETTES)
    art = random.choice(OKAPI_ARTS[size])
    title = random.choice(TITLES if width >= 60 else ("OKAPI", "[ OKAPI ]"))
    lines: list[str] = []
    for _ in range(random.randint(0, 5)):
        star = random.choice(DECORATIONS)
        offset = random.randint(0, max(0, width - 1))
        lines.append(" " * offset + _ansi(star, palette.accent, enabled))
    for line in art.splitlines():
        stripe = any(mark in line for mark in ("==", "##", "--"))
        lines.append(_ansi(_center(line, width), palette.stripe if stripe else palette.body, enabled))
    lines.append("")
    lines.extend(_ansi(_center(line, width), palette.title, enabled) for line in title.splitlines())
    # A plain-text signature is kept even with a decorative title so scripts,
    # screen readers and users always see the product name literally.
    lines.append(_ansi(_center("[ OKAPI ]", width), palette.title, enabled))
    lines.append(_ansi(_center("Network Remediation CLI", width), palette.accent, enabled))
    return "\n".join(lines)
