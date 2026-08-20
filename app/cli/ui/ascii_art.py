"""Legacy asset names kept for import compatibility.

The active catalogue is rebound to fixed-geometry logos at the end of this
module. New code should import :mod:`app.cli.ui.pixel_art` directly.
"""
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


# LARGE 01 — left-facing profile based on the characteristic long muzzle,
# high shoulders and strongly striped rump visible in the supplied photos.
OKAPI_PROFILE_LARGE = AsciiAsset(
    "forest-profile",
    r"""
                /\                         /\
           ____/  \_______________________/  \__
       _.-'          .--.          .--.          `-._
    .-'              / o \________/ o \              `.
   /       _________/       ____       \_________      \
  <_______/          \     .'    `.     /         `-.   |
   `-.                 `-._\______/_.-'              \  |
      `--.___              /  ||  \                   | |
             `-._         /   ||   \                  | |
                 `-._____/    ||    \_____.-----------' |
                       /      ||          /              |
                      /       ||         /               |
             ________/        ||        /________________|______
          .-'                                                       `-.
        .'              .::::::::::::::::::::::::::::::.                 `.
       /                                                               \
      |                                          .-================-.   |---<
      |                                         / == == == == == == \  |
      |                                        | =  =  =  =  =  =  =|  |
       \                                       |== == == == == == ==| /
        `-._______________________________.----\ =  =  =  =  =  = /-'
             |==|          |==|                         |==|      |==|
             |= |          |= |                         |= |      |= |
             |==|          |==|                         |==|      |==|
             |= |          |= |                         |= |      |= |
             |  |          |  |                         |  |      |  |
             |  |          |  |                         |  |      |  |
             /\            /\                           /\        /\
            /__\          /__\                         /__\      /__\
    """.strip("\n"),
)


# LARGE 02 — rear three-quarter pose, echoing the supplied photograph where
# the animal looks back over its broad, striped hindquarters.
OKAPI_LOOKBACK_LARGE = AsciiAsset(
    "look-back",
    r"""
                         /\                 /\
                    ____/  \____       ____/  \____
                 .-'            `-._.-'            `-.
                /       .--.       |       .--.       \
               |       /  o \      |      / o  \       |
               |       \     \_____|_____/     /       |
                \       `-._    ___    _.-'          _/
                 `-._       `--'   `--'          _.-'
                     `---.      / \      .------'
                          \    /   \    /
                    .------\__/     \__/------.
                 .-'                              `-.
               .'          .----------------.        `.
              /          .'                  `.        \
             |          /                      \        |
             |         |        .========.      |       |
             |         |      .'== == == ==`.   |       |
             |         |     / =  =  =  =  = \  |       |
             |          \   |== == == == == ==|/       /
              \          `-.| =  =  =  =  =  =|     .'
               `-.          \== == == == == ==/  _.-'
                  `---.______`-=============-'--'
                      |==|      |==|      |  |      |  |
                      |= |      |= |      |  |      |  |
                      |==|      |==|      |  |      |  |
                      |= |      |= |      |  |      |  |
                      |  |      |  |      |  |      |  |
                      |  |      |  |      |  |      |  |
                      /\        /\        /\        /\
                     /__\      /__\      /__\      /__\
    """.strip("\n"),
)


# MEDIUM 01 — compact profile for 65–99 column terminals.
OKAPI_PROFILE_MEDIUM = AsciiAsset(
    "compact-profile",
    r"""
             /\                    /\
        ____/  \__________________/  \_
    _.-'       / o\____    ____/o \    `-.
 __/     _____/       /____\       \__    \
<_______/      `-.___(______)___.-'   `-.  |
 `--._              /  ||  \             \ |
      `-.___________/   ||   \_____________|____
                    \   ||                     `-.
                     \  ||                        \
                      \_||_________________________|
                       |       .-============-.    |--<
                       |      /== == == == ==  \   |
  _____________________|_____|=  =  =  =  =  = |__|
 |==|       |==|      |== == == == == ==|   |==|   |==|
 |= |       |= |       \=  =  =  =  =  /    |= |   |= |
 |==|       |==|        `-==========--'      |==|   |==|
 |= |       |= |                              |= |   |= |
 |  |       |  |                              |  |   |  |
 |  |       |  |                              |  |   |  |
 /\         /\                                /\     /\
/__\       /__\                              /__\   /__\
    """.strip("\n"),
)


# MEDIUM 02 — frontal/three-quarter stance with open ears and striped thighs.
OKAPI_SENTINEL_MEDIUM = AsciiAsset(
    "forest-sentinel",
    r"""
       /\                                  /\
   ___/  \___                          ___/  \___
 .'          `-.        .--.        .-'          `.
/      .--.     `------/ oo \------'     .--.      \
\_____/    \___________\ -- /___________/    \_____/
                  .-----`--'-----.
              _.-'       ||       `-._
          _.-'           ||           `-._
        .'               ||               `.
       /        .-----------------.          \
      |       .'                   `.         |
      |      /                       \        |
      |     |     == == == == ==     |       |
       \    |    =  =  =  =  =  =    |      /
        `-. |     == == == == ==     |  _.-'
           `\____=__=__=__=__=_____/-'
             |==|     |==|       |==|     |==|
             |= |     |= |       |= |     |= |
             |==|     |==|       |==|     |==|
             |  |     |  |       |  |     |  |
             /\       /\         /\       /\
    """.strip("\n"),
)


# SMALL 01 — all-ASCII profile.  The ears and alternating bars survive even
# in a 40-column terminal.
OKAPI_PROFILE_SMALL = AsciiAsset(
    "pocket-profile",
    r"""
       /\             /\
  ____/  \___________/  \_
<__  o    __              `.
   `-.__(___)__.            \
       \  ||   `------------|
        \_||____ .======.   |--<
         |    | /== == ==\  |
         |==| |==|=  =|==| |==|
         |= | |= |== ==|= | |= |
         |  | |  |     |  | |  |
         /\   /\       /\   /\
    """.strip("\n"),
)


# SMALL 02 — a different, front-facing silhouette rather than a re-skinned
# copy of the profile.
OKAPI_FACE_SMALL = AsciiAsset(
    "pocket-sentinel",
    r"""
 /\                      /\
/  \__     .----.     __/  \
\     `---/ o  o \---'     /
 `--._____\  --  /_____.--'
          /`----'\
      .--'   ||   `--.
     /  .==========.  \
    |  /== == == ==\  |
    |  |=  =  =  = |  |
     \ |== == == ==| /
      `|==|=|==|=|==|'
       /\  /\  /\  /\
    """.strip("\n"),
)


OKAPI_TINY = AsciiAsset(
    "tiny-okapi",
    r"""
 /\        /\
/  \__  __/  \
\ o  /--\  o /
    `--/____\--'
       |====|
       |=||=|
      /\/\  /\/\
    """.strip("\n"),
)


OKAPI_LARGE = (OKAPI_PROFILE_LARGE, OKAPI_LOOKBACK_LARGE)
OKAPI_MEDIUM = (OKAPI_PROFILE_MEDIUM, OKAPI_SENTINEL_MEDIUM)
OKAPI_SMALL = (OKAPI_PROFILE_SMALL, OKAPI_FACE_SMALL, OKAPI_TINY)
OKAPI_ARTS = OKAPI_LARGE + OKAPI_MEDIUM + OKAPI_SMALL


TITLE_BLOCK = AsciiAsset(
    "block",
    """██████╗ ██╗  ██╗ █████╗ ██████╗ ██╗
██╔═══██╗██║ ██╔╝██╔══██╗██╔══██╗██║
██║   ██║█████╔╝ ███████║██████╔╝██║
██║   ██║██╔═██╗ ██╔══██║██╔═══╝ ██║
╚██████╔╝██║  ██╗██║  ██║██║     ██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝""",
    unicode=True,
)

TITLE_HASH = AsciiAsset(
    "hash",
    """ ####  #  #   ##   ####  ###
#  #  # #   #  #  #  #   #
#  #  ##    ####  ####    #
#  #  # #   #  #  #      #
 ####  #  #  #  #  #     ###""",
)

TITLE_LINE = AsciiAsset(
    "line",
    r"""  ___   | /     /\    |---\   |
 /   \  |/     /  \   |   /   |
|     | |\    /----\  |---    |
 \___/  | \  /      \ |       |""",
)

TITLE_DIGITAL = AsciiAsset(
    "digital",
    """01110 1  1  0110  1110  1
1   1 1 1   1  1  1  1  1
1   1 11    1111  1110  1
01110 1  1  1  1  1     1""",
)

TITLE_SYMBOL = AsciiAsset(
    "symbol",
    """@@@  @ @   @   @@@  @
@ @  @@   @@@  @@@  @
@@@  @ @  @ @  @    @""",
)

TITLE_MINIMAL = AsciiAsset("minimal", "O K A P I")

OKAPI_TITLES = (
    TITLE_BLOCK,
    TITLE_HASH,
    TITLE_LINE,
    TITLE_DIGITAL,
    TITLE_SYMBOL,
    TITLE_MINIMAL,
)


def animals_for_width(width: int) -> tuple[AsciiAsset, ...]:
    """Return genuinely different mascots that fit the terminal category."""

    if width >= 100:
        return OKAPI_LARGE + OKAPI_MEDIUM
    if width >= 65:
        return OKAPI_MEDIUM + OKAPI_SMALL
    return OKAPI_SMALL


def titles_for_width(width: int, *, unicode: bool) -> tuple[AsciiAsset, ...]:
    """Return titles whose measured width fits the current terminal."""

    candidates = tuple(
        title
        for title in OKAPI_TITLES
        if title.width <= width and (unicode or not title.unicode)
    )
    return candidates or (TITLE_MINIMAL,)


# The active catalogue is the fixed-geometry pixel system. These assignments
# preserve historical import names without exposing or rendering silhouettes.
from . import pixel_art as _pixel_art

AsciiAsset = _pixel_art.AsciiAsset
LOGO_DESIGNS = _pixel_art.LOGO_DESIGNS
PIXEL_STYLES = _pixel_art.PIXEL_STYLES
LOGO_MASK = _pixel_art.LOGO_MASK
LOGO_WIDTH = _pixel_art.LOGO_WIDTH
LOGO_HEIGHT = _pixel_art.LOGO_HEIGHT
render_pixel_logo = _pixel_art.render_pixel_logo
OKAPI_TITLES = _pixel_art.OKAPI_TITLES
OKAPI_ARTS = _pixel_art.OKAPI_ARTS
OKAPI_LARGE = _pixel_art.OKAPI_LARGE
OKAPI_MEDIUM = _pixel_art.OKAPI_MEDIUM
OKAPI_SMALL = _pixel_art.OKAPI_SMALL
OKAPI_PROFILE_LARGE = OKAPI_TITLES[0]
OKAPI_LOOKBACK_LARGE = OKAPI_TITLES[1]
OKAPI_PROFILE_MEDIUM = OKAPI_TITLES[2]
OKAPI_SENTINEL_MEDIUM = OKAPI_TITLES[3]
OKAPI_PROFILE_SMALL = OKAPI_TITLES[4]
OKAPI_FACE_SMALL = OKAPI_TITLES[0]
OKAPI_TINY = OKAPI_TITLES[1]
TITLE_BLOCK, TITLE_HASH, TITLE_LINE, TITLE_DIGITAL, TITLE_SYMBOL = OKAPI_TITLES
TITLE_MINIMAL = AsciiAsset("minimal", "OKAPI")
titles_for_width = _pixel_art.titles_for_width


def animals_for_width(width: int) -> tuple[AsciiAsset, ...]:
    """Compatibility alias returning logo skins only."""

    del width
    return OKAPI_TITLES
