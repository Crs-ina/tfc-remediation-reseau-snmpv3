# OKAPI — Splash screen professionnel (archive de la version mascotte)

> Ce document décrit l’ancienne version et n’est plus la spécification active.
> Le splash courant ne rend plus aucun animal. Voir
> [OKAPI_PIXEL_SPLASH.md](OKAPI_PIXEL_SPLASH.md) pour le comportement livré.

## Résultat livré

Le splash screen historique a été remplacé par une identité terminal modulaire,
responsive et testable. Les photographies de référence ont guidé les choix
morphologiques suivants : oreilles très larges et ouvertes, tête étroite,
museau allongé, encolure de giraffidé, corps brun massif, croupe ronde, quatre
jambes fines et bandes horizontales contrastées. La couleur renforce cette
lecture, mais aucun dessin ne dépend de la couleur pour être identifiable.

Le catalogue contient :

- 7 dessins réellement distincts : 2 LARGE, 2 MEDIUM et 3 SMALL/TINY ;
- 6 titres : BLOCK, HASH, LINE, DIGITAL, SYMBOL et MINIMAL ;
- 8 compositions : mascot-first, title-first, side-by-side, frame, telemetry,
  constellation, minimal et command-line ;
- 6 palettes ANSI harmonisées : okapi, forest, network, terminal, cyber, mono ;
- 3 animations courtes : dots, progress et steps ;
- 4 sous-titres et 4 messages de démarrage sélectionnables ;
- 0 à 8 décorations, avec fallback ASCII pur.

## A. Aperçu visuel

Les blocs suivants sont des compositions réellement produites par le moteur.
Le catalogue complet, avec les grands dessins et les couleurs ANSI, se consulte
avec la commande indiquée à la fin de ce document.

### VARIANT 01 — MASCOT-FIRST

```text
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

         ####  #  #   ##   ####  ###
        #  #  # #   #  #  #  #   #
        #  #  ##    ####  ####    #
        #  #  # #   #  #  #      #
         ####  #  #  #  #  #     ###

                 [ OKAPI ]
         Network Remediation Engine
```

### VARIANT 02 — TITLE-FIRST

```text
        ___   | /     /\    |---\   |
       /   \  |/     /  \   |   /   |
      |     | |\    /----\  |---    |
       \___/  | \  /      \ |       |

                 [ OKAPI ]

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

        Secure Network Operations CLI
```

### VARIANT 03 — SIDE-BY-SIDE

```text
       /\        /\
      /  \__  __/  \    O K A P I
      \ o  /--\  o /
       `--/____\--'     [ OKAPI ]
          |====|        Observe | Detect | Remediate
          |=||=|
         /\/\  /\/\
```

### VARIANT 04 — FRAME

```text
    +----------------------------------+
    |        /\             /\         |
    |   ____/  \___________/  \_       |
    | <__  o    __              `.     |
    |    `-.__(___)__.            \    |
    |        \  ||   `------------|    |
    |         \_||____ .======.   |--< |
    |          |==| |==|=  =|==| |==|  |
    |          |= | |= |== ==|= | |= | |
    |          /\   /\       /\   /\   |
    |                                  |
    |            [ OKAPI ]             |
    |  Secure Network Operations CLI   |
    +----------------------------------+
```

### VARIANT 05 — TELEMETRY

```text
      [ OKAPI :: SNMPv3 :: AUTHPRIV ]

           @@@  @ @   @   @@@  @
           @ @  @@   @@@  @@@  @
           @@@  @ @  @ @  @    @

             /\             /\
        ____/  \___________/  \_
      <__  o    __              `.
         `-.__(___)__.            \
             \  ||   `------------|
              \_||____ .======.   |--<
               |==| |==|=  =|==| |==|
               |= | |= |== ==|= | |= |
               /\   /\       /\   /\

       SECURE | POLICY LOADED | GUARDED
```

### VARIANT 06 — CONSTELLATION

```text
      *                .                 +

         /\                      /\
        /  \__     .----.     __/  \
        \     `---/ o  o \---'     /
         `--._____\  --  /_____.--'
                  /`----'\
              .--'   ||   `--.
             /  .==========.  \
            |  /== == == ==\  |
             \ |== == == ==| /
              `|==|=|==|=|==|'
               /\  /\  /\  /\

                 [ OKAPI ]
        Observe | Detect | Remediate

            +             *          .
```

### VARIANT 07 — MINIMAL

```text
               /\        /\
              /  \__  __/  \
              \ o  /--\  o /
               `--/____\--'
                  |====|
                  |=||=|
                 /\/\  /\/\

                 [ OKAPI ]
         Network Remediation Engine
```

### VARIANT 08 — COMMAND-LINE

```text
       $ okapi --initialize --secure

         01110 1  1  0110  1110  1
         1   1 1 1   1  1  1  1  1
         1   1 11    1111  1110  1
         01110 1  1  1  1  1     1

               /\        /\
              /  \__  __/  \
              \ o  /--\  o /
               `--/____\--'
                  |====|
                  |=||=|
                 /\/\  /\/\

                 [ OKAPI ]
  observe > detect > validate > remediate
```

## B. Architecture

```text
app/cli/
├── entrypoint.py             # transmet les vrais arguments de la commande
├── okapi.py                  # intégration au menu administrateur
├── okapi_art.py              # façade de compatibilité
└── ui/
    ├── __init__.py
    ├── ascii_art.py          # animaux et titres, sans logique d'affichage
    ├── colors.py             # palettes, RESET, détection ANSI/Unicode
    ├── animations.py         # dots, progress, boot sequence
    ├── splash.py             # sélection, layouts, centrage et affichage sûr
    └── preview.py            # point d'entrée du catalogue visuel
```

La séparation garantit que les dessins n’accèdent ni à Flask, ni à SQLite, ni
au réseau. Le splash n’intervient jamais dans la logique SNMPv3 et ne peut donc
pas modifier le comportement de remédiation.

## C. API directement intégrable

L’API publique principale est :

```python
from app.cli.ui.splash import show_splash

show_splash(
    animated=True,
    fast=False,
    randomize=True,
)
```

Les fonctions auxiliaires livrées sont :

```python
from app.cli.ui.animations import animate_boot_sequence, animate_dots, animate_progress
from app.cli.ui.splash import build_splash, center_multiline, preview_all, render_splash
```

`show_splash()` vérifie `stream.isatty()`. Il retourne `False` et n’écrit aucun
octet lorsque la sortie est redirigée ou lorsque `json_mode=True`. Le bloc
`finally` écrit toujours `RESET` après une sortie colorée.

## D. Configuration et extension

La configuration par défaut est exposée dans `SPLASH_CONFIG` : activation,
randomisation, animation, couleurs, décorations et sous-titre.

- Nouveau dessin : créer un `AsciiAsset` dans `ascii_art.py`, puis l’ajouter au
  tuple de taille appropriée. Les tests imposent des oreilles et des rayures.
- Nouveau titre : ajouter un `AsciiAsset` à `OKAPI_TITLES` ; son `width` est
  calculé automatiquement.
- Nouvelle palette : ajouter une entrée à `PALETTES` dans `colors.py` avec les
  sept rôles body, stripe, title, accent, muted et success.
- Nouvelle animation : ajouter une fonction courte dans `animations.py`, puis
  une identité à `ANIMATION_STYLES` et son dispatch dans
  `animate_boot_sequence()`.
- Sous-titre : modifier `SPLASH_CONFIG["subtitle"]` ou compléter `SUBTITLES`.

Options utilisateur :

```bash
okapi --fast
okapi --no-animation
okapi --no-color
okapi --no-splash
```

Le mode `fast` n’appelle aucun délai. `--no-animation` conserve l’illustration
et affiche immédiatement `OKAPI READY`. `--no-splash` passe directement à
l’interface.

## E. Test et aperçu

Catalogue complet :

```bash
python -m app.cli.ui.preview --preview --width 100
python -m app.cli.ui.preview --preview --width 72 --no-color --ascii
okapi preview-splash --width 100
```

Tests automatisés :

```bash
pytest -q tests/test_okapi_art.py
pytest -q
```

Les tests vérifient la diversité réelle des dessins, les huit layouts, les six
palettes, le centrage malgré ANSI, les largeurs 100/59/40/24/12, le RESET, le
mode rapide sans `sleep`, les options CLI et l’absence totale de sortie dans un
pipeline ou un flux JSON.
