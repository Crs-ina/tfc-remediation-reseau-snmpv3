# OKAPI — splash pixel-art actif

Le splash courant affiche uniquement le mot **OKAPI**. Aucune mascotte ou
silhouette animale n’est sélectionnée ni rendue.

## Invariants visuels

- Une matrice unique de 27 × 7 cellules définit la géométrie du logo.
- O, K, A et P conservent une largeur de cinq cellules ; I reste volontairement
  plus étroit. L’espacement est identique dans toutes les variantes.
- Les designs `block`, `outline`, `shadow`, `glitch` et `layered` modifient
  uniquement l’habillage des cellules actives.
- Les styles `solid`, `shade`, `gradient`, `outline`, `double` et `layered`
  utilisent notamment `█`, `▓`, `▒`, `░`, `▀`, `▄`, `╔`, `═` et leurs
  fallbacks ASCII. Ils ne changent jamais le masque du mot.
- Un terminal de moins de 27 colonnes reçoit le fallback lisible `OKAPI`.

## Randomisation stable

Chaque affichage sélectionne une fois le layout, la palette, le design, le
style de pixels, l’animation, le sous-titre et les décorations. Ce choix est
conservé jusqu’à la dernière frame : l’animation assemble donc le même logo au
même emplacement au lieu d’en sélectionner un nouveau.

Les animations disponibles sont :

- `left_to_right`
- `pixel_reveal`
- `scan_line`
- `letter_by_letter`
- `glitch_assembly`
- `shadow_build`

Elles durent environ 0,72 seconde, redessinent le même bloc avec les séquences
ANSI de déplacement du curseur et restaurent toujours le curseur et `RESET`
dans un bloc `finally`. Le boot complet reste dans la cible de 0,5 à 1,5
seconde. Le mode `--fast` ne fait aucun appel à `sleep`.

## Sécurité de sortie

Le splash reste désactivé pour une sortie redirigée et pour `json_mode=True`.
Les options existantes restent valides : `--no-splash`, `--no-color`, `--fast`
et `--no-animation`.

## Vérification

```bash
python -m app.cli.ui.preview --preview --width 100
pytest -q tests/test_okapi_art.py
```

Les tests contrôlent l’égalité exacte des masques et dimensions pour toutes
les combinaisons design × pixels, les huit compositions, les six animations,
les terminaux étroits et la restauration du curseur après exception.
