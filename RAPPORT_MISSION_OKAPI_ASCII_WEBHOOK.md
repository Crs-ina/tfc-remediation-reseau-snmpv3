# Rapport — identité ASCII OKAPI et configuration webhook Python

## Portée appliquée

Cette intervention traite la demande utilisateur ciblée : améliorer l'apparence
de la CLI OKAPI et préparer le récepteur webhook Python. Elle n'implémente pas
le côté expéditeur Zabbix, ni les autres évolutions fonctionnelles listées dans
la passation jointe.

## Identité visuelle CLI

- Création de `app/cli/okapi_art.py` : un moteur de splash responsive.
- Trois tailles adaptées à la largeur du terminal : large (>= 100), medium
  (60–99) et mini (< 60 colonnes).
- Mascotte en profil gauche : grandes oreilles, tête/museau fins, cou court,
  corps profond, quatre jambes et rayures horizontales visibles sur l'arrière
  train et les pattes même sans ANSI.
- Cinq variantes typographiques du titre, trois rendus de rayures par taille,
  six palettes ANSI harmonieuses, 0–5 décorations ASCII aléatoires et une
  signature textuelle `[ OKAPI ]` systématiquement présente.
- Fallback sans ANSI automatique pour les sorties non interactives. Aucun
  secret, image externe ou emoji n'est utilisé.
- La CLI existante appelle désormais `render_random_banner()` au démarrage,
  tout en conservant les informations de session, calendrier et sécurité SNMP.

## Webhook Python

- `WEBHOOK_BIND_HOST` (défaut `127.0.0.1`) et `WEBHOOK_BIND_PORT` (défaut
  `5000`) sont lus depuis l'environnement et utilisés par `run.py`.
- `WEBHOOK_ALLOWED_SOURCE_IPS` limite par défaut le récepteur à `127.0.0.1`
  et `::1`, ce qui convient à Zabbix et OKAPI colocalisés dans le laboratoire.
- `WEBHOOK_MAX_CONTENT_LENGTH` limite la taille d'une requête à 64 KiB.
- Le contrôle de source intervient avant l'authentification et la validation
  JSON; aucun événement rejeté n'est enregistré.
- `.env.example` et `docs/WEBHOOK_PYTHON_CONFIGURATION.md` documentent les
  variables sans inclure de token réel. L'émetteur Zabbix reste à configurer
  séparément par l'utilisateur.

## Fichiers

Créés : `app/cli/okapi_art.py`, `docs/WEBHOOK_PYTHON_CONFIGURATION.md`,
`tests/test_okapi_art.py`, `tests/test_webhook_configuration.py` et ce rapport.

Modifiés : `app/cli/okapi.py`, `config.py`, `app/routes/webhook.py`, `run.py`
et `.env.example`.

## Vérification

La suite `pytest -q` couvre le rendu sans couleur, le format mini, la remise à
zéro ANSI, les palettes et le refus d'une source webhook non locale. Les tests
EVE-NG restent explicitement opt-in; aucune capacité SNMP supplémentaire n'est
déclarée validée par cette mission.
