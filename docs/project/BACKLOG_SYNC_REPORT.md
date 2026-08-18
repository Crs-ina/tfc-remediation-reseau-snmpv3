# Rapport de synchronisation du backlog GitHub Project

_Date de synchronisation : 18 août 2026_

## Périmètre

- Repository : `Crs-ina/tfc-remediation-reseau-snmpv3`.
- Project : `Suivi TFC - Remédiation réseau` (Project n° 1).
- Source de planification : Gantt révisé fourni par l’étudiante.
- Période de planification : du `2026-04-15` au `2026-08-20`.

Les dates ci-dessous sont des dates de planification. Elles ne remplacent pas les dates historiques des commits, des créations de fichiers ou des fermetures d’issues.

## État initial

### État historique déjà conservé

- Les captures initiales montraient 37 cartes.
- Les issues #1 et #4 avaient déjà été conservées puis fermées comme doublons de #7 et #5.
- Les issues atomiques #40 à #49 avaient déjà été créées et ajoutées au Project.

### État au début de cette synchronisation

- 47 cartes dans le Project.
- 19 cartes `Done`.
- 6 cartes `In Progress`.
- 22 cartes `Todo`.
- 0 carte `blocked`.
- 17 champs déclarés, dont `Status`, `Sprint `, `Priority` et `Due date`.
- Aucun champ `Start date`.
- 24 cartes sans sprint.
- 23 cartes sans priorité.
- 24 cartes sans date de fin.
- 13 issues sans assignee.

## Planning de référence appliqué

| Phase | Début | Fin |
|---|---:|---:|
| Phase 1 — Finalisation de la conception | 2026-04-15 | 2026-04-30 |
| Phase 2 — Laboratoire et connectivité | 2026-04-27 | 2026-05-22 |
| Phase 3 — Développement du module de détection | 2026-05-18 | 2026-07-03 |
| Phase 4 — Remédiation et interface | 2026-07-01 | 2026-08-14 |
| Phase 5 — Tests et finalisation | 2026-08-10 | 2026-08-20 |

Les intervalles détaillés des tâches ont été repris des captures `gan1.png` et `gan2.png`. Aucun item n’a reçu une date postérieure au 20 août 2026.

## Modifications réalisées

### Project et champs

- Conservation du Project existant et de ses deux vues.
- Conservation des 47 cartes existantes.
- Création du champ `Start date` de type date.
- Remplissage de `Start date` et `Due date` pour les 47 cartes.
- Remplissage de `Sprint ` pour les 47 cartes.
- Remplissage de `Priority` pour les 47 cartes.
- Affectation à `Crs-ina` des 13 issues qui n’avaient pas encore d’assignee.
- Aucun changement arbitraire des statuts : les preuves déjà auditées restent la référence.

### Sprints

Les trois sprints historiques ont été conservés et les sprints 4 à 9 ont été ajoutés pour prolonger le suivi jusqu’au 20 août 2026.

| Sprint | Période | Cartes |
|---|---:|---:|
| Sprint 1 | 2026-06-22 → 2026-06-28 | 5 |
| Sprint 2 | 2026-06-29 → 2026-07-05 | 9 |
| Sprint 3 | 2026-07-06 → 2026-07-12 | 17 |
| Sprint 4 | 2026-07-13 → 2026-07-19 | 2 |
| Sprint 5 | 2026-07-20 → 2026-07-26 | 1 |
| Sprint 6 | 2026-07-27 → 2026-08-02 | 1 |
| Sprint 7 | 2026-08-03 → 2026-08-09 | 1 |
| Sprint 8 | 2026-08-10 → 2026-08-16 | 8 |
| Sprint 9 | 2026-08-17 → 2026-08-20 | 3 |

### Priorités

- 26 cartes `Critical`.
- 19 cartes `High`.
- 2 cartes `Medium`.
- 0 carte `Low`.

## Doublons

- #1 reste fermé comme doublon de #7.
- #4 reste fermé comme doublon de #5.
- Aucun doublon n’a été créé ou supprimé pendant cette synchronisation.

## Points volontairement non modifiés

- Aucun item, issue ou sous-issue supprimé.
- Aucun statut déplacé vers `Done` sans preuve supplémentaire.
- Aucune relation parent/sous-issue cassée.
- Aucune vue recréée ou supprimée.
- Aucun champ utile supprimé.
- Aucun titre d’issue modifié pendant cette passe.

## Points à vérifier avec l’étudiante

- Fournir les preuves de laboratoire pour les issues #40, #41, #43 à #46 et #48.
- Confirmer le déploiement systemd et la réponse réelle de `/health` pour #47 et #49.
- Confirmer la version finale des diagrammes encore `In Progress` avant de fermer leurs issues.
- Vérifier les livrables documentaires encore `Todo` avant tout passage à `Done`.

## État final

- 47 cartes au total.
- 22 `Todo`.
- 6 `In Progress`.
- 19 `Done`.
- 0 `blocked`.
- 47 cartes avec statut.
- 47 cartes avec sprint.
- 47 cartes avec priorité.
- 47 cartes avec date de début.
- 47 cartes avec date de fin.
- 47 cartes avec assignee.
- Date la plus ancienne : `2026-04-15`.
- Date la plus tardive : `2026-08-20`.

Le Project est désormais exploitable en vue tableau et en vue Kanban pour suivre les tâches, les priorités, les sprints et les dates du Gantt sans supprimer l’historique existant.
