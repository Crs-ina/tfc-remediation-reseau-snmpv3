# Rapport de synchronisation du backlog GitHub Project

_Date de l’audit : 18 août 2026_

## État initial

- Project concerné : `Crs-ina / Suivi TFC - Remédiation réseau` (Project n° 1).
- Les captures fournies montrent 37 items : 15 `Todo`, 7 `In Progress`, 15 `Done` et 0 `blocked`.
- Les champs visibles sont notamment : Title, Assignees, Status, Linked pull requests, Sub-issues progress, Sprint, Priority et dates.
- Le dépôt comptait 39 issues, dont deux doublons documentaires ouverts.
- Aucun pull request n’est présent.
- La branche `main` ne contient que les documents initiaux ; le prototype fonctionnel est présent sur `feat/snmpv3-arista-remediation`.

## Preuves analysées

La branche d’implémentation contient notamment :

- le prototype OKAPI Flask/SQLAlchemy/SQLite ;
- les clients SNMPv3 et le routage IP → MAC → port ;
- les playbooks JSON ;
- les protections whitelist, dry-run, rollback, audit et capacité fail-closed ;
- l’unité systemd et la route `/health` ;
- les tests automatisés et le rapport final d’implémentation.

Le rapport `docs/FINAL_IMPLEMENTATION_REPORT.md` indique 111 tests réussis et 3 tests d’intégration EVE-NG volontairement ignorés. Les flux matériels restant à rejouer ont été convertis en issues atomiques.

## Modifications réalisées

### Doublons fermés

- #1 — fermé avec le motif `duplicate` : doublon de #7.
- #4 — fermé avec le motif `duplicate` : doublon de #5.

Chaque fermeture comporte un commentaire expliquant le rattachement. Aucun contenu ni issue n’a été supprimé.

### Issues existantes fiabilisées

- #28 renommée en **Décrire la désactivation d’une interface** et complétée avec un objectif, un périmètre, des critères d’acceptation, des preuves attendues et une dépendance de qualification.
- #35 renommée en **Documenter le mode dry-run de la remédiation**, complétée avec des preuves de code et de tests, puis fermée comme terminée.
- #39 renommée en **Rédiger le playbook du conflit d’adresse IP**, complétée avec les preuves du playbook versionné et des tests, puis fermée comme terminée.

Ces trois issues sont assignées à `Crs-ina`.

### Nouvelles issues atomiques

- #40 — Vérifier l’isolement du VLAN 18 dans EVE-NG.
- #41 — Tester le rollback du VLAN de quarantaine.
- #42 — Décrire la réactivation d’une interface.
- #43 — Tester la mise en quarantaine dans le VLAN 18.
- #44 — Tester la chaîne Zabbix vers le webhook OKAPI.
- #45 — Tester le transport SNMPv3 TRAP vers Zabbix.
- #46 — Tester le transport SNMPv3 INFORM vers Zabbix.
- #47 — Vérifier l’endpoint /health après déploiement.
- #48 — Qualifier les actions ifAdminStatus sur Arista vEOS.
- #49 — Déployer le backend OKAPI avec systemd.

Toutes ces issues :

- ont un titre à action unique ;
- sont assignées à `Crs-ina` ;
- contiennent Objectif, Contexte, Périmètre, Hors périmètre, Livrable attendu, Critères d’acceptation, Preuve attendue, Dépendances et Référence TFC ;
- restent ouvertes, car une preuve de laboratoire ou de déploiement reste nécessaire.

## Doublons

- #1 → #7.
- #4 → #5.

Aucune issue existante n’a été supprimée.

## Points volontairement non modifiés

Les items de conception et de documentation qui n’ont pas de preuve de fichier directement identifiable restent inchangés, notamment les diagrammes et les sections du mémoire. Leur statut ne doit pas être déduit d’une date ou d’un intitulé seul.

## Points à vérifier avec l’étudiante

- Rejouer les tests matériels EVE-NG et documenter les preuves dans les issues #40, #41, #43 à #46 et #48.
- Vérifier le déploiement réel de systemd et la réponse du point `/health` dans #47 et #49.
- Vérifier les livrables exacts des diagrammes avant de modifier leurs statuts.
- Ajouter les issues #40 à #49 au Project et renseigner Sprint, Priority, Status et Target date une fois un jeton disposant du droit `read:project`/Project est disponible.

## Limite de synchronisation Project

L’authentification du dépôt est disponible, mais l’API GitHub Project a refusé l’accès faute de droit `read:project`. Les champs et vues du Project n’ont donc pas été modifiés dans cette synchronisation. Cette limitation ne concerne pas les issues du dépôt, qui ont été mises à jour avec succès.

## État final du dépôt

- 49 issues au total.
- 30 issues ouvertes.
- 19 issues fermées.
- Aucun pull request.
- Les nouveaux travaux restants sont séparés en tâches atomiques et vérifiables.

