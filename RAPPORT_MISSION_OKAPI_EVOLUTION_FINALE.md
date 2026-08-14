# Rapport — évolution OKAPI

## Réalisé

- Nouvelle identité CLI **OKAPI**, bannière ASCII (animal et mot OKAPI), état
  du calendrier, sécurité SNMPv3 et accès écriture sans afficher de secret.
- Ajout de la septième entité `ADMINISTRATOR` et de la migration Alembic
  `0003_okapi_administrators`.
- `AUDIT_LOG.administrator_id` est nullable : `ADMINISTRATOR 1 -> 0..N AUDIT_LOG`.
- Création et authentification de comptes via hash Werkzeug. La session est
  volontairement locale au processus de la CLI interactive ; plusieurs SSH
  peuvent donc être connectés simultanément sans partager une identité.
- Menu `flask --app run.py okapi` en anglais : sélection numérotée des
  incidents, approbation/refus liés à l'administrateur, historique, audit et
  rollback après succès. Les identifiants internes restent réservés aux outils
  de maintenance existants.
- Compare-and-set SQL sur l'état `WAITING_ADMIN_APPROVAL` : la première décision
  gagne ; une seconde tentative est refusée et auditée
  `CONCURRENT_DECISION_REJECTED`.
- Filtres `--from` / `--to` ajoutés à `incidents list` et `incidents logs`, au
  format local `Africa/Kinshasa`.

## Préservé

Le calendrier dans `app/services/calendar_policy.py` n'a pas été modifié. Le
rollback continue de restaurer `Remediation.previous_vlan_id`; aucune table
`ROLLBACK` n'a été créée. Le moteur SNMPv3, les MIB locales, la whitelist,
`SNMP_WRITE_ENABLED`, les contrôles VLAN et la validation limitée à Arista vEOS
4.29.2F restent inchangés. UniFi demeure `TO_BE_VALIDATED`.

## Validation

`pytest -q` : **57 passed, 3 skipped**. Les trois tests EVE-NG restent opt-in.
La validation manuelle restante dans EVE-NG concerne le parcours interactif
OKAPI avec deux sessions SSH concurrentes, puis la procédure déjà contrôlée
VLAN 10/64 -> VLAN 18 et son rollback vers le vrai PVID initial.

## Documentation MCD/MLD

La spécification textuelle est mise à jour dans `docs/architecture.md`. Les
sources graphiques MCD/MLD ne sont pas présentes sous une forme éditable dans
ce dépôt ; elles devront donc recevoir manuellement l'entité `ADMINISTRATOR`
et la relation nullable vers `AUDIT_LOG`.
