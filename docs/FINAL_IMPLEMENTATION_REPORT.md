# Rapport final d'implémentation OKAPI

Date de finalisation : 17 août 2026, fuseau `Africa/Kinshasa`.

## Portée de la livraison

Le prototype reste un monolithe modulaire Flask/SQLAlchemy/SQLite avec une CLI
anglaise, des playbooks JSON et deux clients SNMP séparés. Les diagrammes
finaux fournis n'ont pas été modifiés. Le code a été aligné sur leur flux,
avec un comportement fail-closed dès qu'une cible, une capacité, une identité
ou une précondition n'est pas confirmée.

Les sept routes finales sont présentes :

| Incident | Playbook | Action proposée |
|---|---|---|
| `physical_disconnection` | `PB-PHYSICAL-DOWN-001` | `NO_ACTION` |
| `network_loop` | `PB-LOOP-001` | `SHUTDOWN_PORT` |
| `ip_address_conflict` | `PB-IP-CONFLICT-001` | `QUARANTINE_VLAN` |
| `interface_admin_down` | `PB-INTERFACE-DOWN-001` | `REACTIVATE_PORT` |
| `port_flapping` | `PB-PORT-FLAPPING-001` | `SHUTDOWN_PORT` |
| `vlan_policy_violation` | `PB-VLAN-POLICY-001` | `QUARANTINE_VLAN` |
| absent/non reconnu | `PB-UNKNOWN-001` v1.1 | `NO_ACTION` |

## Fichiers créés, modifiés et supprimés

Créés :

- `app/services/runtime_settings.py` : réglage persistant et fail-closed du
  dry-run ;
- `migrations/versions/0004_linux_administrator_identity.py` : suppression
  des identifiants OKAPI et passage à l'identité Linux ;
- `tests/test_cli_identity.py`, `tests/test_cli_critical_actions.py`,
  `tests/test_identification.py` et `tests/test_port_lock.py` : identité/menu,
  réauthentification critique, limite de deux tentatives et concurrence par
  port.

Modifiés :

- bootstrap/configuration : `app/__init__.py`, `config.py`, `.env.example`,
  `.gitignore` ;
- modèles : `app/models/administrator.py`, `app/models/audit_log.py` ;
- services : `administrators.py`, `identification.py`, `incident_service.py`, `port_lock.py`,
  `remediation.py`, `snmp_preparation.py`, `snmp_execution.py` ;
- SNMP : `client.py`, `mib_catalog.py`, `target_resolver.py` ;
- interface/API : `app/cli/okapi.py`, `app/cli/remediation.py`,
  `app/cli/incidents.py`, `app/routes/webhook.py`, `app/routes/health.py` ;
- documentation : `README.md`, `docs/OKAPI_CLI.md`,
  `docs/architecture.md`, `deploy/README.md`, le présent rapport ;
- tests existants : administrateurs, dry-run/status, webhook, règles/MLD,
  préparation/exécution SNMP, MIB, santé et rendu CLI.

Aucun fichier fonctionnel du projet n'a été supprimé. Les suppressions de
documents externes déjà visibles dans le worktree avant cette intervention
n'ont pas été touchées.

## Architecture finale

```text
Zabbix
  -> POST /api/v1/incidents/zabbix
  -> source autorisée + token constant-time + JSON Schema v1.0
  -> filtre PROBLEM/Recovery + périmètre remediation=enabled
  -> idempotence zabbix_event_id
  -> routage playbook
  -> identification/confirmation read-only
       IP -> MAC -> bridge port -> ifIndex -> interface
  -> whitelist contrôle 1
  -> politique SUPERVISED/AUTOMATIC
  -> snapshot pré-action
  -> attente administrateur sans conversion par timeout
  -> whitelist contrôle 2 + capability gate + cooldown + verrou par port
  -> DRY_RUN ou SET autorisé
  -> GET de vérification
  -> SQLite + audit/attention CLI
```

La découverte et l'identification utilisent `SnmpReadClient`. Le transport
`SnmpRemediationClient` est séparé et n'accepte au niveau le plus bas que
`Q-BRIDGE-MIB::dot1qPvid` avec un index et une autorisation explicite. Les
objets `ifAdminStatus` restent lisibles et leurs actions restent routées, mais
aucun SET réel ne peut sortir tant que la capacité demeure
`TO_BE_VALIDATED`.

## Fonctionnalités réellement implémentées

- validation de source, token et schéma du webhook sans journaliser le token ;
- rejet audité, filtre de périmètre, Recovery et doublons idempotents audités ;
- sept routes canoniques et UNKNOWN/physical strictement sans écriture ;
- identification plafonnée à deux tentatives ;
- pour le conflit IP, vérification standard
  `IP-MIB::ipNetToPhysicalPhysAddress`, comparaison de la MAC Zabbix, puis
  Q-BRIDGE/BRIDGE/IF-MIB ; un désaccord devient `TARGET_MISMATCH` ;
- confirmation port-centric sans MAC pour les autres scénarios ;
- lecture optionnelle `ifAdminStatus`/`ifOperStatus` et escalade humaine pour
  `physical_disconnection`, sans créer de remédiation ;
- whitelist externe avant autorisation et juste avant exécution ;
- VLAN 18 exigé existant et isolé pour toute quarantaine ;
- calendrier `Africa/Kinshasa`, `REACTIVATE_PORT` toujours supervisé et aucun
  basculement automatique d'un état `WAITING_ADMIN_APPROVAL` ;
- snapshot réel du PVID ou de l'état administratif avant action ;
- capability gate exact modèle/objet/SHA-256/AES-256 ;
- feature flag d'écriture, cooldown, verrou inter-processus non bloquant par
  switch/port et maximum deux SET/GET ;
- succès uniquement après GET égal à la valeur demandée ;
- dry-run sans SET avec audit `DRY_RUN`, `SIMULATED`, `NO_WRITE` ;
- rollback uniquement explicite, vers le snapshot, avec GET de vérification ;
- audit avec auteur humain ou `SYSTEM`, sans secret SNMP/webhook ;
- `/health` strictement read-only ;
- menu CLI final, attention summary, filtres d'audit et System status réel.

## Migration et schéma final ADMINISTRATOR

La révision finale est `0004_linux_identity`, après
`0003_okapi_administrators`. Elle :

1. renomme `username` en `system_username` ;
2. renomme `last_login_at` en `last_seen_at` ;
3. ajoute `display_name` ;
4. supprime définitivement `password_hash` et `is_active` ;
5. recrée l'unicité et l'index sur `system_username` ;
6. conserve la FK nullable `audit_logs.administrator_id` avec
   `ON DELETE SET NULL`.

Schéma final :

```text
ADMINISTRATOR
  administrator_id  PK, UUID texte
  system_username   UNIQUE, NOT NULL
  display_name      NULL autorisé
  created_at        NOT NULL
  last_seen_at      NULL autorisé
```

La chaîne complète Alembic `0001 -> 0002 -> 0003 -> 0004` a été exécutée sur
une base SQLite neuve. Résultat : sept tables métier exactement et aucun champ
de mot de passe dans `administrators`. Une seconde validation a inséré une
identité dans le schéma 0003, puis appliqué 0004 : `administrator_id` et
`username -> system_username` ont été préservés et le hash historique a été
supprimé.

## Identité Linux vers administrator_id

Au lancement de `okapi` :

```text
uid du processus / compte Linux
  -> pwd.getpwuid(os.geteuid())
  -> system_username + nom GECOS facultatif
  -> SELECT ADMINISTRATOR
  -> INSERT atomique si absent
  -> mise à jour last_seen_at
  -> administrator_id de session
  -> attribution des décisions et rollbacks dans AUDIT_LOG
```

Une course entre deux CLI est gérée par l'unicité SQL et une relecture après
`IntegrityError`. OKAPI ne contient plus de création, liste, changement de mot
de passe, désactivation, suppression ou rôle `SUPER_ADMIN`.

Le message final est :

```text
[ OKAPI ]


Welcome, <nom ou username>.
```

## Réauthentification système

Les actions critiques appellent `sudo -k`, puis `sudo -v` : le premier invalide
le timestamp d'authentification et le second demande une validation via la
pile PAM Linux. Le mot de passe est lu par `sudo` dans le terminal, jamais par
Python. Le code vérifie aussi que l'identité Linux n'a pas changé depuis le
début de la session.

Réauthentification obligatoire pour :

- approbation d'une remédiation disruptive réelle (`DRY_RUN OFF`) ;
- rollback, y compris sa demande en mode simulé ;
- activation ou désactivation du dry-run.

Un échec produit `SYSTEM_REAUTHENTICATION_FAILED`, auteur humain identifié,
résultat `REJECTED`, puis bloque l'action. Aucune activation SNMP n'est exposée
dans le menu ; `SNMP_WRITE_ENABLED` reste une configuration d'exploitation.

## Fonctionnement du dry-run

La valeur `.env` est la valeur initiale. Le menu `Dry-run mode -> Enable /
Disable` exige la réauthentification puis écrit atomiquement le fichier local
ignoré `data/runtime-settings.json` avec permissions restrictives lorsque le
système le permet.

```text
DRY_RUN ON
  -> snapshot et garde-fous applicables
  -> aucun appel set_integer
  -> incident SIMULATED / remediation DRY_RUN
  -> audit DRY_RUN / SIMULATED / NO_WRITE

DRY_RUN OFF
  -> SET possible seulement si tous les autres garde-fous passent
```

Un fichier runtime absent utilise la valeur de configuration. Un fichier
illisible, invalide ou modifié avec une valeur non booléenne force le dry-run
à ON. `System status` recharge la valeur effective et affiche :

```text
Dry-run mode             : ON
SNMP writes              : BLOCKED BY DRY-RUN
```

## Menu CLI final

```text
1   Pending incidents
2   All incidents
3   Incident details
4   Approve remediation
5   Reject remediation
6   Remediation history
7   Audit logs
8   Rollback
9   Dry-run mode
10  System status
L   Logout / Exit
```

L'historique et l'audit affichent `Approved by : <system_username>` pour une
action supervisée et `Executed by : SYSTEM` pour le traitement automatique.

## Correctifs des modes, de l’identité et des rollbacks

La première modification fonctionnelle est maintenant documentée en détail
dans [REMEDIATION_ROLLBACK_CHANGES.md](REMEDIATION_ROLLBACK_CHANGES.md). Elle
couvre les deux seuls modes exposés (`SUPERVISED` et `AUTOMATIC`), l’identité
humaine obligatoire pour une action supervisée, les snapshots avant/après, le
rollback VLAN dynamique sans valeur 20 codée en dur, les états `UP`/`DOWN`, le
blocage en cas de modification externe, l’ordre LIFO par cible et la séparation
entre l’historique complet et `Available Rollbacks`.

La migration `0005_applied_state` est requise pour ajouter les états réellement
appliqués. Les lignes historiques sans ces snapshots restent consultables mais
ne sont pas proposées comme rollbackables.

## Résultats des tests

Commande exécutée :

```text
pytest -q -p no:cacheprovider
```

Résultat final après les correctifs fonctionnels, le splash et les filtres
d’audit : **140 passed, 3 skipped**.

Les trois tests ignorés sont les tests d'intégration EVE-NG, désactivés par
défaut. Aucun test matériel réel n'a été prétendu ni exécuté dans cette
livraison. L'analyse syntaxique a aussi chargé les fichiers Python sans
erreur, et la migration Alembic complète a été validée sur SQLite neuf.

La couverture automatisée comprend notamment les sept routes, UNKNOWN sans
SET, webhook, Recovery, idempotence, TARGET_MISMATCH, IP→MAC, deux tentatives,
double whitelist, calendrier, WAITING immuable, REACTIVATE supervisé,
capability gate, cooldown, verrou même port, dry-run sans SET, rollback,
identité Linux, création automatique ADMINISTRATOR, auteur humain/SYSTEM,
réauthentification, System status et `/health` sans écriture.

## Capacités validées et éléments restant à valider

`LAB_VALIDATED` :

- plateforme exacte : Arista vEOS 4.29.2F ;
- portée : laboratoire EVE-NG uniquement ;
- sécurité : SNMPv3 authPriv, SHA-256, AES-256 ;
- objet : `Q-BRIDGE-MIB::dot1qPvid` ;
- GET et SET, uniquement avec tous les garde-fous ;
- rollback explicite vers `previous_vlan_id` avec GET.

`TO_BE_VALIDATED` :

- tout SET `IF-MIB::ifAdminStatus`, donc shutdown/réactivation réels ;
- équipements UniFi réels, lectures et écritures ;
- SNMPv3 TRAP et INFORM de bout en bout ;
- toute autre plateforme, version, combinaison de protocoles ou objet ;
- comportement multi-utilisateur/permissions SQLite sur le serveur cible.

## Tests E2E matériels restant à effectuer

1. Rejouer Zabbix -> webhook -> préparation -> approbation PAM -> PVID
   10/20 -> 18 -> GET -> audit sur Arista vEOS 4.29.2F.
2. Demander explicitement le rollback -> PVID précédent -> GET.
3. Confirmer dans EVE-NG l'existence et l'isolement total du VLAN 18 avant
   toute écriture.
4. Tester deux processus OKAPI concurrents sur le même port.
5. Valider TRAP et INFORM jusqu'à Zabbix, puis le POST JSON vers OKAPI.
6. Ne tester UniFi ou `ifAdminStatus` qu'après qualification séparée et mise à
   jour explicite de la matrice de capacités.

## Matrice finale de traçabilité

| DIAGRAMME / EXIGENCE | FONCTIONNALITÉ | FICHIER / COMPOSANT | TABLE / CONFIG | TEST | STATUT |
|---|---|---|---|---|---|
| Cas d'utilisation | Zabbix transmet un incident | `routes/webhook.py`, `incident_service.py` | INCIDENT, schéma JSON v1.0 | `test_webhook.py` | IMPLÉMENTÉ |
| Cas d'utilisation | Consulter incidents/détails/historique/audit | `cli/okapi.py`, `cli/incidents.py` | INCIDENT, REMEDIATION, AUDIT_LOG | `test_cli_identity.py`, modèles | IMPLÉMENTÉ |
| Cas d'utilisation | Approuver/refuser avec identité | `administrators.py`, `remediation.py`, CLI | ADMINISTRATOR, AUDIT_LOG | `test_administrators.py`, remediation | IMPLÉMENTÉ |
| Cas d'utilisation | Rollback demandé seulement par administrateur | `snmp_execution.py`, CLI | REMEDIATION snapshots | `test_snmp_execution.py` | IMPLÉMENTÉ / E2E À FAIRE |
| Cas d'utilisation | Activer/désactiver dry-run | `runtime_settings.py`, CLI | `runtime-settings.json` | `test_dry_run_status.py` | IMPLÉMENTÉ |
| Activité 1 | Validation source/token/schéma/périmètre | `routes/webhook.py`, `security.py`, `payload_validation.py` | schéma v1.0, `.env` | webhook/config tests | IMPLÉMENTÉ |
| Activité 1 | PROBLEM/Recovery/idempotence | `incident_service.py` | INCIDENT, AUDIT_LOG | webhook/recovery tests | IMPLÉMENTÉ |
| Activité 1 | Sept routes et UNKNOWN NO_ACTION | `rules.py`, playbooks JSON | `playbook_index.json` | routing/rules tests | IMPLÉMENTÉ |
| Activité 1 | IP→MAC→bridge→ifIndex→interface / TARGET_MISMATCH | `target_resolver.py`, `snmp_preparation.py` | NETWORK_HOST, SWITCH_PORT | target/preparation tests | IMPLÉMENTÉ |
| Activité 1 | Whitelist contrôle 1 | `remediation.py`, `whitelist.py` | `whitelist.json` | remediation/preparation tests | IMPLÉMENTÉ |
| Activité 1 | SUPERVISED/AUTOMATIC, WAITING immuable | `calendar_policy.py`, `rules.py` | `automation_schedule.json` | calendar/rules/remediation tests | IMPLÉMENTÉ |
| Activité 1 | Identité et décision administrateur | `administrators.py`, `cli/okapi.py` | ADMINISTRATOR, AUDIT_LOG | administrator/CLI tests | IMPLÉMENTÉ |
| Activité 2 | Whitelist contrôle 2 | `snmp_execution.py` | `whitelist.json` | execution test | IMPLÉMENTÉ |
| Activité 2 | Capability gate fail-closed | `capabilities.py`, `snmp_execution.py` | `snmp_capabilities.json` | MIB/execution tests | IMPLÉMENTÉ |
| Activité 2 | Cooldown et concurrence même port | `port_lock.py`, `snmp_execution.py` | REMEDIATION, env | cooldown/port-lock tests | IMPLÉMENTÉ / E2E À FAIRE |
| Activité 2 | Snapshot, dry-run, deux SET/GET, vérification | `snmp_preparation.py`, `snmp_execution.py` | REMEDIATION, AUDIT_LOG | preparation/execution tests | IMPLÉMENTÉ |
| Activité 2 | PVID Arista SET/GET | `SnmpRemediationClient` | capability Arista | integration opt-in | LAB_VALIDATED, NON REJOUÉ |
| Activité 2 | ifAdminStatus shutdown/reactivate | capability gate + transport | `TO_BE_VALIDATED` | fail-closed + dry-run | BLOQUÉ SÛREMENT |
| Activité 3 | Rollback explicite et restauration snapshot | `snmp_execution.py` | previous VLAN/status | rollback tests | IMPLÉMENTÉ / E2E À FAIRE |
| Diagramme de classes | Contrôles/services/entités | `app/services`, `app/models`, `app/snmp` | sept tables | model/service tests | ALIGNÉ |
| Diagramme de composants | Connecteur, règles, orchestration, SNMP, persistance, notification CLI | modules Flask | playbooks/config/SQLite | suite complète | ALIGNÉ |
| Déploiement cible | Backend local + CLI SSH | `deploy/systemd`, `deploy/install.sh` | `.env`, SQLite | procédure `/health` | PRÊT À INSTALLER |
| Déploiement expérimental | Arista vEOS 4.29.2F / EVE-NG / VLAN 18 | SNMP + capabilities | env laboratoire | tests integration opt-in | LAB_VALIDATED / E2E À REJOUER |
| MCD | Relations Incident/Remediation/Host/Port/Switch/Audit/Admin | modèles SQLAlchemy | sept entités | `test_mld_models.py` | ALIGNÉ |
| MLD | ADMINISTRATOR identité uniquement | modèle + migration 0004 | cinq colonnes finales | admin/MLD + migration manuelle | ALIGNÉ |
| Exigence sécurité | Aucun secret en audit | `audit.sanitize`, config env | AUDIT_LOG | `test_audit_security.py` | IMPLÉMENTÉ |
| Exigence santé | `/health` sans écriture | `routes/health.py` | lecture config/SQLite/MIB | `test_health.py` | IMPLÉMENTÉ |
