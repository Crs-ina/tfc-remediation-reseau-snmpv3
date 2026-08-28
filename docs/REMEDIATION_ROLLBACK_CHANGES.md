# Correction des modes, de l’identité et des rollbacks

Ce document décrit la première série de modifications fonctionnelles apportées
à OKAPI : simplification des modes d’autorisation, attribution correcte de
l’exécutant, restauration exacte de l’état réseau et séparation entre
l’historique et les rollbacks encore disponibles.

## 1. Modes d’autorisation exposés

OKAPI n’expose plus que deux modes métier :

```text
SUPERVISED
AUTOMATIC
```

`PREAUTHORIZED` et `HUMAN_APPROVAL` ne constituent pas des modes présentés à
l’administrateur. `AUTOMATICALLY_AUTHORIZED` peut subsister comme état interne
du cycle de traitement ; la remédiation associée conserve toutefois
`authorization_mode=AUTOMATIC`.

`REACTIVATE_PORT` reste supervisé. Une politique automatique ne suffit pas à
rendre cette action exécutable et ne contourne jamais les contrôles de
capacité SNMP.

## 2. Identité de l’auteur

La règle appliquée dans l’historique, les audits, les approbations, les refus
et les rollbacks est la suivante :

```text
SUPERVISED -> Approved by : <compte Linux authentifié>
AUTOMATIC  -> Executed by : SYSTEM
ROLLBACK   -> Requested by : <compte Linux authentifié>
```

Le compte provient de l’administrateur associé à la session courante. Aucun
nom d’utilisateur n’est codé en dur. Une remédiation `SUPERVISED` sans audit
d’approbation humaine est refusée avant l’écriture SNMP ; elle ne retombe pas
silencieusement sur `SYSTEM`.

Aucun champ métier ou libellé `Reason` n’a été ajouté à l’interface.

## 3. États persistés pour une restauration sûre

Une remédiation conserve maintenant les deux côtés du changement :

| Action | État avant action | État confirmé après action |
| --- | --- | --- |
| `QUARANTINE_VLAN` | `previous_vlan_id` | `applied_vlan_id` |
| `SHUTDOWN_PORT` / `REACTIVATE_PORT` | `previous_port_status` | `applied_port_status` |

La migration `0005_applied_state` ajoute `applied_vlan_id` et
`applied_port_status` à la table `remediations`. Les anciennes lignes restent
dans l’historique, mais ne deviennent pas rollbackables si leur état appliqué
n’est pas connu : OKAPI ne tente pas de le deviner.

Après mise à jour du code, appliquer la migration :

```bash
flask --app run.py db upgrade
```

## 4. Rollback VLAN dynamique

Le VLAN de retour n’est jamais une constante. La séquence est :

```text
GET VLAN initial
SAVE previous_vlan_id
SET VLAN de quarantaine
GET et SAVE applied_vlan_id

Rollback demandé par un administrateur
GET VLAN courant
COMPARE avec applied_vlan_id
SET previous_vlan_id
GET de vérification
```

Exemples couverts :

```text
VLAN 10 -> quarantaine 18 -> rollback 10
VLAN  8 -> quarantaine 18 -> rollback  8
```

La valeur `20` n’est donc ni un VLAN de restauration par défaut, ni remplacée
par une autre constante.

## 5. Rollback de l’état administratif

Le modèle conserve `previous_port_status` et `applied_port_status`, et le
dry-run peut représenter la séquence attendue :

```text
UP -> SHUTDOWN_PORT -> DOWN -> rollback -> UP
```

Cette séquence n’est pas exécutable réellement dans la version actuelle.
`IF-MIB::ifAdminStatus` reste `TO_BE_VALIDATED`, le service d’exécution bloque
le chemin réel et la frontière de transport SET n’accepte que
`Q-BRIDGE-MIB::dot1qPvid`. Par conséquent, ni le shutdown/réactivation ni leur
rollback n’envoient actuellement de SET `ifAdminStatus`.

Les valeurs SNMP `1` et `2` restent utilisables en interne, mais l’interface
affiche `UP` et `DOWN` dans `Current state` et `Restore to`.

## 6. Protection contre une modification externe

Avant tout SET de rollback VLAN, OKAPI relit l’état réel sous le verrou du port.
Si cet état ne correspond plus à l’état appliqué par la remédiation, aucun SET
n’est envoyé. Le même garde-fou existe dans le chemin préparatoire
`ifAdminStatus`, mais ce chemin reste bloqué avant toute écriture réelle.

Exemple :

```text
Previous VLAN         : 10
Applied VLAN          : 18
Observed before undo  : 20
Result                : ROLLBACK_BLOCKED
```

L’audit `ROLLBACK_BLOCKED_STATE_CHANGED` enregistre l’état attendu, l’état
observé et `manual_verification_required=true`. Une vérification manuelle est
alors nécessaire.

## 7. Historique et rollbacks disponibles

`Remediation History` conserve toutes les opérations, sans limite artificielle
à vingt lignes. Il inclut notamment `SUCCEEDED`, `FAILED`,
`RECOVERED_BEFORE_ACTION`, `NOT_AUTHORIZED` lorsqu’il existe dans les données,
`ROLLBACK_BLOCKED` et `ROLLED_BACK`.

`Available Rollbacks` ne retient qu’une remédiation qui :

1. a le statut `SUCCEEDED` ;
2. correspond à une action rollbackable ;
3. possède un état précédent et un état appliqué ;
4. possède encore une cible switch/port valide ;
5. n’a pas déjà été rollbackée ;
6. est la modification active la plus récente de cette cible.

Les résultats `FAILED` et `RECOVERED_BEFORE_ACTION` restent donc visibles dans
l’historique, mais jamais dans la liste des rollbacks disponibles. Une action
`ROLLED_BACK` disparaît de cette liste sans être supprimée de l’historique.

Pour plusieurs changements sur le même port, la restauration suit un ordre
LIFO : le changement le plus récent doit être annulé en premier. Un rollback
plus ancien ne peut pas écraser un état plus récent.

## 8. Traçabilité d’un rollback

Le demandeur doit être un administrateur identifié et réauthentifié. Les
événements `ROLLBACK_REQUESTED`, `SNMP_ROLLBACK_SUCCEEDED`,
`ROLLBACK_BLOCKED_STATE_CHANGED` ou l’échec correspondant sont liés à son
`administrator_id`.

En cas de réussite, les détails d’audit comprennent l’état avant rollback,
l’état restauré et l’identifiant du demandeur. Le statut de la remédiation et
de l’incident devient `ROLLED_BACK` seulement après le GET de confirmation.

## 9. System status simplifié

Le menu opérationnel n’affiche plus `Backend : RUNNING` ni `Database : OK`.
Il présente le compte connecté et les contrôles utiles à l’exploitation :

```text
Administrator            : exauceeadm
Zabbix integration       : READY
SNMPv3                   : READY
SNMP writes              : ENABLED ou état de blocage
Dry-run mode             : ON/OFF
Authorization mode       : SUPERVISED/AUTOMATIC
Quarantine VLAN          : 18
Remediation cooldown     : 60 s
```

## 10. Fichiers concernés

- `app/models/remediation.py` : persistance de l’état appliqué ;
- `migrations/versions/0005_remediation_applied_state.py` : migration SQL ;
- `app/services/calendar_policy.py` et `app/services/rules.py` : deux modes
  exposés seulement ;
- `app/services/remediation.py` : propagation du mode et de l’identité ;
- `app/services/snmp_execution.py` : snapshots, filtrage, ordre LIFO,
  comparaison de l’état réel et audit du rollback ;
- `app/cli/okapi.py` : historique, rollbacks disponibles et System status ;
- `tests/test_snmp_execution.py` et `tests/test_okapi_remediation_views.py` :
  scénarios d’acceptation et rendu administrateur.

## 11. Validation automatisée

Les tests couvrent explicitement :

- restauration des VLAN 10 et 8 après quarantaine dans le VLAN 18 ;
- absence de SET si le VLAN est passé manuellement à 20 ;
- rendu dry-run `DOWN -> UP` avec libellés lisibles, sans SET réel ;
- blocage du chemin réel `ifAdminStatus` avant toute écriture ;
- identité `SUPERVISED` et identité `AUTOMATIC` ;
- exclusion de `FAILED` et `RECOVERED_BEFORE_ACTION` des rollbacks ;
- retrait d’une action déjà rollbackée ;
- ordre LIFO pour plusieurs remédiations de la même cible ;
- absence du champ `Reason` dans les vues administrateur.

Commande de validation :

```bash
pytest -q tests/test_snmp_execution.py tests/test_okapi_remediation_views.py
pytest -q
```
