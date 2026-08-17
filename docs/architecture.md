# Architecture du prototype

## Monolithe modulaire

```text
Zabbix
  -> HTTP POST /api/v1/incidents/zabbix
  -> Blueprint Flask
  -> validation et authentification
  -> service d'incidents
  -> moteur de regles
       -> playbook
       -> whitelist
       -> calendrier
  -> service de remediation
  -> verification
  -> audit SQLAlchemy / SQLite
  -> persistent CLI attention summary

Administrator
  -> Linux/SSH authenticated session
  -> OKAPI Flask CLI
       -> resolve/create ADMINISTRATOR audit identity
       -> sudo/PAM reauthentication for critical actions
       -> consulter incidents
       -> evaluer le contexte confirme
       -> approuver ou refuser
       -> consulter les journaux

Application
  -> client PySNMP authPriv read-only
  -> guarded remediation client
  -> Arista vEOS 4.29.2F in EVE-NG
```

## Etats principaux

```text
RECEIVED -> ROUTED -> IDENTIFYING_TARGET
                    -> ESCALATED
                    -> WAITING_ADMIN_APPROVAL
                       -> ADMIN_APPROVED
                       -> REJECTED_BY_ADMIN
                    -> AUTOMATICALLY_AUTHORIZED

ADMIN_APPROVED / AUTOMATICALLY_AUTHORIZED
  -> REMEDIATION_IN_PROGRESS
  -> VERIFYING
  -> REMEDIATED / FAILED / BLOCKED_SNMP_CAPABILITY / COOLDOWN_BLOCKED

WAITING_ADMIN_APPROVAL + Zabbix recovery
  -> RECOVERED_BEFORE_ACTION (no SET)
```

## Separation des responsabilites

- `routes/` expose HTTP sans logique SNMP.
- `services/` contient les regles metier et l'audit.
- `models/` contient la persistance SQLAlchemy.
- the seven business entities are `incidents`, `remediations`, `audit_logs`,
  `network_switches`, `switch_ports`, `network_hosts` and `administrators`;
  `audit_logs.administrator_id` is nullable: `ADMINISTRATOR 1 -> 0..N AUDIT_LOG`.
- `snmp/` separe le client read-only du transport de remediation, dont la
  frontiere SET n'accepte que `Q-BRIDGE-MIB::dot1qPvid`.
- `cli/` expose les operations de l'administrateur.
- `playbooks/` reste la source JSON des regles propres aux incidents.
- `config/whitelist.json` protege les ports critiques sans table SQL.
- `config/automation_schedule.json` definit le calendrier d'automatisation.
- `data/runtime-settings.json` conserve le dry-run effectif hors du MLD.

## Politique automatique

L'autorisation automatique est une decision du moteur. Elle ne constitue pas
une preuve que l'equipement supporte l'action. L'execution exige encore les
capacites d'ecriture validees, une sauvegarde pre-action et un controle
post-action. Le passage d'un incident de jour vers la nuit ne transforme pas
une demande en attente en approbation.

Outside the supervised window, only `SHUTDOWN_PORT` and `QUARANTINE_VLAN`
may be pre-authorized by the external calendar. `REACTIVATE_PORT` remains
always supervised. Every write path still applies target confirmation,
whitelist, capability, snapshot, cooldown, per-port serialization, at most two
SET attempts and GET verification.

## Seven playbook routes

`physical_disconnection`, `network_loop`, `ip_address_conflict`,
`interface_admin_down`, `port_flapping`, `vlan_policy_violation`, and the
UNKNOWN fallback are routed through canonical JSON playbooks. UNKNOWN and
physical disconnection are `NO_ACTION`; neither can reach an SNMP SET.

SNMPv3 TRAP/INFORM enters the Zabbix receiver chain, never a parallel Python
detector. Zabbix then sends the existing authenticated JSON webhook to OKAPI.
