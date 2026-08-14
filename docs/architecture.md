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

Administrator
  -> OKAPI Flask CLI (authenticated local session)
       -> consulter incidents
       -> evaluer le contexte confirme
       -> approuver ou refuser
       -> consulter les journaux

Application
  -> client PySNMP authPriv read-only
  -> switch Cisco dans EVE-NG
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
  -> BLOCKED_SNMP_WRITE pendant la phase read-only
```

## Separation des responsabilites

- `routes/` expose HTTP sans logique SNMP.
- `services/` contient les regles metier et l'audit.
- `models/` contient la persistance SQLAlchemy.
- the seven business entities are `incidents`, `remediations`, `audit_logs`,
  `network_switches`, `switch_ports`, `network_hosts` and `administrators`;
  `audit_logs.administrator_id` is nullable: `ADMINISTRATOR 1 -> 0..N AUDIT_LOG`.
- `snmp/` ne contient que les lectures SNMPv3 et la decouverte.
- `cli/` expose les operations de l'administrateur.
- `playbooks/` reste la source JSON des regles propres aux incidents.
- `config/whitelist.json` protege les ports critiques sans table SQL.
- `config/automation_schedule.json` definit le calendrier d'automatisation.

## Politique automatique

L'autorisation automatique est une decision du moteur. Elle ne constitue pas
une preuve que l'equipement supporte l'action. L'execution exige encore les
capacites d'ecriture validees, une sauvegarde pre-action et un controle
post-action. Le passage d'un incident de jour vers la nuit ne transforme pas
une demande en attente en approbation.
