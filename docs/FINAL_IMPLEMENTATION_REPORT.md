# OKAPI final implementation report

## Initial state

- Reference branch: `feat/snmpv3-arista-remediation`.
- Preserved checkpoint: `d48f654`.
- Starting HEAD for this integration: `08fbb02`.
- Measured baseline: **62 passed, 3 skipped**.
- Final work isolated on `feat/final-okapi-integration`.

## Implemented decisions

- Canonical routing now covers the six named incident types plus UNKNOWN.
  UNKNOWN v1.1 and physical disconnection are strictly `NO_ACTION`.
- The external `Africa/Kinshasa` calendar controls authorization. During
  08:00–17:00 disruptive actions are supervised. Outside the supervised
  window only `SHUTDOWN_PORT` and `QUARANTINE_VLAN` can be pre-authorized;
  `REACTIVATE_PORT` is always supervised. A pending request never changes mode
  merely because time passes.
- A matching Zabbix recovery closes a pending request as
  `RECOVERED_BEFORE_ACTION`; it sends no SET and never rolls back automatically.
- IP conflict still requires a MAC. Port-centric incidents may use an
  independently confirmed switch + bridge port + ifIndex/interface without a
  MAC. A hint mismatch becomes `TARGET_MISMATCH` and fails closed.
- Whitelist checks remain both before authorization and immediately before SET.
- `QUARANTINE_VLAN` uses the centrally configured VLAN and restores the actual
  `previous_vlan_id`. Interface actions snapshot and restore the actual prior
  `ifAdminStatus`. No Rollback table was added.
- Writes use at most two SET/GET attempts, succeed only on confirming GET,
  enforce a 60-second cooldown, and serialize the same switch/port with a
  cross-process file lock. `DRY_RUN=true` overrides `SNMP_WRITE_ENABLED` for
  remediation and rollback, never invokes SET, and records `DRY_RUN` /
  `SIMULATED` with `snmp_set_executed=false` in the audit trail.
- `IF-MIB::ifAdminStatus` down/up code paths exist but the capability matrix
  remains `TO_BE_VALIDATED`, so they fail closed before SET. Only
  `Q-BRIDGE-MIB::dot1qPvid` on Arista vEOS 4.29.2F in EVE-NG is
  `LAB_VALIDATED`. UniFi remains `TO_BE_VALIDATED`.
- The direct `okapi` command is preserved. Its English menu now exposes all
  incidents, details, approval/rejection, remediation history, audit filters,
  rollback, system status, account creation, own-password change, account
  listing and disabling. Login displays persistent attention counts.
- `/health` checks SQLite, external policy files, capabilities, quarantine
  configuration and local MIB readiness using read-only operations.
- Gunicorn/systemd deployment is reproducible and bound to `127.0.0.1:5000`.
- SNMPv3 TRAP/INFORM is documented through snmptrapd/Zabbix; no parallel OKAPI
  detection receiver was created.

## Data model and migrations

The existing seven-table model remains sufficient. `Remediation.target_mac_address`
was already nullable and therefore supports port-centric incidents without a
destructive schema change. **No new Alembic migration was necessary.** The
latest migration remains `0003_okapi_administrators`; there is no Playbook,
Notification or Rollback table.

## Important files

- Playbooks: `playbooks/playbook_index.json`, the three new canonical JSON
  files, and updated LOOP/IP-CONFLICT authorization metadata.
- Policies/orchestration: `app/services/rules.py`, `remediation.py`,
  `incident_service.py`, `snmp_preparation.py`, `snmp_execution.py`, and the
  new `port_lock.py`.
- Interface and operations: `app/cli/okapi.py`, other CLI modules,
  `app/routes/webhook.py`, `app/routes/health.py`, `config.py`, `.env.example`.
- Deployment: `deploy/systemd/okapi-backend.service`, `deploy/install.sh`,
  `deploy/zabbix/snmptrapd.conf.example` and `deploy/README.md`.
- Documentation: README, architecture, webhook configuration and
  `docs/ZABBIX_SNMPV3_TRAP_INFORM.md`.

## Deployment commands

```bash
cd /home/exauceeadm/tfc-remediation-reseau-snmpv3
git fetch origin
git switch feat/final-okapi-integration
git pull --ff-only origin feat/final-okapi-integration
.venv/bin/pip install -e .
.venv/bin/flask --app run.py db upgrade
sudo bash deploy/install.sh
okapi
```

Before an application rollback, back up `data/remediation.db`. Switch to the
preserved commit, reinstall the editable package, apply only migrations valid
for that revision, and restart `okapi-backend`. Never force-push or delete the
SQLite database.

## Experimental validation status

`LAB_VALIDATED`: PVID GET/SET for exact Arista vEOS 4.29.2F in EVE-NG with
SNMPv3 authPriv SHA-256/AES-256, subject to every software guard.

`TO_BE_VALIDATED`: Arista `ifAdminStatus` SET down/up, UniFi reads/writes,
TRAP end-to-end, INFORM end-to-end, and all new complete Zabbix-to-SQLite
scenarios. The code deliberately blocks an unvalidated SET.

Required E2E work: run interface-admin-down, port-flapping and VLAN-policy
events through Zabbix → webhook → confirmation → policy → guarded SET → GET →
audit. Revalidate VLAN 20 → 18 and explicit rollback to 20. Test two processes
on the same port and both TRAP and INFORM through Zabbix.

## Traceability matrix

| Diagram / requirement | Functionality | Component/file | Table/config | Test | Status |
|---|---|---|---|---|---|
| Use case | Zabbix reports incident | webhook + incident service | INCIDENT / schema v1.0 | webhook tests | PASS |
| Use case | Administrator authentication | administrator service / OKAPI CLI | ADMINISTRATOR | administrator tests | PASS |
| Activity | Seven-route selection | rules + playbook index | playbooks JSON | final routing tests | PASS |
| Activity | UNKNOWN safety fallback | rules | PB-UNKNOWN-001 | rule/routing tests | PASS |
| Activity | Target confirmation | SNMP preparation | NETWORK_HOST / SWITCH_PORT | target preparation tests | PASS |
| Activity | Port target without MAC | port preparation | REMEDIATION nullable MAC | port-centric test | PASS |
| Activity | Whitelist twice | remediation + execution | whitelist.json | service/execution tests | PASS |
| Activity | Mixed authorization policy | calendar + rules | automation_schedule.json / REMEDIATION | calendar/rule tests | PASS |
| Activity | Recovery before action | webhook + incident service | INCIDENT / AUDIT_LOG | recovery test | PASS |
| Activity | Cooldown and serialization | execution + port lock | REMEDIATION / env config | unit path + E2E pending | CODE PASS / E2E PENDING |
| Sequence | PVID SET/GET | SNMP execution | capabilities.json | execution tests | LAB_VALIDATED |
| Sequence | ifAdminStatus down/up | SNMP execution | capabilities.json | capability-gate path | TO_BE_VALIDATED |
| Sequence | Two attempts and GET proof | SNMP execution | AUDIT_LOG | mismatch/retry tests | PASS |
| Sequence | Explicit rollback | SNMP execution | REMEDIATION snapshots | rollback tests | PASS / IF E2E PENDING |
| Components | Persistent CLI notification | OKAPI attention summary | INCIDENT / REMEDIATION / AUDIT_LOG | CLI/service coverage | PASS |
| MLD | Seven business entities | models | SQLite | model tests | PASS |
| MLD | Administrator audit relation | models/audit | ADMINISTRATOR / AUDIT_LOG | administrator/model tests | PASS |
| Deployment | Local Gunicorn backend | systemd/install artifacts | `.env` / service unit | curl `/health` documented | READY |
| Deployment | TRAP/INFORM via Zabbix | snmptrapd template/docs | Zabbix config | laboratory procedure | TO_BE_VALIDATED |
| Health | Read-only dependency checks | health route | policies/MIB/SQLite | health test | PASS |

## Automated tests

Run with `pytest -q`. EVE-NG tests remain opt-in and are never started by the
normal unit suite. The exact final result is recorded in the delivery commit
and handoff message.
