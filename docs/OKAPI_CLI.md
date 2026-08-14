# OKAPI CLI

Start with `flask --app run.py okapi`. The login session lives only in the
running terminal process, so separate SSH terminals have separate sessions.
The normal menu never prints internal IDs and records human actions with the
authenticated administrator.

For maintenance, `flask --app run.py incidents list --from "2026-01-08 16:00"
--to "2026-01-08 17:00"` and `incidents logs` support the same local-time
filters. SNMP discovery remains read-only. SNMP SET and rollback stay behind
the capability, whitelist, isolation and `SNMP_WRITE_ENABLED` safeguards.
