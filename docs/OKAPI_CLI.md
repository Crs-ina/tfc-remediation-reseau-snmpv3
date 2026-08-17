# OKAPI CLI

Install the package in the deployment virtual environment and run:

```bash
okapi
```

The command obtains `system_username` from the Linux account that owns the
current SSH/session process. It finds or creates the corresponding row in
`administrators`, updates `last_seen_at`, and displays:

```text
[ OKAPI ]


Welcome, <display name or system username>.
```

Linux/SSH performs account management and primary authentication. OKAPI has no
Create/List/Disable/Delete administrator function and never stores a Linux
password or password hash.

The final menu is:

```text
Pending incidents
All incidents
Incident details
Approve remediation
Reject remediation
Remediation history
Audit logs
Rollback
Dry-run mode
System status
Logout / Exit
```

Approving a real disruptive remediation, requesting rollback, and enabling or
disabling dry-run invoke `sudo -k` followed by `sudo -v`. The password exchange
is performed by the system PAM stack directly in the terminal and is never
read by OKAPI. Failure is audited and the action is refused.

Audit and remediation history distinguish `Administrator : <username>` from
`Administrator : SYSTEM`. Dry-run changes persist in the ignored local runtime
settings file and System status always displays the effective ON/OFF value.

For maintenance, `flask --app run.py incidents list --from "2026-01-08 16:00"
--to "2026-01-08 17:00"` and `incidents logs` support local-time filters.
SNMP discovery remains read-only. Real writes remain behind target,
whitelist, capability, snapshot, isolation, cooldown, concurrency,
`SNMP_WRITE_ENABLED` and post-GET safeguards.
