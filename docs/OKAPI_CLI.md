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

Audit and remediation history display `Approved by : <username>` for
supervised actions and `Executed by : SYSTEM` for automatic actions. Dry-run
changes persist in the ignored local runtime
settings file and System status always displays the effective ON/OFF value.

The complete specification for authorization modes, executor identity,
dynamic VLAN/interface rollback, Available Rollbacks filtering and audit
events is in [REMEDIATION_ROLLBACK_CHANGES.md](REMEDIATION_ROLLBACK_CHANGES.md).

## Audit log filters

`Audit logs > Filter logs` accepts these independent optional fields:

```text
Date / period (YYYY, YYYY-MM, or YYYY-MM-DD; blank = any)
Search word or phrase (blank = any)
```

The date is progressive: `2026` selects the whole year, `2026-08` the whole
month and `2026-08-20` the complete local day in `Africa/Kinshasa`. OKAPI
converts those local bounds to UTC before querying `event_timestamp`.

The second field is a case-insensitive free search across the complete useful
context: date, event, incident type/description, action, result, administrator,
switch, equipment/target addresses, port and audit message. It also searches
the linked remediation and inventory when an older audit row does not repeat
all that context. A phrase is split into words, so `VLAN policy` matches a
stored value such as `VLAN_POLICY_VIOLATION`, and `port flapping` matches
`port_flapping`. Every word must be present somewhere in the same audit
context; the words do not have to belong to the same database column. A blank
search returns every entry in the selected period.

Filtered searches return all matches. `Latest logs` remains unchanged and
continues to select the latest 20 entries. Both modes render each entry as a
readable audit card containing date/time, action, result, administrator, switch
and port. When a remediation is linked, `Result` shows its final status. When an
older audit row does not duplicate its switch, port or action, OKAPI obtains
that context from the linked remediation record.

For maintenance, `flask --app run.py incidents list --from "2026-01-08 16:00"
--to "2026-01-08 17:00"` and `incidents logs` support local-time filters.
SNMP discovery remains read-only. Real writes remain behind target,
whitelist, capability, snapshot, isolation, cooldown, concurrency,
`SNMP_WRITE_ENABLED` and post-GET safeguards.
